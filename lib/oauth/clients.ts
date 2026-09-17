/**
 * lib/oauth/clients.ts
 *
 * Where an OAuth client comes from. Three kinds exist and none needs a table:
 *
 *  - Pre-registered clients live in MCP_OAUTH_CLIENTS, for hosts whose settings take an id and a
 *    secret.
 *  - Dynamically registered clients (RFC 7591) get a client_id that *is* their registration: the
 *    metadata, signed. Their secret, when they want one, is derived from the id with the same key,
 *    so it can be checked without having been stored.
 *  - Client ID Metadata Document clients use an HTTPS URL as their id; the document is fetched,
 *    checked and cached for a few minutes.
 */

import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import net from 'node:net';
import { getOAuthSecret, getStaticClients } from '../mcp/config.ts';

export type TokenEndpointAuthMethod = 'none' | 'client_secret_basic' | 'client_secret_post';

export type ClientRecord = {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  token_endpoint_auth_method: TokenEndpointAuthMethod;
  source: 'static' | 'dcr' | 'cimd';
};

export type RegistrationError = { error: string; error_description: string };

export type RegisteredClient = ClientRecord & {
  client_secret?: string;
  client_id_issued_at: number;
  grant_types: string[];
  response_types: string[];
};

const DCR_PREFIX = 'dcr.';
const AUTH_METHODS: TokenEndpointAuthMethod[] = ['none', 'client_secret_basic', 'client_secret_post'];

function hmac(purpose: string, data: string): Buffer {
  return crypto.createHmac('sha256', getOAuthSecret()).update(`${purpose}\n${data}`).digest();
}

function constantTimeEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

function isLoopback(url: URL): boolean {
  const host = url.hostname;
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
}

/** A redirect URI a public or confidential client may register: https, or http on the loopback. */
export function isAllowedRedirectUri(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.hash) return false;
  if (url.protocol === 'https:') return true;
  if (url.protocol === 'http:') return isLoopback(url);
  return false;
}

/**
 * Exact match, with the one relaxation OAuth 2.1 grants native apps: a loopback redirect may use
 * any port, because the app picks a free one when it starts.
 */
export function redirectUriMatches(registered: string, presented: string): boolean {
  if (registered === presented) return true;
  let a: URL;
  let b: URL;
  try {
    a = new URL(registered);
    b = new URL(presented);
  } catch {
    return false;
  }
  if (a.protocol !== 'http:' || b.protocol !== 'http:') return false;
  if (!isLoopback(a) || !isLoopback(b)) return false;
  return a.hostname === b.hostname && a.pathname === b.pathname && a.search === b.search;
}

/* ------------------------------------------------------------------------------------------ */
/* Dynamic Client Registration                                                                 */
/* ------------------------------------------------------------------------------------------ */

type DcrEnvelope = { n: string; r: string[]; a: TokenEndpointAuthMethod; t: number };

export function registerClient(metadata: unknown): RegisteredClient | RegistrationError {
  if (!metadata || typeof metadata !== 'object') {
    return { error: 'invalid_client_metadata', error_description: 'Body must be a JSON object' };
  }
  const m = metadata as Record<string, unknown>;

  const redirectUris = m.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0 || redirectUris.length > 10) {
    return {
      error: 'invalid_redirect_uri',
      error_description: 'redirect_uris must be a non-empty array of at most 10 URIs',
    };
  }
  for (const uri of redirectUris) {
    if (typeof uri !== 'string' || !isAllowedRedirectUri(uri)) {
      return {
        error: 'invalid_redirect_uri',
        error_description: `Redirect URI is not allowed: ${String(uri).slice(0, 200)}. Use https, or http on localhost.`,
      };
    }
  }

  const method = (m.token_endpoint_auth_method ?? 'none') as TokenEndpointAuthMethod;
  if (!AUTH_METHODS.includes(method)) {
    return {
      error: 'invalid_client_metadata',
      error_description: `token_endpoint_auth_method must be one of ${AUTH_METHODS.join(', ')}`,
    };
  }

  const grantTypes = Array.isArray(m.grant_types) && m.grant_types.length > 0 ? m.grant_types : ['authorization_code'];
  for (const g of grantTypes) {
    if (g !== 'authorization_code' && g !== 'refresh_token') {
      return { error: 'invalid_client_metadata', error_description: `Unsupported grant_type ${String(g)}` };
    }
  }
  const responseTypes = Array.isArray(m.response_types) && m.response_types.length > 0 ? m.response_types : ['code'];
  if (responseTypes.some((r) => r !== 'code')) {
    return { error: 'invalid_client_metadata', error_description: 'Only the "code" response_type is supported' };
  }

  const name = typeof m.client_name === 'string' && m.client_name.trim() ? m.client_name.trim().slice(0, 120) : 'MCP client';
  const issuedAt = Math.floor(Date.now() / 1000);
  const envelope: DcrEnvelope = { n: name, r: redirectUris as string[], a: method, t: issuedAt };
  const body = Buffer.from(JSON.stringify(envelope)).toString('base64url');
  const signature = hmac('dcr', body).toString('base64url');
  const clientId = `${DCR_PREFIX}${body}.${signature}`;

  return {
    client_id: clientId,
    client_name: name,
    redirect_uris: envelope.r,
    token_endpoint_auth_method: method,
    source: 'dcr',
    client_secret: method === 'none' ? undefined : clientSecretFor(clientId),
    client_id_issued_at: issuedAt,
    grant_types: grantTypes as string[],
    response_types: ['code'],
  };
}

function resolveDcrClient(clientId: string): ClientRecord | null {
  const rest = clientId.slice(DCR_PREFIX.length);
  const dot = rest.lastIndexOf('.');
  if (dot <= 0) return null;
  const body = rest.slice(0, dot);
  const signature = rest.slice(dot + 1);
  const expected = hmac('dcr', body).toString('base64url');
  if (!constantTimeEquals(signature, expected)) return null;
  let envelope: DcrEnvelope;
  try {
    envelope = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!envelope || !Array.isArray(envelope.r) || !AUTH_METHODS.includes(envelope.a)) return null;
  return {
    client_id: clientId,
    client_name: envelope.n,
    redirect_uris: envelope.r,
    token_endpoint_auth_method: envelope.a,
    source: 'dcr',
  };
}

/** The secret of a dynamically registered confidential client, derived rather than stored. */
export function clientSecretFor(clientId: string): string {
  return hmac('client_secret', clientId).toString('base64url');
}

/* ------------------------------------------------------------------------------------------ */
/* Client ID Metadata Documents                                                                */
/* ------------------------------------------------------------------------------------------ */

const CIMD_MAX_BYTES = 64 * 1024;
const CIMD_CACHE_TTL_MS = 5 * 60 * 1000;
const cimdCache = new Map<string, { record: ClientRecord; expiresAt: number }>();

let cimdFetch: typeof fetch = fetch;
let cimdResolveHost: (hostname: string) => Promise<string[]> = async (hostname) =>
  (await dns.lookup(hostname, { all: true })).map((a) => a.address);

/** Tests hand in a fetcher and a resolver so no document has to exist on the internet. */
export function setCimdTransportForTesting(
  fetcher: typeof fetch | null,
  resolver: ((hostname: string) => Promise<string[]>) | null
): void {
  cimdFetch = fetcher ?? fetch;
  cimdResolveHost =
    resolver ?? (async (hostname) => (await dns.lookup(hostname, { all: true })).map((a) => a.address));
  cimdCache.clear();
}

/** Addresses a server-side fetch must never reach: loopback, link-local, private ranges. */
export function isPrivateAddress(ip: string): boolean {
  const family = net.isIP(ip);
  if (family === 4) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }
  if (family === 6) {
    const lower = ip.toLowerCase();
    if (lower === '::' || lower === '::1') return true;
    if (lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd')) return true;
    if (lower.startsWith('::ffff:')) return isPrivateAddress(lower.slice(7));
    return false;
  }
  return true;
}

export function isCimdClientId(clientId: string): boolean {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:') return false;
  if (!url.pathname || url.pathname === '/') return false;
  if (url.hash || url.username || url.password) return false;
  if (net.isIP(url.hostname) !== 0) return false;
  const host = url.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    return false;
  }
  return true;
}

async function fetchCimd(clientId: string): Promise<ClientRecord | null> {
  const cached = cimdCache.get(clientId);
  if (cached && cached.expiresAt > Date.now()) return cached.record;

  const url = new URL(clientId);
  let addresses: string[];
  try {
    addresses = await cimdResolveHost(url.hostname);
  } catch {
    return null;
  }
  if (addresses.length === 0 || addresses.some(isPrivateAddress)) return null;

  let response: Response;
  try {
    response = await cimdFetch(clientId, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    return null;
  }
  if (!response.ok) return null;
  const text = await response.text();
  if (text.length > CIMD_MAX_BYTES) return null;

  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(text);
  } catch {
    return null;
  }
  if (!doc || typeof doc !== 'object') return null;
  if (doc.client_id !== clientId) return null;
  if (!Array.isArray(doc.redirect_uris) || doc.redirect_uris.length === 0) return null;
  if (!doc.redirect_uris.every((u) => typeof u === 'string' && isAllowedRedirectUri(u))) return null;
  // Only public clients come through a document. A client may prefer another method in the
  // singular field (ChatGPT's says private_key_jwt) while listing "none" among those it supports,
  // and then it uses "none" here because that is all the server metadata offers it.
  const supported = doc.token_endpoint_auth_methods_supported;
  const allowsNone = Array.isArray(supported)
    ? supported.includes('none')
    : (doc.token_endpoint_auth_method ?? 'none') === 'none';
  if (!allowsNone) return null;

  const record: ClientRecord = {
    client_id: clientId,
    client_name:
      typeof doc.client_name === 'string' && doc.client_name.trim()
        ? doc.client_name.trim().slice(0, 120)
        : url.hostname,
    redirect_uris: doc.redirect_uris as string[],
    token_endpoint_auth_method: 'none',
    source: 'cimd',
  };
  cimdCache.set(clientId, { record, expiresAt: Date.now() + CIMD_CACHE_TTL_MS });
  return record;
}

/* ------------------------------------------------------------------------------------------ */
/* Resolution and authentication                                                               */
/* ------------------------------------------------------------------------------------------ */

function resolveStaticClient(clientId: string): ClientRecord | null {
  const found = getStaticClients().find((c) => c.client_id === clientId);
  if (!found) return null;
  return {
    client_id: found.client_id,
    client_name: found.client_name ?? found.client_id,
    redirect_uris: found.redirect_uris,
    token_endpoint_auth_method: found.client_secret ? 'client_secret_basic' : 'none',
    source: 'static',
  };
}

export async function resolveClient(clientId: string): Promise<ClientRecord | null> {
  if (!clientId || clientId.length > 4096) return null;
  const fixed = resolveStaticClient(clientId);
  if (fixed) return fixed;
  if (clientId.startsWith(DCR_PREFIX)) return resolveDcrClient(clientId);
  if (isCimdClientId(clientId)) return fetchCimd(clientId);
  return null;
}

/**
 * Whether the credentials presented at the token endpoint belong to `client`. A public client
 * presents none and must present none; a confidential one must present its secret, by either
 * method, since the spec lets a client that registered one use the other.
 */
export function clientAuthenticates(client: ClientRecord, presentedSecret: string | null): boolean {
  if (client.token_endpoint_auth_method === 'none') return presentedSecret === null;
  if (presentedSecret === null) return false;
  if (client.source === 'static') {
    const stored = getStaticClients().find((c) => c.client_id === client.client_id)?.client_secret;
    return typeof stored === 'string' && constantTimeEquals(stored, presentedSecret);
  }
  return constantTimeEquals(clientSecretFor(client.client_id), presentedSecret);
}
