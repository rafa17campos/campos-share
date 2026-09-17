/**
 * lib/mcp/config.ts
 *
 * Configuration for the MCP endpoint and the OAuth authorization server it relies on. Everything
 * comes from the environment and, as everywhere else in this service, a missing value is an error
 * at the point of use rather than a silent default.
 */

import { getBaseUrl } from '../config.ts';

export const SCOPE_READ = 'files:read';
export const SCOPE_WRITE = 'files:write';
export const SCOPE_DELETE = 'files:delete';
export const ALL_SCOPES = [SCOPE_READ, SCOPE_WRITE, SCOPE_DELETE];

/**
 * Largest decoded payload `upload_file` accepts. Vercel rejects function bodies above 4.5 MB, and
 * base64 plus the JSON envelope adds roughly a third, so three mebibytes of file keeps the request
 * under the ceiling with room to spare.
 */
export const MAX_INLINE_BYTES = 3 * 1024 * 1024;

export const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
export const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
export const AUTH_CODE_TTL_SECONDS = 60;
export const AUTH_REQUEST_TTL_SECONDS = 10 * 60;

function required(name: string): string {
  const value = process.env[name];
  if (!value || value.trim().length === 0) {
    throw new Error(`${name} environment variable is required and must not be empty.`);
  }
  return value.trim();
}

/** The OAuth issuer is the service itself. */
export function getIssuer(): string {
  return getBaseUrl();
}

/** The canonical resource identifier of the MCP server (RFC 8707), and the token audience. */
export function getResourceUrl(): string {
  return `${getBaseUrl()}/mcp`;
}

/** Key that signs every token this server issues. Rotating it invalidates all of them. */
export function getOAuthSecret(): Uint8Array {
  const secret = required('MCP_OAUTH_SECRET');
  if (secret.length < 32) {
    throw new Error('MCP_OAUTH_SECRET must be at least 32 characters long.');
  }
  return new TextEncoder().encode(secret);
}

/** scrypt hash of the login passphrase, produced by `npm run passphrase:hash`. */
export function getPassphraseHash(): string {
  const hash = required('MCP_LOGIN_PASSPHRASE_HASH');
  if (!hash.startsWith('scrypt$')) {
    throw new Error('MCP_LOGIN_PASSPHRASE_HASH must be a hash produced by `npm run passphrase:hash`.');
  }
  return hash;
}

export type StaticToken = { token: string; scopes: string[] };

/**
 * Optional bearer token for terminal clients that cannot run an OAuth flow. Absent means the
 * feature is off. Its scopes default to read and write, never delete, unless configured.
 */
export function getStaticToken(): StaticToken | null {
  const token = process.env.MCP_STATIC_TOKEN?.trim();
  if (!token) return null;
  if (token.length < 32) {
    throw new Error('MCP_STATIC_TOKEN must be at least 32 characters long.');
  }
  const configured = process.env.MCP_STATIC_TOKEN_SCOPES?.trim();
  const scopes = configured ? configured.split(/\s+/) : [SCOPE_READ, SCOPE_WRITE];
  const unknown = scopes.find((s) => !ALL_SCOPES.includes(s));
  if (unknown) {
    throw new Error(`MCP_STATIC_TOKEN_SCOPES contains an unknown scope "${unknown}".`);
  }
  return { token, scopes };
}

/**
 * Origins allowed to reach `/mcp` from a browser. `*` (the default) accepts any origin: the
 * endpoint holds no ambient authority, every call carries a bearer token, so cross-origin calls
 * cannot borrow a session. A list of hostnames turns on strict Origin validation.
 */
export function getAllowedOrigins(): '*' | string[] {
  const raw = process.env.MCP_ALLOWED_ORIGINS?.trim();
  if (!raw || raw === '*') return '*';
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      try {
        return new URL(s).hostname;
      } catch {
        return s;
      }
    });
}

/** Language stamped on shares the MCP tools create; the API requires one. */
export function getDefaultLang(): string {
  return process.env.SHARE_DEFAULT_LANG?.trim() || 'es';
}

export type StaticClient = {
  client_id: string;
  client_secret?: string;
  client_name?: string;
  redirect_uris: string[];
};

/**
 * Optional pre-registered OAuth clients, for hosts whose connector settings take a client id and
 * secret instead of registering themselves. JSON array in MCP_OAUTH_CLIENTS.
 */
export function getStaticClients(): StaticClient[] {
  const raw = process.env.MCP_OAUTH_CLIENTS?.trim();
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('MCP_OAUTH_CLIENTS must be a JSON array.');
  }
  if (!Array.isArray(parsed)) {
    throw new Error('MCP_OAUTH_CLIENTS must be a JSON array.');
  }
  return parsed.map((entry, i) => {
    const c = entry as Partial<StaticClient>;
    if (!c || typeof c.client_id !== 'string' || !c.client_id) {
      throw new Error(`MCP_OAUTH_CLIENTS[${i}] needs a client_id.`);
    }
    if (!Array.isArray(c.redirect_uris) || c.redirect_uris.some((u) => typeof u !== 'string')) {
      throw new Error(`MCP_OAUTH_CLIENTS[${i}] needs a redirect_uris array of strings.`);
    }
    return {
      client_id: c.client_id,
      client_secret: typeof c.client_secret === 'string' ? c.client_secret : undefined,
      client_name: typeof c.client_name === 'string' ? c.client_name : undefined,
      redirect_uris: c.redirect_uris,
    };
  });
}
