/**
 * lib/oauth/handlers.ts
 *
 * The authorization server, as web-standard request handlers so the Next.js routes are one line
 * each and the tests can drive the whole flow without a socket. It implements the subset of
 * OAuth 2.1 the MCP authorization spec asks for: authorization code with PKCE S256, refresh
 * tokens, RFC 8414 metadata, RFC 9728 resource metadata, RFC 7591 registration, Client ID
 * Metadata Documents, RFC 8707 resource binding and the RFC 9207 `iss` parameter.
 *
 * There is one resource owner. Authenticating is proving knowledge of the passphrase whose scrypt
 * hash lives in the environment; that same step is the consent.
 */

import { verifyPassword, runDummyPasswordCheck } from '../auth.ts';
import {
  ACCESS_TOKEN_TTL_SECONDS,
  ALL_SCOPES,
  getIssuer,
  getPassphraseHash,
  getResourceUrl,
} from '../mcp/config.ts';
import { corsHeaders, preflight } from '../mcp/cors.ts';
import { clientAddress, loginLimiter, registrationLimiter, tokenLimiter } from '../mcp/ratelimit.ts';
import { clientAuthenticates, redirectUriMatches, registerClient, resolveClient, type ClientRecord } from './clients.ts';
import { renderAuthorizePage, renderErrorPage } from './pages.ts';
import {
  pkceChallengeMatches,
  signAccessToken,
  signAuthRequest,
  signCode,
  signRefreshToken,
  verifyAuthRequest,
  verifyCode,
  verifyRefreshToken,
  type PendingAuthorization,
} from './tokens.ts';

/** The subject every token names. There is exactly one person this server speaks for. */
const OWNER_SUBJECT = 'owner';

const NO_STORE = { 'Cache-Control': 'no-store', Pragma: 'no-cache' };

function json(body: unknown, status: number, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...NO_STORE, ...extra },
  });
}

function html(body: string, status: number): Response {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', ...NO_STORE, 'X-Robots-Tag': 'noindex, nofollow' },
  });
}

function oauthError(error: string, description: string, status = 400, extra: Record<string, string> = {}) {
  return json({ error, error_description: description }, status, extra);
}

/* ------------------------------------------------------------------------------------------ */
/* Discovery                                                                                   */
/* ------------------------------------------------------------------------------------------ */

export function authorizationServerMetadata(): Record<string, unknown> {
  const issuer = getIssuer();
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/oauth/register`,
    scopes_supported: ALL_SCOPES,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
  };
}

export function protectedResourceMetadata(): Record<string, unknown> {
  return {
    resource: getResourceUrl(),
    authorization_servers: [getIssuer()],
    scopes_supported: ALL_SCOPES,
    bearer_methods_supported: ['header'],
    resource_name: 'campos-share files',
  };
}

function discoveryResponse(request: Request, body: unknown): Response {
  if (request.method === 'OPTIONS') return preflight(request, 'GET, OPTIONS');
  if (request.method !== 'GET') {
    return new Response(null, { status: 405, headers: { Allow: 'GET, OPTIONS' } });
  }
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=300',
      ...corsHeaders(request, 'GET, OPTIONS'),
    },
  });
}

export function handleAuthorizationServerMetadata(request: Request): Response {
  return discoveryResponse(request, authorizationServerMetadata());
}

export function handleProtectedResourceMetadata(request: Request): Response {
  return discoveryResponse(request, protectedResourceMetadata());
}

/* ------------------------------------------------------------------------------------------ */
/* Dynamic Client Registration                                                                 */
/* ------------------------------------------------------------------------------------------ */

export async function handleRegister(request: Request): Promise<Response> {
  if (request.method === 'OPTIONS') return preflight(request, 'POST, OPTIONS');
  if (request.method !== 'POST') {
    return new Response(null, { status: 405, headers: { Allow: 'POST, OPTIONS' } });
  }
  const cors = corsHeaders(request, 'POST, OPTIONS');
  const limit = registrationLimiter.hit(clientAddress(request));
  if (!limit.allowed) {
    return oauthError('temporarily_unavailable', 'Too many registrations; try again later', 429, {
      'Retry-After': String(limit.retryAfterSeconds),
      ...cors,
    });
  }

  let metadata: unknown;
  try {
    metadata = await request.json();
  } catch {
    return oauthError('invalid_client_metadata', 'Body must be JSON', 400, cors);
  }

  const result = registerClient(metadata);
  if ('error' in result) return json(result, 400, cors);

  const { source: _source, ...client } = result;
  return json(
    {
      ...client,
      client_secret_expires_at: client.client_secret ? 0 : undefined,
    },
    201,
    cors
  );
}

/* ------------------------------------------------------------------------------------------ */
/* Authorization endpoint                                                                      */
/* ------------------------------------------------------------------------------------------ */

function redirectTo(redirectUri: string, params: Record<string, string | undefined>): Response {
  const url = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) url.searchParams.set(k, v);
  }
  return new Response(null, { status: 303, headers: { Location: url.toString(), ...NO_STORE } });
}

function redirectError(redirectUri: string, state: string | undefined, error: string, description: string): Response {
  return redirectTo(redirectUri, { error, error_description: description, state, iss: getIssuer() });
}

type ResolvedRedirect = { client: ClientRecord; redirectUri: string } | Response;

/** The client and redirect must both check out before anything is sent back to the redirect. */
async function resolveRedirect(params: URLSearchParams): Promise<ResolvedRedirect> {
  const clientId = params.get('client_id');
  if (!clientId) return html(renderErrorPage('Invalid request', 'The request names no client_id.'), 400);

  const client = await resolveClient(clientId);
  if (!client) {
    return html(
      renderErrorPage(
        'Unknown client',
        'The client_id is not registered here and is not a reachable Client ID Metadata Document.'
      ),
      400
    );
  }

  const presented = params.get('redirect_uri');
  if (presented) {
    if (!client.redirect_uris.some((r) => redirectUriMatches(r, presented))) {
      return html(renderErrorPage('Invalid redirect', 'The redirect_uri does not match the client registration.'), 400);
    }
    return { client, redirectUri: presented };
  }
  if (client.redirect_uris.length === 1) return { client, redirectUri: client.redirect_uris[0] };
  return html(renderErrorPage('Invalid request', 'The request names no redirect_uri.'), 400);
}

async function authorizeGet(request: Request): Promise<Response> {
  const params = new URL(request.url).searchParams;
  const resolved = await resolveRedirect(params);
  if (resolved instanceof Response) return resolved;
  const { client, redirectUri } = resolved;
  const state = params.get('state') ?? undefined;

  if (params.get('response_type') !== 'code') {
    return redirectError(redirectUri, state, 'unsupported_response_type', 'Only response_type=code is supported');
  }
  const challenge = params.get('code_challenge');
  if (!challenge || !/^[A-Za-z0-9\-_]{43}$/.test(challenge)) {
    return redirectError(redirectUri, state, 'invalid_request', 'A PKCE code_challenge (S256) is required');
  }
  if ((params.get('code_challenge_method') ?? 'plain') !== 'S256') {
    return redirectError(redirectUri, state, 'invalid_request', 'code_challenge_method must be S256');
  }
  const resource = params.get('resource');
  if (resource && resource !== getResourceUrl()) {
    return redirectError(redirectUri, state, 'invalid_target', `Unknown resource; this server is ${getResourceUrl()}`);
  }
  const requestedScopes = (params.get('scope') ?? '').split(/\s+/).filter(Boolean);
  const unknown = requestedScopes.find((s) => !ALL_SCOPES.includes(s));
  if (unknown) {
    return redirectError(redirectUri, state, 'invalid_scope', `Unknown scope "${unknown}"`);
  }
  const scope = requestedScopes.length > 0 ? Array.from(new Set(requestedScopes)) : ALL_SCOPES;

  const pending: PendingAuthorization = {
    client_id: client.client_id,
    client_name: client.client_name,
    redirect_uri: redirectUri,
    scope,
    state,
    code_challenge: challenge,
    resource: getResourceUrl(),
  };
  return html(
    renderAuthorizePage({
      action: `${getIssuer()}/oauth/authorize`,
      clientName: client.client_name,
      clientId: client.client_id,
      scopes: scope,
      requestToken: await signAuthRequest(pending),
    }),
    200
  );
}

async function authorizePost(request: Request): Promise<Response> {
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return html(renderErrorPage('Invalid request', 'The form could not be read.'), 400);
  }
  const requestToken = String(form.get('request') ?? '');
  const pending = requestToken ? await verifyAuthRequest(requestToken) : null;
  if (!pending) {
    return html(
      renderErrorPage('Request expired', 'The authorization request has expired. Start again from the application.'),
      400
    );
  }

  if (String(form.get('decision')) !== 'allow') {
    return redirectError(pending.redirect_uri, pending.state, 'access_denied', 'The resource owner denied the request');
  }

  const rerender = (error: string, status: number) =>
    html(
      renderAuthorizePage({
        action: `${getIssuer()}/oauth/authorize`,
        clientName: pending.client_name,
        clientId: pending.client_id,
        scopes: pending.scope,
        requestToken,
        error,
      }),
      status
    );

  const limit = loginLimiter.hit(clientAddress(request));
  if (!limit.allowed) {
    await runDummyPasswordCheck();
    return rerender(`Too many attempts. Try again in ${limit.retryAfterSeconds} seconds.`, 429);
  }

  const passphrase = String(form.get('passphrase') ?? '');
  const ok = passphrase.length > 0 && (await verifyPassword(passphrase, getPassphraseHash()));
  if (!ok) {
    if (passphrase.length === 0) await runDummyPasswordCheck();
    return rerender('That passphrase is not right.', 200);
  }

  const code = await signCode({ ...pending, sub: OWNER_SUBJECT });
  return redirectTo(pending.redirect_uri, { code, state: pending.state, iss: getIssuer() });
}

export async function handleAuthorize(request: Request): Promise<Response> {
  if (request.method === 'GET') return authorizeGet(request);
  if (request.method === 'POST') return authorizePost(request);
  return new Response(null, { status: 405, headers: { Allow: 'GET, POST' } });
}

/* ------------------------------------------------------------------------------------------ */
/* Token endpoint                                                                              */
/* ------------------------------------------------------------------------------------------ */

async function readTokenRequest(request: Request): Promise<URLSearchParams | null> {
  const contentType = request.headers.get('content-type') ?? '';
  try {
    if (contentType.includes('application/x-www-form-urlencoded')) {
      return new URLSearchParams(await request.text());
    }
    if (contentType.includes('application/json')) {
      const body = await request.json();
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(body ?? {})) {
        if (typeof v === 'string') params.set(k, v);
      }
      return params;
    }
  } catch {
    return null;
  }
  return null;
}

type ClientCredentials = { clientId: string | null; secret: string | null; viaHeader: boolean };

function readClientCredentials(request: Request, params: URLSearchParams): ClientCredentials | Response {
  const header = request.headers.get('authorization');
  if (header && /^basic\s/i.test(header)) {
    let decoded: string;
    try {
      decoded = Buffer.from(header.slice(6).trim(), 'base64').toString('utf8');
    } catch {
      return oauthError('invalid_client', 'Malformed Authorization header', 401);
    }
    const colon = decoded.indexOf(':');
    if (colon < 0) return oauthError('invalid_client', 'Malformed Authorization header', 401);
    const clientId = decodeURIComponent(decoded.slice(0, colon));
    const secret = decodeURIComponent(decoded.slice(colon + 1));
    const bodyClientId = params.get('client_id');
    if (bodyClientId && bodyClientId !== clientId) {
      return oauthError('invalid_request', 'client_id in the body does not match the Authorization header');
    }
    return { clientId, secret, viaHeader: true };
  }
  return { clientId: params.get('client_id'), secret: params.get('client_secret'), viaHeader: false };
}

async function issueTokens(input: { client_id: string; sub: string; scope: string[]; refreshExpiresAt?: number }) {
  const [access_token, refresh_token] = await Promise.all([
    signAccessToken(input),
    signRefreshToken({ ...input, expiresAt: input.refreshExpiresAt }),
  ]);
  return {
    access_token,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    refresh_token,
    scope: input.scope.join(' '),
  };
}

export async function handleToken(request: Request): Promise<Response> {
  if (request.method === 'OPTIONS') return preflight(request, 'POST, OPTIONS');
  if (request.method !== 'POST') {
    return new Response(null, { status: 405, headers: { Allow: 'POST, OPTIONS' } });
  }
  const cors = corsHeaders(request, 'POST, OPTIONS');
  const limit = tokenLimiter.hit(clientAddress(request));
  if (!limit.allowed) {
    return oauthError('temporarily_unavailable', 'Too many token requests; try again later', 429, {
      'Retry-After': String(limit.retryAfterSeconds),
      ...cors,
    });
  }

  const params = await readTokenRequest(request);
  if (!params) {
    return oauthError('invalid_request', 'Send application/x-www-form-urlencoded or JSON', 400, cors);
  }

  const credentials = readClientCredentials(request, params);
  if (credentials instanceof Response) return credentials;
  if (!credentials.clientId) return oauthError('invalid_client', 'client_id is required', 401, cors);

  const client = await resolveClient(credentials.clientId);
  const unauthorized = () =>
    oauthError('invalid_client', 'Client authentication failed', 401, {
      ...cors,
      ...(credentials.viaHeader ? { 'WWW-Authenticate': 'Basic realm="oauth"' } : {}),
    });
  if (!client || !clientAuthenticates(client, credentials.secret)) return unauthorized();

  const grantType = params.get('grant_type');

  if (grantType === 'authorization_code') {
    const code = params.get('code');
    const verifier = params.get('code_verifier');
    if (!code || !verifier) {
      return oauthError('invalid_request', 'code and code_verifier are required', 400, cors);
    }
    const payload = await verifyCode(code);
    if (!payload || payload.client_id !== client.client_id) {
      return oauthError('invalid_grant', 'The authorization code is invalid or expired', 400, cors);
    }
    const redirectUri = params.get('redirect_uri');
    if (redirectUri && redirectUri !== payload.redirect_uri) {
      return oauthError('invalid_grant', 'redirect_uri does not match the authorization request', 400, cors);
    }
    if (!pkceChallengeMatches(verifier, payload.code_challenge)) {
      return oauthError('invalid_grant', 'PKCE verification failed', 400, cors);
    }
    const resource = params.get('resource');
    if (resource && resource !== payload.resource) {
      return oauthError('invalid_target', `Unknown resource; this server is ${payload.resource}`, 400, cors);
    }
    const tokens = await issueTokens({ client_id: client.client_id, sub: payload.sub, scope: payload.scope });
    return json(tokens, 200, cors);
  }

  if (grantType === 'refresh_token') {
    const presented = params.get('refresh_token');
    if (!presented) return oauthError('invalid_request', 'refresh_token is required', 400, cors);
    const payload = await verifyRefreshToken(presented);
    if (!payload || payload.client_id !== client.client_id) {
      return oauthError('invalid_grant', 'The refresh token is invalid or expired', 400, cors);
    }
    const resource = params.get('resource');
    if (resource && resource !== getResourceUrl()) {
      return oauthError('invalid_target', `Unknown resource; this server is ${getResourceUrl()}`, 400, cors);
    }
    let scope = payload.scope;
    const requested = (params.get('scope') ?? '').split(/\s+/).filter(Boolean);
    if (requested.length > 0) {
      if (requested.some((s) => !payload.scope.includes(s))) {
        return oauthError('invalid_scope', 'Requested scope exceeds the original grant', 400, cors);
      }
      scope = requested;
    }
    const tokens = await issueTokens({
      client_id: client.client_id,
      sub: payload.sub,
      scope,
      refreshExpiresAt: payload.exp,
    });
    return json(tokens, 200, cors);
  }

  return oauthError('unsupported_grant_type', 'Use authorization_code or refresh_token', 400, cors);
}
