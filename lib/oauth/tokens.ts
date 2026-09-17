/**
 * lib/oauth/tokens.ts
 *
 * Every artefact the authorization server hands out is a signed, self-describing JWT: the pending
 * authorization request carried through the login page, the authorization code, the access token
 * and the refresh token. Nothing is stored, so there is no table to keep and nothing to leak, and
 * rotating MCP_OAUTH_SECRET invalidates all of it at once. Each kind carries a `kind` claim and is
 * verified as that kind only, so a refresh token cannot be replayed as an access token.
 */

import { SignJWT, jwtVerify, errors as joseErrors, type JWTPayload } from 'jose';
import crypto from 'node:crypto';
import {
  ACCESS_TOKEN_TTL_SECONDS,
  AUTH_CODE_TTL_SECONDS,
  AUTH_REQUEST_TTL_SECONDS,
  REFRESH_TOKEN_TTL_SECONDS,
  getIssuer,
  getOAuthSecret,
  getResourceUrl,
} from '../mcp/config.ts';

export type TokenKind = 'authreq' | 'code' | 'access' | 'refresh';

/** What an authorization request looks like once it has been validated and the client resolved. */
export type PendingAuthorization = {
  client_id: string;
  client_name: string;
  redirect_uri: string;
  scope: string[];
  state?: string;
  code_challenge: string;
  resource: string;
};

export type CodePayload = PendingAuthorization & { sub: string };

export type AccessPayload = {
  client_id: string;
  sub: string;
  scope: string[];
  exp: number;
};

export type RefreshPayload = AccessPayload;

const ALG = 'HS256';

async function sign(kind: TokenKind, claims: Record<string, unknown>, ttlSeconds: number, audience: string) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ ...claims, kind })
    .setProtectedHeader({ alg: ALG })
    .setIssuer(getIssuer())
    .setAudience(audience)
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .setJti(crypto.randomBytes(16).toString('base64url'))
    .sign(getOAuthSecret());
}

async function verify(kind: TokenKind, token: string, audience: string): Promise<JWTPayload | null> {
  try {
    const { payload } = await jwtVerify(token, getOAuthSecret(), {
      issuer: getIssuer(),
      audience,
      algorithms: [ALG],
    });
    if (payload.kind !== kind) return null;
    return payload;
  } catch (err) {
    if (err instanceof joseErrors.JOSEError) return null;
    throw err;
  }
}

export function signAuthRequest(pending: PendingAuthorization): Promise<string> {
  return sign('authreq', { req: pending }, AUTH_REQUEST_TTL_SECONDS, getIssuer());
}

export async function verifyAuthRequest(token: string): Promise<PendingAuthorization | null> {
  const payload = await verify('authreq', token, getIssuer());
  return payload ? (payload.req as PendingAuthorization) : null;
}

export function signCode(code: CodePayload): Promise<string> {
  return sign('code', { req: code }, AUTH_CODE_TTL_SECONDS, getIssuer());
}

export async function verifyCode(token: string): Promise<CodePayload | null> {
  const payload = await verify('code', token, getIssuer());
  return payload ? (payload.req as CodePayload) : null;
}

export function signAccessToken(input: { client_id: string; sub: string; scope: string[] }): Promise<string> {
  return sign(
    'access',
    { client_id: input.client_id, sub: input.sub, scope: input.scope.join(' ') },
    ACCESS_TOKEN_TTL_SECONDS,
    getResourceUrl()
  );
}

export async function verifyAccessToken(token: string): Promise<AccessPayload | null> {
  const payload = await verify('access', token, getResourceUrl());
  if (!payload || typeof payload.client_id !== 'string' || typeof payload.sub !== 'string') return null;
  return {
    client_id: payload.client_id,
    sub: payload.sub,
    scope: typeof payload.scope === 'string' && payload.scope ? payload.scope.split(' ') : [],
    exp: payload.exp ?? 0,
  };
}

/**
 * A refresh token keeps the absolute expiry of the grant it belongs to: exchanging it yields a new
 * refresh token that dies at the same instant, so a grant never outlives its first thirty days.
 */
export function signRefreshToken(input: {
  client_id: string;
  sub: string;
  scope: string[];
  expiresAt?: number;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const exp = input.expiresAt ?? now + REFRESH_TOKEN_TTL_SECONDS;
  return sign(
    'refresh',
    { client_id: input.client_id, sub: input.sub, scope: input.scope.join(' ') },
    Math.max(1, exp - now),
    getIssuer()
  );
}

export async function verifyRefreshToken(token: string): Promise<RefreshPayload | null> {
  const payload = await verify('refresh', token, getIssuer());
  if (!payload || typeof payload.client_id !== 'string' || typeof payload.sub !== 'string') return null;
  return {
    client_id: payload.client_id,
    sub: payload.sub,
    scope: typeof payload.scope === 'string' && payload.scope ? payload.scope.split(' ') : [],
    exp: payload.exp ?? 0,
  };
}

/** PKCE S256: the challenge is the base64url SHA-256 of the verifier (RFC 7636). */
export function pkceChallengeMatches(verifier: string, challenge: string): boolean {
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) return false;
  const computed = crypto.createHash('sha256').update(verifier).digest('base64url');
  const a = Buffer.from(computed);
  const b = Buffer.from(challenge);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
