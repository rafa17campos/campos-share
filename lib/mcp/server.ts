/**
 * lib/mcp/server.ts
 *
 * The MCP endpoint: one stateless Streamable HTTP handler serving both the 2026-07-28 protocol
 * and 2025-era clients, behind a bearer-token gate. Tokens are either the ones our own
 * authorization server issued for this resource, or the optional static token for terminal
 * clients. Everything here is a web-standard `(Request) => Response`, so the Next.js route is a
 * re-export and the tests call it directly.
 */

import crypto from 'node:crypto';
import {
  McpServer,
  OAuthError,
  OAuthErrorCode,
  createMcpHandler,
  getOAuthProtectedResourceMetadataUrl,
  originValidationResponse,
  requireBearerAuth,
  type AuthInfo,
  type McpHttpHandler,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';
import { getStorage } from '../storage.ts';
import { verifyAccessToken } from '../oauth/tokens.ts';
import { getAllowedOrigins, getResourceUrl, getStaticToken } from './config.ts';
import { preflight, withCors } from './cors.ts';
import { toolCallLimiter } from './ratelimit.ts';
import { registerShareTools } from './tools.ts';

const METHODS = 'POST, GET, DELETE, OPTIONS';

const INSTRUCTIONS =
  'Publishes files at public URLs. A folder (prefix) holds files; a path is "<prefix>/<filename>". ' +
  'Use upload_file for content you hold inline (up to 3 MB decoded), create_upload_url plus complete_upload for ' +
  'larger files or when you can run curl, list_files and get_file_info to find things, delete_file to remove them.';

/* ------------------------------------------------------------------------------------------ */
/* Token verification                                                                          */
/* ------------------------------------------------------------------------------------------ */

const STATIC_CLIENT_ID = 'static-token';

function staticTokenMatches(presented: string): { scopes: string[] } | null {
  const configured = getStaticToken();
  if (!configured) return null;
  const a = Buffer.from(configured.token);
  const b = Buffer.from(presented);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return { scopes: configured.scopes };
}

export const tokenVerifier: OAuthTokenVerifier = {
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const resource = new URL(getResourceUrl());

    const fixed = staticTokenMatches(token);
    if (fixed) {
      return {
        token,
        clientId: STATIC_CLIENT_ID,
        scopes: fixed.scopes,
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        resource,
        extra: { sub: 'owner', via: 'static-token' },
      };
    }

    const payload = await verifyAccessToken(token);
    if (!payload) {
      throw new OAuthError(OAuthErrorCode.InvalidToken, 'The access token is invalid, expired, or not meant for this server');
    }
    return {
      token,
      clientId: payload.client_id,
      scopes: payload.scope,
      expiresAt: payload.exp,
      resource,
      extra: { sub: payload.sub, via: 'oauth' },
    };
  },
};

/* ------------------------------------------------------------------------------------------ */
/* Handler                                                                                     */
/* ------------------------------------------------------------------------------------------ */

let handler: McpHttpHandler | null = null;

function getHandler(): McpHttpHandler {
  if (!handler) {
    handler = createMcpHandler(
      () => {
        const server = new McpServer({ name: 'campos-share', version: '1.0.0' }, { instructions: INSTRUCTIONS });
        registerShareTools(server, { storage: getStorage() });
        return server;
      },
      { legacy: 'stateless' }
    );
  }
  return handler;
}

/** Tests swap storage between cases; the handler builds a server per request so nothing is cached. */
export async function closeMcpHandlerForTesting(): Promise<void> {
  await handler?.close();
  handler = null;
}

function jsonError(status: number, message: string, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message }, id: null }), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

export async function serveMcp(request: Request): Promise<Response> {
  if (request.method === 'OPTIONS') return preflight(request, METHODS);

  const respond = (response: Response) => withCors(request, response, METHODS);

  if (request.method !== 'POST') {
    return respond(new Response('Method not allowed.', { status: 405, headers: { Allow: METHODS } }));
  }

  const allowedOrigins = getAllowedOrigins();
  if (allowedOrigins !== '*') {
    const rejected = originValidationResponse(request, allowedOrigins);
    if (rejected) return respond(rejected);
  }

  let gate: (request: Request) => Promise<AuthInfo | Response>;
  try {
    gate = requireBearerAuth({
      verifier: tokenVerifier,
      resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL(getResourceUrl())),
    });
  } catch (err) {
    return respond(jsonError(503, `MCP endpoint is not configured: ${(err as Error).message}`));
  }

  const auth = await gate(request);
  if (auth instanceof Response) return respond(auth);

  const subject = `${auth.clientId}:${String(auth.extra?.sub ?? '')}`;
  const limit = toolCallLimiter.hit(subject);
  if (!limit.allowed) {
    return respond(
      jsonError(429, 'Too many requests; slow down.', { 'Retry-After': String(limit.retryAfterSeconds) })
    );
  }

  const response = await getHandler().fetch(request, { authInfo: auth });
  return respond(response);
}
