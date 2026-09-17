/**
 * lib/mcp/cors.ts
 *
 * CORS for the MCP endpoint and the OAuth discovery documents. The endpoint authenticates with a
 * bearer token and never with a cookie, so reflecting the caller's origin grants nothing a
 * cross-origin page could not already do with a token it holds.
 */

import { getAllowedOrigins } from './config.ts';

const ALLOW_HEADERS =
  'Authorization, Content-Type, Accept, Mcp-Protocol-Version, Mcp-Method, Mcp-Name, Mcp-Session-Id, Last-Event-ID';
const EXPOSE_HEADERS = 'WWW-Authenticate, Mcp-Session-Id, Content-Type';

export function corsHeaders(request: Request, methods: string): Record<string, string> {
  const origin = request.headers.get('origin');
  const allowed = getAllowedOrigins();
  let allowOrigin: string | null = null;
  if (allowed === '*') {
    allowOrigin = origin ?? '*';
  } else if (origin) {
    try {
      if (allowed.includes(new URL(origin).hostname)) allowOrigin = origin;
    } catch {
      allowOrigin = null;
    }
  }
  const headers: Record<string, string> = {
    Vary: 'Origin',
    'Access-Control-Allow-Methods': methods,
    'Access-Control-Allow-Headers': ALLOW_HEADERS,
    'Access-Control-Expose-Headers': EXPOSE_HEADERS,
    'Access-Control-Max-Age': '86400',
  };
  if (allowOrigin) headers['Access-Control-Allow-Origin'] = allowOrigin;
  return headers;
}

export function withCors(request: Request, response: Response, methods: string): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(corsHeaders(request, methods))) headers.set(k, v);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export function preflight(request: Request, methods: string): Response {
  return new Response(null, { status: 204, headers: corsHeaders(request, methods) });
}
