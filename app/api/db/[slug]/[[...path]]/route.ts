/**
 * /api/db/{slug}[/{collection}[/{id}]]
 *
 * The database of one published page. Two callers: the page itself, with the page token injected
 * into it (`Authorization: Bearer pagedb.…`), from its sandboxed opaque origin; and the owner, with
 * `Authorization: Bearer <SHARE_API_TOKEN>`. Every rule lives in lib/pageDb.ts; this only maps
 * HTTP onto it. CORS is open (`*`, no credentials) because the page's origin is `null`.
 */

import { verifyApiToken } from '../../../../../lib/auth.ts';
import { getStorage } from '../../../../../lib/storage.ts';
import { SLUG_REGEX } from '../../../../../lib/shareInput.ts';
import { clientAddress } from '../../../../../lib/mcp/ratelimit.ts';
import {
  checkDbAccess,
  deleteCollection,
  deleteDocument,
  getDocument,
  isDbRejection,
  listCollections,
  listDocuments,
  pageDbTokenFromRequest,
  pageDbWriteLimiter,
  verifyPageDbToken,
  writeDocument,
  DB_LIMITS,
  type DbCaller,
  type DbRejection,
} from '../../../../../lib/pageDb.ts';

type Params = { params: Promise<{ slug: string; path?: string[] }> };

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Max-Age': '600',
};

function json(body: unknown, status: number, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Robots-Tag': 'noindex, nofollow',
      ...CORS_HEADERS,
      ...extra,
    },
  });
}

function reject(rejection: DbRejection): Response {
  return json(rejection.missing ? { error: rejection.error, missing: rejection.missing } : { error: rejection.error }, rejection.status);
}

/** Largest request body read: one document at its limit plus the envelope. */
const MAX_BODY_BYTES = DB_LIMITS.documentBytes + 1024;

type Target = { slug: string; collection?: string; id?: string };

async function readTarget({ params }: Params): Promise<Target | null> {
  const { slug, path = [] } = await params;
  if (!SLUG_REGEX.test(slug) || path.length > 2) return null;
  return { slug, collection: path[0], id: path[1] };
}

/**
 * Who is calling and whether they may: the owner token, or a page token valid for this page as it
 * is now. Returns the caller, or the response that ends the request.
 */
async function authorize(request: Request, target: Target, mode: 'read' | 'write'): Promise<DbCaller | Response> {
  const pageToken = pageDbTokenFromRequest(request);
  const caller: DbCaller | null = pageToken ? 'page' : verifyApiToken(request) ? 'owner' : null;
  if (!caller) return json({ error: 'Unauthorized' }, 401);

  const meta = await getStorage().getMeta(target.slug);
  if (caller === 'page' && meta && !verifyPageDbToken(pageToken, meta)) {
    return json({ error: 'This page token is no longer valid; reload the page' }, 401);
  }
  const denied = checkDbAccess(target.slug, meta, mode, caller);
  if (denied) return reject(denied);

  if (caller === 'page' && mode === 'write') {
    const decision = pageDbWriteLimiter.hit(`${clientAddress(request)}:${target.slug}`);
    if (!decision.allowed) {
      return json({ error: 'Too many writes; try again shortly' }, 429, { 'Retry-After': String(decision.retryAfterSeconds) });
    }
  }
  return caller;
}

async function readData(request: Request): Promise<{ data: unknown } | Response> {
  const text = await request.text();
  if (Buffer.byteLength(text, 'utf8') > MAX_BODY_BYTES) {
    return json({ error: `The request body is above ${MAX_BODY_BYTES} bytes` }, 413);
  }
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return json({ error: 'Invalid JSON payload' }, 400);
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body) || !('data' in body)) {
    return json({ error: 'Send {"data": <the JSON value to store>}' }, 400);
  }
  return { data: (body as { data: unknown }).data };
}

export async function OPTIONS(): Promise<Response> {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

export async function GET(request: Request, ctx: Params): Promise<Response> {
  const target = await readTarget(ctx);
  if (!target) return json({ error: 'Not Found' }, 404);
  const caller = await authorize(request, target, 'read');
  if (caller instanceof Response) return caller;
  const storage = getStorage();

  if (target.collection === undefined) {
    return json({ collections: await listCollections(storage, target.slug) }, 200);
  }
  if (target.id === undefined) {
    const docs = await listDocuments(storage, target.slug, target.collection);
    if (isDbRejection(docs)) return reject(docs);
    return json({ collection: target.collection, documents: docs }, 200);
  }
  const doc = await getDocument(storage, target.slug, target.collection, target.id);
  if (isDbRejection(doc)) return reject(doc);
  return json(doc, 200);
}

export async function POST(request: Request, ctx: Params): Promise<Response> {
  const target = await readTarget(ctx);
  if (!target || target.collection === undefined) return json({ error: 'Not Found' }, 404);
  if (target.id !== undefined) {
    return json({ error: 'POST adds a document with a new id to a collection; use PUT to write a document by id' }, 405);
  }
  const caller = await authorize(request, target, 'write');
  if (caller instanceof Response) return caller;
  const body = await readData(request);
  if (body instanceof Response) return body;
  const result = await writeDocument(getStorage(), target.slug, target.collection, 'add', undefined, body.data);
  if (isDbRejection(result)) return reject(result);
  return json(result.document, 201);
}

async function writeById(request: Request, ctx: Params, action: 'set' | 'update'): Promise<Response> {
  const target = await readTarget(ctx);
  if (!target || target.collection === undefined || target.id === undefined) return json({ error: 'Not Found' }, 404);
  const caller = await authorize(request, target, 'write');
  if (caller instanceof Response) return caller;
  const body = await readData(request);
  if (body instanceof Response) return body;
  const result = await writeDocument(getStorage(), target.slug, target.collection, action, target.id, body.data);
  if (isDbRejection(result)) return reject(result);
  return json(result.document, result.created ? 201 : 200);
}

export async function PUT(request: Request, ctx: Params): Promise<Response> {
  return writeById(request, ctx, 'set');
}

export async function PATCH(request: Request, ctx: Params): Promise<Response> {
  return writeById(request, ctx, 'update');
}

export async function DELETE(request: Request, ctx: Params): Promise<Response> {
  const target = await readTarget(ctx);
  if (!target || target.collection === undefined) return json({ error: 'Not Found' }, 404);
  const caller = await authorize(request, target, 'write');
  if (caller instanceof Response) return caller;
  const storage = getStorage();

  if (target.id === undefined) {
    if (caller !== 'owner') return json({ error: 'Only the owner can delete a whole collection' }, 403);
    const result = await deleteCollection(storage, target.slug, target.collection);
    if (isDbRejection(result)) return reject(result);
    return json(result, 200);
  }
  const result = await deleteDocument(storage, target.slug, target.collection, target.id);
  if (isDbRejection(result)) return reject(result);
  return json(result, 200);
}
