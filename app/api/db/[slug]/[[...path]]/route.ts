/**
 * /api/db/{slug}[/{collection}[/{id}]]
 *
 * The database of one published page. Two callers: the page itself, with the page token injected
 * into it (`Authorization: Bearer pagedb.…`), from its sandboxed opaque origin; and the owner, with
 * `Authorization: Bearer <SHARE_API_TOKEN>`. Every rule lives in lib/pageDb.ts; this only maps
 * HTTP onto it. CORS is open (`*`, no credentials) because the page's origin is `null`, and every
 * response carries it, failures included, or the page would see an opaque network error.
 */

import { verifyApiToken } from '../../../../../lib/auth.ts';
import { getStorage, type ShareMeta } from '../../../../../lib/storage.ts';
import { SLUG_REGEX, isRejection } from '../../../../../lib/shareInput.ts';
import { clientAddress, type RateLimiter } from '../../../../../lib/mcp/ratelimit.ts';
import {
  checkDbAccess,
  deleteCollection,
  deleteDocument,
  getDocument,
  listCollections,
  listDocuments,
  pageDbReadLimiter,
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

/** Any failure the rules did not foresee still answers with CORS, so the page can read its status. */
function guarded(handler: (request: Request, ctx: Params) => Promise<Response>) {
  return async (request: Request, ctx: Params): Promise<Response> => {
    try {
      return await handler(request, ctx);
    } catch (err) {
      console.error('page database request failed', (err as Error)?.name, (err as Error)?.message);
      return json({ error: 'The database is unavailable right now; try again' }, 503, { 'Retry-After': '5' });
    }
  };
}

/**
 * Largest request body read. The document limit is checked on the parsed value; this ceiling only
 * stops a body from being buffered whole, and leaves room for whitespace and escapes around a
 * document at its limit.
 */
const MAX_BODY_BYTES = 4 * DB_LIMITS.documentBytes;

type Target = { slug: string; collection?: string; id?: string };

async function readTarget({ params }: Params): Promise<Target | null> {
  const { slug, path = [] } = await params;
  if (!SLUG_REGEX.test(slug) || path.length > 2) return null;
  return { slug, collection: path[0], id: path[1] };
}

type Credentials = { caller: DbCaller; pageToken: string | null };

function credentialsOf(request: Request): Credentials | null {
  const pageToken = pageDbTokenFromRequest(request);
  if (pageToken) return { caller: 'page', pageToken };
  return verifyApiToken(request) ? { caller: 'owner', pageToken: null } : null;
}

const UNAUTHORIZED = { error: 'Unauthorized' };
const STALE_TOKEN = { error: 'This page token is not valid; reload the page' };

/**
 * Whether these credentials may act on this page now. A page token that does not verify gets the
 * same 401 whether the slug is a page, a folder or nothing at all, so a forged token learns nothing
 * about which slugs exist. Returns null when allowed, or the response that ends the request.
 */
async function authorize(
  request: Request,
  target: Target,
  creds: Credentials,
  mode: 'read' | 'write'
): Promise<Response | null> {
  const meta: ShareMeta | null = await getStorage().getMeta(target.slug);
  if (creds.caller === 'page') {
    if (!meta || meta.kind !== 'uploaded' || !verifyPageDbToken(creds.pageToken, meta)) return json(STALE_TOKEN, 401);
  }
  const denied = checkDbAccess(target.slug, meta, mode, creds.caller);
  return denied ? reject(denied) : null;
}

/**
 * Requests made with a page token, counted per address and page before any storage is touched, so
 * a page polling too fast, or a forged token, costs no Blob operation once over the limit.
 */
function rateLimit(request: Request, target: Target, creds: Credentials, mode: 'read' | 'write'): Response | null {
  if (creds.caller !== 'page') return null;
  const limiter: RateLimiter = mode === 'write' ? pageDbWriteLimiter : pageDbReadLimiter;
  const decision = limiter.hit(`${clientAddress(request)}:${target.slug}`);
  if (decision.allowed) return null;
  return json({ error: `Too many ${mode}s; try again shortly` }, 429, { 'Retry-After': String(decision.retryAfterSeconds) });
}

/** The body, read up to MAX_BODY_BYTES and no further, as `{ data }`. */
async function readData(request: Request): Promise<{ data: unknown } | Response> {
  const tooLarge = () => json({ error: `The request body is above ${MAX_BODY_BYTES} bytes` }, 413);
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return tooLarge();

  const chunks: Uint8Array[] = [];
  let size = 0;
  if (request.body) {
    const reader = request.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel().catch(() => {});
        return tooLarge();
      }
      chunks.push(value);
    }
  }
  let body: unknown;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
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

async function read(target: Target): Promise<Response> {
  const storage = getStorage();
  if (target.collection === undefined) {
    return json({ collections: await listCollections(storage, target.slug) }, 200);
  }
  if (target.id === undefined) {
    const docs = await listDocuments(storage, target.slug, target.collection);
    if (isRejection(docs)) return reject(docs);
    return json({ collection: target.collection, documents: docs }, 200);
  }
  const doc = await getDocument(storage, target.slug, target.collection, target.id);
  if (isRejection(doc)) return reject(doc);
  return json(doc, 200);
}

export const GET = guarded(async (request, ctx) => {
  const target = await readTarget(ctx);
  if (!target) return json({ error: 'Not Found' }, 404);
  const creds = credentialsOf(request);
  if (!creds) return json(UNAUTHORIZED, 401);
  const limited = rateLimit(request, target, creds, 'read');
  if (limited) return limited;
  // The record and the store are read at the same time; the data is only answered once allowed.
  const pending = read(target).then(
    (response) => ({ response }),
    (error: unknown) => ({ error })
  );
  const denied = await authorize(request, target, creds, 'read');
  const outcome = await pending;
  if (denied) return denied;
  if ('error' in outcome) throw outcome.error;
  return outcome.response;
});

async function startWrite(request: Request, target: Target): Promise<Response | null> {
  const creds = credentialsOf(request);
  if (!creds) return json(UNAUTHORIZED, 401);
  return rateLimit(request, target, creds, 'write') ?? authorize(request, target, creds, 'write');
}

export const POST = guarded(async (request, ctx) => {
  const target = await readTarget(ctx);
  if (!target || target.collection === undefined) return json({ error: 'Not Found' }, 404);
  if (target.id !== undefined) {
    return json({ error: 'POST adds a document with a new id to a collection; use PUT to write a document by id' }, 405);
  }
  const denied = await startWrite(request, target);
  if (denied) return denied;
  const body = await readData(request);
  if (body instanceof Response) return body;
  const result = await writeDocument(getStorage(), target.slug, target.collection, 'add', undefined, body.data);
  if (isRejection(result)) return reject(result);
  return json(result.document, 201);
});

function writeById(action: 'set' | 'update') {
  return guarded(async (request, ctx) => {
    const target = await readTarget(ctx);
    if (!target || target.collection === undefined || target.id === undefined) return json({ error: 'Not Found' }, 404);
    const denied = await startWrite(request, target);
    if (denied) return denied;
    const body = await readData(request);
    if (body instanceof Response) return body;
    const result = await writeDocument(getStorage(), target.slug, target.collection, action, target.id, body.data);
    if (isRejection(result)) return reject(result);
    return json(result.document, result.created ? 201 : 200);
  });
}

export const PUT = writeById('set');
export const PATCH = writeById('update');

export const DELETE = guarded(async (request, ctx) => {
  const target = await readTarget(ctx);
  if (!target || target.collection === undefined) return json({ error: 'Not Found' }, 404);
  const creds = credentialsOf(request);
  if (!creds) return json(UNAUTHORIZED, 401);
  const denied = rateLimit(request, target, creds, 'write') ?? (await authorize(request, target, creds, 'write'));
  if (denied) return denied;
  const storage = getStorage();

  if (target.id === undefined) {
    if (creds.caller !== 'owner') return json({ error: 'Only the owner can delete a whole collection' }, 403);
    const result = await deleteCollection(storage, target.slug, target.collection);
    if (isRejection(result)) return reject(result);
    return json(result, 200);
  }
  const result = await deleteDocument(storage, target.slug, target.collection, target.id);
  if (isRejection(result)) return reject(result);
  return json(result, 200);
});
