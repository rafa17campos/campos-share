/**
 * lib/pageDb.ts
 *
 * The per-page database: a small JSON store a published page (`kind: "uploaded"`) can keep, shared
 * by everyone who opens the page and by the owner. It is one blob per page, `<slug>/__db.json`,
 * next to the page's HTML; the `__` prefix keeps it out of reach of every file route and tool, and
 * deleting the share deletes it with the rest of the prefix.
 *
 * Like lib/shares.ts for shares, this is the one place the store is read and changed: the HTTP
 * routes under `app/api/db/` and the MCP tools both call it. A write reads the blob with its ETag,
 * changes it, writes it back only if nobody wrote in between, and starts over when somebody did.
 *
 * Pages are served sandboxed (opaque origin, no cookies), so a page cannot use the unlock cookie.
 * It gets a page token instead, injected into the page by `app/[slug]/route.ts` only after the
 * expiry check and the password gate. The token is an HMAC with SHARE_COOKIE_SECRET over the slug,
 * the day it was issued and a fingerprint of the page's creation time and password hash, so
 * setting or changing the password, or deleting and recreating the page, invalidates every token
 * handed out before. Expiry and the `database` flag are checked on every request, not baked in.
 */

import crypto from 'node:crypto';
import { sameSignature, signWithCookieSecret } from './auth.ts';
import { AssetConflictError, type ShareMeta, type StorageProvider } from './storage.ts';
import { hasExpired, isRejection, type ShareInputRejection } from './shareInput.ts';
import { RateLimiter } from './mcp/ratelimit.ts';

export const PAGE_DB_ASSET_NAME = '__db.json';

export const DB_LIMITS = {
  /** The whole store, serialised. */
  storeBytes: 1024 * 1024,
  /** One document's data, serialised. */
  documentBytes: 64 * 1024,
  collections: 50,
  documentsPerCollection: 5000,
} as const;

export const COLLECTION_REGEX = /^[a-z0-9][a-z0-9_-]{0,63}$/;
/** Ids starting with "__" are refused: they could name an object's own machinery. */
export const DOCUMENT_ID_REGEX = /^(?!__)[A-Za-z0-9_-]{1,128}$/;

type StoredDocument = { data: unknown; createdAt: string; updatedAt: string };
type PageDb = { v: 1; collections: Record<string, Record<string, StoredDocument>> };

export type DbDocument = { id: string; data: unknown; createdAt: string; updatedAt: string };
export type DbCollection = { name: string; count: number };
/** A refusal; `missing: "document"` marks the one 404 a client may read as "not there yet". */
export type DbRejection = ShareInputRejection & { missing?: 'document' };

/* ------------------------------------------------------------------------------------------ */
/* Access                                                                                      */
/* ------------------------------------------------------------------------------------------ */

export type DbCaller = 'owner' | 'page';

/**
 * Whether `caller` may read or write the database of the share `meta`. The owner reads a page's
 * data even when its database is off or the page has expired (turning the database off keeps the
 * data); nobody writes to a page whose database is off. A page token works only while the page is
 * served: database on and not expired.
 */
export function checkDbAccess(
  slug: string,
  meta: ShareMeta | null,
  mode: 'read' | 'write',
  caller: DbCaller
): DbRejection | null {
  if (!meta) return { error: `Nothing is published under "${slug}"`, status: 404 };
  if (meta.kind !== 'uploaded') {
    return { error: `"${slug}" is a folder of files, not a page; only pages have a database`, status: 404 };
  }
  if (caller === 'page' && (!meta.database || hasExpired(meta.expiresAt))) {
    return { error: 'Not Found', status: 404 };
  }
  if (mode === 'write' && !meta.database) {
    return {
      error: `The page "${slug}" has no database. Turn it on with "database": true on update_page (or PUT /api/shares/${slug}); its data, if any, is kept while it is off.`,
      status: 409,
    };
  }
  return null;
}

/* ------------------------------------------------------------------------------------------ */
/* Page tokens                                                                                 */
/* ------------------------------------------------------------------------------------------ */

const DAY_MS = 24 * 60 * 60 * 1000;
/** A token is valid on the day it was issued and the seven after it. */
export const PAGE_DB_TOKEN_DAYS = 8;
const TOKEN_PREFIX = 'pagedb.';

/** What a token is bound to besides the slug: changes when the password changes or the page is recreated. */
function bindingOf(meta: ShareMeta): string {
  return crypto
    .createHash('sha256')
    .update(`${meta.createdAt}\n${meta.passwordHash ?? ''}`)
    .digest('hex')
    .slice(0, 32);
}

function signToken(meta: ShareMeta, day: number): string {
  return signWithCookieSecret(`pagedb:${meta.slug}:${day}:${bindingOf(meta)}`);
}

/**
 * The token a page uses to reach its own database. Day-bucketed, so the page served all day is the
 * same document and keeps its ETag.
 */
export function issuePageDbToken(meta: ShareMeta, now: number = Date.now()): string {
  const day = Math.floor(now / DAY_MS);
  return `${TOKEN_PREFIX}${day}.${signToken(meta, day)}`;
}

export function verifyPageDbToken(token: string | null | undefined, meta: ShareMeta, now: number = Date.now()): boolean {
  if (!token || !token.startsWith(TOKEN_PREFIX)) return false;
  const parts = token.slice(TOKEN_PREFIX.length).split('.');
  if (parts.length !== 2 || !/^\d{1,8}$/.test(parts[0])) return false;
  const day = Number(parts[0]);
  const today = Math.floor(now / DAY_MS);
  if (day > today || today - day >= PAGE_DB_TOKEN_DAYS) return false;
  return sameSignature(parts[1], signToken(meta, day));
}

/** The page token a request carries as `Authorization: Bearer pagedb.…`, or null. */
export function pageDbTokenFromRequest(request: Request): string | null {
  const header = request.headers.get('authorization');
  if (!header || !header.startsWith('Bearer ')) return null;
  const token = header.slice(7).trim();
  return token.startsWith(TOKEN_PREFIX) ? token : null;
}

/** Writes made with a page token, per address and page. Best-effort, per instance (see ratelimit.ts). */
export const pageDbWriteLimiter = new RateLimiter(60, 60 * 1000);
/** Reads made with a page token, per address and page: room for a page polling every second or so. */
export const pageDbReadLimiter = new RateLimiter(120, 60 * 1000);

/* ------------------------------------------------------------------------------------------ */
/* Names and payloads                                                                          */
/* ------------------------------------------------------------------------------------------ */

export function checkCollectionName(name: unknown): DbRejection | null {
  if (typeof name === 'string' && COLLECTION_REGEX.test(name)) return null;
  return {
    error: `"${String(name)}" is not a valid collection name: 1-64 characters, lowercase letters, digits, "_" and "-", starting with a letter or digit`,
    status: 400,
  };
}

export function checkDocumentId(id: unknown): DbRejection | null {
  if (typeof id === 'string' && DOCUMENT_ID_REGEX.test(id)) return null;
  return {
    error: `"${String(id)}" is not a valid document id: 1-128 characters, letters, digits, "_" and "-", not starting with "__"`,
    status: 400,
  };
}

function checkData(data: unknown, action: WriteAction): DbRejection | null {
  if (data === undefined) return { error: 'Field "data" is required: the JSON value to store', status: 400 };
  if (action === 'update' && !isPlainObject(data)) {
    return { error: 'An update merges an object into the document: "data" must be a JSON object', status: 400 };
  }
  const size = Buffer.byteLength(JSON.stringify(data), 'utf8');
  if (size > DB_LIMITS.documentBytes) {
    return {
      error: `The document is ${size} bytes, above the ${DB_LIMITS.documentBytes} bytes one document may hold`,
      status: 413,
    };
  }
  return null;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function newDocumentId(): string {
  return crypto.randomBytes(12).toString('base64url').replace(/^_+/, 'x');
}

/* ------------------------------------------------------------------------------------------ */
/* Reading and changing the store                                                              */
/* ------------------------------------------------------------------------------------------ */

function emptyDb(): PageDb {
  return { v: 1, collections: {} };
}

async function readDb(storage: StorageProvider, slug: string): Promise<{ db: PageDb; etag: string | null }> {
  const read = await storage.getAsset(slug, PAGE_DB_ASSET_NAME);
  if (!read || !read.stream) return { db: emptyDb(), etag: null };
  const parsed = JSON.parse(await new Response(read.stream).text()) as PageDb;
  if (parsed?.v !== 1 || !isPlainObject(parsed.collections)) {
    throw new Error(`The database of "${slug}" is not in a format this version reads`);
  }
  return { db: parsed, etag: read.etag };
}

function own<T>(record: Record<string, T>, key: string): T | undefined {
  return Object.hasOwn(record, key) ? record[key] : undefined;
}

function toDocument(id: string, doc: StoredDocument): DbDocument {
  return { id, data: doc.data, createdAt: doc.createdAt, updatedAt: doc.updatedAt };
}

const MUTATION_ATTEMPTS = 8;

type Change<T> = { value: T; write: boolean };

/**
 * Read the store, let `change` edit it in place, and write it back only if it is still the version
 * read. `change` runs again on a fresh copy after a conflict, so it must decide from the copy it is
 * given, never from an earlier attempt.
 */
async function mutateDb<T>(
  storage: StorageProvider,
  slug: string,
  change: (db: PageDb) => Change<T> | DbRejection
): Promise<T | DbRejection> {
  for (let attempt = 1; ; attempt++) {
    const { db, etag } = await readDb(storage, slug);
    const result = change(db);
    if (isRejection(result)) return result;
    if (!result.write) return result.value;
    const text = JSON.stringify(db);
    const size = Buffer.byteLength(text, 'utf8');
    if (size > DB_LIMITS.storeBytes) {
      return {
        error: `The database of "${slug}" would grow to ${size} bytes, above its ${DB_LIMITS.storeBytes}-byte limit; delete documents first`,
        status: 413,
      };
    }
    try {
      await storage.putAsset(
        slug,
        PAGE_DB_ASSET_NAME,
        text,
        'application/json; charset=utf-8',
        etag ? { ifMatch: etag } : { ifAbsent: true }
      );
      return result.value;
    } catch (err) {
      if (!(err instanceof AssetConflictError)) throw err;
      if (attempt >= MUTATION_ATTEMPTS) {
        return { error: `The database of "${slug}" is busy with other writes; try again`, status: 409 };
      }
    }
  }
}

/**
 * Creates an empty store if the page has none yet, so later writes are all conditional on an ETag.
 * Best-effort: it never fails the caller, because the first write creates the store anyway.
 */
export async function ensurePageDb(storage: StorageProvider, slug: string): Promise<void> {
  try {
    const head = await storage.headAsset(slug, PAGE_DB_ASSET_NAME);
    if (head?.exists) return;
    await storage.putAsset(slug, PAGE_DB_ASSET_NAME, JSON.stringify(emptyDb()), 'application/json; charset=utf-8', {
      ifAbsent: true,
    });
  } catch {
    // Created by someone else, or the store hiccupped: mutateDb creates it on the first write.
  }
}

export async function listCollections(storage: StorageProvider, slug: string): Promise<DbCollection[]> {
  const { db } = await readDb(storage, slug);
  return Object.keys(db.collections)
    .sort()
    .map((name) => ({ name, count: Object.keys(db.collections[name]).length }));
}

/** Every document of a collection, oldest first; an empty list for a collection that does not exist. */
export async function listDocuments(
  storage: StorageProvider,
  slug: string,
  collection: string
): Promise<DbDocument[] | DbRejection> {
  const bad = checkCollectionName(collection);
  if (bad) return bad;
  const { db } = await readDb(storage, slug);
  const docs = own(db.collections, collection) ?? {};
  return Object.entries(docs)
    .map(([id, doc]) => toDocument(id, doc))
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id));
}

export async function getDocument(
  storage: StorageProvider,
  slug: string,
  collection: string,
  id: string
): Promise<DbDocument | DbRejection> {
  const bad = checkCollectionName(collection) ?? checkDocumentId(id);
  if (bad) return bad;
  const { db } = await readDb(storage, slug);
  const docs = own(db.collections, collection);
  const doc = docs ? own(docs, id) : undefined;
  if (!doc) return { error: `No document "${id}" in collection "${collection}"`, status: 404, missing: 'document' };
  return toDocument(id, doc);
}

export type WriteAction = 'add' | 'set' | 'update';
export type WriteResult = { document: DbDocument; created: boolean };

/**
 * `add` stores `data` under a new random id. `set` creates or replaces the document `id`. `update`
 * shallow-merges the object `data` into the document `id`, creating it when absent; the document
 * must hold an object to be merged into.
 */
export async function writeDocument(
  storage: StorageProvider,
  slug: string,
  collection: string,
  action: WriteAction,
  id: string | undefined,
  data: unknown
): Promise<WriteResult | DbRejection> {
  const badCollection = checkCollectionName(collection);
  if (badCollection) return badCollection;
  if (action !== 'add') {
    const badId = checkDocumentId(id);
    if (badId) return badId;
  }
  const badData = checkData(data, action);
  if (badData) return badData;

  return mutateDb<WriteResult>(storage, slug, (db) => {
    let docs = own(db.collections, collection);
    if (!docs) {
      if (Object.keys(db.collections).length >= DB_LIMITS.collections) {
        return { error: `The database of "${slug}" already has ${DB_LIMITS.collections} collections, its limit`, status: 409 };
      }
      docs = {};
      db.collections[collection] = docs;
    }
    const docId = action === 'add' ? newDocumentId() : (id as string);
    const existing = own(docs, docId);
    if (!existing && Object.keys(docs).length >= DB_LIMITS.documentsPerCollection) {
      return {
        error: `Collection "${collection}" already has ${DB_LIMITS.documentsPerCollection} documents, its limit`,
        status: 409,
      };
    }
    let next: unknown = data;
    if (action === 'update' && existing) {
      if (!isPlainObject(existing.data)) {
        return { error: `Document "${docId}" does not hold an object, so it cannot be merged into; use set to replace it`, status: 409 };
      }
      next = { ...existing.data, ...(data as Record<string, unknown>) };
      const size = Buffer.byteLength(JSON.stringify(next), 'utf8');
      if (size > DB_LIMITS.documentBytes) {
        return { error: `The merged document is ${size} bytes, above the ${DB_LIMITS.documentBytes} bytes one document may hold`, status: 413 };
      }
    }
    const now = new Date().toISOString();
    const stored: StoredDocument = { data: next, createdAt: existing?.createdAt ?? now, updatedAt: now };
    docs[docId] = stored;
    return { value: { document: toDocument(docId, stored), created: !existing }, write: true };
  });
}

/** Deletes one document; deleting one that is not there is not an error. */
export async function deleteDocument(
  storage: StorageProvider,
  slug: string,
  collection: string,
  id: string
): Promise<{ deleted: boolean } | DbRejection> {
  const bad = checkCollectionName(collection) ?? checkDocumentId(id);
  if (bad) return bad;
  return mutateDb<{ deleted: boolean }>(storage, slug, (db) => {
    const docs = own(db.collections, collection);
    if (!docs || !own(docs, id)) return { value: { deleted: false }, write: false };
    delete docs[id];
    if (Object.keys(docs).length === 0) delete db.collections[collection];
    return { value: { deleted: true }, write: true };
  });
}

/** Deletes a whole collection, answering how many documents went with it. */
export async function deleteCollection(
  storage: StorageProvider,
  slug: string,
  collection: string
): Promise<{ deleted: number } | DbRejection> {
  const bad = checkCollectionName(collection);
  if (bad) return bad;
  return mutateDb<{ deleted: number }>(storage, slug, (db) => {
    const docs = own(db.collections, collection);
    if (!docs) return { value: { deleted: 0 }, write: false };
    const count = Object.keys(docs).length;
    delete db.collections[collection];
    return { value: { deleted: count }, write: true };
  });
}
