/**
 * lib/storage.ts
 *
 * The sole module in the codebase that imports and interacts with @vercel/blob.
 * Isolating Blob access here preserves the repatriation escape hatch:
 * switching to S3, MinIO, or local disk requires modifying only this file.
 */

import { createHash } from 'node:crypto';
import {
  put,
  del,
  head,
  list,
  get,
  issueSignedToken,
  presignUrl,
  BlobNotFoundError,
  BlobPreconditionFailedError,
  type ListBlobResult,
} from '@vercel/blob';

/**
 * Every blob this service writes is private, so the store has no second door.
 *
 * A public blob is reachable at `<storeId>.public.blob.vercel-storage.com/<slug>/<file>`,
 * which bypasses the expiry check, the password gate and `X-Robots-Tag`, and would put
 * `__meta.json` — password hash included — on an anonymous URL. Shares stay public through
 * `share.example.invalid/<slug>`, which is the only door and the one that enforces.
 */
const BLOB_ACCESS = 'private' as const;

export interface ShareAsset {
  name: string;
  originalName: string;
  contentType: string;
  sizeBytes: number;
  /** The store's ETag for the current bytes; absent on records written before it was kept. */
  etag?: string;
  /** Lowercase hex SHA-256 of the current bytes, when the writer knew or declared it. */
  sha256?: string;
  /** When the bytes were last replaced in place; absent when never replaced. */
  updatedAt?: string;
}

export interface ShareMeta {
  slug: string;
  title: string;
  description?: string;
  lang: string;
  createdAt: string;
  kind: 'generated' | 'uploaded';
  assets: ShareAsset[];
  expiresAt?: string | null;
  passwordHash?: string | null;
  /** An uploaded page that keeps a shared data store at `<slug>/__db.json` (see lib/pageDb.ts). */
  database?: boolean;
}

export interface UploadRequestFile {
  name: string;
  contentType: string;
  sizeBytes: number;
  /** Allow the upload to replace a blob already at that pathname. */
  overwrite?: boolean;
}

export interface AssetRead {
  /** The bytes, or null when `notModified` is true. */
  stream: ReadableStream<Uint8Array> | null;
  contentType: string;
  size: number;
  etag: string;
  /** True when the caller's `ifNoneMatch` matched and nothing was transferred. */
  notModified: boolean;
}

export interface AssetHead {
  exists: boolean;
  size: number;
  contentType: string;
  etag: string;
}

/**
 * Blob keeps a CDN cache in front of its store and serves reads from it for up to a minute after a
 * delete or an overwrite. Every read here bypasses it: the record is the source of truth and a
 * stale record is how a file just deleted reads as "already exists", or a file just added gets
 * dropped by the next write. Writes also ask for the shortest cache the store allows, so anything
 * that does read through the cache goes stale for a minute at most.
 */
const BLOB_CACHE_MAX_AGE_SECONDS = 60;

export interface IssuedFileToken {
  name: string;
  pathname: string;
  /** Presigned `PUT` URL, valid for one pathname, one content type and one size. */
  uploadUrl: string;
}

export interface UploadTokensResult {
  slug: string;
  prefix: string;
  tokens: IssuedFileToken[];
  /** Epoch ms after which every URL in `tokens` is rejected. */
  validUntil: number;
}

/** How long a presigned upload URL stays usable. */
const UPLOAD_URL_TTL_MS = 15 * 60 * 1000;

/**
 * Checks if a filename contains any path segment starting with '__'.
 * Such names are reserved for system blobs (e.g. __meta.json, __page.html)
 * and must never be used for user asset files.
 */
export function isReservedAssetName(name: string): boolean {
  if (!name || typeof name !== 'string') return true;
  const segments = name.split('/');
  return segments.some((segment) => segment.startsWith('__'));
}

/** Thrown by `saveMeta` when `ifMatch` names a version of the record that is no longer current. */
export class MetaConflictError extends Error {
  constructor(slug: string) {
    super(`The record of "${slug}" changed since it was read`);
    this.name = 'MetaConflictError';
  }
}

/** Thrown by `putAsset` when `ifMatch` names a version of the file that is no longer current. */
export class AssetConflictError extends Error {
  constructor(slug: string, filename: string) {
    super(`"${slug}/${filename}" changed since it was read`);
    this.name = 'AssetConflictError';
  }
}

export interface PutAssetOptions {
  /** Write only if the file still carries this ETag; otherwise throw `AssetConflictError`. */
  ifMatch?: string;
  /** Write only if no file exists at that name yet; otherwise throw `AssetConflictError`. */
  ifAbsent?: boolean;
}

export interface MetaRead {
  meta: ShareMeta;
  /** The store's ETag of the record as read; hand it back to `saveMeta` as `ifMatch`. */
  etag: string;
}

function isNotFound(err: unknown): boolean {
  return (
    err instanceof BlobNotFoundError ||
    (err as { name?: string })?.name === 'BlobNotFoundError' ||
    Boolean((err as Error)?.message?.toLowerCase().includes('not found'))
  );
}

export interface SaveMetaOptions {
  /** Write only if the record still carries this ETag; otherwise throw `MetaConflictError`. */
  ifMatch?: string;
}

export interface StorageProvider {
  getMeta(slug: string): Promise<ShareMeta | null>;
  readMeta(slug: string): Promise<MetaRead | null>;
  saveMeta(slug: string, meta: ShareMeta, options?: SaveMetaOptions): Promise<void>;
  putAsset(
    slug: string,
    filename: string,
    data: Buffer | Uint8Array | string,
    contentType: string,
    options?: PutAssetOptions
  ): Promise<{ url: string; size: number; etag: string }>;
  getAsset(slug: string, filename: string, options?: { ifNoneMatch?: string }): Promise<AssetRead | null>;
  /**
   * A file's text with the ETag a conditional write (`ifMatch`) compares against. Use this, never
   * `getAsset`, to read something you are about to rewrite: see `VercelBlobStorage.readForUpdate`.
   */
  readAssetForUpdate(slug: string, filename: string): Promise<{ text: string; etag: string } | null>;
  headAsset(slug: string, filename: string): Promise<AssetHead | null>;
  createUploadTokens(slug: string, files: UploadRequestFile[]): Promise<UploadTokensResult>;
  deleteShare(slug: string): Promise<void>;
  deleteBlobs(urls: string[]): Promise<void>;
  /** Every share's record, or only those whose slug starts with `slugPrefix`, filtered before any record is read. */
  listAllShares(slugPrefix?: string): Promise<ShareMeta[]>;
  listOrphanPrefixes(olderThanMs?: number): Promise<string[]>;
}

/**
 * Production storage provider backed by @vercel/blob
 */
export class VercelBlobStorage implements StorageProvider {
  private token?: string;

  constructor(token?: string) {
    this.token = token || process.env.BLOB_READ_WRITE_TOKEN;
  }

  /** A blob's text, read past the CDN cache; null when it does not exist. */
  private async fetchText(pathname: string): Promise<string | null> {
    try {
      const result = await get(pathname, { access: BLOB_ACCESS, token: this.token, useCache: false });
      if (!result || result.statusCode !== 200 || !result.stream) return null;
      return await new Response(result.stream).text();
    } catch (err: unknown) {
      if (isNotFound(err)) return null;
      throw err;
    }
  }

  /**
   * A blob's text together with the ETag that `put({ ifMatch })` compares against.
   *
   * That ETag is the one the API reports (`head`), not the one on a download: once a blob is large
   * enough for the CDN to compress (about 1 KB), `get` answers with a different, weak validator, and
   * a conditional write sent with it fails every time — every retry reads the same mismatched value.
   * So the ETag is taken with `head` *before* the content is read. If a write lands in between, the
   * content may be newer than that ETag, but then the store no longer carries it either, the
   * conditional write fails and the caller reads again: a mismatch can only cost a retry, never an
   * update.
   */
  private async readForUpdate(pathname: string): Promise<{ text: string; etag: string } | null> {
    const before = await this.headPath(pathname);
    if (!before) return null;
    const text = await this.fetchText(pathname);
    return text === null ? null : { text, etag: before.etag };
  }

  private async headPath(pathname: string): Promise<{ size: number; contentType: string; etag: string } | null> {
    try {
      const result = await head(pathname, { token: this.token });
      return { size: result.size, contentType: result.contentType, etag: result.etag };
    } catch (err: unknown) {
      if (isNotFound(err)) return null;
      throw err;
    }
  }

  async getMeta(slug: string): Promise<ShareMeta | null> {
    const text = await this.fetchText(`${slug}/__meta.json`);
    return text === null ? null : (JSON.parse(text) as ShareMeta);
  }

  async readMeta(slug: string): Promise<MetaRead | null> {
    const read = await this.readForUpdate(`${slug}/__meta.json`);
    return read ? { meta: JSON.parse(read.text) as ShareMeta, etag: read.etag } : null;
  }

  async readAssetForUpdate(slug: string, filename: string): Promise<{ text: string; etag: string } | null> {
    return this.readForUpdate(`${slug}/${filename}`);
  }

  async saveMeta(slug: string, meta: ShareMeta, options: SaveMetaOptions = {}): Promise<void> {
    const metaPath = `${slug}/__meta.json`;
    try {
      await put(metaPath, JSON.stringify(meta, null, 2), {
        access: BLOB_ACCESS,
        contentType: 'application/json; charset=utf-8',
        addRandomSuffix: false,
        allowOverwrite: true,
        cacheControlMaxAge: BLOB_CACHE_MAX_AGE_SECONDS,
        token: this.token,
        ...(options.ifMatch ? { ifMatch: options.ifMatch } : {}),
      });
    } catch (err: unknown) {
      if (err instanceof BlobPreconditionFailedError || (err as { name?: string })?.name === 'BlobPreconditionFailedError') {
        throw new MetaConflictError(slug);
      }
      throw err;
    }
  }

  async putAsset(
    slug: string,
    filename: string,
    data: Buffer | Uint8Array | string,
    contentType: string,
    options: PutAssetOptions = {}
  ): Promise<{ url: string; size: number; etag: string }> {
    const assetPath = `${slug}/${filename}`;
    const body = typeof data === 'string' ? data : Buffer.from(data);
    let result;
    try {
      result = await put(assetPath, body, {
        access: BLOB_ACCESS,
        contentType,
        addRandomSuffix: false,
        allowOverwrite: !options.ifAbsent,
        cacheControlMaxAge: BLOB_CACHE_MAX_AGE_SECONDS,
        token: this.token,
        ...(options.ifMatch ? { ifMatch: options.ifMatch } : {}),
      });
    } catch (err: unknown) {
      if (err instanceof BlobPreconditionFailedError || (err as { name?: string })?.name === 'BlobPreconditionFailedError') {
        throw new AssetConflictError(slug, filename);
      }
      // Blob has no dedicated error for a create-only put onto an existing pathname (the SDK reports
      // it as an unknown error), so ask the store: if the file exists now, somebody else created it.
      if (options.ifAbsent) {
        const now = await this.headAsset(slug, filename).catch(() => null);
        if (now?.exists) throw new AssetConflictError(slug, filename);
      }
      throw err;
    }
    const size = typeof data === 'string' ? Buffer.byteLength(data, 'utf8') : data.length;
    return { url: result.url, size, etag: result.etag };
  }

  async getAsset(
    slug: string,
    filename: string,
    options: { ifNoneMatch?: string } = {}
  ): Promise<AssetRead | null> {
    const assetPath = `${slug}/${filename}`;
    try {
      const result = await get(assetPath, {
        access: BLOB_ACCESS,
        token: this.token,
        useCache: false,
        ifNoneMatch: options.ifNoneMatch,
      });
      if (!result) return null;
      if (result.statusCode === 304) {
        return { stream: null, contentType: '', size: 0, etag: result.blob.etag, notModified: true };
      }
      if (result.statusCode !== 200 || !result.stream) {
        return null;
      }
      return {
        stream: result.stream,
        contentType: result.blob.contentType || 'application/octet-stream',
        size: result.blob.size,
        etag: result.blob.etag,
        notModified: false,
      };
    } catch (err: unknown) {
      if (err instanceof BlobNotFoundError || (err as { name?: string })?.name === 'BlobNotFoundError') {
        return null;
      }
      if ((err as Error)?.message?.toLowerCase().includes('not found')) {
        return null;
      }
      throw err;
    }
  }

  async headAsset(slug: string, filename: string): Promise<AssetHead | null> {
    const result = await this.headPath(`${slug}/${filename}`);
    return result ? { exists: true, ...result } : null;
  }

  async createUploadTokens(
    slug: string,
    files: UploadRequestFile[]
  ): Promise<UploadTokensResult> {
    const prefix = `${slug}/`;
    const tokens: IssuedFileToken[] = [];
    const validUntil = Date.now() + UPLOAD_URL_TTL_MS;

    for (const file of files) {
      if (isReservedAssetName(file.name)) {
        throw new Error(
          `Asset name "${file.name}" is reserved because it contains a segment starting with "__".`
        );
      }
      const pathname = `${slug}/${file.name}`;
      const constraints = {
        allowedContentTypes: [file.contentType],
        maximumSizeInBytes: file.sizeBytes,
        addRandomSuffix: false,
        allowOverwrite: Boolean(file.overwrite),
        cacheControlMaxAge: BLOB_CACHE_MAX_AGE_SECONDS,
      };
      const signedToken = await issueSignedToken({
        token: this.token,
        pathname,
        operations: ['put'],
        validUntil,
        ...constraints,
      });
      const { presignedUrl } = await presignUrl(signedToken, {
        access: BLOB_ACCESS,
        operation: 'put',
        pathname,
        ...constraints,
      });
      tokens.push({
        name: file.name,
        pathname,
        uploadUrl: presignedUrl,
      });
    }

    return { slug, prefix, tokens, validUntil };
  }

  async deleteBlobs(urls: string[]): Promise<void> {
    if (urls.length === 0) return;
    await del(urls, { token: this.token });
  }

  async deleteShare(slug: string): Promise<void> {
    const prefix = `${slug}/`;
    let cursor: string | undefined = undefined;
    const urlsToDelete: string[] = [];

    do {
      const listResult: ListBlobResult = await list({
        prefix,
        cursor,
        limit: 1000,
        token: this.token,
      });
      for (const blob of listResult.blobs) {
        urlsToDelete.push(blob.url);
      }
      cursor = listResult.hasMore ? listResult.cursor : undefined;
    } while (cursor);

    if (urlsToDelete.length > 0) {
      await del(urlsToDelete, { token: this.token });
    }
  }

  async listAllShares(slugPrefix: string = ''): Promise<ShareMeta[]> {
    let cursor: string | undefined = undefined;
    const metaBlobs: { url: string; pathname: string }[] = [];

    do {
      // Listing by prefix is a store-side filter: records of other slugs are never fetched.
      const listResult: ListBlobResult = await list({
        cursor,
        limit: 1000,
        token: this.token,
        ...(slugPrefix ? { prefix: slugPrefix } : {}),
      });
      for (const b of listResult.blobs) {
        if (b.pathname.endsWith('/__meta.json')) {
          metaBlobs.push(b);
        }
      }
      cursor = listResult.hasMore ? listResult.cursor : undefined;
    } while (cursor);

    // Fetch meta.json records with bounded concurrency
    const BATCH_SIZE = 10;
    const results: ShareMeta[] = [];

    for (let i = 0; i < metaBlobs.length; i += BATCH_SIZE) {
      const batch = metaBlobs.slice(i, i + BATCH_SIZE);
      const batchResults = await Promise.all(
        batch.map(async (item) => {
          try {
            const res = await get(item.pathname, { access: BLOB_ACCESS, token: this.token, useCache: false });
            if (!res || res.statusCode !== 200 || !res.stream) return null;
            const text = await new Response(res.stream).text();
            return JSON.parse(text) as ShareMeta;
          } catch {
            return null;
          }
        })
      );
      for (const r of batchResults) {
        if (r) results.push(r);
      }
    }

    return results;
  }

  async listOrphanPrefixes(olderThanMs: number = 24 * 60 * 60 * 1000): Promise<string[]> {
    const cutoffTime = Date.now() - olderThanMs;
    const prefixMap = new Map<string, { hasMeta: boolean; oldestUpload: number }>();
    let cursor: string | undefined = undefined;

    do {
      const listResult: ListBlobResult = await list({
        cursor,
        limit: 1000,
        token: this.token,
      });

      for (const b of listResult.blobs) {
        const slashIndex = b.pathname.indexOf('/');
        if (slashIndex === -1) continue;
        const prefix = b.pathname.slice(0, slashIndex);
        const uploadedTime = new Date(b.uploadedAt).getTime();

        const current = prefixMap.get(prefix) || { hasMeta: false, oldestUpload: uploadedTime };
        if (b.pathname === `${prefix}/__meta.json`) {
          current.hasMeta = true;
        }
        if (uploadedTime < current.oldestUpload) {
          current.oldestUpload = uploadedTime;
        }
        prefixMap.set(prefix, current);
      }

      cursor = listResult.hasMore ? listResult.cursor : undefined;
    } while (cursor);

    const orphans: string[] = [];
    for (const [prefix, data] of prefixMap.entries()) {
      if (!data.hasMeta && data.oldestUpload < cutoffTime) {
        orphans.push(prefix);
      }
    }
    return orphans;
  }
}

/**
 * In-memory storage provider for isolated tests and offline operation
 */
function memoryEtag(data: Uint8Array): string {
  return `"${createHash('sha256').update(data).digest('hex').slice(0, 32)}"`;
}

export class MemoryStorage implements StorageProvider {
  public blobs = new Map<string, { data: Uint8Array; contentType: string; uploadedAt: Date }>();

  async getMeta(slug: string): Promise<ShareMeta | null> {
    const read = await this.readMeta(slug);
    return read ? read.meta : null;
  }

  async readMeta(slug: string): Promise<MetaRead | null> {
    const entry = this.blobs.get(`${slug}/__meta.json`);
    if (!entry) return null;
    const text = new TextDecoder().decode(entry.data);
    return { meta: JSON.parse(text) as ShareMeta, etag: memoryEtag(entry.data) };
  }

  async saveMeta(slug: string, meta: ShareMeta, options: SaveMetaOptions = {}): Promise<void> {
    if (options.ifMatch) {
      const current = this.blobs.get(`${slug}/__meta.json`);
      if (!current || memoryEtag(current.data) !== options.ifMatch) throw new MetaConflictError(slug);
    }
    const text = JSON.stringify(meta, null, 2);
    const data = new TextEncoder().encode(text);
    this.blobs.set(`${slug}/__meta.json`, {
      data,
      contentType: 'application/json; charset=utf-8',
      uploadedAt: new Date(),
    });
  }

  async putAsset(
    slug: string,
    filename: string,
    data: Buffer | Uint8Array | string,
    contentType: string,
    options: PutAssetOptions = {}
  ): Promise<{ url: string; size: number; etag: string }> {
    if (options.ifMatch) {
      const current = this.blobs.get(`${slug}/${filename}`);
      if (!current || memoryEtag(current.data) !== options.ifMatch) throw new AssetConflictError(slug, filename);
    }
    if (options.ifAbsent && this.blobs.has(`${slug}/${filename}`)) {
      throw new AssetConflictError(slug, filename);
    }
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data);
    this.blobs.set(`${slug}/${filename}`, {
      data: bytes,
      contentType,
      uploadedAt: new Date(),
    });
    const baseUrl = process.env.SHARE_BASE_URL
      ? process.env.SHARE_BASE_URL.replace(/\/+$/, '')
      : 'https://blob.local';
    return {
      url: `${baseUrl}/${slug}/${filename}`,
      size: bytes.length,
      etag: memoryEtag(bytes),
    };
  }

  async getAsset(
    slug: string,
    filename: string,
    options: { ifNoneMatch?: string } = {}
  ): Promise<AssetRead | null> {
    const entry = this.blobs.get(`${slug}/${filename}`);
    if (!entry) return null;
    const etag = memoryEtag(entry.data);
    if (options.ifNoneMatch && options.ifNoneMatch === etag) {
      return { stream: null, contentType: '', size: 0, etag, notModified: true };
    }

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(entry.data);
        controller.close();
      },
    });

    return {
      stream,
      contentType: entry.contentType,
      size: entry.data.length,
      etag,
      notModified: false,
    };
  }

  async readAssetForUpdate(slug: string, filename: string): Promise<{ text: string; etag: string } | null> {
    const entry = this.blobs.get(`${slug}/${filename}`);
    if (!entry) return null;
    return { text: new TextDecoder().decode(entry.data), etag: memoryEtag(entry.data) };
  }

  async headAsset(slug: string, filename: string): Promise<AssetHead | null> {
    const entry = this.blobs.get(`${slug}/${filename}`);
    if (!entry) return null;
    return {
      exists: true,
      size: entry.data.length,
      contentType: entry.contentType,
      etag: memoryEtag(entry.data),
    };
  }

  async createUploadTokens(
    slug: string,
    files: UploadRequestFile[]
  ): Promise<UploadTokensResult> {
    const prefix = `${slug}/`;
    const tokens: IssuedFileToken[] = [];
    const validUntil = Date.now() + UPLOAD_URL_TTL_MS;

    for (const file of files) {
      if (isReservedAssetName(file.name)) {
        throw new Error(
          `Asset name "${file.name}" is reserved because it contains a segment starting with "__".`
        );
      }
      const pathname = `${slug}/${file.name}`;
      tokens.push({
        name: file.name,
        pathname,
        uploadUrl: `https://mock.blob.local/${pathname}?operation=put&access=${BLOB_ACCESS}`,
      });
    }

    return { slug, prefix, tokens, validUntil };
  }

  async deleteBlobs(urls: string[]): Promise<void> {
    for (const url of urls) {
      for (const [key] of this.blobs.entries()) {
        if (key === url || url.endsWith(`/${key}`)) {
          this.blobs.delete(key);
        }
      }
    }
  }

  async deleteShare(slug: string): Promise<void> {
    const prefix = `${slug}/`;
    for (const key of Array.from(this.blobs.keys())) {
      if (key.startsWith(prefix)) {
        this.blobs.delete(key);
      }
    }
  }

  async listAllShares(slugPrefix: string = ''): Promise<ShareMeta[]> {
    const results: ShareMeta[] = [];
    for (const [key, entry] of this.blobs.entries()) {
      if (key.startsWith(slugPrefix) && key.endsWith('/__meta.json')) {
        const text = new TextDecoder().decode(entry.data);
        results.push(JSON.parse(text));
      }
    }
    return results;
  }

  async listOrphanPrefixes(olderThanMs: number = 24 * 60 * 60 * 1000): Promise<string[]> {
    const cutoffTime = Date.now() - olderThanMs;
    const prefixMap = new Map<string, { hasMeta: boolean; oldestUpload: number }>();

    for (const [key, entry] of this.blobs.entries()) {
      const slashIndex = key.indexOf('/');
      if (slashIndex === -1) continue;
      const prefix = key.slice(0, slashIndex);
      const uploadedTime = entry.uploadedAt.getTime();

      const current = prefixMap.get(prefix) || { hasMeta: false, oldestUpload: uploadedTime };
      if (key === `${prefix}/__meta.json`) {
        current.hasMeta = true;
      }
      if (uploadedTime < current.oldestUpload) {
        current.oldestUpload = uploadedTime;
      }
      prefixMap.set(prefix, current);
    }

    const orphans: string[] = [];
    for (const [prefix, data] of prefixMap.entries()) {
      if (!data.hasMeta && data.oldestUpload < cutoffTime) {
        orphans.push(prefix);
      }
    }
    return orphans;
  }
}

// Global active storage provider
let currentStorage: StorageProvider =
  process.env.STORAGE_PROVIDER === 'memory'
    ? new MemoryStorage()
    : new VercelBlobStorage();

export function getStorage(): StorageProvider {
  return currentStorage;
}

export function setStorageForTesting(storage: StorageProvider): void {
  currentStorage = storage;
}
