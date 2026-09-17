/**
 * lib/shares.ts
 *
 * The one place a share is created, replaced, extended or removed. The HTTP API and the MCP tools
 * are two doors into the same operations, and keeping the operations here means a rule such as
 * "a share cannot be created under a reserved slug" holds behind both doors.
 *
 * Every function takes the storage it works on rather than reaching for the global, so a test can
 * hand it a MemoryStorage and the HTTP routes can hand it the real one.
 */

import {
  MetaConflictError,
  isReservedAssetName,
  type ShareAsset,
  type ShareMeta,
  type StorageProvider,
  type UploadTokensResult,
} from './storage.ts';
import crypto from 'node:crypto';
import { hashPassword } from './auth.ts';
import { getBaseUrl } from './config.ts';
import {
  SLUG_REGEX,
  hasExpired,
  isRejection,
  readSha256,
  validateShareInput,
  type ShareInputBody,
  type ShareInputRejection,
} from './shareInput.ts';

export { SLUG_REGEX, hasExpired, isRejection };
export type { ShareInputRejection };

/** Largest single upload the service accepts, enforced by the presigned URL constraints. */
export const MAX_FILE_SIZE = 20 * 1024 * 1024;

/**
 * The blob an uploaded page's HTML lives in. It carries the reserved `__` prefix, so it is not an
 * asset any caller can name, list or replace through the file operations: a page is changed by
 * replacing the share itself.
 */
export const PAGE_ASSET_NAME = '__page.html';

/**
 * Slugs that would sit on top of an application route. The static routes win in Next.js, so a
 * share created under one of these would exist in storage and be unreachable on the web.
 */
const RESERVED_SLUGS = new Set(['api', 'mcp', 'oauth']);

export function isValidSlug(slug: unknown): slug is string {
  return typeof slug === 'string' && SLUG_REGEX.test(slug) && !RESERVED_SLUGS.has(slug);
}

export function invalidSlugRejection(): ShareInputRejection {
  return {
    error:
      'Invalid slug. Slugs must be lowercase alphanumeric with single hyphens, and "api", "mcp" and "oauth" are reserved.',
    status: 400,
  };
}

/** Whether an asset name can be stored and served: no traversal, no absolute path, no reserved segment. */
export function isValidAssetName(name: unknown): name is string {
  if (typeof name !== 'string' || name.length === 0 || name.length > 255) return false;
  if (name.includes('..') || name.startsWith('/') || name.endsWith('/')) return false;
  if (name.includes('\\')) return false;
  for (let i = 0; i < name.length; i++) {
    if (name.charCodeAt(i) < 32) return false;
  }
  return !isReservedAssetName(name);
}

export function shareUrl(slug: string): string {
  return `${getBaseUrl()}/${encodeURIComponent(slug)}`;
}

export function assetUrl(slug: string, name: string): string {
  return `${getBaseUrl()}/${encodeURIComponent(slug)}/${encodeURIComponent(name)}`;
}

export type AssetView = ShareAsset & { url: string };

export function toAssetView(slug: string, asset: ShareAsset): AssetView {
  return {
    name: asset.name,
    originalName: asset.originalName,
    contentType: asset.contentType,
    sizeBytes: asset.sizeBytes,
    etag: asset.etag,
    sha256: asset.sha256,
    updatedAt: asset.updatedAt,
    url: assetUrl(slug, asset.name),
  };
}

export type ShareSummary = {
  slug: string;
  title: string;
  description?: string;
  lang: string;
  kind: ShareMeta['kind'];
  createdAt: string;
  url: string;
  assetCount: number;
  totalSize: number;
  expiresAt: string | null;
  isExpired: boolean;
  isPasswordProtected: boolean;
};

export type ShareDetail = ShareSummary & { assets: AssetView[] };

/** The public shape of a share: everything in the record except the password hash. */
export function toShareSummary(meta: ShareMeta): ShareSummary {
  return {
    slug: meta.slug,
    title: meta.title,
    description: meta.description,
    lang: meta.lang,
    kind: meta.kind,
    createdAt: meta.createdAt,
    url: shareUrl(meta.slug),
    assetCount: meta.assets.length,
    totalSize: meta.assets.reduce((sum, a) => sum + (a.sizeBytes || 0), 0),
    expiresAt: meta.expiresAt || null,
    isExpired: hasExpired(meta.expiresAt),
    isPasswordProtected: Boolean(meta.passwordHash),
  };
}

export function toShareDetail(meta: ShareMeta): ShareDetail {
  return {
    ...toShareSummary(meta),
    assets: meta.assets.map((a) => toAssetView(meta.slug, a)),
  };
}

export type UploadRequest = { name: string; contentType: string; sizeBytes: number; overwrite?: boolean };

/**
 * Issues presigned upload URLs for `files` under `slug`. A slug that already exists is fine as
 * long as none of the names is already one of its assets: that is how a file joins an existing
 * share. A name that is already there is a conflict, because create never overwrites, unless the
 * file says `overwrite`, in which case the upload replaces the bytes behind the same URL.
 */
export async function issueUploadUrls(
  storage: StorageProvider,
  slug: string,
  files: UploadRequest[]
): Promise<UploadTokensResult | ShareInputRejection> {
  if (!isValidSlug(slug)) return invalidSlugRejection();
  if (files.length === 0) {
    return { error: 'At least one file must be declared in files array', status: 400 };
  }
  for (const f of files) {
    if (!f.name || typeof f.name !== 'string' || !f.contentType || typeof f.contentType !== 'string') {
      return { error: 'Each file must specify a valid name and contentType', status: 400 };
    }
    if (isReservedAssetName(f.name)) {
      return {
        error: `Asset name "${f.name}" contains a reserved prefix ("__"). File segments starting with "__" are reserved.`,
        status: 400,
      };
    }
    if (!isValidAssetName(f.name)) {
      return { error: `Asset name "${f.name}" is not a valid file name`, status: 400 };
    }
    if (typeof f.sizeBytes !== 'number' || !Number.isFinite(f.sizeBytes) || f.sizeBytes <= 0) {
      return { error: `File "${f.name}" must specify a positive numeric sizeBytes`, status: 400 };
    }
    if (f.sizeBytes > MAX_FILE_SIZE) {
      return {
        error: `File "${f.name}" exceeds the maximum allowed size of 20 MB (${MAX_FILE_SIZE} bytes)`,
        status: 400,
      };
    }
  }

  const existing = await storage.getMeta(slug);
  if (existing) {
    if (existing.kind !== 'generated') {
      return {
        error: `Share "${slug}" is an uploaded page and cannot hold files`,
        status: 409,
      };
    }
    const taken = files.find((f) => !f.overwrite && existing.assets.some((a) => a.name === f.name));
    if (taken) {
      return {
        error: `Share "${slug}" already has a file named "${taken.name}"; choose another name, delete it first, or declare overwrite`,
        status: 409,
      };
    }
  }

  return storage.createUploadTokens(slug, files);
}

export type ShareWriteResult = { meta: ShareMeta; created: boolean };

type AssetAddition = { name: string; originalName?: string; contentType: string; sha256?: string };

export function sha256Hex(data: Buffer | Uint8Array | string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

const MUTATION_ATTEMPTS = 5;

/**
 * Read the record, change it, write it back only if nobody else wrote it in between, and start
 * over when somebody did. This is what makes adding, replacing and removing single files safe to
 * run concurrently: two callers never build their record from the same stale copy and silently
 * undo each other. `change` returns the new record, or a rejection to stop with.
 */
async function mutateShare(
  storage: StorageProvider,
  slug: string,
  change: (meta: ShareMeta) => Promise<ShareMeta | ShareInputRejection>
): Promise<ShareWriteResult | ShareInputRejection> {
  if (!SLUG_REGEX.test(slug)) return { error: 'Not Found', status: 404 };
  for (let attempt = 1; ; attempt++) {
    const current = await storage.readMeta(slug);
    if (!current) return { error: 'Not Found', status: 404 };
    const next = await change(current.meta);
    if (isRejection(next)) return next;
    try {
      await storage.saveMeta(slug, next, { ifMatch: current.etag });
      return { meta: next, created: false };
    } catch (err) {
      if (!(err instanceof MetaConflictError) || attempt >= MUTATION_ATTEMPTS) throw err;
    }
  }
}

/**
 * Creates a share from validated input. The record is written last, so the share only becomes
 * visible once every file it names exists.
 */
export async function createShare(
  storage: StorageProvider,
  slug: string,
  body: ShareInputBody
): Promise<ShareWriteResult | ShareInputRejection> {
  if (!isValidSlug(slug)) return invalidSlugRejection();

  const existing = await storage.getMeta(slug);
  if (existing) {
    return { error: `Share "${slug}" already exists`, status: 409 };
  }

  const validated = await validateShareInput(slug, body, storage);
  if (isRejection(validated)) return validated;

  const passwordHash = validated.password ? await hashPassword(validated.password) : null;

  if (validated.kind === 'uploaded' && validated.html) {
    await storage.putAsset(slug, PAGE_ASSET_NAME, validated.html, 'text/html; charset=utf-8');
  }

  const meta: ShareMeta = {
    slug,
    title: validated.title,
    description: validated.description,
    lang: validated.lang,
    createdAt: new Date().toISOString(),
    kind: validated.kind,
    assets: validated.assets,
    expiresAt: validated.expiresAt || null,
    passwordHash,
  };
  await storage.saveMeta(slug, meta);
  return { meta, created: true };
}

/**
 * Replaces the metadata and asset set of an existing share, pruning the blobs that are no longer
 * named. Fields absent from `body` for expiry and password keep their stored value. The record is
 * written before anything is pruned, so a write that loses the race deletes nothing.
 */
export async function replaceShare(
  storage: StorageProvider,
  slug: string,
  body: ShareInputBody
): Promise<ShareWriteResult | ShareInputRejection> {
  let obsolete: string[] = [];
  const result = await mutateShare(storage, slug, async (existing) => {
    const validated = await validateShareInput(slug, body, storage);
    if (isRejection(validated)) return validated;

    const keep = new Set(validated.assets.map((a) => a.name));
    obsolete = existing.assets.filter((a) => !keep.has(a.name)).map((a) => `${slug}/${a.name}`);
    if (existing.kind === 'uploaded' && validated.kind !== 'uploaded') {
      obsolete.push(`${slug}/${PAGE_ASSET_NAME}`);
    }

    if (validated.kind === 'uploaded' && validated.html) {
      await storage.putAsset(slug, PAGE_ASSET_NAME, validated.html, 'text/html; charset=utf-8');
    }

    let passwordHash = existing.passwordHash;
    if (validated.password !== undefined) {
      passwordHash = validated.password ? await hashPassword(validated.password) : null;
    }

    return {
      slug,
      title: validated.title,
      description: validated.description,
      lang: validated.lang,
      createdAt: existing.createdAt,
      kind: validated.kind,
      assets: validated.assets,
      expiresAt: validated.expiresAt !== undefined ? validated.expiresAt : existing.expiresAt,
      passwordHash,
    };
  });
  if (isRejection(result)) return result;
  if (obsolete.length > 0) {
    await storage.deleteBlobs(obsolete);
  }
  return result;
}

function notAFolder(slug: string): ShareInputRejection {
  return { error: `Share "${slug}" is an uploaded page and cannot hold files`, status: 409 };
}

function noSuchFile(slug: string, name: string): ShareInputRejection {
  return { error: `Share "${slug}" has no file named "${name}"`, status: 404 };
}

/**
 * Adds already-uploaded files to a generated share, keeping everything else as it is. Each file
 * must already exist in storage; its size and ETag come from there, never from the caller.
 */
export async function appendAssets(
  storage: StorageProvider,
  slug: string,
  additions: AssetAddition[]
): Promise<ShareWriteResult | ShareInputRejection> {
  if (additions.length === 0) {
    return { error: 'At least one asset is required', status: 400 };
  }
  for (const f of additions) {
    if (!f.name || typeof f.name !== 'string' || !f.contentType || typeof f.contentType !== 'string') {
      return { error: 'Each asset must specify "name" and "contentType"', status: 400 };
    }
    if (isReservedAssetName(f.name)) {
      return {
        error: `Asset name "${f.name}" contains a reserved prefix ("__"). File segments starting with "__" are reserved.`,
        status: 400,
      };
    }
    if (!isValidAssetName(f.name)) {
      return { error: `Asset name "${f.name}" is not a valid file name`, status: 400 };
    }
    const digest = readSha256(f.sha256);
    if (typeof digest === 'object') return digest;
  }
  const names = new Set<string>();
  for (const f of additions) {
    if (names.has(f.name)) return { error: `Asset "${f.name}" is declared twice`, status: 400 };
    names.add(f.name);
  }

  return mutateShare(storage, slug, async (meta) => {
    if (meta.kind !== 'generated') return notAFolder(slug);
    const taken = additions.find((f) => meta.assets.some((a) => a.name === f.name));
    if (taken) {
      return {
        error: `Share "${slug}" already has a file named "${taken.name}"; choose another name or delete it first`,
        status: 409,
      };
    }
    const resolved: ShareAsset[] = [];
    for (const f of additions) {
      const head = await storage.headAsset(slug, f.name);
      if (!head || !head.exists) {
        return {
          error: `Declared asset "${f.name}" does not exist in storage under prefix "${slug}/"`,
          status: 400,
        };
      }
      const sha256 = readSha256(f.sha256) as string | undefined;
      resolved.push({
        name: f.name,
        originalName: f.originalName || f.name,
        contentType: f.contentType,
        sizeBytes: head.size,
        etag: head.etag,
        ...(sha256 ? { sha256 } : {}),
      });
    }
    return { ...meta, assets: [...meta.assets, ...resolved] };
  });
}

/**
 * Replaces the bytes of one file in place. The URL stays the same; the record notes the new size,
 * the store's new ETag and when it happened.
 */
export async function replaceAssetContent(
  storage: StorageProvider,
  slug: string,
  name: string,
  data: Buffer | Uint8Array | string,
  contentType: string
): Promise<ShareWriteResult | ShareInputRejection> {
  const before = await storage.getMeta(slug);
  if (!before) return { error: 'Not Found', status: 404 };
  if (before.kind !== 'generated') return notAFolder(slug);
  if (!before.assets.some((a) => a.name === name)) return noSuchFile(slug, name);

  const written = await storage.putAsset(slug, name, data, contentType);
  const sha256 = sha256Hex(data);
  const updatedAt = new Date().toISOString();
  return mutateShare(storage, slug, async (meta) => {
    if (!meta.assets.some((a) => a.name === name)) return noSuchFile(slug, name);
    return {
      ...meta,
      assets: meta.assets.map((a) =>
        a.name === name ? { ...a, contentType, sizeBytes: written.size, etag: written.etag, sha256, updatedAt } : a
      ),
    };
  });
}

export type SyncAssetResult = { meta: ShareMeta; changed: boolean };

/**
 * Brings the record of one file in line with the bytes actually in storage, after a presigned
 * upload replaced them. A record with the store's current ETag is left alone. Safe to repeat.
 */
export async function syncAssetFromStorage(
  storage: StorageProvider,
  slug: string,
  name: string,
  options: { contentType?: string; originalName?: string; sha256?: string } = {}
): Promise<SyncAssetResult | ShareInputRejection> {
  const declared = readSha256(options.sha256);
  if (typeof declared === 'object') return declared;
  const head = await storage.headAsset(slug, name);
  let changed = false;
  const result = await mutateShare(storage, slug, async (meta) => {
    const stored = meta.assets.find((a) => a.name === name);
    if (!stored) return noSuchFile(slug, name);
    if (!head || !head.exists) {
      return { error: `File "${name}" is missing from storage under "${slug}/"`, status: 404 };
    }
    const renamed = options.originalName !== undefined && options.originalName !== stored.originalName;
    const retyped = options.contentType !== undefined && options.contentType !== stored.contentType;
    const redigested = declared !== undefined && declared !== stored.sha256;
    // A record written before etags were kept can only be compared by size; it adopts the etag now.
    const bytesChanged = stored.etag ? stored.etag !== head.etag : stored.sizeBytes !== head.size;
    changed = bytesChanged || renamed || retyped || redigested;
    if (!changed && stored.etag === head.etag) return meta;
    return {
      ...meta,
      assets: meta.assets.map((a) =>
        a.name === name
          ? {
              ...a,
              originalName: options.originalName ?? a.originalName,
              contentType: options.contentType ?? a.contentType,
              sizeBytes: head.size,
              etag: head.etag,
              // A digest the caller did not restate no longer describes bytes that changed.
              ...(declared !== undefined ? { sha256: declared } : bytesChanged ? { sha256: undefined } : {}),
              ...(bytesChanged ? { updatedAt: new Date().toISOString() } : {}),
            }
          : a
      ),
    };
  });
  if (isRejection(result)) return result;
  return { meta: result.meta, changed };
}

export type RemoveAssetResult = { meta: ShareMeta | null; shareDeleted: boolean };

/**
 * Removes one file from a generated share. A generated share must name at least one file, so
 * removing the last one removes the share. The record is written first, so a caller that lost the
 * race to an addition sees its file in the new record instead of an empty share.
 */
export async function removeAsset(
  storage: StorageProvider,
  slug: string,
  name: string
): Promise<RemoveAssetResult | ShareInputRejection> {
  const result = await mutateShare(storage, slug, async (meta) => {
    if (meta.kind !== 'generated') return notAFolder(slug);
    if (!meta.assets.some((a) => a.name === name)) return noSuchFile(slug, name);
    return { ...meta, assets: meta.assets.filter((a) => a.name !== name) };
  });
  if (isRejection(result)) return result;
  if (result.meta.assets.length === 0) {
    await storage.deleteShare(slug);
    return { meta: null, shareDeleted: true };
  }
  await storage.deleteBlobs([`${slug}/${name}`]);
  return { meta: result.meta, shareDeleted: false };
}

export async function deleteShare(storage: StorageProvider, slug: string): Promise<void> {
  await storage.deleteShare(slug);
}

/** Every share, oldest first, so pages and listings are stable between calls. */
export async function listShares(storage: StorageProvider): Promise<ShareMeta[]> {
  const all = await storage.listAllShares();
  return all.sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.slug.localeCompare(b.slug));
}
