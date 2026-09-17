/**
 * lib/shareInput.ts
 *
 * The one place a share's fields are validated. Creating and replacing are the same shape with a
 * different verb, and keeping two copies of these rules is how replacing came to reject a share
 * without a description long after creating had stopped.
 *
 * `hasExpired` lives here rather than at each read because it is the same rule seen from the other
 * side: five routes each carried their own copy of the comparison, and every copy skipped the
 * check when the stored date would not parse — an expiry that fails open is not an expiry.
 */

import {
  isReservedAssetName,
  type ShareAsset,
  type StorageProvider,
} from './storage.ts';

export const SLUG_REGEX = /^[a-z0-9]+(-[a-z0-9]+)*$/;

export type ShareInputBody = {
  title?: unknown;
  description?: unknown;
  lang?: unknown;
  kind?: unknown;
  html?: unknown;
  expiresAt?: unknown;
  password?: unknown;
  assets?: Array<{ name?: string; originalName?: string; contentType?: string; sha256?: string }>;
};

export const SHA256_HEX = /^[0-9a-f]{64}$/;

/** A declared digest, normalised; undefined when absent; a rejection when malformed. */
export function readSha256(raw: unknown): string | undefined | ShareInputRejection {
  if (raw === undefined || raw === null || raw === '') return undefined;
  if (typeof raw !== 'string' || !SHA256_HEX.test(raw.trim().toLowerCase())) {
    return { error: 'Field "sha256" must be the 64-character lowercase hex SHA-256 of the file', status: 400 };
  }
  return raw.trim().toLowerCase();
}

export type ShareInputRejection = { error: string; status: number };

export type ShareInputAccepted = {
  title: string;
  description?: string;
  lang: string;
  kind: 'generated' | 'uploaded';
  html: string | null;
  assets: ShareAsset[];
  /** Absent means "leave it as it is"; null clears it; a string is a canonical ISO instant. */
  expiresAt?: string | null;
  /** Absent means "leave it as it is"; null removes the password; a string sets one. */
  password?: string | null;
};

/**
 * Whether a share has stopped being served. A stored date that will not parse counts as expired:
 * the alternative is serving a share whose expiry silently did nothing.
 */
export function hasExpired(expiresAt: string | null | undefined, now: number = Date.now()): boolean {
  if (!expiresAt) return false;
  const at = new Date(expiresAt).getTime();
  return Number.isNaN(at) ? true : now > at;
}

type FieldResult<T> = { value: T } | ShareInputRejection;

function readExpiresAt(raw: unknown): FieldResult<string | null | undefined> {
  if (raw === undefined) return { value: undefined };
  if (raw === null || raw === '') return { value: null };
  if (typeof raw !== 'string') {
    return { error: 'Field "expiresAt" must be an ISO date string, null, or omitted', status: 400 };
  }
  const at = new Date(raw).getTime();
  if (Number.isNaN(at)) {
    return { error: `Field "expiresAt" is not a date this can read: "${raw}"`, status: 400 };
  }
  return { value: new Date(at).toISOString() };
}

function readPassword(raw: unknown): FieldResult<string | null | undefined> {
  if (raw === undefined) return { value: undefined };
  if (raw === null || raw === '') return { value: null };
  if (typeof raw !== 'string') {
    return { error: 'Field "password" must be a string, null, or omitted', status: 400 };
  }
  return { value: raw };
}

export function isRejection<T extends object>(
  result: ShareInputRejection | T
): result is ShareInputRejection {
  return 'error' in result && 'status' in result;
}

export function rejectionResponse(rejection: ShareInputRejection): Response {
  return new Response(JSON.stringify({ error: rejection.error }), {
    status: rejection.status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export async function validateShareInput(
  slug: string,
  body: ShareInputBody,
  storage: StorageProvider
): Promise<ShareInputRejection | ShareInputAccepted> {
  const { title, description, lang, kind, html, assets } = body;

  const expiry = readExpiresAt(body.expiresAt);
  if ('error' in expiry) return expiry;
  const secret = readPassword(body.password);
  if ('error' in secret) return secret;

  if (!title || typeof title !== 'string' || !title.trim()) {
    return { error: 'Field "title" is required and must be non-empty', status: 400 };
  }

  if (description !== undefined && description !== null && typeof description !== 'string') {
    return { error: 'Field "description" must be a string when present', status: 400 };
  }

  if (!lang || typeof lang !== 'string' || !lang.trim()) {
    return { error: 'Field "lang" is required and must be non-empty', status: 400 };
  }

  if (kind !== 'generated' && kind !== 'uploaded') {
    return { error: 'Field "kind" must be either "generated" or "uploaded"', status: 400 };
  }

  if (kind === 'uploaded') {
    if (!html || typeof html !== 'string' || !html.trim()) {
      return {
        error: 'For kind "uploaded", "html" is required and must be non-empty',
        status: 400,
      };
    }
    if (assets && assets.length > 0) {
      return {
        error: 'For kind "uploaded", assets array must be empty or omitted',
        status: 400,
      };
    }
    return {
      title,
      description: (description as string | undefined) ?? undefined,
      lang,
      kind,
      html,
      assets: [],
      expiresAt: expiry.value,
      password: secret.value,
    };
  }

  if (html) {
    return { error: 'For kind "generated", "html" field must be null or omitted', status: 400 };
  }
  if (!Array.isArray(assets) || assets.length === 0) {
    return { error: 'For kind "generated", at least one asset is required', status: 400 };
  }

  const resolved: ShareAsset[] = [];
  for (const asset of assets) {
    if (
      !asset.name ||
      typeof asset.name !== 'string' ||
      !asset.contentType ||
      typeof asset.contentType !== 'string'
    ) {
      return { error: 'Each asset must specify "name" and "contentType"', status: 400 };
    }
    if (isReservedAssetName(asset.name)) {
      return {
        error: `Asset name "${asset.name}" contains a reserved prefix ("__"). File segments starting with "__" are reserved.`,
        status: 400,
      };
    }
    const sha256 = readSha256(asset.sha256);
    if (typeof sha256 === 'object') return sha256;
    const head = await storage.headAsset(slug, asset.name);
    if (!head || !head.exists) {
      return {
        error: `Declared asset "${asset.name}" does not exist in storage under prefix "${slug}/"`,
        status: 400,
      };
    }
    resolved.push({
      name: asset.name,
      originalName: asset.originalName || asset.name,
      contentType: asset.contentType || head.contentType,
      sizeBytes: head.size,
      etag: head.etag,
      ...(sha256 ? { sha256 } : {}),
    });
  }

  return {
    title,
    description: (description as string | undefined) ?? undefined,
    lang,
    kind,
    html: null,
    assets: resolved,
    expiresAt: expiry.value,
    password: secret.value,
  };
}
