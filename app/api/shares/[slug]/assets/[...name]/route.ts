import { getStorage } from '../../../../../../lib/storage.ts';
import { verifyApiToken } from '../../../../../../lib/auth.ts';
import { rejectionResponse } from '../../../../../../lib/shareInput.ts';
import {
  SLUG_REGEX,
  isRejection,
  isValidAssetName,
  removeAsset,
  syncAssetFromStorage,
  toShareDetail,
} from '../../../../../../lib/shares.ts';

type Params = { params: Promise<{ slug: string; name: string[] }> };

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function resolve(request: Request, { params }: Params) {
  if (!verifyApiToken(request)) {
    return json({ error: 'Unauthorized' }, 401);
  }
  const { slug, name } = await params;
  const assetName = (name ?? []).join('/');
  if (!SLUG_REGEX.test(slug) || !isValidAssetName(assetName)) {
    return json({ error: 'Not Found' }, 404);
  }
  return { slug, assetName };
}

/**
 * Brings the record of one file in line with the bytes in storage, after an upload with
 * `overwrite` replaced them. Idempotent: calling it again changes nothing.
 */
export async function PUT(request: Request, ctx: Params) {
  const resolved = await resolve(request, ctx);
  if (resolved instanceof Response) return resolved;

  let body: { contentType?: unknown; originalName?: unknown; sha256?: unknown } = {};
  const raw = await request.text();
  if (raw.trim()) {
    try {
      body = JSON.parse(raw);
    } catch {
      return json({ error: 'Invalid JSON payload' }, 400);
    }
  }
  if (body.contentType !== undefined && (typeof body.contentType !== 'string' || !body.contentType.trim())) {
    return json({ error: 'Field "contentType" must be a non-empty string when present' }, 400);
  }
  if (body.originalName !== undefined && (typeof body.originalName !== 'string' || !body.originalName.trim())) {
    return json({ error: 'Field "originalName" must be a non-empty string when present' }, 400);
  }
  if (body.sha256 !== undefined && typeof body.sha256 !== 'string') {
    return json({ error: 'Field "sha256" must be a string when present' }, 400);
  }

  const result = await syncAssetFromStorage(getStorage(), resolved.slug, resolved.assetName, {
    contentType: body.contentType as string | undefined,
    originalName: body.originalName as string | undefined,
    sha256: body.sha256 as string | undefined,
  });
  if (isRejection(result)) return rejectionResponse(result);
  return json(toShareDetail(result.meta), 200);
}

/** Removes one file. Removing the last one removes the share, and the response says so. */
export async function DELETE(request: Request, ctx: Params) {
  const resolved = await resolve(request, ctx);
  if (resolved instanceof Response) return resolved;

  const result = await removeAsset(getStorage(), resolved.slug, resolved.assetName);
  if (isRejection(result)) return rejectionResponse(result);
  return json(
    {
      unpublished: result.shareDeleted,
      share: result.meta ? toShareDetail(result.meta) : null,
    },
    200
  );
}
