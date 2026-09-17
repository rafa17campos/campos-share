import { hasExpired } from '../../../lib/shareInput.ts';
import { getStorage, isReservedAssetName } from '../../../lib/storage.ts';
import {
  verifyUnlockCookieValue,
  getUnlockCookieFromRequest,
} from '../../../lib/auth.ts';

const SLUG_REGEX = /^[a-z0-9]+(-[a-z0-9]+)*$/;

function notFound(): Response {
  return new Response('Not Found', {
    status: 404,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'X-Robots-Tag': 'noindex, nofollow',
    },
  });
}

export async function GET(
  request: Request,
  { params }: { params: Promise<{ slug: string; filename: string[] }> }
) {
  const { slug, filename } = await params;

  if (!SLUG_REGEX.test(slug) || !filename || filename.length === 0) {
    return notFound();
  }

  const assetName = filename.join('/');
  // Prevent path traversal or reserved system blobs (any segment starting with __)
  if (assetName.includes('..') || assetName.startsWith('/') || isReservedAssetName(assetName)) {
    return notFound();
  }

  const storage = getStorage();
  const meta = await storage.getMeta(slug);

  if (!meta) {
    return notFound();
  }

  // Phase 2: Expiry check
  if (hasExpired(meta.expiresAt)) {
    return notFound();
  }

  // Phase 2: Password protection check
  const isProtected = Boolean(meta.passwordHash);
  if (isProtected) {
    const cookieValue = getUnlockCookieFromRequest(request, slug);
    const isUnlocked = verifyUnlockCookieValue(cookieValue, slug);

    if (!isUnlocked) {
      return new Response('Unauthorized', {
        status: 401,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'private, no-cache',
          'X-Robots-Tag': 'noindex, nofollow',
        },
      });
    }
  }

  // The served type comes from the record, never from the stored object. A presigned upload URL
  // carries an allowedContentTypes constraint that the store does not enforce (measured), so a
  // blob's own content type is attacker-influenced; __meta.json holds what was declared and
  // accepted. Serving the blob's type would let an upload land as text/html and run as script on
  // this origin, alongside every other share and its unlock cookie.
  const declared = meta.assets.find((a) => a.name === assetName)?.contentType;
  if (!declared) {
    return notFound();
  }

  // A file can be replaced in place and keep its URL, so nothing may cache it as immutable. Every
  // response carries the store's ETag and the browser's If-None-Match goes through to the store,
  // which answers 304 without moving the bytes when nothing changed.
  const asset = await storage.getAsset(slug, assetName, {
    ifNoneMatch: request.headers.get('if-none-match') ?? undefined,
  });
  if (!asset) {
    return notFound();
  }

  let cacheControl = 'public, max-age=0, must-revalidate';
  if (isProtected) {
    cacheControl = 'private, no-cache';
  } else if (meta.expiresAt) {
    cacheControl = 'private, max-age=0, must-revalidate';
  }

  const headers: Record<string, string> = {
    'Content-Type': declared,
    'Cache-Control': cacheControl,
    'X-Robots-Tag': 'noindex, nofollow',
    'X-Content-Type-Options': 'nosniff',
    ETag: asset.etag,
  };

  if (asset.notModified || !asset.stream) {
    return new Response(null, { status: 304, headers });
  }

  headers['Content-Length'] = String(asset.size);
  return new Response(asset.stream, { status: 200, headers });
}
