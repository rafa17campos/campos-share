import { hasExpired } from '../../lib/shareInput.ts';
import crypto from 'node:crypto';
import { getStorage } from '../../lib/storage.ts';
import { isInlineText } from '../../lib/text.ts';
import { getBaseUrl } from '../../lib/config.ts';
import { PAGE_ASSET_NAME } from '../../lib/shares.ts';
import {
  renderSharePage,
  injectUploadedHtml,
  renderPasswordPrompt,
} from '../../lib/renderer.ts';
import {
  verifyUnlockCookieValue,
  getUnlockCookieFromRequest,
} from '../../lib/auth.ts';

const SLUG_REGEX = /^[a-z0-9]+(-[a-z0-9]+)*$/;

const UPLOADED_PAGE_SANDBOX = 'sandbox allow-scripts';

/**
 * The text of every asset small enough to show in the page, so a note reads as itself rather than
 * as a download card. A read that fails leaves that asset as a card rather than failing the page.
 */
async function readInlineText(
  storage: ReturnType<typeof getStorage>,
  meta: Awaited<ReturnType<ReturnType<typeof getStorage>['getMeta']>>,
): Promise<Record<string, string>> {
  if (!meta) return {};
  const entries = await Promise.all(
    meta.assets
      .filter((a) => isInlineText(a.name, a.contentType, a.sizeBytes))
      .map(async (a) => {
        try {
          const asset = await storage.getAsset(meta.slug, a.name);
          if (!asset || !asset.stream) return null;
          return [a.name, await new Response(asset.stream).text()] as const;
        } catch {
          return null;
        }
      }),
  );
  return Object.fromEntries(entries.filter((e): e is readonly [string, string] => e !== null));
}

export async function GET(
  request: Request,
  { params }: { params: Promise<{ slug: string }> }
) {
  const { slug } = await params;

  if (!SLUG_REGEX.test(slug)) {
    return new Response('Not Found', {
      status: 404,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-Robots-Tag': 'noindex, nofollow',
      },
    });
  }

  const storage = getStorage();
  const meta = await storage.getMeta(slug);

  if (!meta) {
    return new Response('Not Found', {
      status: 404,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-Robots-Tag': 'noindex, nofollow',
      },
    });
  }

  // Phase 2: Expiry evaluation
  if (hasExpired(meta.expiresAt)) {
    return new Response('Not Found', {
      status: 404,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-Robots-Tag': 'noindex, nofollow',
      },
    });
  }

  // Phase 2: Password protection evaluation
  const isProtected = Boolean(meta.passwordHash);
  if (isProtected) {
    const cookieValue = getUnlockCookieFromRequest(request, slug);
    const isUnlocked = verifyUnlockCookieValue(cookieValue, slug);

    if (!isUnlocked) {
      const url = new URL(request.url);
      const hasError = url.searchParams.get('error') === '1';
      const promptHtml = renderPasswordPrompt(slug, hasError);
      return new Response(promptHtml, {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'private, no-cache',
          'X-Robots-Tag': 'noindex, nofollow',
        },
      });
    }
  }

  // Determine standard Cache-Control header:
  // Pages must revalidate (max-age=0, must-revalidate) because metadata/assets change on PUT.
  // Only binary assets under immutable filenames are cached with immutable.
  let cacheControl = 'public, max-age=0, must-revalidate';
  if (isProtected) {
    cacheControl = 'private, no-cache';
  } else if (meta.expiresAt) {
    cacheControl = 'private, max-age=0, must-revalidate';
  }

  const baseUrl = getBaseUrl();
  let contentHtml = '';
  // An uploaded page is HTML we did not write, served from the same origin as every other share.
  // The sandbox directive gives it an opaque origin, so document.cookie is empty, storage throws,
  // and a fetch back to this origin is cross-origin and unauthenticated — an uploaded page cannot
  // reach another share's unlock cookie. allow-scripts keeps ordinary pages working; it is safe
  // only while allow-same-origin is absent, and allow-same-origin must never be added.
  let sandboxPolicy: string | null = null;

  if (meta.kind === 'uploaded') {
    const htmlAsset = await storage.getAsset(slug, PAGE_ASSET_NAME);
    if (htmlAsset) {
      const response = new Response(htmlAsset.stream);
      const rawHtml = await response.text();
      contentHtml = injectUploadedHtml(rawHtml, meta);
      sandboxPolicy = UPLOADED_PAGE_SANDBOX;
    } else {
      contentHtml = renderSharePage(meta, baseUrl, await readInlineText(storage, meta));
    }
  } else {
    contentHtml = renderSharePage(meta, baseUrl, await readInlineText(storage, meta));
  }

  // ETag for revalidation
  const etag = `"${crypto.createHash('sha256').update(contentHtml).digest('base64url')}"`;
  const headers: Record<string, string> = {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': cacheControl,
    'X-Robots-Tag': 'noindex, nofollow',
    'X-Content-Type-Options': 'nosniff',
    ETag: etag,
  };
  if (sandboxPolicy) {
    headers['Content-Security-Policy'] = sandboxPolicy;
  }

  const ifNoneMatch = request.headers.get('if-none-match');
  if (ifNoneMatch === etag) {
    return new Response(null, { status: 304, headers });
  }

  return new Response(contentHtml, { status: 200, headers });
}
