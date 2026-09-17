import { getStorage } from '../../../../../lib/storage.ts';
import { verifyApiToken } from '../../../../../lib/auth.ts';
import { rejectionResponse } from '../../../../../lib/shareInput.ts';
import { SLUG_REGEX, appendAssets, isRejection, toShareDetail } from '../../../../../lib/shares.ts';

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Adds already-uploaded files to a share. Unlike `PUT /api/shares/{slug}`, the caller names only
 * the files that join; the record is updated with a conditional write, so two callers adding at
 * the same time both end up in it.
 */
export async function POST(
  request: Request,
  { params }: { params: Promise<{ slug: string }> }
) {
  if (!verifyApiToken(request)) {
    return json({ error: 'Unauthorized' }, 401);
  }

  const { slug } = await params;
  if (!SLUG_REGEX.test(slug)) {
    return json({ error: 'Not Found' }, 404);
  }

  let body: { assets?: Array<{ name?: unknown; originalName?: unknown; contentType?: unknown; sha256?: unknown }> };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON payload' }, 400);
  }
  if (!Array.isArray(body?.assets)) {
    return json({ error: 'Field "assets" must be an array' }, 400);
  }

  const result = await appendAssets(
    getStorage(),
    slug,
    body.assets.map((a) => ({
      name: a?.name as string,
      originalName: typeof a?.originalName === 'string' ? a.originalName : undefined,
      contentType: a?.contentType as string,
      sha256: typeof a?.sha256 === 'string' ? a.sha256 : undefined,
    }))
  );
  if (isRejection(result)) return rejectionResponse(result);
  return json(toShareDetail(result.meta), 200);
}
