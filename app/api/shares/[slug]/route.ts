import { getStorage } from '../../../../lib/storage.ts';
import { verifyApiToken } from '../../../../lib/auth.ts';
import { rejectionResponse, type ShareInputBody } from '../../../../lib/shareInput.ts';
import {
  SLUG_REGEX,
  deleteShare,
  isRejection,
  replaceShare,
  toShareDetail,
} from '../../../../lib/shares.ts';

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export async function GET(
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

  const meta = await getStorage().getMeta(slug);
  if (!meta) {
    return json({ error: 'Not Found' }, 404);
  }

  // Never expose passwordHash in API response
  return json(toShareDetail(meta), 200);
}

export async function PUT(
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

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON payload' }, 400);
  }

  const result = await replaceShare(getStorage(), slug, body as ShareInputBody);
  if (isRejection(result)) return rejectionResponse(result);

  const detail = toShareDetail(result.meta);
  return json(
    {
      slug: detail.slug,
      title: detail.title,
      description: detail.description,
      lang: detail.lang,
      kind: detail.kind,
      createdAt: detail.createdAt,
      url: detail.url,
      assets: detail.assets,
      isPasswordProtected: detail.isPasswordProtected,
      expiresAt: detail.expiresAt,
    },
    200
  );
}

export async function DELETE(
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

  await deleteShare(getStorage(), slug);
  return new Response(null, { status: 204 });
}
