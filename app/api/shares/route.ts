import { getStorage } from '../../../lib/storage.ts';
import { verifyApiToken } from '../../../lib/auth.ts';
import { rejectionResponse, type ShareInputBody } from '../../../lib/shareInput.ts';
import {
  createShare,
  isRejection,
  listShares,
  toShareDetail,
  toShareSummary,
} from '../../../lib/shares.ts';

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export async function POST(request: Request) {
  if (!verifyApiToken(request)) {
    return json({ error: 'Unauthorized' }, 401);
  }

  let body: { slug?: unknown } & Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON payload' }, 400);
  }

  const { slug } = body;
  if (typeof slug !== 'string') {
    return json(
      { error: 'Invalid slug. Slugs must be lowercase alphanumeric with single hyphens.' },
      400
    );
  }

  const result = await createShare(getStorage(), slug, body as ShareInputBody);
  if (isRejection(result)) return rejectionResponse(result);

  const detail = toShareDetail(result.meta);
  return json(
    {
      slug: detail.slug,
      url: detail.url,
      createdAt: detail.createdAt,
      assets: detail.assets,
    },
    201
  );
}

export async function GET(request: Request) {
  if (!verifyApiToken(request)) {
    return json({ error: 'Unauthorized' }, 401);
  }

  const shares = await listShares(getStorage());
  // passwordHash is never part of a summary
  return json(shares.map(toShareSummary), 200);
}
