import { getStorage } from '../../../lib/storage.ts';
import { verifyApiToken } from '../../../lib/auth.ts';
import { issueUploadUrls, isRejection } from '../../../lib/shares.ts';
import { rejectionResponse } from '../../../lib/shareInput.ts';

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

  let body: {
    slug?: string;
    files?: Array<{ name?: string; contentType?: string; sizeBytes?: number; overwrite?: boolean }>;
  };

  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON payload' }, 400);
  }

  const { slug, files } = body;
  if (typeof slug !== 'string') {
    return json(
      { error: 'Invalid slug. Slugs must be lowercase alphanumeric with single hyphens.' },
      400
    );
  }
  if (!Array.isArray(files)) {
    return json({ error: 'At least one file must be declared in files array' }, 400);
  }

  try {
    const result = await issueUploadUrls(
      getStorage(),
      slug,
      files.map((f) => ({
        name: f.name as string,
        contentType: f.contentType as string,
        sizeBytes: f.sizeBytes as number,
        overwrite: f.overwrite === true,
      }))
    );
    if (isRejection(result)) return rejectionResponse(result);
    return json(
      {
        slug: result.slug,
        prefix: result.prefix,
        tokens: result.tokens,
        validUntil: result.validUntil,
      },
      200
    );
  } catch (err: unknown) {
    return json({ error: (err as Error)?.message || 'Failed to issue upload token' }, 500);
  }
}
