import { hasExpired } from '../../../lib/shareInput.ts';
import { getStorage } from '../../../lib/storage.ts';
import {
  verifyPassword,
  runDummyPasswordCheck,
  createUnlockCookieValue,
  unlockBinding,
} from '../../../lib/auth.ts';
import { clientAddress, unlockLimiter } from '../../../lib/mcp/ratelimit.ts';

const SLUG_REGEX = /^[a-z0-9]+(-[a-z0-9]+)*$/;

export async function POST(
  request: Request,
  { params }: { params: Promise<{ slug: string }> }
) {
  const { slug } = await params;

  if (!SLUG_REGEX.test(slug)) {
    return new Response('Not Found', { status: 404 });
  }

  // scrypt makes each guess slow, not few: count them, whether or not the slug exists, so the
  // answer says nothing about which slugs do.
  const limit = unlockLimiter.hit(`${clientAddress(request)}:${slug}`);
  if (!limit.allowed) {
    return new Response('Demasiados intentos. Espera unos minutos y vuelve a probar.', {
      status: 429,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Retry-After': String(limit.retryAfterSeconds),
        'Cache-Control': 'no-store',
      },
    });
  }

  let password = '';
  try {
    const contentType = request.headers.get('content-type') || '';
    if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
      const formData = await request.formData();
      password = String(formData.get('password') || '');
    } else if (contentType.includes('application/json')) {
      const json = await request.json();
      password = String(json.password || '');
    }
  } catch {
    // Proceed with empty password
  }

  const storage = getStorage();
  const meta = await storage.getMeta(slug);

  // If slug doesn't exist, has expired, or is not protected, execute dummy check
  // to ensure constant-time response and prevent slug probing attacks
  if (!meta || !meta.passwordHash) {
    await runDummyPasswordCheck();
    return new Response(null, {
      status: 303,
      headers: {
        Location: `/${encodeURIComponent(slug)}?error=1`,
      },
    });
  }

  // If expired, execute dummy check and return error
  if (hasExpired(meta.expiresAt)) {
    await runDummyPasswordCheck();
    return new Response(null, {
      status: 303,
      headers: {
        Location: `/${encodeURIComponent(slug)}?error=1`,
      },
    });
  }

  const isValid = await verifyPassword(password, meta.passwordHash);

  if (!isValid) {
    return new Response(null, {
      status: 303,
      headers: {
        Location: `/${encodeURIComponent(slug)}?error=1`,
      },
    });
  }

  // Password is correct; issue unlock cookie scoped to Path=/[slug]
  const cookieValue = createUnlockCookieValue(slug, unlockBinding(meta));
  const cookieName = `share_unlock_${slug}`;
  const isProd = process.env.NODE_ENV === 'production';
  const secureFlag = isProd ? '; Secure' : '';
  const setCookieHeader = `${cookieName}=${encodeURIComponent(cookieValue)}; Path=/${encodeURIComponent(slug)}; HttpOnly; SameSite=Lax; Max-Age=604800${secureFlag}`;

  return new Response(null, {
    status: 303,
    headers: {
      Location: `/${encodeURIComponent(slug)}`,
      'Set-Cookie': setCookieHeader,
    },
  });
}
