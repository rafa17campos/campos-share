import test from 'node:test';
import assert from 'node:assert/strict';
import {
  renderSharePage,
  injectUploadedHtml,
  renderPasswordPrompt,
  escapeHtml,
  formatFileSize,
} from '../lib/renderer.ts';
import {
  hashPassword,
  verifyPassword,
  runDummyPasswordCheck,
  createUnlockCookieValue,
  verifyUnlockCookieValue,
} from '../lib/auth.ts';
import { getBaseUrl } from '../lib/config.ts';
import { hasExpired, validateShareInput } from '../lib/shareInput.ts';

test('escapeHtml properly escapes special characters and preserves Spanish accents', () => {
  const input = '<div class="alojamiento">Habitación en Málaga: 100€ & "desayuno"</div>';
  const escaped = escapeHtml(input);
  assert.ok(!escaped.includes('<div'));
  assert.ok(escaped.includes('&lt;div'));
  assert.ok(escaped.includes('Habitación en Málaga'));
  assert.ok(escaped.includes('&quot;desayuno&quot;'));
  assert.ok(escaped.includes('&amp;'));
});

test('formatFileSize formats bytes correctly', () => {
  assert.equal(formatFileSize(500), '500 B');
  assert.equal(formatFileSize(2048), '2.0 KB');
  assert.equal(formatFileSize(5 * 1024 * 1024), '5.0 MB');
});

test('renderSharePage satisfies all template invariants (ascending validator)', () => {
  const meta = {
    slug: 'hoteles-lisboa',
    title: 'Comparativa de hoteles (Lisboa & Oporto)',
    description: 'Precios, imágenes y ubicación de tres opciones con encanto',
    lang: 'es',
    createdAt: '2026-09-14T18:20:00Z',
    kind: 'generated',
    assets: [
      {
        name: 'hotel-fachada.jpg',
        originalName: 'Hotel Fachada (Lisboa).jpg',
        contentType: 'image/jpeg',
        sizeBytes: 250000,
      },
      {
        name: 'resumen.pdf',
        originalName: 'Resumen precios.pdf',
        contentType: 'application/pdf',
        sizeBytes: 150000,
      },
    ],
  };

  const html = renderSharePage(meta, 'https://share.example.invalid');

  // Invariants
  assert.ok(html.includes('<!DOCTYPE html>'));
  assert.ok(html.includes('<html lang="es">'));
  assert.ok(html.includes('<meta charset="UTF-8">'));
  assert.ok(html.includes('<meta name="viewport" content="width=device-width, initial-scale=1.0">'));
  assert.ok(html.includes('<meta name="robots" content="noindex,nofollow">'));
  assert.ok(html.includes('<meta name="description" content="Precios, imágenes y ubicación de tres opciones con encanto">'));
  assert.ok(html.includes('<title>Comparativa de hoteles (Lisboa &amp; Oporto)</title>'));
  assert.ok(html.includes('<meta property="og:title" content="Comparativa de hoteles (Lisboa &amp; Oporto)">'));
  assert.ok(html.includes('<meta property="og:description" content="Precios, imágenes y ubicación de tres opciones con encanto">'));
  assert.ok(html.includes('<meta property="og:type" content="website">'));

  // og:image is present for unexpired, unprotected share with an image
  assert.ok(
    html.includes(
      '<meta property="og:image" content="https://share.example.invalid/hoteles-lisboa/hotel-fachada.jpg">'
    )
  );

  // Spanish accents preserved
  assert.ok(html.includes('imágenes'));
  assert.ok(html.includes('ubicación'));
});

test('renderSharePage NEVER includes og:image when password-protected', () => {
  const meta = {
    slug: 'secret-share',
    title: 'Protected share',
    description: 'Secret confidential files',
    lang: 'en',
    createdAt: '2026-09-14T18:20:00Z',
    kind: 'generated',
    passwordHash: 'scrypt$dummy',
    assets: [
      {
        name: 'secret.png',
        originalName: 'secret.png',
        contentType: 'image/png',
        sizeBytes: 1000,
      },
    ],
  };

  const html = renderSharePage(meta, 'https://share.example.invalid');
  assert.ok(!html.includes('og:image'));
});

test('renderSharePage NEVER includes og:image when expiring', () => {
  const meta = {
    slug: 'expiring-share',
    title: 'Expiring share',
    description: 'Temporary files',
    lang: 'en',
    createdAt: '2026-09-14T18:20:00Z',
    kind: 'generated',
    expiresAt: '2026-09-20T00:00:00Z',
    assets: [
      {
        name: 'temp.png',
        originalName: 'temp.png',
        contentType: 'image/png',
        sizeBytes: 1000,
      },
    ],
  };

  const html = renderSharePage(meta, 'https://share.example.invalid');
  assert.ok(!html.includes('og:image'));
});

test('injectUploadedHtml injects missing required tags', () => {
  const rawHtml = `<!DOCTYPE html><html><head><title>Original</title></head><body><h1>Hello</h1></body></html>`;
  const meta = {
    slug: 'uploaded-test',
    title: 'Uploaded title',
    description: 'Uploaded description',
    lang: 'es',
    createdAt: '2026-09-14T18:20:00Z',
    kind: 'uploaded',
    assets: [],
  };

  const result = injectUploadedHtml(rawHtml, meta);
  assert.ok(result.includes('lang="es"'));
  assert.ok(result.includes('<meta name="robots" content="noindex,nofollow">'));
  assert.ok(result.includes('<meta name="viewport" content="width=device-width, initial-scale=1.0">'));
  assert.ok(result.includes('<meta name="description" content="Uploaded description">'));
  assert.ok(result.includes('<meta property="og:title" content="Uploaded title">'));
});

test('renderPasswordPrompt renders accessible form with action to slug unlock', () => {
  const html = renderPasswordPrompt('mi-viaje', false);
  assert.ok(html.includes('action="/mi-viaje/unlock"'));
  assert.ok(html.includes('type="password"'));
  assert.ok(html.includes('noindex,nofollow'));
});

test('Password hashing and verification with scrypt', async () => {
  const password = 'miSuperPassword123!_áñ';
  const hash = await hashPassword(password);

  assert.ok(hash.startsWith('scrypt$N=32768$r=8$p=1$'));
  const isValid = await verifyPassword(password, hash);
  assert.equal(isValid, true);

  const isInvalid = await verifyPassword('wrong_password', hash);
  assert.equal(isInvalid, false);
});

test('runDummyPasswordCheck executes without error', async () => {
  await runDummyPasswordCheck();
});

test('Unlock cookie creation and verification', () => {
  process.env.SHARE_COOKIE_SECRET = 'test-secret-key-1234567890';
  const slug = 'viaje-oporto';
  const cookie = createUnlockCookieValue(slug);

  assert.ok(verifyUnlockCookieValue(cookie, slug));
  // Wrong slug fails
  assert.equal(verifyUnlockCookieValue(cookie, 'otro-slug'), false);
  // Tampered cookie fails
  assert.equal(verifyUnlockCookieValue(cookie + 'x', slug), false);
});

test('Missing SHARE_COOKIE_SECRET throws immediately without fallback', () => {
  const originalSecret = process.env.SHARE_COOKIE_SECRET;
  delete process.env.SHARE_COOKIE_SECRET;
  try {
    assert.throws(() => createUnlockCookieValue('test-slug'), {
      message: /SHARE_COOKIE_SECRET environment variable is required/,
    });
    assert.throws(
      () => verifyUnlockCookieValue(`test-slug:${Date.now()}:${'a'.repeat(64)}`, 'test-slug'),
      { message: /SHARE_COOKIE_SECRET environment variable is required/ }
    );
  } finally {
    process.env.SHARE_COOKIE_SECRET = originalSecret;
  }
});

test('Missing SHARE_BASE_URL throws immediately without fallback', () => {
  const originalBaseUrl = process.env.SHARE_BASE_URL;
  delete process.env.SHARE_BASE_URL;
  try {
    assert.throws(() => getBaseUrl(), {
      message: /SHARE_BASE_URL environment variable is required/,
    });
  } finally {
    process.env.SHARE_BASE_URL = originalBaseUrl;
  }
});

test('Configured SHARE_BASE_URL returns normalized base URL', () => {
  const originalBaseUrl = process.env.SHARE_BASE_URL;
  process.env.SHARE_BASE_URL = 'https://share.custom.domain///';
  try {
    assert.equal(getBaseUrl(), 'https://share.custom.domain');
  } finally {
    process.env.SHARE_BASE_URL = originalBaseUrl;
  }
});

const storageWithAsset = {
  headAsset: async () => ({ exists: true, size: 12, contentType: 'text/plain' }),
};

function uploadedBody(extra) {
  return { title: 'T', lang: 'es', kind: 'uploaded', html: '<p>x</p>', ...extra };
}

test('hasExpired treats a date it cannot read as expired, not as no expiry', () => {
  assert.equal(hasExpired('not a date'), true);
  assert.equal(hasExpired('2026-13-45T99:99:99Z'), true);
});

test('hasExpired says no when there is no expiry at all', () => {
  assert.equal(hasExpired(null), false);
  assert.equal(hasExpired(undefined), false);
  assert.equal(hasExpired(''), false);
});

test('hasExpired compares against the instant it is given', () => {
  const at = '2026-01-01T00:00:00.000Z';
  assert.equal(hasExpired(at, Date.parse('2025-12-31T23:59:59Z')), false);
  assert.equal(hasExpired(at, Date.parse('2026-01-01T00:00:01Z')), true);
});

test('validateShareInput refuses an expiresAt that is not a date', async () => {
  const result = await validateShareInput('s', uploadedBody({ expiresAt: 'mañana' }), storageWithAsset);
  assert.ok('error' in result);
  assert.equal(result.status, 400);
  assert.match(result.error, /expiresAt/);
});

test('validateShareInput refuses an expiresAt that is not a string', async () => {
  const result = await validateShareInput('s', uploadedBody({ expiresAt: 1767225600000 }), storageWithAsset);
  assert.ok('error' in result);
  assert.equal(result.status, 400);
});

test('validateShareInput normalises a readable expiresAt to a canonical instant', async () => {
  const result = await validateShareInput(
    's',
    uploadedBody({ expiresAt: '2026-01-01T12:00:00+01:00' }),
    storageWithAsset
  );
  assert.ok(!('error' in result));
  assert.equal(result.expiresAt, '2026-01-01T11:00:00.000Z');
});

test('validateShareInput keeps apart "leave it alone" and "clear it"', async () => {
  const absent = await validateShareInput('s', uploadedBody({}), storageWithAsset);
  assert.ok(!('error' in absent));
  assert.equal(absent.expiresAt, undefined);
  assert.equal(absent.password, undefined);

  const cleared = await validateShareInput(
    's',
    uploadedBody({ expiresAt: null, password: '' }),
    storageWithAsset
  );
  assert.ok(!('error' in cleared));
  assert.equal(cleared.expiresAt, null);
  assert.equal(cleared.password, null);
});

test('validateShareInput refuses a password that is not a string', async () => {
  const result = await validateShareInput('s', uploadedBody({ password: 1234 }), storageWithAsset);
  assert.ok('error' in result);
  assert.equal(result.status, 400);
  assert.match(result.error, /password/);
});

test('validateShareInput passes a real password through untouched, unhashed', async () => {
  const result = await validateShareInput('s', uploadedBody({ password: 'ábrete sésamo' }), storageWithAsset);
  assert.ok(!('error' in result));
  assert.equal(result.password, 'ábrete sésamo');
});
