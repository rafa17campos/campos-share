import test from 'node:test';
import assert from 'node:assert/strict';

process.env.SHARE_API_TOKEN = 'secret-test-token-xyz789';
process.env.SHARE_COOKIE_SECRET = 'cookie-secret-test-abc123';
process.env.SHARE_BASE_URL = 'https://share.example.invalid';
process.env.MCP_OAUTH_SECRET = 'test-oauth-signing-secret-with-enough-length-0123456789';
process.env.MCP_LOGIN_PASSPHRASE_HASH = 'scrypt$N=32768$r=8$p=1$aa$bb';

import { SignJWT } from 'jose';
import { MemoryStorage, setStorageForTesting } from '../lib/storage.ts';
import { renderMarkdown, safeHref } from '../lib/text.ts';
import { GET as handleViewShare } from '../app/[slug]/route.ts';
import { GET as handleStreamAsset } from '../app/[slug]/[...filename]/route.ts';
import { POST as handleUnlockShare } from '../app/[slug]/unlock/route.ts';
import { unlockLimiter } from '../lib/mcp/ratelimit.ts';
import { signAccessToken, signRefreshToken, verifyAccessToken, verifyRefreshToken } from '../lib/oauth/tokens.ts';
import { createShare } from '../lib/shares.ts';

const BASE = 'https://share.example.invalid';

test('markdown links and images cannot carry a script scheme', () => {
  for (const bad of [
    'javascript:alert(1)',
    'JAVASCRIPT:alert(1)',
    ' javascript:alert(1)',
    'java\tscript:alert(1)',
    'java\nscript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox(1)',
  ]) {
    assert.equal(safeHref(bad), '#', JSON.stringify(bad));
  }
  for (const good of ['https://example.com/a?b#c', 'http://x.y', 'mailto:a@b.c', 'tel:+34600000000', '/otra', 'otra/pagina', '#ancla', '?q=1', 'foto.png']) {
    assert.equal(safeHref(good), good);
  }
  const html = renderMarkdown(
    '[a](javascript:alert(1)) ![b](javascript:alert(2)) [c][ref] <https://ok.example> [d](https://ok.example)\n\n[ref]: data:text/html,x'
  );
  assert.doesNotMatch(html, /javascript:|data:text/i, html);
  assert.match(html, /href="https:\/\/ok\.example"/);
  assert.match(html, /href="#"/);
});

async function seed(storage, slug, assets) {
  const recorded = [];
  for (const [name, body, type] of assets) {
    await storage.putAsset(slug, name, Buffer.from(body), type);
    recorded.push({ name, originalName: name, contentType: type, sizeBytes: Buffer.byteLength(body) });
  }
  await storage.saveMeta(slug, { slug, title: 'T', lang: 'es', createdAt: new Date().toISOString(), kind: 'generated', assets: recorded });
}

test('a folder page allows no script; script-capable files are sandboxed, others are not', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);
  await seed(storage, 'mixta', [
    ['nota.md', '[x](javascript:alert(1))', 'text/markdown'],
    ['pagina.html', '<script>fetch("/otra")</script>', 'text/html; charset=utf-8'],
    ['dibujo.svg', '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', 'image/svg+xml'],
    ['datos.xml', '<a/>', 'application/xml'],
    ['foto.png', 'png', 'image/png'],
    ['doc.pdf', '%PDF', 'application/pdf'],
  ]);

  const page = await handleViewShare(new Request(`${BASE}/mixta`), { params: Promise.resolve({ slug: 'mixta' }) });
  assert.match(page.headers.get('content-security-policy'), /script-src 'none'/);
  assert.doesNotMatch(await page.text(), /javascript:/);

  const csp = async (name) =>
    (await handleStreamAsset(new Request(`${BASE}/mixta/${name}`), { params: Promise.resolve({ slug: 'mixta', filename: [name] }) })).headers.get(
      'content-security-policy'
    );
  assert.equal(await csp('pagina.html'), 'sandbox allow-scripts');
  assert.equal(await csp('dibujo.svg'), 'sandbox allow-scripts');
  assert.equal(await csp('datos.xml'), 'sandbox allow-scripts');
  assert.equal(await csp('foto.png'), null);
  assert.equal(await csp('doc.pdf'), null, 'a sandbox would stop the browser PDF viewer');
});

test('the password prompt allows no script', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);
  await createShare(storage, 'cerrada', { title: 'C', lang: 'es', kind: 'uploaded', html: '<p>x</p>', password: 'clave-larga-1' });
  const res = await handleViewShare(new Request(`${BASE}/cerrada`), { params: Promise.resolve({ slug: 'cerrada' }) });
  assert.match(res.headers.get('content-security-policy'), /script-src 'none'/);
  assert.match(res.headers.get('content-security-policy'), /form-action 'self'/);
});

test('password guesses are limited per address and share, existing or not', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);
  unlockLimiter.reset();
  await createShare(storage, 'cofre', { title: 'C', lang: 'es', kind: 'uploaded', html: '<p>x</p>', password: 'clave-correcta-9' });
  const attempt = (slug, password, ip = '203.0.113.5') =>
    handleUnlockShare(
      new Request(`${BASE}/${slug}/unlock`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-forwarded-for': ip },
        body: new URLSearchParams({ password }).toString(),
      }),
      { params: Promise.resolve({ slug }) }
    );

  for (let i = 0; i < 10; i++) assert.equal((await attempt('cofre', `mala-${i}`)).status, 303);
  const limited = await attempt('cofre', 'clave-correcta-9');
  assert.equal(limited.status, 429, 'even the right password waits once over the limit');
  assert.ok(Number(limited.headers.get('retry-after')) > 0);
  assert.equal(limited.headers.get('set-cookie'), null);

  const other = await attempt('cofre', 'clave-correcta-9', '203.0.113.6');
  assert.equal(other.status, 303);
  assert.ok(other.headers.get('set-cookie'), 'another address is unaffected');

  for (let i = 0; i < 10; i++) await attempt('no-existe', 'x');
  assert.equal((await attempt('no-existe', 'x')).status, 429, 'a slug that does not exist answers the same');
  unlockLimiter.reset();
});

test('changing the login passphrase ends every OAuth grant made with the old one', async () => {
  const input = { client_id: 'dcr.test', sub: 'owner', scope: ['files:read'] };
  const access = await signAccessToken(input);
  const refresh = await signRefreshToken(input);
  assert.ok(await verifyAccessToken(access));
  assert.ok(await verifyRefreshToken(refresh));

  const original = process.env.MCP_LOGIN_PASSPHRASE_HASH;
  process.env.MCP_LOGIN_PASSPHRASE_HASH = 'scrypt$N=32768$r=8$p=1$cc$dd';
  try {
    assert.equal(await verifyAccessToken(access), null);
    assert.equal(await verifyRefreshToken(refresh), null);
    assert.ok(await verifyAccessToken(await signAccessToken(input)), 'grants made after the change work');
  } finally {
    process.env.MCP_LOGIN_PASSPHRASE_HASH = original;
  }

  // A token signed before grants carried the fingerprint is refused too.
  const now = Math.floor(Date.now() / 1000);
  const legacy = await new SignJWT({ client_id: 'dcr.test', sub: 'owner', scope: 'files:read', kind: 'access' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(BASE)
    .setAudience(`${BASE}/mcp`)
    .setIssuedAt(now)
    .setExpirationTime(now + 600)
    .sign(new TextEncoder().encode(process.env.MCP_OAUTH_SECRET));
  assert.equal(await verifyAccessToken(legacy), null);
});
