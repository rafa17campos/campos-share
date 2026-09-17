import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryStorage, setStorageForTesting } from '../lib/storage.ts';

// Import Route handlers
import { POST as handleUploads } from '../app/api/uploads/route.ts';
import { POST as handleCreateShare, GET as handleListShares } from '../app/api/shares/route.ts';
import {
  GET as handleGetShare,
  PUT as handleUpdateShare,
  DELETE as handleDeleteShare,
} from '../app/api/shares/[slug]/route.ts';
import { POST as handleSweepOrphans } from '../app/api/shares/orphans/route.ts';
import { GET as handleViewShare } from '../app/[slug]/route.ts';
import { POST as handleUnlockShare } from '../app/[slug]/unlock/route.ts';
import { GET as handleStreamAsset } from '../app/[slug]/[...filename]/route.ts';

const TEST_API_TOKEN = 'secret-test-token-xyz789';
const TEST_COOKIE_SECRET = 'cookie-secret-test-abc123';
const TEST_BASE_URL = 'https://share.example.invalid';

process.env.SHARE_API_TOKEN = TEST_API_TOKEN;
process.env.SHARE_COOKIE_SECRET = TEST_COOKIE_SECRET;
process.env.SHARE_BASE_URL = TEST_BASE_URL;

function createApiRequest(url, method = 'GET', body = null, token = TEST_API_TOKEN, cookie = null) {
  const headers = new Headers();
  if (token) {
    headers.set('authorization', `Bearer ${token}`);
  }
  if (body) {
    headers.set('content-type', 'application/json');
  }
  if (cookie) {
    headers.set('cookie', cookie);
  }
  return new Request(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });
}

test('API upload token issuance (POST /api/uploads)', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  // 1. Missing auth
  const reqNoAuth = createApiRequest('https://share.example.invalid/api/uploads', 'POST', {
    slug: 'hotel-test',
    files: [{ name: 'info.pdf', contentType: 'application/pdf' }],
  }, null);
  const resNoAuth = await handleUploads(reqNoAuth);
  assert.equal(resNoAuth.status, 401);

  // 2. Invalid slug
  const reqBadSlug = createApiRequest('https://share.example.invalid/api/uploads', 'POST', {
    slug: 'Invalid_Slug!',
    files: [{ name: 'info.pdf', contentType: 'application/pdf' }],
  });
  const resBadSlug = await handleUploads(reqBadSlug);
  assert.equal(resBadSlug.status, 400);

  // 3. File missing sizeBytes
  const reqMissingSize = createApiRequest('https://share.example.invalid/api/uploads', 'POST', {
    slug: 'size-test',
    files: [{ name: 'info.pdf', contentType: 'application/pdf' }],
  });
  const resMissingSize = await handleUploads(reqMissingSize);
  assert.equal(resMissingSize.status, 400);

  // 4. File exceeding 20 MB
  const reqTooLarge = createApiRequest('https://share.example.invalid/api/uploads', 'POST', {
    slug: 'large-test',
    files: [{ name: 'video.mp4', contentType: 'video/mp4', sizeBytes: 25 * 1024 * 1024 }],
  });
  const resTooLarge = await handleUploads(reqTooLarge);
  assert.equal(resTooLarge.status, 400);
  const jsonTooLarge = await resTooLarge.json();
  assert.ok(jsonTooLarge.error.includes('20 MB'));

  // 5. Success
  const reqSuccess = createApiRequest('https://share.example.invalid/api/uploads', 'POST', {
    slug: 'hotel-lisboa',
    files: [{ name: 'info.pdf', contentType: 'application/pdf', sizeBytes: 500000 }],
  });
  const resSuccess = await handleUploads(reqSuccess);
  assert.equal(resSuccess.status, 200);
  const jsonSuccess = await resSuccess.json();
  assert.ok(Array.isArray(jsonSuccess.tokens) && jsonSuccess.tokens[0].uploadUrl);
  assert.equal(jsonSuccess.prefix, 'hotel-lisboa/');
  assert.equal(jsonSuccess.tokens.length, 1);
  assert.equal(jsonSuccess.tokens[0].pathname, 'hotel-lisboa/info.pdf');

  // 6. An existing share accepts new file names (that is how a file joins it)...
  await storage.saveMeta('hotel-lisboa', {
    slug: 'hotel-lisboa',
    title: 'Existing',
    description: 'Existing',
    lang: 'es',
    createdAt: new Date().toISOString(),
    kind: 'generated',
    assets: [{ name: 'info.pdf', originalName: 'info.pdf', contentType: 'application/pdf', sizeBytes: 10 }],
  });
  const reqJoin = createApiRequest('https://share.example.invalid/api/uploads', 'POST', {
    slug: 'hotel-lisboa',
    files: [{ name: 'mapa.png', contentType: 'image/png', sizeBytes: 500000 }],
  });
  const resJoin = await handleUploads(reqJoin);
  assert.equal(resJoin.status, 200, await resJoin.text());

  // ...but a name it already holds is a conflict, because create never overwrites
  const reqConflict = createApiRequest('https://share.example.invalid/api/uploads', 'POST', {
    slug: 'hotel-lisboa',
    files: [{ name: 'info.pdf', contentType: 'application/pdf', sizeBytes: 500000 }],
  });
  const resConflict = await handleUploads(reqConflict);
  assert.equal(resConflict.status, 409);

  // 7. Reserved slugs never become shares
  const reqReserved = createApiRequest('https://share.example.invalid/api/uploads', 'POST', {
    slug: 'mcp',
    files: [{ name: 'info.pdf', contentType: 'application/pdf', sizeBytes: 500000 }],
  });
  assert.equal((await handleUploads(reqReserved)).status, 400);
});

test('Share creation lifecycle: POST /api/shares', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  const sharePayload = {
    slug: 'comparativa-hoteles',
    title: 'Comparativa de Hoteles',
    description: 'Tres opciones en el centro',
    lang: 'es',
    kind: 'generated',
    assets: [
      {
        name: 'dossier.pdf',
        originalName: 'Dossier Hoteles.pdf',
        contentType: 'application/pdf',
      },
    ],
  };

  // 1. Rejected if declared asset was never uploaded
  const reqMissingAsset = createApiRequest(
    'https://share.example.invalid/api/shares',
    'POST',
    sharePayload
  );
  const resMissing = await handleCreateShare(reqMissingAsset);
  assert.equal(resMissing.status, 400);
  const jsonMissing = await resMissing.json();
  assert.ok(jsonMissing.error.includes('does not exist in storage'));

  // 2. Upload asset into storage first, then create share
  await storage.putAsset(
    'comparativa-hoteles',
    'dossier.pdf',
    Buffer.from('%PDF-1.4 dummy pdf content'),
    'application/pdf'
  );

  const reqValidCreate = createApiRequest(
    'https://share.example.invalid/api/shares',
    'POST',
    sharePayload
  );
  const resCreated = await handleCreateShare(reqValidCreate);
  assert.equal(resCreated.status, 201);
  const jsonCreated = await resCreated.json();
  assert.equal(jsonCreated.slug, 'comparativa-hoteles');
  assert.equal(jsonCreated.url, 'https://share.example.invalid/comparativa-hoteles');
  assert.equal(jsonCreated.assets.length, 1);
  assert.equal(
    jsonCreated.assets[0].url,
    'https://share.example.invalid/comparativa-hoteles/dossier.pdf'
  );

  // 3. Create never overwrites -> 409
  const reqDuplicate = createApiRequest(
    'https://share.example.invalid/api/shares',
    'POST',
    sharePayload
  );
  const resDuplicate = await handleCreateShare(reqDuplicate);
  assert.equal(resDuplicate.status, 409);
});

test('Share listing and detail: GET /api/shares & GET /api/shares/[slug]', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  // Upload an asset and create a protected share
  await storage.putAsset('secret-plans', 'plan.png', Buffer.from('png-data'), 'image/png');
  const createReq = createApiRequest('https://share.example.invalid/api/shares', 'POST', {
    slug: 'secret-plans',
    title: 'Secret Plans',
    description: 'Classified architecture',
    lang: 'es',
    kind: 'generated',
    password: 'superPassword123',
    assets: [{ name: 'plan.png', originalName: 'plan.png', contentType: 'image/png' }],
  });
  await handleCreateShare(createReq);

  // 1. GET /api/shares
  const listReq = createApiRequest('https://share.example.invalid/api/shares', 'GET');
  const listRes = await handleListShares(listReq);
  assert.equal(listRes.status, 200);
  const listJson = await listRes.json();
  assert.equal(listJson.length, 1);
  assert.equal(listJson[0].slug, 'secret-plans');
  assert.equal(listJson[0].isPasswordProtected, true);
  // CRITICAL: passwordHash is NEVER exposed
  assert.equal(listJson[0].passwordHash, undefined);

  // 2. GET /api/shares/[slug]
  const getReq = createApiRequest('https://share.example.invalid/api/shares/secret-plans', 'GET');
  const getRes = await handleGetShare(getReq, { params: Promise.resolve({ slug: 'secret-plans' }) });
  assert.equal(getRes.status, 200);
  const getJson = await getRes.json();
  assert.equal(getJson.slug, 'secret-plans');
  assert.equal(getJson.isPasswordProtected, true);
  assert.equal(getJson.passwordHash, undefined);

  // 3. GET /api/shares/non-existent -> 404
  const notFoundReq = createApiRequest('https://share.example.invalid/api/shares/no-such-slug', 'GET');
  const notFoundRes = await handleGetShare(notFoundReq, {
    params: Promise.resolve({ slug: 'no-such-slug' }),
  });
  assert.equal(notFoundRes.status, 404);
});

test('PUT accepts a share with no description, exactly as POST does', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  await storage.putAsset('sin-desc', '__page.html', '<h1>v1</h1>', 'text/html');
  await storage.saveMeta('sin-desc', {
    slug: 'sin-desc',
    title: 'Sin descripcion',
    lang: 'es',
    createdAt: new Date().toISOString(),
    kind: 'uploaded',
    assets: [],
  });

  const res = await handleUpdateShare(
    createApiRequest('https://share.example.invalid/api/shares/sin-desc', 'PUT', {
      title: 'Sin descripcion v2',
      lang: 'es',
      kind: 'uploaded',
      html: '<h1>v2</h1>',
      assets: [],
    }),
    { params: Promise.resolve({ slug: 'sin-desc' }) }
  );

  assert.equal(res.status, 200, await res.text());
});

test('Update and Delete: PUT /api/shares/[slug] & DELETE /api/shares/[slug]', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  await storage.putAsset('project-docs', 'v1.pdf', Buffer.from('v1 pdf data'), 'application/pdf');
  await handleCreateShare(
    createApiRequest('https://share.example.invalid/api/shares', 'POST', {
      slug: 'project-docs',
      title: 'Project Docs',
      description: 'Initial version',
      lang: 'en',
      kind: 'generated',
      assets: [{ name: 'v1.pdf', originalName: 'v1.pdf', contentType: 'application/pdf' }],
    })
  );

  // Pre-upload replacement asset under a new name (suffixing to keep immutable cache valid)
  await storage.putAsset('project-docs', 'v2.pdf', Buffer.from('v2 pdf data'), 'application/pdf');

  // PUT replaces metadata and asset set
  const updateReq = createApiRequest('https://share.example.invalid/api/shares/project-docs', 'PUT', {
    title: 'Project Docs (Updated)',
    description: 'Second version',
    lang: 'en',
    kind: 'generated',
    assets: [{ name: 'v2.pdf', originalName: 'v2.pdf', contentType: 'application/pdf' }],
  });
  const updateRes = await handleUpdateShare(updateReq, {
    params: Promise.resolve({ slug: 'project-docs' }),
  });
  assert.equal(updateRes.status, 200);
  const updateJson = await updateRes.json();
  assert.equal(updateJson.title, 'Project Docs (Updated)');
  assert.equal(updateJson.assets.length, 1);
  assert.equal(updateJson.assets[0].name, 'v2.pdf');

  // Verify old asset v1.pdf was pruned from storage
  const oldAssetHead = await storage.headAsset('project-docs', 'v1.pdf');
  assert.equal(oldAssetHead, null);

  // DELETE deletes all blobs under slug
  const deleteReq = createApiRequest('https://share.example.invalid/api/shares/project-docs', 'DELETE');
  const deleteRes = await handleDeleteShare(deleteReq, {
    params: Promise.resolve({ slug: 'project-docs' }),
  });
  assert.equal(deleteRes.status, 204);

  // Verify meta and v2.pdf are completely gone
  const metaAfterDelete = await storage.getMeta('project-docs');
  assert.equal(metaAfterDelete, null);
  const v2AfterDelete = await storage.headAsset('project-docs', 'v2.pdf');
  assert.equal(v2AfterDelete, null);
});

test('Web View & Cache Headers: GET /[slug] & GET /[slug]/[...filename]', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  const fileBytes = Buffer.from('image content 123');
  await storage.putAsset('public-trip', 'photo.jpg', fileBytes, 'image/jpeg');
  await handleCreateShare(
    createApiRequest('https://share.example.invalid/api/shares', 'POST', {
      slug: 'public-trip',
      title: 'Viaje a Lisboa',
      description: 'Fotos del viaje',
      lang: 'es',
      kind: 'generated',
      assets: [{ name: 'photo.jpg', originalName: 'Foto.jpg', contentType: 'image/jpeg' }],
    })
  );

  // 1. GET /[slug] on public share -> max-age=0, must-revalidate with ETag
  const viewReq = new Request('https://share.example.invalid/public-trip');
  const viewRes = await handleViewShare(viewReq, {
    params: Promise.resolve({ slug: 'public-trip' }),
  });
  assert.equal(viewRes.status, 200);
  assert.equal(viewRes.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.equal(
    viewRes.headers.get('cache-control'),
    'public, max-age=0, must-revalidate'
  );
  assert.equal(viewRes.headers.get('x-robots-tag'), 'noindex, nofollow');
  const etag = viewRes.headers.get('etag');
  assert.ok(etag);
  const viewHtml = await viewRes.text();
  assert.ok(viewHtml.includes('Viaje a Lisboa'));
  assert.ok(viewHtml.includes('og:image'));

  // 1b. Revalidation with If-None-Match returns 304 Not Modified
  const revalReq = new Request('https://share.example.invalid/public-trip', {
    headers: { 'if-none-match': etag },
  });
  const revalRes = await handleViewShare(revalReq, {
    params: Promise.resolve({ slug: 'public-trip' }),
  });
  assert.equal(revalRes.status, 304);
  assert.equal(revalRes.headers.get('etag'), etag);
  assert.equal(revalRes.headers.get('x-robots-tag'), 'noindex, nofollow');

  // 2. GET /[slug]/[...filename] on public share -> revalidating cache header, ETag and X-Robots-Tag.
  // A file can be replaced in place behind the same URL, so nothing may cache it as immutable.
  const assetReq = new Request('https://share.example.invalid/public-trip/photo.jpg');
  const assetRes = await handleStreamAsset(assetReq, {
    params: Promise.resolve({ slug: 'public-trip', filename: ['photo.jpg'] }),
  });
  assert.equal(assetRes.status, 200);
  assert.equal(assetRes.headers.get('content-type'), 'image/jpeg');
  assert.equal(assetRes.headers.get('cache-control'), 'public, max-age=0, must-revalidate');
  assert.equal(assetRes.headers.get('x-robots-tag'), 'noindex, nofollow');
  assert.equal(assetRes.headers.get('content-length'), String(fileBytes.length));
  const assetEtag = assetRes.headers.get('etag');
  assert.ok(assetEtag);

  // 2b. If-None-Match with the current ETag -> 304 without a body
  const assetRevalRes = await handleStreamAsset(
    new Request('https://share.example.invalid/public-trip/photo.jpg', { headers: { 'if-none-match': assetEtag } }),
    { params: Promise.resolve({ slug: 'public-trip', filename: ['photo.jpg'] }) }
  );
  assert.equal(assetRevalRes.status, 304);
  assert.equal(assetRevalRes.headers.get('etag'), assetEtag);

  // 2c. Replacing the bytes changes the ETag, so the stale copy is not confirmed
  await storage.putAsset('public-trip', 'photo.jpg', Buffer.from('new image content'), 'image/jpeg');
  const afterReplace = await handleStreamAsset(
    new Request('https://share.example.invalid/public-trip/photo.jpg', { headers: { 'if-none-match': assetEtag } }),
    { params: Promise.resolve({ slug: 'public-trip', filename: ['photo.jpg'] }) }
  );
  assert.equal(afterReplace.status, 200);
  assert.notEqual(afterReplace.headers.get('etag'), assetEtag);
  assert.equal(await afterReplace.text(), 'new image content');
});

test('A file is replaced in place: POST /api/uploads with overwrite, then PUT /api/shares/[slug]', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  await storage.putAsset('notes', 'readme.md', Buffer.from('v1'), 'text/markdown');
  await handleCreateShare(
    createApiRequest('https://share.example.invalid/api/shares', 'POST', {
      slug: 'notes',
      title: 'Notes',
      lang: 'en',
      kind: 'generated',
      assets: [{ name: 'readme.md', originalName: 'readme.md', contentType: 'text/markdown' }],
    })
  );
  const before = (await storage.getMeta('notes')).assets[0];
  assert.ok(before.etag, 'the record keeps the store etag');

  // Without overwrite the name is a conflict
  const conflict = await handleUploads(
    createApiRequest('https://share.example.invalid/api/uploads', 'POST', {
      slug: 'notes',
      files: [{ name: 'readme.md', contentType: 'text/markdown', sizeBytes: 2 }],
    })
  );
  assert.equal(conflict.status, 409);

  // With overwrite the upload URL is issued for the same pathname
  const issued = await handleUploads(
    createApiRequest('https://share.example.invalid/api/uploads', 'POST', {
      slug: 'notes',
      files: [{ name: 'readme.md', contentType: 'text/markdown', sizeBytes: 2, overwrite: true }],
    })
  );
  const issuedJson = await issued.json();
  assert.equal(issued.status, 200, JSON.stringify(issuedJson));
  assert.equal(issuedJson.tokens[0].pathname, 'notes/readme.md');

  // The PUT happens (simulated), then the share is re-declared with the same asset list
  await storage.putAsset('notes', 'readme.md', Buffer.from('v2 longer'), 'text/markdown');
  const updated = await handleUpdateShare(
    createApiRequest('https://share.example.invalid/api/shares/notes', 'PUT', {
      title: 'Notes',
      lang: 'en',
      kind: 'generated',
      assets: [{ name: 'readme.md', originalName: 'readme.md', contentType: 'text/markdown' }],
    }),
    { params: Promise.resolve({ slug: 'notes' }) }
  );
  const updatedJson = await updated.json();
  assert.equal(updated.status, 200, JSON.stringify(updatedJson));
  const after = updatedJson.assets[0];
  assert.equal(after.sizeBytes, 9);
  assert.notEqual(after.etag, before.etag);
  assert.equal(after.url, 'https://share.example.invalid/notes/readme.md');
});

test('Password Gate & Expiry Gate: Full Security Flow', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  await storage.putAsset('vip-docs', 'confidential.pdf', Buffer.from('classified data'), 'application/pdf');
  await handleCreateShare(
    createApiRequest('https://share.example.invalid/api/shares', 'POST', {
      slug: 'vip-docs',
      title: 'VIP Documentation',
      description: 'Strictly confidential',
      lang: 'en',
      kind: 'generated',
      password: 'correct-password-42',
      assets: [{ name: 'confidential.pdf', originalName: 'doc.pdf', contentType: 'application/pdf' }],
    })
  );

  // 1. Visiting /[slug] without cookie returns password prompt with private no-cache
  const unauthReq = new Request('https://share.example.invalid/vip-docs');
  const unauthRes = await handleViewShare(unauthReq, {
    params: Promise.resolve({ slug: 'vip-docs' }),
  });
  assert.equal(unauthRes.status, 200);
  assert.equal(unauthRes.headers.get('cache-control'), 'private, no-cache');
  const promptHtml = await unauthRes.text();
  assert.ok(promptHtml.includes('action="/vip-docs/unlock"'));

  // 2. Direct asset request without cookie is rejected with 401
  const directAssetReq = new Request('https://share.example.invalid/vip-docs/confidential.pdf');
  const directAssetRes = await handleStreamAsset(directAssetReq, {
    params: Promise.resolve({ slug: 'vip-docs', filename: ['confidential.pdf'] }),
  });
  assert.equal(directAssetRes.status, 401);
  assert.equal(directAssetRes.headers.get('cache-control'), 'private, no-cache');

  // 3. Unlock with wrong password redirects to ?error=1
  const wrongUnlockReq = new Request('https://share.example.invalid/vip-docs/unlock', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'wrong' }),
  });
  const wrongUnlockRes = await handleUnlockShare(wrongUnlockReq, {
    params: Promise.resolve({ slug: 'vip-docs' }),
  });
  assert.equal(wrongUnlockRes.status, 303);
  assert.equal(wrongUnlockRes.headers.get('location'), '/vip-docs?error=1');
  assert.equal(wrongUnlockRes.headers.get('set-cookie'), null);

  // 4. Unlock with correct password sets Set-Cookie
  const correctUnlockReq = new Request('https://share.example.invalid/vip-docs/unlock', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'correct-password-42' }),
  });
  const correctUnlockRes = await handleUnlockShare(correctUnlockReq, {
    params: Promise.resolve({ slug: 'vip-docs' }),
  });
  assert.equal(correctUnlockRes.status, 303);
  assert.equal(correctUnlockRes.headers.get('location'), '/vip-docs');
  const cookieHeader = correctUnlockRes.headers.get('set-cookie');
  assert.ok(cookieHeader);
  assert.ok(cookieHeader.includes('share_unlock_vip-docs='));
  assert.ok(cookieHeader.includes('Path=/vip-docs'));
  assert.ok(cookieHeader.includes('HttpOnly'));

  const cookieVal = cookieHeader.split(';')[0];

  // 5. Now visiting /[slug] with cookie renders the content
  const authViewReq = new Request('https://share.example.invalid/vip-docs', {
    headers: { cookie: cookieVal },
  });
  const authViewRes = await handleViewShare(authViewReq, {
    params: Promise.resolve({ slug: 'vip-docs' }),
  });
  assert.equal(authViewRes.status, 200);
  assert.equal(authViewRes.headers.get('cache-control'), 'private, no-cache');
  const pageHtml = await authViewRes.text();
  assert.ok(pageHtml.includes('VIP Documentation'));
  // And still no og:image because it is password protected
  assert.ok(!pageHtml.includes('og:image'));

  // 6. Direct asset request with cookie returns 200 with private no-cache
  const authAssetReq = new Request('https://share.example.invalid/vip-docs/confidential.pdf', {
    headers: { cookie: cookieVal },
  });
  const authAssetRes = await handleStreamAsset(authAssetReq, {
    params: Promise.resolve({ slug: 'vip-docs', filename: ['confidential.pdf'] }),
  });
  assert.equal(authAssetRes.status, 200);
  assert.equal(authAssetRes.headers.get('cache-control'), 'private, no-cache');

  // 7. Expired share returns 404
  await storage.saveMeta('expired-share', {
    slug: 'expired-share',
    title: 'Expired',
    description: 'Past link',
    lang: 'es',
    createdAt: '2026-09-01T00:00:00Z',
    expiresAt: '2026-09-10T00:00:00Z', // In the past
    kind: 'generated',
    assets: [{ name: 'file.txt', originalName: 'file.txt', contentType: 'text/plain', sizeBytes: 10 }],
  });
  await storage.putAsset('expired-share', 'file.txt', Buffer.from('hello'), 'text/plain');

  const expViewRes = await handleViewShare(new Request('https://share.example.invalid/expired-share'), {
    params: Promise.resolve({ slug: 'expired-share' }),
  });
  assert.equal(expViewRes.status, 404);

  const expAssetRes = await handleStreamAsset(
    new Request('https://share.example.invalid/expired-share/file.txt'),
    { params: Promise.resolve({ slug: 'expired-share', filename: ['file.txt'] }) }
  );
  assert.equal(expAssetRes.status, 404);
});

test('Orphan Sweep endpoint: POST /api/shares/orphans', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  // Upload an asset under orphan-test but do NOT save meta.json
  // Set upload time to 48 hours ago
  const oldDate = new Date(Date.now() - 48 * 60 * 60 * 1000);
  storage.blobs.set('orphan-slug/lost-file.png', {
    data: Buffer.from('orphan bytes'),
    contentType: 'image/png',
    uploadedAt: oldDate,
  });

  const sweepReq = createApiRequest('https://share.example.invalid/api/shares/orphans', 'POST');
  const sweepRes = await handleSweepOrphans(sweepReq);
  assert.equal(sweepRes.status, 200);
  const sweepJson = await sweepRes.json();
  assert.equal(sweepJson.count, 1);
  assert.equal(sweepJson.sweptPrefixes[0], 'orphan-slug');

  // Verify blob was removed
  assert.equal(storage.blobs.has('orphan-slug/lost-file.png'), false);
});

test('Canonical URLs are immune to Host header spoofing', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  await storage.putAsset('anti-spoof', 'doc.pdf', Buffer.from('data'), 'application/pdf');
  const createReq = new Request('https://evil-attacker.com/api/shares', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${TEST_API_TOKEN}`,
      'content-type': 'application/json',
      host: 'evil-attacker.com',
    },
    body: JSON.stringify({
      slug: 'anti-spoof',
      title: 'Anti Spoof',
      description: 'Test Host Header',
      lang: 'en',
      kind: 'generated',
      assets: [{ name: 'doc.pdf', originalName: 'doc.pdf', contentType: 'application/pdf' }],
    }),
  });
  const createRes = await handleCreateShare(createReq);
  const createJson = await createRes.json();
  assert.ok(createJson.url.startsWith('https://share.example.invalid/'));
  assert.ok(!createJson.url.includes('evil-attacker.com'));
});

test('Each declared file gets its own URL bound to its own pathname', async () => {
  const storage = new MemoryStorage();
  const uploadResult = await storage.createUploadTokens('my-trip', [
    { name: 'photo1.jpg', contentType: 'image/jpeg', sizeBytes: 1024 },
    { name: 'report.pdf', contentType: 'application/pdf', sizeBytes: 2048 },
  ]);

  assert.equal(uploadResult.tokens.length, 2);
  assert.equal(uploadResult.tokens[0].pathname, 'my-trip/photo1.jpg');
  assert.equal(uploadResult.tokens[1].pathname, 'my-trip/report.pdf');

  // One URL per file, never one URL covering the prefix.
  assert.notEqual(uploadResult.tokens[0].uploadUrl, uploadResult.tokens[1].uploadUrl);
  for (const t of uploadResult.tokens) {
    assert.ok(t.uploadUrl.includes(t.pathname));
  }
  assert.ok(uploadResult.validUntil > Date.now());

  await assert.rejects(
    () => storage.createUploadTokens('my-trip', [
      { name: '__meta.json', contentType: 'application/json', sizeBytes: 10 },
    ]),
    /reserved/
  );
});

test('An uploaded page is sandboxed into an opaque origin; a generated one is not', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  await storage.putAsset('pagina-ajena', '__page.html', '<h1>hola</h1>', 'text/html');
  await storage.saveMeta('pagina-ajena', {
    slug: 'pagina-ajena',
    title: 'Pagina ajena',
    description: 'HTML que no escribimos nosotros',
    lang: 'es',
    createdAt: new Date().toISOString(),
    kind: 'uploaded',
    assets: [],
  });

  const uploaded = await handleViewShare(
    new Request('https://share.example.invalid/pagina-ajena'),
    { params: Promise.resolve({ slug: 'pagina-ajena' }) }
  );
  const csp = uploaded.headers.get('content-security-policy');
  assert.equal(uploaded.status, 200);
  assert.ok(csp && csp.includes('sandbox'), `expected a sandbox policy, got ${csp}`);
  // allow-same-origin would hand the page back the origin the sandbox exists to take away.
  assert.ok(!csp.includes('allow-same-origin'), csp);
  assert.equal(uploaded.headers.get('x-content-type-options'), 'nosniff');

  await storage.putAsset('propia', 'foto.png', Buffer.from('x'), 'image/png');
  await storage.saveMeta('propia', {
    slug: 'propia',
    title: 'Propia',
    description: 'Pagina que renderizamos nosotros',
    lang: 'es',
    createdAt: new Date().toISOString(),
    kind: 'generated',
    assets: [
      { name: 'foto.png', originalName: 'foto.png', contentType: 'image/png', sizeBytes: 1 },
    ],
  });
  const generated = await handleViewShare(
    new Request('https://share.example.invalid/propia'),
    { params: Promise.resolve({ slug: 'propia' }) }
  );
  assert.equal(generated.status, 200);
  assert.equal(generated.headers.get('content-security-policy'), null);
});

test('Shows a markdown asset as the page, not as a download card', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  const md = '# Lentejas\n\nCon **chorizo** y <script>alert(1)</script>\n';
  await storage.putAsset('receta', 'receta.md', Buffer.from(md), 'text/markdown');
  await storage.saveMeta('receta', {
    slug: 'receta',
    title: 'Receta',
    lang: 'es',
    createdAt: new Date().toISOString(),
    kind: 'generated',
    assets: [
      {
        name: 'receta.md',
        originalName: 'receta.md',
        contentType: 'text/markdown',
        sizeBytes: Buffer.byteLength(md),
      },
    ],
  });

  const res = await handleViewShare(new Request('https://share.example.invalid/receta'), {
    params: Promise.resolve({ slug: 'receta' }),
  });
  const html = await res.text();

  assert.ok(html.includes('<h1>Lentejas</h1>'), html.slice(0, 400));
  assert.ok(html.includes('<strong>chorizo</strong>'));
  // Raw HTML in a markdown source never becomes an element on our origin.
  assert.ok(!html.includes('<script>alert(1)</script>'), 'script survived the markdown renderer');
});

test('Shows a plain text asset inline, escaped rather than parsed', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  const txt = 'linea uno\n<b>no soy html</b>\n';
  await storage.putAsset('notas', 'notas.txt', Buffer.from(txt), 'text/plain');
  await storage.saveMeta('notas', {
    slug: 'notas',
    title: 'Notas',
    lang: 'es',
    createdAt: new Date().toISOString(),
    kind: 'generated',
    assets: [
      {
        name: 'notas.txt',
        originalName: 'notas.txt',
        contentType: 'text/plain',
        sizeBytes: Buffer.byteLength(txt),
      },
    ],
  });

  const res = await handleViewShare(new Request('https://share.example.invalid/notas'), {
    params: Promise.resolve({ slug: 'notas' }),
  });
  const html = await res.text();

  assert.ok(html.includes('<pre class="asset-code">'), html.slice(0, 400));
  assert.ok(html.includes('&lt;b&gt;no soy html&lt;/b&gt;'));
});

test('Leaves a text asset too large to inline as a download', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  await storage.putAsset('grande', 'grande.txt', Buffer.from('x'), 'text/plain');
  await storage.saveMeta('grande', {
    slug: 'grande',
    title: 'Grande',
    lang: 'es',
    createdAt: new Date().toISOString(),
    kind: 'generated',
    assets: [
      {
        name: 'grande.txt',
        originalName: 'grande.txt',
        contentType: 'text/plain',
        sizeBytes: 5 * 1024 * 1024,
      },
    ],
  });

  const res = await handleViewShare(new Request('https://share.example.invalid/grande'), {
    params: Promise.resolve({ slug: 'grande' }),
  });
  const html = await res.text();

  assert.ok(
    !html.includes('<pre class="asset-code">'),
    'a 5 MB text file was inlined into the page'
  );
  assert.ok(html.includes('Descargar'));
});

test('Serves the declared content type, not the one the stored blob carries', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  // What a presigned upload can actually land in the store: the store does not enforce
  // allowedContentTypes, so the blob's own type is attacker-influenced.
  await storage.putAsset('tipo-mentiroso', 'nota.txt', Buffer.from('<script>alert(1)</script>'), 'text/html');
  await storage.saveMeta('tipo-mentiroso', {
    slug: 'tipo-mentiroso',
    title: 'Tipo mentiroso',
    description: 'El blob dice html, el registro dice texto',
    lang: 'es',
    createdAt: new Date().toISOString(),
    kind: 'generated',
    assets: [
      { name: 'nota.txt', originalName: 'nota.txt', contentType: 'text/plain', sizeBytes: 25 },
    ],
  });

  const res = await handleStreamAsset(
    new Request('https://share.example.invalid/tipo-mentiroso/nota.txt'),
    { params: Promise.resolve({ slug: 'tipo-mentiroso', filename: ['nota.txt'] }) }
  );
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'text/plain');

  // An asset the record does not name is not servable at all.
  const ghost = await handleStreamAsset(
    new Request('https://share.example.invalid/tipo-mentiroso/otro.txt'),
    { params: Promise.resolve({ slug: 'tipo-mentiroso', filename: ['otro.txt'] }) }
  );
  assert.equal(ghost.status, 404);
});

test('Generated share with literal index.html asset and X-Robots-Tag verification', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  const htmlContent = '<h1>This is raw user index.html asset</h1>';
  const pdfContent = '%PDF-1.4 test pdf';
  const imgContent = Buffer.from([0xff, 0xd8, 0xff, 0xe0]); // fake jpeg

  // 1. Upload tokens for index.html, report.pdf, and banner.jpg
  const uploadReq = createApiRequest('https://share.example.invalid/api/uploads', 'POST', {
    slug: 'my-project',
    files: [
      { name: 'index.html', contentType: 'text/html', sizeBytes: Buffer.byteLength(htmlContent) },
      { name: 'report.pdf', contentType: 'application/pdf', sizeBytes: Buffer.byteLength(pdfContent) },
      { name: 'banner.jpg', contentType: 'image/jpeg', sizeBytes: imgContent.length },
    ],
  });
  const uploadRes = await handleUploads(uploadReq);
  assert.equal(uploadRes.status, 200);

  // 2. Put assets in storage
  await storage.putAsset('my-project', 'index.html', Buffer.from(htmlContent), 'text/html');
  await storage.putAsset('my-project', 'report.pdf', Buffer.from(pdfContent), 'application/pdf');
  await storage.putAsset('my-project', 'banner.jpg', imgContent, 'image/jpeg');

  // 3. Create generated share naming the assets
  const createReq = createApiRequest('https://share.example.invalid/api/shares', 'POST', {
    slug: 'my-project',
    title: 'Project Files',
    description: 'Documentation and assets',
    lang: 'en',
    kind: 'generated',
    assets: [
      { name: 'index.html', originalName: 'index.html', contentType: 'text/html' },
      { name: 'report.pdf', originalName: 'annual-report.pdf', contentType: 'application/pdf' },
      { name: 'banner.jpg', originalName: 'banner.jpg', contentType: 'image/jpeg' },
    ],
  });
  const createRes = await handleCreateShare(createReq);
  assert.equal(createRes.status, 201);

  // 4. Listing includes index.html as an asset
  const getShareRes = await handleGetShare(
    createApiRequest('https://share.example.invalid/api/shares/my-project'),
    { params: Promise.resolve({ slug: 'my-project' }) }
  );
  assert.equal(getShareRes.status, 200);
  const shareJson = await getShareRes.json();
  assert.equal(shareJson.assets.length, 3);
  const indexAsset = shareJson.assets.find((a) => a.name === 'index.html');
  assert.ok(indexAsset);
  assert.equal(indexAsset.url, 'https://share.example.invalid/my-project/index.html');

  // 5. Canonical page /<slug> serves the rendered viewer (NOT raw index.html asset)
  const canonicalRes = await handleViewShare(
    new Request('https://share.example.invalid/my-project'),
    { params: Promise.resolve({ slug: 'my-project' }) }
  );
  assert.equal(canonicalRes.status, 200);
  assert.equal(canonicalRes.headers.get('x-robots-tag'), 'noindex, nofollow');
  const canonicalText = await canonicalRes.text();
  assert.ok(canonicalText.includes('<!DOCTYPE html>'));
  assert.ok(canonicalText.includes('Project Files'));
  assert.ok(canonicalText.includes('annual-report.pdf'));

  // 6. Direct asset request /<slug>/index.html serves the raw uploaded asset
  const assetIndexRes = await handleStreamAsset(
    new Request('https://share.example.invalid/my-project/index.html'),
    { params: Promise.resolve({ slug: 'my-project', filename: ['index.html'] }) }
  );
  assert.equal(assetIndexRes.status, 200);
  assert.equal(assetIndexRes.headers.get('content-type'), 'text/html');
  assert.equal(assetIndexRes.headers.get('x-robots-tag'), 'noindex, nofollow');
  const assetIndexText = await assetIndexRes.text();
  assert.equal(assetIndexText, htmlContent);

  // 7. Direct asset request /<slug>/report.pdf carries X-Robots-Tag: noindex, nofollow
  const assetPdfRes = await handleStreamAsset(
    new Request('https://share.example.invalid/my-project/report.pdf'),
    { params: Promise.resolve({ slug: 'my-project', filename: ['report.pdf'] }) }
  );
  assert.equal(assetPdfRes.status, 200);
  assert.equal(assetPdfRes.headers.get('content-type'), 'application/pdf');
  assert.equal(assetPdfRes.headers.get('x-robots-tag'), 'noindex, nofollow');

  // 8. Direct asset request /<slug>/banner.jpg carries X-Robots-Tag: noindex, nofollow
  const assetImgRes = await handleStreamAsset(
    new Request('https://share.example.invalid/my-project/banner.jpg'),
    { params: Promise.resolve({ slug: 'my-project', filename: ['banner.jpg'] }) }
  );
  assert.equal(assetImgRes.status, 200);
  assert.equal(assetImgRes.headers.get('content-type'), 'image/jpeg');
  assert.equal(assetImgRes.headers.get('x-robots-tag'), 'noindex, nofollow');

  // 9. Internal system blobs cannot be served via the asset route
  const internalMetaRes = await handleStreamAsset(
    new Request('https://share.example.invalid/my-project/__meta.json'),
    { params: Promise.resolve({ slug: 'my-project', filename: ['__meta.json'] }) }
  );
  assert.equal(internalMetaRes.status, 404);
  assert.equal(internalMetaRes.headers.get('x-robots-tag'), 'noindex, nofollow');
});

test('Asset names with segments starting with __ are rejected across all endpoints', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);

  // 1. POST /api/uploads rejects files with __ prefix or __ segment
  const badNames = ['__meta.json', '__page.html', '__secret.pdf', 'folder/__nested.jpg'];
  for (const name of badNames) {
    const uploadReq = createApiRequest('https://share.example.invalid/api/uploads', 'POST', {
      slug: 'test-reserved',
      files: [{ name, contentType: 'application/pdf', sizeBytes: 100 }],
    });
    const uploadRes = await handleUploads(uploadReq);
    assert.equal(uploadRes.status, 400);
    const errJson = await uploadRes.json();
    assert.ok(errJson.error.includes('reserved prefix ("__")'));
  }

  // 2. POST /api/shares rejects files with __
  const createReq = createApiRequest('https://share.example.invalid/api/shares', 'POST', {
    slug: 'test-reserved',
    title: 'Reserved',
    description: 'Reserved test',
    lang: 'en',
    kind: 'generated',
    assets: [{ name: '__illegal.pdf', contentType: 'application/pdf' }],
  });
  const createRes = await handleCreateShare(createReq);
  assert.equal(createRes.status, 400);
  const createErr = await createRes.json();
  assert.ok(createErr.error.includes('reserved prefix ("__")'));
});
