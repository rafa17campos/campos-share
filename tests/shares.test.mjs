import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

process.env.SHARE_API_TOKEN = 'secret-test-token-xyz789';
process.env.SHARE_COOKIE_SECRET = 'cookie-secret-test-abc123';
process.env.SHARE_BASE_URL = 'https://share.example.invalid';

import { MemoryStorage, MetaConflictError, setStorageForTesting } from '../lib/storage.ts';
import { appendAssets, removeAsset, replaceAssetContent, replaceShare, syncAssetFromStorage } from '../lib/shares.ts';
import { POST as handleAddAssets } from '../app/api/shares/[slug]/assets/route.ts';
import { PUT as handleSyncAsset, DELETE as handleRemoveAsset } from '../app/api/shares/[slug]/assets/[...name]/route.ts';

const TOKEN = process.env.SHARE_API_TOKEN;

async function seed(storage, slug, files) {
  const assets = [];
  for (const [name, content, contentType] of files) {
    const written = await storage.putAsset(slug, name, Buffer.from(content), contentType);
    assets.push({ name, originalName: name, contentType, sizeBytes: Buffer.byteLength(content), etag: written.etag });
  }
  await storage.saveMeta(slug, {
    slug,
    title: `Folder ${slug}`,
    description: 'desc',
    lang: 'es',
    createdAt: '2026-09-15T10:00:00.000Z',
    kind: 'generated',
    assets,
  });
}

function apiRequest(path, method, body, token = TOKEN) {
  const headers = new Headers();
  if (token) headers.set('authorization', `Bearer ${token}`);
  if (body !== undefined) headers.set('content-type', 'application/json');
  return new Request(`https://share.example.invalid${path}`, {
    method,
    headers,
    body: body === undefined ? null : JSON.stringify(body),
  });
}

/** Reads the body once and asserts the status with it, so a failure shows what came back. */
async function okJson(res) {
  const body = await res.json();
  assert.equal(res.status, 200, JSON.stringify(body));
  return body;
}

const params = (slug, name) => ({ params: Promise.resolve(name === undefined ? { slug } : { slug, name: name.split('/') }) });

/* ------------------------------------------------------------------------------------------ */
/* Conditional writes                                                                          */
/* ------------------------------------------------------------------------------------------ */

test('saveMeta with ifMatch refuses a record that changed since it was read', async () => {
  const storage = new MemoryStorage();
  await seed(storage, 'docs', [['a.txt', 'a', 'text/plain']]);
  const first = await storage.readMeta('docs');
  await storage.saveMeta('docs', { ...first.meta, title: 'changed elsewhere' });
  await assert.rejects(
    () => storage.saveMeta('docs', { ...first.meta, title: 'stale' }, { ifMatch: first.etag }),
    (err) => err instanceof MetaConflictError
  );
  const fresh = await storage.readMeta('docs');
  await storage.saveMeta('docs', { ...fresh.meta, title: 'current' }, { ifMatch: fresh.etag });
  assert.equal((await storage.getMeta('docs')).title, 'current');
});

test('two files added concurrently both end up in the record', async () => {
  const storage = new MemoryStorage();
  await seed(storage, 'docs', [['a.txt', 'a', 'text/plain']]);
  await storage.putAsset('docs', 'b.txt', Buffer.from('bb'), 'text/plain');
  await storage.putAsset('docs', 'c.txt', Buffer.from('ccc'), 'text/plain');

  // Interleave: the first mutation reads the record, then a second write lands before it saves.
  let intruded = false;
  const original = storage.headAsset.bind(storage);
  storage.headAsset = async (slug, name) => {
    if (!intruded && name === 'b.txt') {
      intruded = true;
      const other = await appendAssets(storage, 'docs', [{ name: 'c.txt', contentType: 'text/plain' }]);
      assert.equal('error' in other, false, JSON.stringify(other));
    }
    return original(slug, name);
  };

  const result = await appendAssets(storage, 'docs', [{ name: 'b.txt', contentType: 'text/plain' }]);
  assert.equal('error' in result, false, JSON.stringify(result));
  assert.deepEqual(
    (await storage.getMeta('docs')).assets.map((a) => a.name).sort(),
    ['a.txt', 'b.txt', 'c.txt']
  );
  assert.equal(intruded, true);
});

test('removing a file while another caller adds one keeps the added file', async () => {
  const storage = new MemoryStorage();
  await seed(storage, 'docs', [['a.txt', 'a', 'text/plain'], ['b.txt', 'b', 'text/plain']]);
  await storage.putAsset('docs', 'c.txt', Buffer.from('c'), 'text/plain');

  let intruded = false;
  const original = storage.readMeta.bind(storage);
  storage.readMeta = async (slug) => {
    const read = await original(slug);
    if (!intruded) {
      intruded = true;
      await appendAssets(storage, 'docs', [{ name: 'c.txt', contentType: 'text/plain' }]);
    }
    return read;
  };

  const result = await removeAsset(storage, 'docs', 'a.txt');
  assert.equal('error' in result, false, JSON.stringify(result));
  assert.equal(result.shareDeleted, false);
  assert.deepEqual(result.meta.assets.map((a) => a.name).sort(), ['b.txt', 'c.txt']);
  assert.equal(await storage.headAsset('docs', 'a.txt'), null, 'the removed blob is pruned');
  assert.ok(await storage.headAsset('docs', 'c.txt'), 'the concurrently added blob survives');
});

test('replaceShare writes the record before it prunes, so a lost race deletes nothing', async () => {
  const storage = new MemoryStorage();
  await seed(storage, 'docs', [['a.txt', 'a', 'text/plain'], ['b.txt', 'b', 'text/plain']]);
  const result = await replaceShare(storage, 'docs', {
    title: 'Folder docs',
    lang: 'es',
    kind: 'generated',
    assets: [{ name: 'b.txt', contentType: 'text/plain' }],
  });
  assert.equal('error' in result, false, JSON.stringify(result));
  assert.equal(await storage.headAsset('docs', 'a.txt'), null);
  assert.deepEqual((await storage.getMeta('docs')).assets.map((a) => a.name), ['b.txt']);
});

test('replaceAssetContent and syncAssetFromStorage refresh one file and leave the rest alone', async () => {
  const storage = new MemoryStorage();
  await seed(storage, 'docs', [['a.txt', 'a', 'text/plain'], ['b.txt', 'b', 'text/plain']]);
  const before = (await storage.getMeta('docs')).assets;

  const replaced = await replaceAssetContent(storage, 'docs', 'a.txt', Buffer.from('AAAA'), 'text/markdown');
  assert.equal('error' in replaced, false);
  const a = replaced.meta.assets.find((x) => x.name === 'a.txt');
  assert.equal(a.sizeBytes, 4);
  assert.equal(a.contentType, 'text/markdown');
  assert.notEqual(a.etag, before[0].etag);
  assert.ok(a.updatedAt);
  assert.deepEqual(replaced.meta.assets.find((x) => x.name === 'b.txt'), before[1]);

  await storage.putAsset('docs', 'b.txt', Buffer.from('bbbbbb'), 'text/plain');
  const synced = await syncAssetFromStorage(storage, 'docs', 'b.txt', { originalName: 'B (final).txt' });
  assert.equal(synced.changed, true);
  const b = synced.meta.assets.find((x) => x.name === 'b.txt');
  assert.equal(b.sizeBytes, 6);
  assert.equal(b.originalName, 'B (final).txt');
  assert.ok(b.updatedAt);

  const again = await syncAssetFromStorage(storage, 'docs', 'b.txt');
  assert.equal(again.changed, false);

  const missing = await syncAssetFromStorage(storage, 'docs', 'zzz.txt');
  assert.equal(missing.status, 404);
  const page = await replaceAssetContent(storage, 'nope', 'a.txt', Buffer.from('x'), 'text/plain');
  assert.equal(page.status, 404);
});

/* ------------------------------------------------------------------------------------------ */
/* Per-file API                                                                                */
/* ------------------------------------------------------------------------------------------ */

test('POST /api/shares/{slug}/assets appends uploaded files and answers the full record', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);
  await seed(storage, 'docs', [['a.txt', 'a', 'text/plain']]);
  await storage.putAsset('docs', 'b.pdf', Buffer.from('%PDF'), 'application/pdf');

  const unauth = await handleAddAssets(apiRequest('/api/shares/docs/assets', 'POST', { assets: [] }, null), params('docs'));
  assert.equal(unauth.status, 401);

  const ok = await handleAddAssets(
    apiRequest('/api/shares/docs/assets', 'POST', { assets: [{ name: 'b.pdf', originalName: 'Informe.pdf', contentType: 'application/pdf' }] }),
    params('docs')
  );
  const body = await okJson(ok);
  assert.equal(body.slug, 'docs');
  assert.equal(body.title, 'Folder docs');
  assert.equal(body.lang, 'es');
  assert.equal(body.assetCount, 2);
  assert.deepEqual(body.assets.map((x) => x.name), ['a.txt', 'b.pdf']);
  const added = body.assets[1];
  assert.equal(added.originalName, 'Informe.pdf');
  assert.equal(added.sizeBytes, 4);
  assert.ok(added.etag);
  assert.equal(added.url, 'https://share.example.invalid/docs/b.pdf');
  assert.equal(body.passwordHash, undefined);

  const dup = await handleAddAssets(
    apiRequest('/api/shares/docs/assets', 'POST', { assets: [{ name: 'a.txt', contentType: 'text/plain' }] }),
    params('docs')
  );
  assert.equal(dup.status, 409);

  const notUploaded = await handleAddAssets(
    apiRequest('/api/shares/docs/assets', 'POST', { assets: [{ name: 'ghost.txt', contentType: 'text/plain' }] }),
    params('docs')
  );
  assert.equal(notUploaded.status, 400);
  assert.match((await notUploaded.json()).error, /does not exist in storage/);

  const reserved = await handleAddAssets(
    apiRequest('/api/shares/docs/assets', 'POST', { assets: [{ name: '__meta.json', contentType: 'text/plain' }] }),
    params('docs')
  );
  assert.equal(reserved.status, 400);

  const unknown = await handleAddAssets(
    apiRequest('/api/shares/nope/assets', 'POST', { assets: [{ name: 'a.txt', contentType: 'text/plain' }] }),
    params('nope')
  );
  assert.equal(unknown.status, 404);

  const badBody = await handleAddAssets(apiRequest('/api/shares/docs/assets', 'POST', { assets: 'x' }), params('docs'));
  assert.equal(badBody.status, 400);

  await storage.putAsset('landing', '__page.html', '<h1>x</h1>', 'text/html');
  await storage.saveMeta('landing', { slug: 'landing', title: 'L', lang: 'en', createdAt: '2026-09-15T10:00:00.000Z', kind: 'uploaded', assets: [] });
  await storage.putAsset('landing', 'x.txt', Buffer.from('x'), 'text/plain');
  const page = await handleAddAssets(
    apiRequest('/api/shares/landing/assets', 'POST', { assets: [{ name: 'x.txt', contentType: 'text/plain' }] }),
    params('landing')
  );
  assert.equal(page.status, 409);
});

test('a declared sha256 is validated, stored, echoed and dropped when the bytes change without one', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);
  await seed(storage, 'docs', [['a.txt', 'a', 'text/plain']]);
  await storage.putAsset('docs', 'b.txt', Buffer.from('bb'), 'text/plain');
  const digest = crypto.createHash('sha256').update('bb').digest('hex');

  const bad = await handleAddAssets(
    apiRequest('/api/shares/docs/assets', 'POST', { assets: [{ name: 'b.txt', contentType: 'text/plain', sha256: 'nope' }] }),
    params('docs')
  );
  assert.equal(bad.status, 400);

  const added = await okJson(
    await handleAddAssets(
      apiRequest('/api/shares/docs/assets', 'POST', { assets: [{ name: 'b.txt', contentType: 'text/plain', sha256: digest.toUpperCase() }] }),
      params('docs')
    )
  );
  assert.equal(added.assets[1].sha256, digest, 'stored lowercase and echoed');

  // The bytes change through a presigned overwrite; a refresh that restates the digest keeps one,
  // a refresh that does not leaves the record without a digest rather than with a wrong one.
  await storage.putAsset('docs', 'b.txt', Buffer.from('ccc'), 'text/plain');
  const silent = await okJson(await handleSyncAsset(apiRequest('/api/shares/docs/assets/b.txt', 'PUT', {}), params('docs', 'b.txt')));
  assert.equal(silent.assets[1].sha256, undefined);
  const newDigest = crypto.createHash('sha256').update('ccc').digest('hex');
  const declared = await okJson(
    await handleSyncAsset(apiRequest('/api/shares/docs/assets/b.txt', 'PUT', { sha256: newDigest }), params('docs', 'b.txt'))
  );
  assert.equal(declared.assets[1].sha256, newDigest);

  // In-place replacement through the service computes it itself.
  const replaced = await replaceAssetContent(storage, 'docs', 'a.txt', Buffer.from('AAAA'), 'text/plain');
  assert.equal(replaced.meta.assets[0].sha256, crypto.createHash('sha256').update('AAAA').digest('hex'));

  // The whole-record write accepts it as well.
  const whole = await replaceShare(storage, 'docs', {
    title: 'Folder docs',
    lang: 'es',
    kind: 'generated',
    assets: [{ name: 'a.txt', contentType: 'text/plain', sha256: crypto.createHash('sha256').update('AAAA').digest('hex') }],
  });
  assert.equal(whole.meta.assets[0].sha256, crypto.createHash('sha256').update('AAAA').digest('hex'));
});

test('PUT /api/shares/{slug}/assets/{name} refreshes a replaced file, idempotently', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);
  await seed(storage, 'docs', [['a.txt', 'a', 'text/plain'], ['sub/deep.txt', 'd', 'text/plain']]);
  const before = (await storage.getMeta('docs')).assets[0];

  const same = await handleSyncAsset(apiRequest('/api/shares/docs/assets/a.txt', 'PUT', {}), params('docs', 'a.txt'));
  const sameBody = await okJson(same);
  assert.equal((sameBody).assets[0].etag, before.etag);

  await storage.putAsset('docs', 'a.txt', Buffer.from('new content'), 'text/plain');
  const refreshed = await handleSyncAsset(
    apiRequest('/api/shares/docs/assets/a.txt', 'PUT', { contentType: 'text/markdown', originalName: 'A.md' }),
    params('docs', 'a.txt')
  );
  const refreshedBody = await okJson(refreshed);
  const asset = refreshedBody.assets[0];
  assert.equal(asset.sizeBytes, 11);
  assert.equal(asset.contentType, 'text/markdown');
  assert.equal(asset.originalName, 'A.md');
  assert.notEqual(asset.etag, before.etag);
  assert.ok(asset.updatedAt);

  const noBody = await handleSyncAsset(apiRequest('/api/shares/docs/assets/sub/deep.txt', 'PUT'), params('docs', 'sub/deep.txt'));
  await okJson(noBody);

  const badType = await handleSyncAsset(apiRequest('/api/shares/docs/assets/a.txt', 'PUT', { contentType: '' }), params('docs', 'a.txt'));
  assert.equal(badType.status, 400);

  const missing = await handleSyncAsset(apiRequest('/api/shares/docs/assets/zzz.txt', 'PUT', {}), params('docs', 'zzz.txt'));
  assert.equal(missing.status, 404);
  const unknown = await handleSyncAsset(apiRequest('/api/shares/nope/assets/a.txt', 'PUT', {}), params('nope', 'a.txt'));
  assert.equal(unknown.status, 404);
  const unauth = await handleSyncAsset(apiRequest('/api/shares/docs/assets/a.txt', 'PUT', {}, null), params('docs', 'a.txt'));
  assert.equal(unauth.status, 401);
});

test('DELETE /api/shares/{slug}/assets/{name} removes one file and unpublishes on the last', async () => {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);
  await seed(storage, 'docs', [['a.txt', 'a', 'text/plain'], ['b.txt', 'b', 'text/plain']]);

  const first = await handleRemoveAsset(apiRequest('/api/shares/docs/assets/a.txt', 'DELETE'), params('docs', 'a.txt'));
  const body = await okJson(first);
  assert.equal(body.unpublished, false);
  assert.deepEqual(body.share.assets.map((x) => x.name), ['b.txt']);
  assert.equal(await storage.headAsset('docs', 'a.txt'), null);

  const again = await handleRemoveAsset(apiRequest('/api/shares/docs/assets/a.txt', 'DELETE'), params('docs', 'a.txt'));
  assert.equal(again.status, 404);

  const last = await handleRemoveAsset(apiRequest('/api/shares/docs/assets/b.txt', 'DELETE'), params('docs', 'b.txt'));
  assert.equal(last.status, 200);
  const lastBody = await last.json();
  assert.equal(lastBody.unpublished, true);
  assert.equal(lastBody.share, null);
  assert.equal(await storage.getMeta('docs'), null);
  assert.equal(await storage.headAsset('docs', 'b.txt'), null);

  const unknown = await handleRemoveAsset(apiRequest('/api/shares/docs/assets/b.txt', 'DELETE'), params('docs', 'b.txt'));
  assert.equal(unknown.status, 404);
  const unauth = await handleRemoveAsset(apiRequest('/api/shares/docs/assets/b.txt', 'DELETE', undefined, null), params('docs', 'b.txt'));
  assert.equal(unauth.status, 401);
});
