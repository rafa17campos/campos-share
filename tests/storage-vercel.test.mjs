import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import http from 'node:http';
import { Agent, getGlobalDispatcher, setGlobalDispatcher } from 'undici';

process.env.SHARE_COOKIE_SECRET = 'cookie-secret-test-abc123';
process.env.SHARE_BASE_URL = 'https://share.example.invalid';
process.env.VERCEL_BLOB_API_URL = 'https://blob-api.test/api/blob';
process.env.VERCEL_BLOB_RETRIES = '0';

import { VercelBlobStorage, MetaConflictError } from '../lib/storage.ts';
import { appendAssets } from '../lib/shares.ts';
import { PAGE_DB_ASSET_NAME, listDocuments, writeDocument, deleteDocument } from '../lib/pageDb.ts';

const STORE = 'store123';
const TOKEN = `vercel_blob_rw_${STORE}_secret`;

/**
 * Enough of Vercel Blob to run VercelBlobStorage against: the API (head, put with ifMatch and
 * allowOverwrite) and the private download host behind its CDN, served by a local HTTP server that
 * every SDK request is redirected to. The CDN behaves as the real one did in production: a download
 * above 1 KB comes back with a weak ETag that is not the blob's, whatever the request asks for, and
 * without a usable Content-Length unless identity was asked for. ETags follow content (MD5, as
 * S3-style stores do), so repeated bytes repeat the ETag.
 */
async function fakeBlob() {
  const blobs = new Map();
  const counts = { head: 0, get: 0, put: 0, conflicts: 0 };
  const etagOf = (data) => `"${createHash('md5').update(data).digest('hex')}"`;
  const json = (res, status, body) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };

  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    const host = req.headers['x-orig-host'];
    const url = new URL(req.url, 'http://local');

    if (host === 'blob-api.test' && req.method === 'GET') {
      counts.head++;
      const pathname = url.searchParams.get('url');
      const blob = blobs.get(pathname);
      if (!blob) return json(res, 404, { error: { code: 'not_found', message: 'The requested blob does not exist' } });
      return json(res, 200, {
        url: `https://${STORE}.private.blob.vercel-storage.com/${pathname}`,
        downloadUrl: '',
        pathname,
        size: blob.data.length,
        contentType: blob.contentType,
        contentDisposition: '',
        cacheControl: '',
        uploadedAt: new Date().toISOString(),
        etag: blob.etag,
      });
    }
    if (host === 'blob-api.test' && req.method === 'PUT') {
      counts.put++;
      const pathname = url.searchParams.get('pathname');
      const current = blobs.get(pathname);
      const ifMatch = req.headers['x-if-match'];
      if (ifMatch && (!current || current.etag !== ifMatch)) {
        counts.conflicts++;
        return json(res, 412, { error: { code: 'precondition_failed', message: 'ETag mismatch' } });
      }
      if (current && req.headers['x-allow-overwrite'] !== '1') {
        return json(res, 400, { error: { code: 'bad_request', message: 'This blob already exists' } });
      }
      const blob = { data: body, contentType: req.headers['x-content-type'] || 'application/octet-stream', etag: etagOf(body) };
      blobs.set(pathname, blob);
      return json(res, 200, { url: '', downloadUrl: '', pathname, contentType: blob.contentType, contentDisposition: '', etag: blob.etag });
    }
    if (host === `${STORE}.private.blob.vercel-storage.com` && req.method === 'GET') {
      counts.get++;
      const blob = blobs.get(decodeURIComponent(url.pathname.slice(1)));
      if (!blob) {
        res.writeHead(404);
        return res.end('not found');
      }
      const big = blob.data.length > 1000;
      const identity = String(req.headers['accept-encoding'] ?? '').includes('identity');
      const headers = { etag: big ? `W/"cdn-${blob.etag.slice(1, 9)}"` : blob.etag, 'content-type': blob.contentType };
      if (big && !identity) headers['transfer-encoding'] = 'chunked';
      else headers['content-length'] = String(blob.data.length);
      res.writeHead(200, headers);
      return res.end(blob.data);
    }
    res.writeHead(500);
    res.end(`unexpected ${req.method} ${host}${req.url}`);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const local = `http://127.0.0.1:${server.address().port}`;

  /** Sends every request to the local server, telling it which host it was meant for. */
  class Redirect extends Agent {
    dispatch(opts, handler) {
      const host = new URL(opts.origin).host;
      const headers = Array.isArray(opts.headers)
        ? [...opts.headers, 'x-orig-host', host]
        : { ...(opts.headers ?? {}), 'x-orig-host': host };
      return super.dispatch({ ...opts, origin: local, headers }, handler);
    }
  }
  const dispatcher = new Redirect();
  const close = async () => {
    await dispatcher.close();
    await new Promise((resolve) => server.close(resolve));
  };
  return { dispatcher, blobs, counts, close };
}

let previous;
let current;
async function useFakeBlob() {
  current = await fakeBlob();
  setGlobalDispatcher(current.dispatcher);
  return current;
}
test.beforeEach(() => {
  previous = getGlobalDispatcher();
});
test.afterEach(async () => {
  setGlobalDispatcher(previous);
  await current?.close();
  current = undefined;
});

test('page database writes keep working against Blob once the store is served compressed', async () => {
  const fake = await useFakeBlob();
  const storage = new VercelBlobStorage(TOKEN);
  await storage.saveMeta('lista', { slug: 'lista', title: 'L', lang: 'es', createdAt: new Date().toISOString(), kind: 'uploaded', assets: [], database: true });

  for (let i = 0; i < 15; i++) {
    const r = await writeDocument(storage, 'lista', 'items', 'add', undefined, { name: `cosa ${i}`, nota: 'x'.repeat(50) });
    assert.equal(r.created, true, `write ${i}: ${JSON.stringify(r)}`);
  }
  assert.ok(fake.blobs.get(`lista/${PAGE_DB_ASSET_NAME}`).data.length > 1000, 'past the size the CDN compresses');
  assert.equal(fake.counts.conflicts, 0, 'no write was refused for a stale ETag');
  assert.equal((await listDocuments(storage, 'lista', 'items')).length, 15);

  // A burst of simultaneous removals, as a page clearing its list does, all land.
  const docs = await listDocuments(storage, 'lista', 'items');
  const results = await Promise.all(docs.slice(0, 6).map((d) => deleteDocument(storage, 'lista', 'items', d.id)));
  assert.ok(results.every((r) => r.deleted === true), JSON.stringify(results));
  assert.equal((await listDocuments(storage, 'lista', 'items')).length, 9);
});

test('record writes keep working against Blob once the record is served compressed', async () => {
  const fake = await useFakeBlob();
  const storage = new VercelBlobStorage(TOKEN);
  const assets = [];
  for (let i = 0; i < 8; i++) {
    const name = `archivo-con-un-nombre-largo-${i}.txt`;
    await storage.putAsset('carpeta', name, `contenido ${i}`, 'text/plain');
    assets.push({ name, originalName: name, contentType: 'text/plain', sizeBytes: 11 });
  }
  await storage.saveMeta('carpeta', { slug: 'carpeta', title: 'C', lang: 'es', createdAt: new Date().toISOString(), kind: 'generated', assets });
  assert.ok(fake.blobs.get('carpeta/__meta.json').data.length > 1000);

  await storage.putAsset('carpeta', 'nuevo.txt', 'hola', 'text/plain');
  const appended = await appendAssets(storage, 'carpeta', [{ name: 'nuevo.txt', contentType: 'text/plain' }]);
  assert.ok(!('error' in appended), JSON.stringify(appended));
  assert.equal((await storage.getMeta('carpeta')).assets.length, 9);
  assert.equal(fake.counts.conflicts, 0);
});

test('every record save writes new bytes, so its ETag never comes back', async () => {
  const fake = await useFakeBlob();
  const storage = new VercelBlobStorage(TOKEN);
  const meta = { slug: 'mismo', title: 'M', lang: 'es', createdAt: '2026-11-10T00:00:00.000Z', kind: 'uploaded', assets: [] };
  await storage.saveMeta('mismo', meta);
  const first = fake.blobs.get('mismo/__meta.json').etag;
  await storage.saveMeta('mismo', meta);
  assert.notEqual(fake.blobs.get('mismo/__meta.json').etag, first, 'the same record saved twice gets a new ETag');

  // And a conditional save with the ETag from before the other save is refused.
  const stale = await storage.readMeta('mismo');
  await storage.saveMeta('mismo', meta);
  await assert.rejects(storage.saveMeta('mismo', meta, { ifMatch: stale.etag }), MetaConflictError);
});

test('assets are downloaded uncompressed, so their size and ETag are the blob\'s', async () => {
  const fake = await useFakeBlob();
  const storage = new VercelBlobStorage(TOKEN);
  const body = 'línea de texto\n'.repeat(200);
  await storage.putAsset('docs', 'nota.md', body, 'text/markdown');
  const read = await storage.getAsset('docs', 'nota.md');
  assert.equal(read.size, Buffer.byteLength(body), 'Content-Length is the real size');
  assert.equal(await new Response(read.stream).text(), body);
});
