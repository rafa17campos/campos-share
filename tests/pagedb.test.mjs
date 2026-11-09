import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';

process.env.SHARE_API_TOKEN = 'secret-test-token-xyz789';
process.env.SHARE_COOKIE_SECRET = 'cookie-secret-test-abc123';
process.env.SHARE_BASE_URL = 'https://share.example.invalid';
process.env.MCP_OAUTH_SECRET = 'test-oauth-signing-secret-with-enough-length-0123456789';
process.env.MCP_STATIC_TOKEN = 'static-terminal-token-0123456789abcdefghij';
delete process.env.MCP_STATIC_TOKEN_SCOPES;
delete process.env.MCP_ALLOWED_ORIGINS;

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { AssetConflictError, MemoryStorage, setStorageForTesting } from '../lib/storage.ts';
import { createShare, replaceShare, deleteShare } from '../lib/shares.ts';
import {
  DB_LIMITS,
  PAGE_DB_ASSET_NAME,
  deleteDocument,
  getDocument,
  issuePageDbToken,
  listCollections,
  listDocuments,
  pageDbAddressLimiter,
  pageDbReadLimiter,
  pageDbWriteLimiter,
  verifyPageDbToken,
  writeDocument,
} from '../lib/pageDb.ts';
import * as dbRoute from '../app/api/db/[slug]/[[...path]]/route.ts';
import { POST as handleCreateShare, GET as handleListShares } from '../app/api/shares/route.ts';
import { GET as handleViewShare } from '../app/[slug]/route.ts';
import { POST as handleUnlockShare } from '../app/[slug]/unlock/route.ts';
import { closeMcpHandlerForTesting, serveMcp } from '../lib/mcp/server.ts';
import { toolCallLimiter } from '../lib/mcp/ratelimit.ts';
import { signAccessToken } from '../lib/oauth/tokens.ts';
import { ALL_SCOPES } from '../lib/mcp/config.ts';

const BASE = 'https://share.example.invalid';
const OWNER = process.env.SHARE_API_TOKEN;
const DAY_MS = 24 * 60 * 60 * 1000;

function fresh() {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);
  pageDbWriteLimiter.reset();
  pageDbReadLimiter.reset();
  pageDbAddressLimiter.reset();
  toolCallLimiter.reset();
  return storage;
}

async function publishPage(storage, slug, extra = {}) {
  const result = await createShare(storage, slug, {
    title: `Página ${slug}`,
    lang: 'es',
    kind: 'uploaded',
    html: '<!doctype html><html><head><title>t</title></head><body><p>hola</p></body></html>',
    database: true,
    ...extra,
  });
  assert.ok(!('error' in result), JSON.stringify(result));
  return result.meta;
}

/** Calls the /api/db route the way Next.js does: method handler, request, params promise. */
async function db(method, path, { token, body, headers = {} } = {}) {
  const [slug, ...rest] = path.split('/');
  const h = new Headers(headers);
  if (token) h.set('authorization', `Bearer ${token}`);
  if (body !== undefined) h.set('content-type', 'application/json');
  const request = new Request(`${BASE}/api/db/${path}`, {
    method,
    headers: h,
    body: body === undefined ? null : typeof body === 'string' ? body : JSON.stringify(body),
  });
  const res = await dbRoute[method](request, { params: Promise.resolve({ slug, path: rest.length ? rest : undefined }) });
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: text ? JSON.parse(text) : null };
}

async function viewPage(slug, cookie) {
  const headers = new Headers();
  if (cookie) headers.set('cookie', cookie);
  const res = await handleViewShare(new Request(`${BASE}/${slug}`, { headers }), { params: Promise.resolve({ slug }) });
  return { res, html: await res.text() };
}

function injectedToken(html) {
  const m = html.match(/T = "(pagedb\.[0-9]+\.[0-9a-f]+)"/);
  return m ? m[1] : null;
}

/* ------------------------------------------------------------------------------------------ */
/* The store                                                                                   */
/* ------------------------------------------------------------------------------------------ */

test('add, set, update, get, list and delete documents', async () => {
  const storage = fresh();
  await publishPage(storage, 'encuesta');
  assert.ok(storage.blobs.has(`encuesta/${PAGE_DB_ASSET_NAME}`), 'publishing with a database creates the store');

  const added = await writeDocument(storage, 'encuesta', 'votos', 'add', undefined, { choice: 'b' });
  assert.equal(added.created, true);
  assert.match(added.document.id, /^[A-Za-z0-9_-]{16}$/);

  const set = await writeDocument(storage, 'encuesta', 'votos', 'set', 'ana', { choice: 'a', nota: 'sí' });
  assert.equal(set.created, true);
  const updated = await writeDocument(storage, 'encuesta', 'votos', 'update', 'ana', { nota: 'ñandú' });
  assert.equal(updated.created, false);
  assert.deepEqual(updated.document.data, { choice: 'a', nota: 'ñandú' });
  assert.equal(updated.document.createdAt, set.document.createdAt);

  const got = await getDocument(storage, 'encuesta', 'votos', 'ana');
  assert.deepEqual(got.data, { choice: 'a', nota: 'ñandú' });
  const missing = await getDocument(storage, 'encuesta', 'votos', 'nadie');
  assert.equal(missing.status, 404);
  assert.equal(missing.missing, 'document');

  const docs = await listDocuments(storage, 'encuesta', 'votos');
  assert.equal(docs.length, 2);
  assert.deepEqual(await listCollections(storage, 'encuesta'), [{ name: 'votos', count: 2 }]);
  assert.deepEqual(await listDocuments(storage, 'encuesta', 'vacia'), []);

  assert.deepEqual(await deleteDocument(storage, 'encuesta', 'votos', 'ana'), { deleted: true });
  assert.deepEqual(await deleteDocument(storage, 'encuesta', 'votos', 'ana'), { deleted: false });
  assert.deepEqual(await deleteDocument(storage, 'encuesta', 'votos', added.document.id), { deleted: true });
  assert.deepEqual(await listCollections(storage, 'encuesta'), [], 'an emptied collection disappears');
});

test('names, payloads and limits are checked', async () => {
  const storage = fresh();
  await publishPage(storage, 'limites');

  assert.equal((await writeDocument(storage, 'limites', 'Mayúsculas', 'add', undefined, 1)).status, 400);
  assert.equal((await writeDocument(storage, 'limites', 'ok', 'set', '__proto__', 1)).status, 400);
  assert.equal((await writeDocument(storage, 'limites', 'ok', 'set', 'a/b', 1)).status, 400);
  assert.equal((await writeDocument(storage, 'limites', 'ok', 'set', 'x', undefined)).status, 400);
  assert.equal((await writeDocument(storage, 'limites', 'ok', 'update', 'x', [1, 2])).status, 400);

  const big = 'x'.repeat(DB_LIMITS.documentBytes);
  assert.equal((await writeDocument(storage, 'limites', 'ok', 'set', 'grande', big)).status, 413);

  // A document that holds no object cannot be merged into.
  await writeDocument(storage, 'limites', 'ok', 'set', 'numero', 7);
  assert.equal((await writeDocument(storage, 'limites', 'ok', 'update', 'numero', { a: 1 })).status, 409);

  // The whole store has a ceiling too.
  const chunk = 'y'.repeat(60 * 1024);
  let refused = null;
  for (let i = 0; i < 20 && !refused; i++) {
    const r = await writeDocument(storage, 'limites', 'trozos', 'set', `t${i}`, chunk);
    if (r.status) refused = r;
  }
  assert.equal(refused?.status, 413);
  assert.match(refused.error, /delete documents first/);

  // "constructor" and friends are ordinary names, not the object's machinery.
  const ctor = await writeDocument(storage, 'limites', 'constructor', 'set', 'constructor', { ok: true });
  assert.equal(ctor.created, true);
  assert.equal((await getDocument(storage, 'limites', 'otra', 'toString')).status, 404);
});

test('concurrent writes to one page all land', async () => {
  const storage = fresh();
  await publishPage(storage, 'carrera');
  await Promise.all(
    Array.from({ length: 6 }, (_, i) => writeDocument(storage, 'carrera', 'firmas', 'set', `p${i}`, { i }))
  );
  const docs = await listDocuments(storage, 'carrera', 'firmas');
  assert.equal(docs.length, 6);
});

test('a store that disappeared is created again on the next write', async () => {
  const storage = fresh();
  await publishPage(storage, 'sin-blob');
  storage.blobs.delete(`sin-blob/${PAGE_DB_ASSET_NAME}`);
  const r = await writeDocument(storage, 'sin-blob', 'c', 'set', 'a', 1);
  assert.equal(r.created, true);
});

/* ------------------------------------------------------------------------------------------ */
/* Lifecycle                                                                                   */
/* ------------------------------------------------------------------------------------------ */

test('turning the database off keeps the data, deleting the page removes it, a folder cannot have one', async () => {
  const storage = fresh();
  await publishPage(storage, 'ciclo');
  await writeDocument(storage, 'ciclo', 'c', 'set', 'a', { v: 1 });

  const replaced = await replaceShare(storage, 'ciclo', { title: 't', lang: 'es', kind: 'uploaded', html: '<p>v2</p>' });
  assert.equal(replaced.meta.database, true, 'a replace that does not mention it keeps the database');

  const off = await replaceShare(storage, 'ciclo', { title: 't', lang: 'es', kind: 'uploaded', html: '<p>v3</p>', database: false });
  assert.equal(off.meta.database, undefined);
  assert.equal((await getDocument(storage, 'ciclo', 'c', 'a')).data.v, 1, 'data kept while off');
  assert.equal((await db('PUT', 'ciclo/c/a', { token: OWNER, body: { data: 2 } })).status, 409, 'no writes while off');

  const on = await replaceShare(storage, 'ciclo', { title: 't', lang: 'es', kind: 'uploaded', html: '<p>v4</p>', database: true });
  assert.equal(on.meta.database, true);
  assert.equal((await getDocument(storage, 'ciclo', 'c', 'a')).data.v, 1, 'data back when on again');

  await deleteShare(storage, 'ciclo');
  assert.ok(!storage.blobs.has(`ciclo/${PAGE_DB_ASSET_NAME}`));

  const res = await handleCreateShare(
    new Request(`${BASE}/api/shares`, {
      method: 'POST',
      headers: { authorization: `Bearer ${OWNER}`, 'content-type': 'application/json' },
      body: JSON.stringify({ slug: 'carpeta', title: 't', lang: 'es', kind: 'generated', assets: [], database: true }),
    })
  );
  assert.equal(res.status, 400);

  const notBool = await createShare(storage, 'raro', { title: 't', lang: 'es', kind: 'uploaded', html: '<p>x</p>', database: 'yes' });
  assert.equal(notBool.status, 400);
});

test('the share listing says which pages have a database', async () => {
  const storage = fresh();
  await publishPage(storage, 'con-datos');
  await publishPage(storage, 'sin-datos', { database: false });
  const res = await handleListShares(new Request(`${BASE}/api/shares`, { headers: { authorization: `Bearer ${OWNER}` } }));
  const list = await res.json();
  const by = Object.fromEntries(list.map((s) => [s.slug, s.hasDatabase]));
  assert.deepEqual(by, { 'con-datos': true, 'sin-datos': false });
});

/* ------------------------------------------------------------------------------------------ */
/* Page tokens                                                                                 */
/* ------------------------------------------------------------------------------------------ */

test('a page token is bound to its page, its password and eight days', async () => {
  const storage = fresh();
  const meta = await publishPage(storage, 'token');
  const now = Date.now();
  const token = issuePageDbToken(meta, now);
  assert.equal(token, issuePageDbToken(meta, now + 1000), 'stable within the day');
  assert.ok(verifyPageDbToken(token, meta, now));
  assert.ok(verifyPageDbToken(token, meta, now + 7 * DAY_MS));
  assert.ok(!verifyPageDbToken(token, meta, now + 8 * DAY_MS), 'expires after eight days');
  assert.ok(!verifyPageDbToken(token, meta, now - DAY_MS), 'not before it was issued');
  assert.ok(!verifyPageDbToken(token, { ...meta, slug: 'otra' }, now), 'other page');
  assert.ok(!verifyPageDbToken(token, { ...meta, passwordHash: 'scrypt$x' }, now), 'password set since');
  assert.ok(!verifyPageDbToken(token, { ...meta, createdAt: new Date(now + 5).toISOString() }, now), 'page recreated');
  assert.ok(!verifyPageDbToken(token.replace(/.$/, (c) => (c === '0' ? '1' : '0')), meta, now), 'tampered');
  assert.ok(!verifyPageDbToken('pagedb.x.y', meta, now));
  assert.ok(!verifyPageDbToken(null, meta, now));
});

/* ------------------------------------------------------------------------------------------ */
/* The page and the HTTP API                                                                   */
/* ------------------------------------------------------------------------------------------ */

test('the page carries window.shareDb only when it has a database', async () => {
  const storage = fresh();
  await publishPage(storage, 'con');
  await publishPage(storage, 'sin', { database: false });

  const withDb = await viewPage('con');
  assert.equal(withDb.res.status, 200);
  assert.equal(withDb.res.headers.get('content-security-policy'), 'sandbox allow-scripts');
  assert.ok(injectedToken(withDb.html), 'token injected');
  assert.match(withDb.html, /var E = "https:\/\/share\.example\.invalid\/api\/db\/con"/);
  assert.ok(withDb.html.indexOf('shareDb') < withDb.html.indexOf('<title>'), 'client comes first in <head>');
  const again = await viewPage('con');
  assert.equal(again.res.headers.get('etag'), withDb.res.headers.get('etag'), 'same document all day');

  const without = await viewPage('sin');
  assert.doesNotMatch(without.html, /shareDb/);
});

test('a password-protected page hands out its token only after unlock', async () => {
  const storage = fresh();
  await publishPage(storage, 'privada', { password: 'clave-secreta-1' });
  const locked = await viewPage('privada');
  assert.equal(injectedToken(locked.html), null);

  const form = new URLSearchParams({ password: 'clave-secreta-1' });
  const unlock = await handleUnlockShare(
    new Request(`${BASE}/privada/unlock`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    }),
    { params: Promise.resolve({ slug: 'privada' }) }
  );
  const cookie = unlock.headers.get('set-cookie').split(';')[0];
  const open = await viewPage('privada', cookie);
  const token = injectedToken(open.html);
  assert.ok(token);
  assert.equal((await db('PUT', 'privada/c/a', { token, body: { data: 1 } })).status, 201);

  // Changing the password revokes every token handed out under the old one.
  await replaceShare(storage, 'privada', { title: 't', lang: 'es', kind: 'uploaded', html: '<p>v2</p>', password: 'otra-clave-22' });
  const after = await db('GET', 'privada/c', { token });
  assert.equal(after.status, 401);
  assert.match(after.body.error, /reload/);
});

test('HTTP API: auth, CORS, verbs and status codes', async () => {
  const storage = fresh();
  const meta = await publishPage(storage, 'mi-api');
  const token = issuePageDbToken(meta);

  const pre = await dbRoute.OPTIONS();
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get('access-control-allow-origin'), '*');
  assert.match(pre.headers.get('access-control-allow-headers'), /Authorization/);
  assert.match(pre.headers.get('access-control-allow-methods'), /PATCH/);

  assert.equal((await db('GET', 'mi-api')).status, 401);
  assert.equal((await db('GET', 'mi-api', { token: 'wrong' })).status, 401);
  assert.equal((await db('GET', 'mi-api', { token: 'pagedb.1.00' })).status, 401);

  const added = await db('POST', 'mi-api/firmas', { token, body: { data: { nombre: 'Íñigo' } } });
  assert.equal(added.status, 201);
  assert.equal(added.headers.get('access-control-allow-origin'), '*');
  assert.equal(added.headers.get('cache-control'), 'no-store');
  assert.equal(added.body.data.nombre, 'Íñigo');

  assert.equal((await db('PUT', 'mi-api/firmas/ana', { token, body: { data: { a: 1 } } })).status, 201);
  assert.equal((await db('PUT', 'mi-api/firmas/ana', { token, body: { data: { a: 2 } } })).status, 200);
  const patched = await db('PATCH', 'mi-api/firmas/ana', { token, body: { data: { b: 3 } } });
  assert.deepEqual(patched.body.data, { a: 2, b: 3 });

  const list = await db('GET', 'mi-api/firmas', { token });
  assert.equal(list.body.documents.length, 2);
  const cols = await db('GET', 'mi-api', { token: OWNER });
  assert.deepEqual(cols.body.collections, [{ name: 'firmas', count: 2 }]);
  const one = await db('GET', 'mi-api/firmas/ana', { token });
  assert.equal(one.body.id, 'ana');
  const none = await db('GET', 'mi-api/firmas/nadie', { token });
  assert.equal(none.status, 404);
  assert.equal(none.body.missing, 'document');

  assert.equal((await db('POST', 'mi-api/firmas/ana', { token, body: { data: 1 } })).status, 405);
  assert.equal((await db('PUT', 'mi-api/firmas/x', { token, body: { nodata: 1 } })).status, 400);
  assert.equal((await db('PUT', 'mi-api/firmas/x', { token, body: '{not json' })).status, 400);
  assert.equal((await db('PUT', 'mi-api/firmas/x', { token, body: { data: 'z'.repeat(DB_LIMITS.documentBytes + 2048) } })).status, 413);
  assert.equal((await db('GET', 'mi-api/a/b/c', { token })).status, 404);

  assert.deepEqual((await db('DELETE', 'mi-api/firmas/ana', { token })).body, { deleted: true });
  assert.equal((await db('DELETE', 'mi-api/firmas', { token })).status, 403, 'a page cannot wipe a collection');
  assert.deepEqual((await db('DELETE', 'mi-api/firmas', { token: OWNER })).body, { deleted: 1 });

  assert.equal((await db('GET', 'nada', { token: OWNER })).status, 404);
});

test('HTTP API: an expired page or one without a database refuses its page token; the owner still reads', async () => {
  const storage = fresh();
  const meta = await publishPage(storage, 'caduca', { expiresAt: new Date(Date.now() + 60_000).toISOString() });
  const token = issuePageDbToken(meta);
  await writeDocument(storage, 'caduca', 'c', 'set', 'a', 1);
  assert.equal((await db('GET', 'caduca/c', { token })).status, 200);

  const record = await storage.getMeta('caduca');
  await storage.saveMeta('caduca', { ...record, expiresAt: new Date(Date.now() - 1000).toISOString() });
  assert.equal((await db('GET', 'caduca/c', { token })).status, 404);
  assert.equal((await db('GET', 'caduca/c', { token: OWNER })).body.documents.length, 1);

  await storage.saveMeta('caduca', { ...record, database: undefined });
  assert.equal((await db('GET', 'caduca/c', { token })).status, 404);
  assert.equal((await db('GET', 'caduca/c', { token: OWNER })).status, 200);
});

test('HTTP API: writes with a page token are rate limited per address', async () => {
  const storage = fresh();
  const meta = await publishPage(storage, 'spam');
  const token = issuePageDbToken(meta);
  let last;
  for (let i = 0; i < 61; i++) {
    last = await db('PUT', `spam/c/k${i % 3}`, { token, body: { data: i }, headers: { 'x-forwarded-for': '203.0.113.9' } });
  }
  assert.equal(last.status, 429);
  assert.ok(Number(last.headers.get('retry-after')) > 0);
  const other = await db('PUT', 'spam/c/k0', { token, body: { data: 0 }, headers: { 'x-forwarded-for': '203.0.113.10' } });
  assert.equal(other.status, 200);
  assert.equal((await db('PUT', 'spam/c/k0', { token: OWNER, body: { data: 0 } })).status, 200, 'the owner is not limited');
});

test('the injected client works end to end against the API', async () => {
  const storage = fresh();
  await publishPage(storage, 'cliente');
  const { html } = await viewPage('cliente');
  const start = html.indexOf('<script>') + '<script>'.length;
  const script = html.slice(start, html.indexOf('</script>', start));

  const fetchThroughRoute = async (url, init = {}) => {
    const u = new URL(url);
    const [, , , slug, ...rest] = u.pathname.split('/');
    const method = init.method || 'GET';
    const request = new Request(url, { method, headers: init.headers, body: init.body ?? null });
    const params = Promise.resolve({ slug, path: rest.length ? rest.map(decodeURIComponent) : undefined });
    return dbRoute[method](request, { params });
  };
  const sandbox = { window: {}, fetch: fetchThroughRoute, Error, JSON, Object, String };
  vm.runInNewContext(script, sandbox);
  const shareDb = sandbox.window.shareDb;
  assert.ok(Object.isFrozen(shareDb));

  const added = await shareDb.add('votos', { choice: 'b' });
  assert.equal(added.data.choice, 'b');
  await shareDb.set('votos', 'ana', { choice: 'a' });
  const merged = await shareDb.update('votos', 'ana', { nota: 'x' });
  assert.deepEqual(merged.data, { choice: 'a', nota: 'x' });
  assert.equal((await shareDb.get('votos', 'ana')).data.nota, 'x');
  assert.equal(await shareDb.get('votos', 'nadie'), null);
  assert.equal((await shareDb.list('votos')).length, 2);
  assert.deepEqual(await shareDb.collections(), [{ name: 'votos', count: 2 }]);
  assert.equal(await shareDb.remove('votos', 'ana'), true);
  assert.equal(await shareDb.remove('votos', 'ana'), false);
  await assert.rejects(shareDb.set('Mal', 'x', 1), (err) => err.status === 400 && /collection name/.test(err.message));
});

test('a forged page token learns nothing about which slugs exist', async () => {
  const storage = fresh();
  await publishPage(storage, 'existe');
  await storage.saveMeta('carpeta', { slug: 'carpeta', title: 'c', lang: 'es', createdAt: new Date().toISOString(), kind: 'generated', assets: [] });
  const answers = await Promise.all(
    ['existe', 'carpeta', 'no-existe'].map((slug) => db('GET', `${slug}/c`, { token: 'pagedb.1.00' }))
  );
  for (const a of answers) {
    assert.equal(a.status, 401);
    assert.deepEqual(a.body, answers[0].body);
  }
  // A valid token for one page opens no other page.
  const token = issuePageDbToken(await storage.getMeta('existe'));
  await publishPage(storage, 'otra');
  const other = await db('GET', 'otra/c', { token });
  assert.equal(other.status, 401);
  assert.deepEqual(other.body, answers[0].body);
});

test('failures the rules did not foresee still answer JSON with CORS; contention is a 409', async () => {
  const storage = fresh();
  const meta = await publishPage(storage, 'rota');
  const token = issuePageDbToken(meta);

  const original = storage.getAsset.bind(storage);
  storage.getAsset = async () => {
    throw new Error('blob down');
  };
  const down = await db('GET', 'rota/c', { token });
  assert.equal(down.status, 503);
  assert.equal(down.headers.get('access-control-allow-origin'), '*');
  assert.match(down.body.error, /unavailable/);
  storage.getAsset = original;

  storage.putAsset = async (slug, name) => {
    throw new AssetConflictError(slug, name);
  };
  const busy = await writeDocument(storage, 'rota', 'c', 'set', 'a', 1);
  assert.equal(busy.status, 409);
  assert.match(busy.error, /busy/);
  const busyHttp = await db('PUT', 'rota/c/a', { token, body: { data: 1 } });
  assert.equal(busyHttp.status, 409);
  assert.equal(busyHttp.headers.get('access-control-allow-origin'), '*');
});

test('reads with a page token are rate limited before any storage is read', async () => {
  const storage = fresh();
  const meta = await publishPage(storage, 'sondeo');
  const token = issuePageDbToken(meta);
  const headers = { 'x-forwarded-for': '198.51.100.7' };
  for (let i = 0; i < 120; i++) assert.equal((await db('GET', 'sondeo/c', { token, headers })).status, 200);
  let reads = 0;
  const getAsset = storage.getAsset.bind(storage);
  const getMeta = storage.getMeta.bind(storage);
  storage.getAsset = (...a) => (reads++, getAsset(...a));
  storage.getMeta = (...a) => (reads++, getMeta(...a));
  const limited = await db('GET', 'sondeo/c', { token, headers });
  assert.equal(limited.status, 429);
  assert.equal(reads, 0);
  assert.equal((await db('GET', 'sondeo/c', { token: OWNER, headers })).status, 200, 'the owner is not limited');
});

test('request bodies are capped while read, and only the parsed document size counts', async () => {
  const storage = fresh();
  const meta = await publishPage(storage, 'cuerpos');
  const token = issuePageDbToken(meta);

  const declared = await db('PUT', 'cuerpos/c/a', { token, body: { data: 1 }, headers: { 'content-length': String(10 * 1024 * 1024) } });
  assert.equal(declared.status, 413);

  // A streamed body with no declared length is cut off at the ceiling, not buffered whole.
  let pulled = 0;
  const chunk = new TextEncoder().encode('x'.repeat(64 * 1024));
  const stream = new ReadableStream({
    pull(controller) {
      pulled++;
      if (pulled > 100) controller.close();
      else controller.enqueue(chunk);
    },
  });
  const request = new Request(`${BASE}/api/db/cuerpos/c/a`, {
    method: 'PUT',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: stream,
    duplex: 'half',
  });
  const res = await dbRoute.PUT(request, { params: Promise.resolve({ slug: 'cuerpos', path: ['c', 'a'] }) });
  assert.equal(res.status, 413);
  assert.ok(pulled < 10, `stopped reading early (pulled ${pulled} chunks)`);

  // Pretty-printed JSON around a document under its limit is accepted.
  const near = { texto: 'z'.repeat(DB_LIMITS.documentBytes - 1024) };
  const pretty = JSON.stringify({ data: near }, null, 8) + ' '.repeat(8 * 1024);
  assert.ok(Buffer.byteLength(pretty) > DB_LIMITS.documentBytes + 1024);
  assert.equal((await db('PUT', 'cuerpos/c/b', { token, body: pretty })).status, 201);
});

test('turning the database on creates the store once; replaces after that do not touch it, and a failure there does not fail the publish', async () => {
  const storage = fresh();
  await publishPage(storage, 'una-vez', { database: false });
  let heads = 0;
  const headAsset = storage.headAsset.bind(storage);
  storage.headAsset = (slug, name) => (name === PAGE_DB_ASSET_NAME && heads++, headAsset(slug, name));
  const body = { title: 't', lang: 'es', kind: 'uploaded', html: '<p>x</p>' };
  await replaceShare(storage, 'una-vez', { ...body, database: true });
  assert.equal(heads, 1);
  assert.ok(storage.blobs.has(`una-vez/${PAGE_DB_ASSET_NAME}`));
  await replaceShare(storage, 'una-vez', body);
  await replaceShare(storage, 'una-vez', { ...body, database: true });
  assert.equal(heads, 1, 'already on: no extra round trip');

  const putAsset = storage.putAsset.bind(storage);
  storage.putAsset = (slug, name, ...rest) => {
    if (name === PAGE_DB_ASSET_NAME) throw new Error('blob hiccup');
    return putAsset(slug, name, ...rest);
  };
  const created = await createShare(storage, 'tolerante', { ...body, database: true });
  assert.equal(created.created, true);
  assert.equal(created.meta.database, true);
});

test('a write whose body arrives slowly is judged against the page as it is when the body is in', async () => {
  const storage = fresh();
  const meta = await publishPage(storage, 'lenta');
  const token = issuePageDbToken(meta);

  const slowPut = (onFirstPull) => {
    let pulled = false;
    const body = new ReadableStream({
      async pull(controller) {
        if (!pulled) {
          pulled = true;
          await onFirstPull();
          controller.enqueue(new TextEncoder().encode('{"data": {"intruso": true}}'));
        } else controller.close();
      },
    });
    const request = new Request(`${BASE}/api/db/lenta/c/a`, {
      method: 'PUT',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body,
      duplex: 'half',
    });
    return dbRoute.PUT(request, { params: Promise.resolve({ slug: 'lenta', path: ['c', 'a'] }) });
  };

  // Deleted and published again while the body was on its way: the old token is refused.
  const recreated = await slowPut(async () => {
    await deleteShare(storage, 'lenta');
    await new Promise((r) => setTimeout(r, 5));
    await publishPage(storage, 'lenta');
  });
  assert.equal(recreated.status, 401);
  assert.deepEqual(await listCollections(storage, 'lenta'), [], 'nothing written into the new page');

  // Deleted outright: refused, and no orphan store is left behind.
  const fresh2 = issuePageDbToken(await storage.getMeta('lenta'));
  const goneBody = new ReadableStream({
    async pull(controller) {
      await deleteShare(storage, 'lenta');
      controller.enqueue(new TextEncoder().encode('{"data": 1}'));
      controller.close();
    },
  });
  const gone = await dbRoute.PUT(
    new Request(`${BASE}/api/db/lenta/c/a`, {
      method: 'PUT',
      headers: { authorization: `Bearer ${fresh2}`, 'content-type': 'application/json' },
      body: goneBody,
      duplex: 'half',
    }),
    { params: Promise.resolve({ slug: 'lenta', path: ['c', 'a'] }) }
  );
  assert.equal(gone.status, 401);
  assert.ok(!storage.blobs.has(`lenta/${PAGE_DB_ASSET_NAME}`));
});

test('forged tokens spread over many slugs hit a per-address limit and never read a store', async () => {
  const storage = fresh();
  let metaReads = 0;
  let storeReads = 0;
  const getMeta = storage.getMeta.bind(storage);
  const getAsset = storage.getAsset.bind(storage);
  storage.getMeta = (...a) => (metaReads++, getMeta(...a));
  storage.getAsset = (...a) => (storeReads++, getAsset(...a));
  const headers = { 'x-forwarded-for': '192.0.2.44' };
  let last;
  for (let i = 0; i < 301; i++) last = await db('GET', `slug-${i}/c`, { token: 'pagedb.1.00', headers });
  assert.equal(last.status, 429);
  assert.equal(metaReads, 300, 'one record read per allowed request, none once limited');
  assert.equal(storeReads, 0, 'a forged token never reaches the store');
});

/* ------------------------------------------------------------------------------------------ */
/* MCP                                                                                         */
/* ------------------------------------------------------------------------------------------ */

async function connect(token) {
  const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`), {
    fetch: (url, init) => serveMcp(new Request(url, init)),
    authProvider: { token: async () => token },
  });
  const client = new Client({ name: 'test-harness', version: '1.0.0' }, { versionNegotiation: { mode: 'auto' } });
  await client.connect(transport);
  return client;
}

test('MCP: publish_page with a database, then read_page_data and write_page_data', async (t) => {
  t.after(() => closeMcpHandlerForTesting());
  fresh();
  const client = await connect(await signAccessToken({ client_id: 'dcr.test', sub: 'owner', scope: ALL_SCOPES }));

  const pub = await client.callTool({
    name: 'publish_page',
    arguments: { prefix: 'mcp-encuesta', title: 'Encuesta', html: '<p>vota</p>', database: true },
  });
  assert.equal(pub.isError, undefined, JSON.stringify(pub));
  assert.equal(pub.structuredContent.database, true);
  assert.match(pub.content[0].text, /with a database/);

  const empty = await client.callTool({ name: 'read_page_data', arguments: { prefix: 'mcp-encuesta' } });
  assert.deepEqual(empty.structuredContent.collections, []);

  const add = await client.callTool({
    name: 'write_page_data',
    arguments: { prefix: 'mcp-encuesta', collection: 'votos', action: 'add', data_json: '{"choice":"b"}' },
  });
  assert.equal(add.isError, undefined, JSON.stringify(add));
  const newId = add.structuredContent.id;

  const set = await client.callTool({
    name: 'write_page_data',
    arguments: { prefix: 'mcp-encuesta', collection: 'votos', action: 'set', id: 'ana', data_json: '{"choice":"a"}' },
  });
  assert.equal(set.structuredContent.created, true);

  const bad = await client.callTool({
    name: 'write_page_data',
    arguments: { prefix: 'mcp-encuesta', collection: 'votos', action: 'set', id: 'ana', data_json: '{oops' },
  });
  assert.equal(bad.isError, true);
  assert.match(bad.content[0].text, /not valid JSON/);
  const noId = await client.callTool({
    name: 'write_page_data',
    arguments: { prefix: 'mcp-encuesta', collection: 'votos', action: 'update', data_json: '{}' },
  });
  assert.equal(noId.isError, true);

  const list = await client.callTool({ name: 'read_page_data', arguments: { prefix: 'mcp-encuesta', collection: 'votos' } });
  assert.equal(list.structuredContent.documents.length, 2);
  const one = await client.callTool({ name: 'read_page_data', arguments: { prefix: 'mcp-encuesta', collection: 'votos', id: 'ana' } });
  assert.equal(one.structuredContent.found, true);
  assert.deepEqual(one.structuredContent.document.data, { choice: 'a' });
  const gone = await client.callTool({ name: 'read_page_data', arguments: { prefix: 'mcp-encuesta', collection: 'votos', id: 'zz' } });
  assert.equal(gone.structuredContent.found, false);

  // Deleting a document needs files:delete, which the static token does not carry by default.
  const limited = await connect(process.env.MCP_STATIC_TOKEN);
  const denied = await limited.callTool({
    name: 'write_page_data',
    arguments: { prefix: 'mcp-encuesta', collection: 'votos', action: 'delete', id: newId },
  });
  assert.equal(denied.isError, true);
  assert.match(denied.content[0].text, /files:delete/);
  await limited.close();

  const del = await client.callTool({
    name: 'write_page_data',
    arguments: { prefix: 'mcp-encuesta', collection: 'votos', action: 'delete', id: newId },
  });
  assert.equal(del.isError, undefined, JSON.stringify(del));
  assert.equal(del.structuredContent.deleted, true);

  const info = await client.callTool({ name: 'get_file_info', arguments: { path: 'mcp-encuesta' } });
  assert.equal(info.structuredContent.database, true);

  const off = await client.callTool({ name: 'update_page', arguments: { prefix: 'mcp-encuesta', html: '<p>cerrada</p>', database: false } });
  assert.equal(off.structuredContent.database, false);
  const refused = await client.callTool({
    name: 'write_page_data',
    arguments: { prefix: 'mcp-encuesta', collection: 'votos', action: 'set', id: 'x', data_json: '1' },
  });
  assert.equal(refused.isError, true);
  assert.match(refused.content[0].text, /"database": true/);
  const kept = await client.callTool({ name: 'read_page_data', arguments: { prefix: 'mcp-encuesta', collection: 'votos' } });
  assert.equal(kept.structuredContent.documents.length, 1);
  assert.match(kept.content[0].text, /turned off/);

  await client.callTool({ name: 'upload_file', arguments: { filename: 'notas.txt', content: 'x', encoding: 'text', prefix: 'carpeta' } });
  const folder = await client.callTool({ name: 'read_page_data', arguments: { prefix: 'carpeta' } });
  assert.equal(folder.isError, true);
  assert.match(folder.content[0].text, /not a page/);

  await client.close();
});

test('MCP: read_page_data pages a large collection by size', async (t) => {
  t.after(() => closeMcpHandlerForTesting());
  const storage = fresh();
  await publishPage(storage, 'grande');
  const filler = 'q'.repeat(40 * 1024);
  for (let i = 0; i < 24; i++) await writeDocument(storage, 'grande', 'docs', 'set', `d${String(i).padStart(2, '0')}`, { filler });
  const client = await connect(process.env.MCP_STATIC_TOKEN);
  const seen = [];
  let cursor;
  let calls = 0;
  do {
    const r = await client.callTool({ name: 'read_page_data', arguments: { prefix: 'grande', collection: 'docs', ...(cursor ? { cursor } : {}) } });
    assert.equal(r.isError, undefined, JSON.stringify(r).slice(0, 300));
    assert.equal(r.structuredContent.total_count, 24);
    assert.ok(Buffer.byteLength(r.content[0].text) < 600 * 1024);
    seen.push(...r.structuredContent.documents.map((d) => d.id));
    cursor = r.structuredContent.next_cursor;
    calls++;
  } while (cursor);
  assert.ok(calls > 1, 'more than one page');
  assert.equal(new Set(seen).size, 24);
  const bad = await client.callTool({ name: 'read_page_data', arguments: { prefix: 'grande', collection: 'docs', cursor: 'nope' } });
  assert.equal(bad.isError, true);
  await client.close();
});

test('MCP: read_page_data cursor survives deletions between pages, and ids sort by code unit', async (t) => {
  t.after(() => closeMcpHandlerForTesting());
  const storage = fresh();
  await publishPage(storage, 'orden');
  const filler = 'q'.repeat(60 * 1024);
  // Ids with mixed case and "-"/"_", where locale order and code-unit order disagree.
  const ids = ['b', 'B', 'a-1', 'a_1', 'Z', 'z', 'A', 'm', 'M', 'n-2', 'n_2', 'Y'];
  for (const id of ids) {
    const r = await writeDocument(storage, 'orden', 'docs', 'set', id, { filler });
    assert.equal(r.created, true, JSON.stringify(r).slice(0, 200));
  }
  const client = await connect(await signAccessToken({ client_id: 'dcr.test', sub: 'owner', scope: ALL_SCOPES }));
  const page = (cursor) =>
    client.callTool({ name: 'read_page_data', arguments: { prefix: 'orden', collection: 'docs', ...(cursor ? { cursor } : {}) } });

  const first = await page();
  const firstIds = first.structuredContent.documents.map((d) => d.id);
  assert.ok(first.structuredContent.next_cursor);
  // Someone deletes a document already seen: the next page must not skip an unseen one.
  await deleteDocument(storage, 'orden', 'docs', firstIds[0]);
  const seen = [...firstIds];
  let cursor = first.structuredContent.next_cursor;
  while (cursor) {
    const r = await page(cursor);
    seen.push(...r.structuredContent.documents.map((d) => d.id));
    cursor = r.structuredContent.next_cursor;
  }
  assert.deepEqual([...seen].sort(), [...ids].sort(), 'every document seen exactly once');
  assert.equal(new Set(seen).size, seen.length);

  // A deeply nested document comes back compact, not indented by its depth.
  let deep = 1;
  for (let i = 0; i < 2000; i++) deep = { n: deep };
  const wrote = await client.callTool({
    name: 'write_page_data',
    arguments: { prefix: 'orden', collection: 'hondo', action: 'set', id: 'x', data_json: JSON.stringify(deep) },
  });
  assert.equal(wrote.isError, undefined);
  assert.ok(Buffer.byteLength(wrote.content[0].text) < 40 * 1024, `write result is ${Buffer.byteLength(wrote.content[0].text)} bytes`);
  const read = await client.callTool({ name: 'read_page_data', arguments: { prefix: 'orden', collection: 'hondo', id: 'x' } });
  assert.ok(Buffer.byteLength(read.content[0].text) < 40 * 1024);
  await client.close();
});
