import test from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT } from 'jose';
import { createHash } from 'node:crypto';

process.env.SHARE_API_TOKEN = 'secret-test-token-xyz789';
process.env.SHARE_COOKIE_SECRET = 'cookie-secret-test-abc123';
process.env.SHARE_BASE_URL = 'https://share.example.invalid';
process.env.MCP_OAUTH_SECRET = 'test-oauth-signing-secret-with-enough-length-0123456789';
process.env.MCP_STATIC_TOKEN = 'static-terminal-token-0123456789abcdefghij';
delete process.env.MCP_STATIC_TOKEN_SCOPES;
delete process.env.MCP_ALLOWED_ORIGINS;

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { MemoryStorage, setStorageForTesting } from '../lib/storage.ts';
import { closeMcpHandlerForTesting, serveMcp } from '../lib/mcp/server.ts';
import { GET as handleViewShare } from '../app/[slug]/route.ts';
import { toolCallLimiter } from '../lib/mcp/ratelimit.ts';
import { signAccessToken } from '../lib/oauth/tokens.ts';
import { ALL_SCOPES } from '../lib/mcp/config.ts';

const MCP_URL = 'https://share.example.invalid/mcp';
const STATIC_TOKEN = process.env.MCP_STATIC_TOKEN;

const inProcessFetch = (url, init) => serveMcp(new Request(url, init));

async function connect(token) {
  const transport = new StreamableHTTPClientTransport(new URL(MCP_URL), {
    fetch: inProcessFetch,
    authProvider: token ? { token: async () => token } : undefined,
  });
  const client = new Client({ name: 'test-harness', version: '1.0.0' }, { versionNegotiation: { mode: 'auto' } });
  await client.connect(transport);
  return client;
}

async function ownerToken(scope = ALL_SCOPES) {
  return signAccessToken({ client_id: 'dcr.test', sub: 'owner', scope });
}

function fresh() {
  const storage = new MemoryStorage();
  setStorageForTesting(storage);
  toolCallLimiter.reset();
  return storage;
}

async function seedFolder(storage, slug, files, extra = {}) {
  const assets = [];
  for (const [name, content, contentType] of files) {
    const written = await storage.putAsset(slug, name, Buffer.from(content), contentType);
    assets.push({ name, originalName: name, contentType, sizeBytes: Buffer.byteLength(content), etag: written.etag });
  }
  await storage.saveMeta(slug, {
    slug,
    title: `Folder ${slug}`,
    lang: 'es',
    createdAt: new Date(Date.now() - files.length * 1000).toISOString(),
    kind: 'generated',
    assets,
    ...extra,
  });
}

test.afterEach(async () => {
  await closeMcpHandlerForTesting();
});

/* ------------------------------------------------------------------------------------------ */

const FORBIDDEN_KEYWORDS = ['$schema', 'anyOf', 'oneOf', 'allOf', 'not', '$ref', '$defs', 'additionalProperties', 'default', 'if', 'then', 'else', 'patternProperties'];
const ALLOWED_TYPES = ['string', 'integer', 'number', 'boolean', 'array', 'object'];

function walk(node, visit, path = '') {
  if (Array.isArray(node)) {
    node.forEach((n, i) => walk(n, visit, `${path}[${i}]`));
    return;
  }
  if (node && typeof node === 'object') {
    visit(node, path);
    for (const [k, v] of Object.entries(node)) {
      if (k === 'enum' || k === 'required' || k === 'description') continue;
      walk(v, visit, `${path}.${k}`);
    }
  }
}

test('tools/list advertises the nine tools with least-common-denominator schemas and annotations', async () => {
  fresh();
  const client = await connect(STATIC_TOKEN);
  const { tools } = await client.listTools();
  await client.close();

  assert.deepEqual(
    tools.map((t) => t.name).sort(),
    [
      'complete_upload',
      'create_upload_url',
      'delete_file',
      'get_file_info',
      'list_files',
      'publish_page',
      'update_file',
      'update_page',
      'upload_file',
    ]
  );

  for (const tool of tools) {
    assert.match(tool.name, /^[a-z][a-z0-9_]*$/, `${tool.name} is snake_case`);
    assert.ok(tool.title, `${tool.name} has a title`);
    assert.ok(tool.description.length > 40, `${tool.name} has a description`);
    assert.ok(tool.outputSchema, `${tool.name} has an outputSchema`);
    assert.equal(typeof tool.annotations?.readOnlyHint, 'boolean', `${tool.name} readOnlyHint`);
    assert.equal(typeof tool.annotations?.destructiveHint, 'boolean', `${tool.name} destructiveHint`);
    assert.equal(typeof tool.annotations?.idempotentHint, 'boolean', `${tool.name} idempotentHint`);

    const schema = tool.inputSchema;
    assert.equal(schema.type, 'object');
    assert.ok(Array.isArray(schema.required), `${tool.name} has explicit required`);
    for (const [prop, def] of Object.entries(schema.properties)) {
      assert.ok(def.description, `${tool.name}.${prop} has a description`);
      assert.ok(ALLOWED_TYPES.includes(def.type), `${tool.name}.${prop} has a basic type, got ${def.type}`);
      if (def.enum) assert.ok(def.enum.every((v) => typeof v === 'string'), `${tool.name}.${prop} enum is strings`);
    }
    walk(schema, (node, path) => {
      for (const key of FORBIDDEN_KEYWORDS) {
        assert.ok(!(key in node), `${tool.name} inputSchema${path} must not use "${key}"`);
      }
    });
    walk(tool.outputSchema, (node, path) => {
      for (const key of ['$schema', 'anyOf', 'oneOf', '$ref']) {
        assert.ok(!(key in node), `${tool.name} outputSchema${path} must not use "${key}"`);
      }
    });
    assert.doesNotMatch(tool.description, /claude|gpt|gemini|openai|anthropic/i, `${tool.name} description names no model`);
  }

  const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
  assert.equal(byName.delete_file.annotations.destructiveHint, true);
  assert.equal(byName.list_files.annotations.readOnlyHint, true);
  assert.equal(byName.get_file_info.annotations.readOnlyHint, true);
  assert.equal(byName.complete_upload.annotations.idempotentHint, true);
  assert.equal(byName.update_file.annotations.destructiveHint, true);
  assert.equal(byName.update_file.annotations.idempotentHint, true);
  assert.equal(byName.upload_file.annotations.destructiveHint, false);
  assert.equal(byName.publish_page.annotations.destructiveHint, false);
  assert.equal(byName.update_page.annotations.destructiveHint, true);
  assert.equal(byName.update_page.annotations.idempotentHint, true);
  assert.deepEqual(byName.publish_page.inputSchema.required, ['prefix', 'html', 'title']);
  assert.deepEqual(byName.update_page.inputSchema.required, ['prefix', 'html']);
  assert.deepEqual(byName.upload_file.inputSchema.required, ['filename', 'content', 'encoding']);
  assert.deepEqual(byName.upload_file.inputSchema.properties.encoding.enum, ['text', 'base64']);
});

test('a request without a token gets 401 with a resource_metadata challenge and CORS headers', async () => {
  fresh();
  const res = await serveMcp(
    new Request(MCP_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', origin: 'https://inspector.example' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
    })
  );
  assert.equal(res.status, 401);
  const challenge = res.headers.get('www-authenticate');
  assert.match(challenge, /^Bearer /);
  assert.ok(
    challenge.includes('resource_metadata="https://share.example.invalid/.well-known/oauth-protected-resource/mcp"'),
    challenge
  );
  assert.equal(res.headers.get('access-control-allow-origin'), 'https://inspector.example');
  assert.ok(res.headers.get('access-control-expose-headers').includes('WWW-Authenticate'));
});

test('a token minted for another audience or signed with another key is rejected', async () => {
  fresh();
  const secret = new TextEncoder().encode(process.env.MCP_OAUTH_SECRET);
  const foreignAudience = await new SignJWT({ kind: 'access', client_id: 'x', sub: 'owner', scope: 'files:read' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer('https://share.example.invalid')
    .setAudience('https://other.example/mcp')
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(secret);
  const otherKey = await new SignJWT({ kind: 'access', client_id: 'x', sub: 'owner', scope: 'files:read' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer('https://share.example.invalid')
    .setAudience(MCP_URL)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(new TextEncoder().encode('another-secret-another-secret-another-secret'));
  const refreshAsAccess = await new SignJWT({ kind: 'refresh', client_id: 'x', sub: 'owner', scope: 'files:read' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer('https://share.example.invalid')
    .setAudience(MCP_URL)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(secret);

  for (const token of [foreignAudience, otherKey, refreshAsAccess, 'not-a-token']) {
    const res = await serveMcp(
      new Request(MCP_URL, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      })
    );
    assert.equal(res.status, 401);
    assert.match(res.headers.get('www-authenticate'), /invalid_token/);
  }
});

test('GET and DELETE answer 405, OPTIONS answers a CORS preflight', async () => {
  fresh();
  const get = await serveMcp(new Request(MCP_URL, { method: 'GET' }));
  assert.equal(get.status, 405);
  const del = await serveMcp(new Request(MCP_URL, { method: 'DELETE' }));
  assert.equal(del.status, 405);
  const options = await serveMcp(new Request(MCP_URL, { method: 'OPTIONS', headers: { origin: 'https://app.example' } }));
  assert.equal(options.status, 204);
  assert.equal(options.headers.get('access-control-allow-origin'), 'https://app.example');
  assert.ok(options.headers.get('access-control-allow-headers').includes('Authorization'));
  assert.ok(options.headers.get('access-control-allow-headers').includes('Mcp-Protocol-Version'));
});

test('a 2025-era client can still initialize and list tools on the same endpoint', async () => {
  fresh();
  const post = (body, headers = {}) =>
    serveMcp(
      new Request(MCP_URL, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          authorization: `Bearer ${STATIC_TOKEN}`,
          ...headers,
        },
        body: JSON.stringify(body),
      })
    );
  const init = await post({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'legacy', version: '1' } },
  });
  assert.equal(init.status, 200);
  const initText = await init.text();
  assert.ok(initText.includes('"protocolVersion":"2025-06-18"'), initText);

  const list = await post({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }, { 'mcp-protocol-version': '2025-06-18' });
  assert.equal(list.status, 200);
  const listText = await list.text();
  assert.ok(listText.includes('"name":"upload_file"'), listText);
});

/* ------------------------------------------------------------------------------------------ */

test('upload_file publishes text, derives the content type and creates a folder', async () => {
  const storage = fresh();
  const client = await connect(STATIC_TOKEN);
  const result = await client.callTool({
    name: 'upload_file',
    arguments: { filename: 'Notas de viaje.md', content: '# Lisboa\n\nHabitación con vistas.', encoding: 'text' },
  });
  await client.close();

  assert.equal(result.isError, undefined);
  const out = result.structuredContent;
  assert.match(out.prefix, /^notas-de-viaje-[a-z0-9]{6}$/);
  assert.equal(out.filename, 'Notas de viaje.md');
  assert.equal(out.path, `${out.prefix}/Notas de viaje.md`);
  assert.equal(out.content_type, 'text/markdown; charset=utf-8');
  assert.equal(out.folder_created, true);
  assert.equal(out.url, `https://share.example.invalid/${out.prefix}/Notas%20de%20viaje.md`);
  assert.equal(out.page_url, `https://share.example.invalid/${out.prefix}`);
  assert.ok(result.content[0].text.includes(out.url));

  const meta = await storage.getMeta(out.prefix);
  assert.equal(meta.assets[0].sha256, createHash('sha256').update('# Lisboa\n\nHabitación con vistas.').digest('hex'));
  assert.equal(meta.title, 'Notas de viaje.md');
  assert.equal(meta.lang, 'es');
  assert.equal(meta.kind, 'generated');
  assert.equal(meta.assets[0].sizeBytes, Buffer.byteLength('# Lisboa\n\nHabitación con vistas.'));
  const stored = await storage.getAsset(out.prefix, 'Notas de viaje.md');
  assert.equal(await new Response(stored.stream).text(), '# Lisboa\n\nHabitación con vistas.');
});

test('upload_file decodes base64, honours prefix and title, and adds to an existing folder', async () => {
  const storage = fresh();
  const bytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 1, 2, 3]);
  const client = await connect(STATIC_TOKEN);

  const first = await client.callTool({
    name: 'upload_file',
    arguments: { filename: 'logo.png', content: bytes.toString('base64'), encoding: 'base64', prefix: 'brand-kit', title: 'Brand kit' },
  });
  assert.equal(first.isError, undefined, JSON.stringify(first));
  assert.equal(first.structuredContent.prefix, 'brand-kit');
  assert.equal(first.structuredContent.content_type, 'image/png');
  assert.equal(first.structuredContent.size_bytes, 8);
  const stored = await storage.getAsset('brand-kit', 'logo.png');
  assert.deepEqual(Buffer.from(await new Response(stored.stream).arrayBuffer()), bytes);
  assert.equal((await storage.getMeta('brand-kit')).title, 'Brand kit');

  const second = await client.callTool({
    name: 'upload_file',
    arguments: { filename: 'palette.json', content: '{"blue":"#2563eb"}', encoding: 'text', prefix: 'brand-kit', content_type: 'application/json' },
  });
  assert.equal(second.isError, undefined, JSON.stringify(second));
  assert.equal(second.structuredContent.folder_created, false);
  assert.equal(second.structuredContent.content_type, 'application/json');
  assert.equal((await storage.getMeta('brand-kit')).assets.length, 2);
  assert.equal((await storage.getMeta('brand-kit')).title, 'Brand kit');

  const duplicate = await client.callTool({
    name: 'upload_file',
    arguments: { filename: 'logo.png', content: 'AAAA', encoding: 'base64', prefix: 'brand-kit' },
  });
  assert.equal(duplicate.isError, true);
  assert.match(duplicate.content[0].text, /already exists/);
  assert.match(duplicate.content[0].text, /update_file/);
  await client.close();
});

test('upload_file refuses bad input with actionable messages', async () => {
  const storage = fresh();
  await storage.putAsset('landing', '__page.html', '<h1>hi</h1>', 'text/html');
  await storage.saveMeta('landing', { slug: 'landing', title: 'Landing', lang: 'en', createdAt: new Date().toISOString(), kind: 'uploaded', assets: [] });
  const client = await connect(STATIC_TOKEN);

  const cases = [
    [{ filename: 'a.txt', content: 'x'.repeat(3 * 1024 * 1024 + 1), encoding: 'text' }, /create_upload_url/],
    [{ filename: 'a.txt', content: '', encoding: 'text' }, /empty/],
    [{ filename: 'a.bin', content: '!!!not base64!!!', encoding: 'base64' }, /base64/],
    [{ filename: '../escape.txt', content: 'x', encoding: 'text' }, /not a valid file name/],
    [{ filename: '__meta.json', content: 'x', encoding: 'text' }, /not a valid file name/],
    [{ filename: 'a.txt', content: 'x', encoding: 'text', prefix: 'mcp' }, /reserved/],
    [{ filename: 'a.txt', content: 'x', encoding: 'text', prefix: 'Bad Prefix' }, /not a valid prefix/],
    [{ filename: 'a.txt', content: 'x', encoding: 'text', prefix: 'landing' }, /published page/],
  ];
  for (const [args, pattern] of cases) {
    const result = await client.callTool({ name: 'upload_file', arguments: args });
    assert.equal(result.isError, true, JSON.stringify(args).slice(0, 80));
    assert.match(result.content[0].text, pattern);
  }
  assert.equal(await storage.getMeta('mcp'), null);
  await client.close();
});

test('create_upload_url issues a signed PUT and complete_upload publishes the file once', async () => {
  const storage = fresh();
  const client = await connect(STATIC_TOKEN);

  const issued = await client.callTool({
    name: 'create_upload_url',
    arguments: { filename: 'informe.pdf', content_type: 'application/pdf', size_bytes: 1234, prefix: 'informes-2026' },
  });
  assert.equal(issued.isError, undefined, JSON.stringify(issued));
  const out = issued.structuredContent;
  assert.equal(out.method, 'PUT');
  assert.equal(out.content_type_header, 'application/pdf');
  assert.equal(out.path, 'informes-2026/informe.pdf');
  assert.equal(out.url, 'https://share.example.invalid/informes-2026/informe.pdf');
  assert.match(out.upload_url, /^https:\/\/.+informes-2026\/informe\.pdf/);
  assert.ok(new Date(out.expires_at).getTime() > Date.now());
  assert.ok(out.curl_example.includes('-X PUT'));
  assert.ok(issued.content[0].text.includes('complete_upload'));
  assert.equal(await storage.getMeta('informes-2026'), null, 'nothing is published before the PUT');

  const early = await client.callTool({ name: 'complete_upload', arguments: { path: 'informes-2026/informe.pdf' } });
  assert.equal(early.isError, true);
  assert.match(early.content[0].text, /not succeeded yet|expired/);

  await storage.putAsset('informes-2026', 'informe.pdf', Buffer.alloc(1234, 1), 'application/pdf');

  const done = await client.callTool({ name: 'complete_upload', arguments: { path: 'informes-2026/informe.pdf', title: 'Informes 2026' } });
  assert.equal(done.isError, undefined, JSON.stringify(done));
  assert.equal(done.structuredContent.already_published, false);
  assert.equal(done.structuredContent.size_bytes, 1234);
  assert.equal(done.structuredContent.url, out.url);
  assert.equal((await storage.getMeta('informes-2026')).title, 'Informes 2026');

  const again = await client.callTool({ name: 'complete_upload', arguments: { path: 'informes-2026/informe.pdf' } });
  assert.equal(again.isError, undefined);
  assert.equal(again.structuredContent.already_published, true);

  const tooBig = await client.callTool({
    name: 'create_upload_url',
    arguments: { filename: 'video.mp4', content_type: 'video/mp4', size_bytes: 21 * 1024 * 1024 },
  });
  assert.equal(tooBig.isError, true);
  assert.match(tooBig.content[0].text, /20 MB/);

  const taken = await client.callTool({
    name: 'create_upload_url',
    arguments: { filename: 'informe.pdf', content_type: 'application/pdf', size_bytes: 10, prefix: 'informes-2026' },
  });
  assert.equal(taken.isError, true);
  assert.match(taken.content[0].text, /already has a file/);
  await client.close();
});

test('update_file replaces content behind the same URL and refuses what does not exist', async () => {
  const storage = fresh();
  await seedFolder(storage, 'notes', [['readme.md', '# v1', 'text/markdown; charset=utf-8'], ['a.txt', 'a', 'text/plain']]);
  const client = await connect(STATIC_TOKEN);

  const before = await storage.headAsset('notes', 'readme.md');
  const updated = await client.callTool({
    name: 'update_file',
    arguments: { path: 'notes/readme.md', content: '# v2\n\nUna línea más', encoding: 'text' },
  });
  assert.equal(updated.isError, undefined, JSON.stringify(updated));
  const out = updated.structuredContent;
  assert.equal(out.path, 'notes/readme.md');
  assert.equal(out.url, 'https://share.example.invalid/notes/readme.md');
  assert.equal(out.previous_size_bytes, 4);
  assert.equal(out.size_bytes, Buffer.byteLength('# v2\n\nUna línea más'));
  assert.equal(out.content_type, 'text/markdown; charset=utf-8');
  assert.ok(out.updated_at);
  assert.match(updated.content[0].text, /URL is unchanged/);

  const stored = await storage.getAsset('notes', 'readme.md');
  assert.equal(await new Response(stored.stream).text(), '# v2\n\nUna línea más');
  const meta = await storage.getMeta('notes');
  const asset = meta.assets.find((a) => a.name === 'readme.md');
  assert.equal(asset.sizeBytes, out.size_bytes);
  assert.notEqual(asset.etag, before.etag);
  assert.equal(asset.updatedAt, out.updated_at);
  assert.equal(meta.assets.length, 2, 'the other file is untouched');

  const retyped = await client.callTool({
    name: 'update_file',
    arguments: { path: 'notes/a.txt', content: 'eyJvayI6dHJ1ZX0=', encoding: 'base64', content_type: 'application/json' },
  });
  assert.equal(retyped.isError, undefined, JSON.stringify(retyped));
  assert.equal(retyped.structuredContent.content_type, 'application/json');
  assert.equal((await storage.getMeta('notes')).assets.find((a) => a.name === 'a.txt').contentType, 'application/json');

  const missing = await client.callTool({ name: 'update_file', arguments: { path: 'notes/nope.md', content: 'x', encoding: 'text' } });
  assert.equal(missing.isError, true);
  assert.match(missing.content[0].text, /upload_file/);

  const noFolder = await client.callTool({ name: 'update_file', arguments: { path: 'nothing/x.md', content: 'x', encoding: 'text' } });
  assert.equal(noFolder.isError, true);

  const folderOnly = await client.callTool({ name: 'update_file', arguments: { path: 'notes', content: 'x', encoding: 'text' } });
  assert.equal(folderOnly.isError, true);

  const tooBig = await client.callTool({
    name: 'update_file',
    arguments: { path: 'notes/readme.md', content: 'x'.repeat(3 * 1024 * 1024 + 1), encoding: 'text' },
  });
  assert.equal(tooBig.isError, true);
  assert.match(tooBig.content[0].text, /create_upload_url/);
  assert.equal((await storage.getMeta('notes')).assets.find((a) => a.name === 'readme.md').sizeBytes, out.size_bytes, 'nothing changed');
  await client.close();
});

test('publish_page puts a document at its own URL and never overwrites one', async () => {
  const storage = fresh();
  const client = await connect(STATIC_TOKEN);

  const html = '<!DOCTYPE html><html><body><h1>Plan de cenas</h1></body></html>';
  const published = await client.callTool({
    name: 'publish_page',
    arguments: { prefix: 'plan-de-cenas', html, title: 'Plan de cenas', description: 'Dos semanas', lang: 'es' },
  });
  assert.equal(published.isError, undefined, JSON.stringify(published));
  const out = published.structuredContent;
  assert.equal(out.prefix, 'plan-de-cenas');
  assert.equal(out.url, 'https://share.example.invalid/plan-de-cenas');
  assert.equal(out.page_url, out.url);
  assert.equal(out.title, 'Plan de cenas');
  assert.equal(out.size_bytes, Buffer.byteLength(html));
  assert.ok(out.created_at);

  const meta = await storage.getMeta('plan-de-cenas');
  assert.equal(meta.kind, 'uploaded');
  assert.equal(meta.description, 'Dos semanas');
  assert.equal(meta.lang, 'es');
  assert.equal(meta.assets.length, 0, 'a page is not made of assets');
  const stored = await storage.getAsset('plan-de-cenas', '__page.html');
  assert.equal(await new Response(stored.stream).text(), html);

  const again = await client.callTool({
    name: 'publish_page',
    arguments: { prefix: 'plan-de-cenas', html: '<p>otro</p>', title: 'Otro' },
  });
  assert.equal(again.isError, true);
  assert.match(again.content[0].text, /update_page/);
  assert.equal(await new Response((await storage.getAsset('plan-de-cenas', '__page.html')).stream).text(), html);

  await seedFolder(storage, 'docs', [['a.txt', 'a', 'text/plain']]);
  const cases = [
    [{ prefix: 'docs', html: '<p>x</p>', title: 'T' }, /folder of files/],
    [{ prefix: 'mcp', html: '<p>x</p>', title: 'T' }, /reserved/],
    [{ prefix: 'Bad Prefix', html: '<p>x</p>', title: 'T' }, /not a valid page name/],
    [{ prefix: 'empty-one', html: '   ', title: 'T' }, /empty/],
    [{ prefix: 'huge-one', html: 'x'.repeat(3 * 1024 * 1024 + 1), title: 'T' }, /upload_file/],
  ];
  for (const [args, pattern] of cases) {
    const result = await client.callTool({ name: 'publish_page', arguments: args });
    assert.equal(result.isError, true, JSON.stringify(args));
    assert.match(result.content[0].text, pattern);
  }
  assert.equal(await storage.getMeta('huge-one'), null);
  await client.close();
});

test('update_page replaces a page behind the same URL and keeps what it was not told', async () => {
  const storage = fresh();
  await storage.putAsset('landing', '__page.html', '<p>v1</p>', 'text/html; charset=utf-8');
  await storage.saveMeta('landing', {
    slug: 'landing',
    title: 'Landing',
    description: 'La original',
    lang: 'es',
    createdAt: '2026-01-01T00:00:00.000Z',
    kind: 'uploaded',
    assets: [],
    expiresAt: null,
    passwordHash: null,
  });
  await seedFolder(storage, 'notes', [['a.md', '# a', 'text/markdown']]);
  const client = await connect(STATIC_TOKEN);

  const html = '<!DOCTYPE html><html><body><p>v2, con acentos: ñáéíóú</p></body></html>';
  const updated = await client.callTool({ name: 'update_page', arguments: { prefix: 'landing', html } });
  assert.equal(updated.isError, undefined, JSON.stringify(updated));
  const out = updated.structuredContent;
  assert.equal(out.url, 'https://share.example.invalid/landing');
  assert.equal(out.previous_size_bytes, 9);
  assert.equal(out.size_bytes, Buffer.byteLength(html));
  assert.equal(out.title, 'Landing', 'the title it was not given stays');
  assert.match(updated.content[0].text, /URL is unchanged/);

  const meta = await storage.getMeta('landing');
  assert.equal(meta.kind, 'uploaded');
  assert.equal(meta.title, 'Landing');
  assert.equal(meta.description, 'La original');
  assert.equal(meta.createdAt, '2026-01-01T00:00:00.000Z', 'the page is not republished, only rewritten');
  assert.equal(await new Response((await storage.getAsset('landing', '__page.html')).stream).text(), html);

  const retitled = await client.callTool({
    name: 'update_page',
    arguments: { prefix: 'landing', html: '<p>v3</p>', title: 'Portada', description: '', lang: 'en' },
  });
  assert.equal(retitled.isError, undefined, JSON.stringify(retitled));
  const after = await storage.getMeta('landing');
  assert.equal(after.title, 'Portada');
  assert.equal(after.description, '', 'an empty description clears the one it had');
  assert.equal(after.lang, 'en');

  const noPage = await client.callTool({ name: 'update_page', arguments: { prefix: 'nothing-here', html: '<p>x</p>' } });
  assert.equal(noPage.isError, true);
  assert.match(noPage.content[0].text, /publish_page/);

  const aFolder = await client.callTool({ name: 'update_page', arguments: { prefix: 'notes', html: '<p>x</p>' } });
  assert.equal(aFolder.isError, true);
  assert.match(aFolder.content[0].text, /update_file/);
  assert.equal((await storage.getMeta('notes')).kind, 'generated', 'the folder is not turned into a page');

  const tooBig = await client.callTool({
    name: 'update_page',
    arguments: { prefix: 'landing', html: 'x'.repeat(3 * 1024 * 1024 + 1) },
  });
  assert.equal(tooBig.isError, true);
  assert.equal(await new Response((await storage.getAsset('landing', '__page.html')).stream).text(), '<p>v3</p>', 'nothing changed');
  await client.close();
});

test('a page published through the tools is live at its URL and stays there when replaced', async () => {
  fresh();
  const client = await connect(STATIC_TOKEN);

  const v1 = '<!DOCTYPE html><html><body><h1>Cenas</h1></body></html>';
  const published = await client.callTool({
    name: 'publish_page',
    arguments: { prefix: 'cenas', html: v1, title: 'Cenas', description: 'Dos semanas', lang: 'es' },
  });
  assert.equal(published.isError, undefined, JSON.stringify(published));

  const served = await handleViewShare(new Request('https://share.example.invalid/cenas'), { params: Promise.resolve({ slug: 'cenas' }) });
  assert.equal(served.status, 200);
  assert.equal(served.headers.get('content-security-policy'), 'sandbox allow-scripts', 'a page stays in an opaque origin');
  const firstEtag = served.headers.get('etag');
  const firstBody = await served.text();
  assert.match(firstBody, /<h1>Cenas<\/h1>/);
  assert.match(firstBody, /<meta name="robots" content="noindex,nofollow">/, 'the template invariants are injected');
  assert.match(firstBody, /<meta name="description" content="Dos semanas">/);

  const v2 = '<!DOCTYPE html><html><body><h1>Cenas, versión 2</h1></body></html>';
  const updated = await client.callTool({ name: 'update_page', arguments: { prefix: 'cenas', html: v2 } });
  assert.equal(updated.isError, undefined, JSON.stringify(updated));
  assert.equal(updated.structuredContent.url, 'https://share.example.invalid/cenas');

  const again = await handleViewShare(new Request('https://share.example.invalid/cenas'), { params: Promise.resolve({ slug: 'cenas' }) });
  assert.equal(again.status, 200);
  const secondBody = await again.text();
  assert.match(secondBody, /Cenas, versión 2/);
  assert.doesNotMatch(secondBody, /<h1>Cenas<\/h1>/, 'the old document is gone');
  assert.notEqual(again.headers.get('etag'), firstEtag, 'a cached copy revalidates to the new one');
  await client.close();
});

test('the file tools send a page to update_page instead of claiming it holds nothing', async () => {
  const storage = fresh();
  await storage.putAsset('landing', '__page.html', '<p>v1</p>', 'text/html; charset=utf-8');
  await storage.saveMeta('landing', { slug: 'landing', title: 'Landing', lang: 'es', createdAt: new Date().toISOString(), kind: 'uploaded', assets: [] });
  const client = await connect(STATIC_TOKEN);

  const asFile = await client.callTool({
    name: 'update_file',
    arguments: { path: 'landing/index.html', content: '<p>v2</p>', encoding: 'text' },
  });
  assert.equal(asFile.isError, true);
  assert.match(asFile.content[0].text, /update_page/);

  const added = await client.callTool({
    name: 'upload_file',
    arguments: { filename: 'x.txt', content: 'x', encoding: 'text', prefix: 'landing' },
  });
  assert.equal(added.isError, true);
  assert.match(added.content[0].text, /update_page/);

  const presigned = await client.callTool({
    name: 'create_upload_url',
    arguments: { filename: 'x.bin', content_type: 'application/octet-stream', size_bytes: 10, prefix: 'landing' },
  });
  assert.equal(presigned.isError, true);
  assert.match(presigned.content[0].text, /update_page/);

  const deleter = await connect(await ownerToken());
  const deleted = await deleter.callTool({ name: 'delete_file', arguments: { path: 'landing/index.html' } });
  assert.equal(deleted.isError, true);
  assert.match(deleted.content[0].text, /passing "landing" alone/);
  assert.ok(await storage.getMeta('landing'), 'the page is still there');
  await deleter.close();
  await client.close();
});

test('create_upload_url with overwrite plus complete_upload replaces a large file in place', async () => {
  const storage = fresh();
  await seedFolder(storage, 'media', [['clip.mp4', 'old bytes', 'video/mp4']]);
  const client = await connect(STATIC_TOKEN);

  const refused = await client.callTool({
    name: 'create_upload_url',
    arguments: { filename: 'clip.mp4', content_type: 'video/mp4', size_bytes: 12, prefix: 'media' },
  });
  assert.equal(refused.isError, true);
  assert.match(refused.content[0].text, /overwrite/);

  const issued = await client.callTool({
    name: 'create_upload_url',
    arguments: { filename: 'clip.mp4', content_type: 'video/mp4', size_bytes: 12, prefix: 'media', overwrite: true },
  });
  assert.equal(issued.isError, undefined, JSON.stringify(issued));
  assert.equal(issued.structuredContent.path, 'media/clip.mp4');

  const untouched = await client.callTool({ name: 'complete_upload', arguments: { path: 'media/clip.mp4' } });
  assert.equal(untouched.structuredContent.already_published, true, 'nothing was PUT yet');

  await storage.putAsset('media', 'clip.mp4', Buffer.from('twelve bytes'), 'video/mp4');
  const replaced = await client.callTool({ name: 'complete_upload', arguments: { path: 'media/clip.mp4' } });
  assert.equal(replaced.isError, undefined, JSON.stringify(replaced));
  assert.equal(replaced.structuredContent.already_published, false);
  assert.equal(replaced.structuredContent.size_bytes, 12);
  assert.match(replaced.content[0].text, /Replaced/);
  const asset = (await storage.getMeta('media')).assets[0];
  assert.equal(asset.sizeBytes, 12);
  assert.ok(asset.updatedAt);

  const again = await client.callTool({ name: 'complete_upload', arguments: { path: 'media/clip.mp4' } });
  assert.equal(again.structuredContent.already_published, true);
  await client.close();
});

test('list_files filters by prefix and pages with a cursor', async () => {
  const storage = fresh();
  await seedFolder(storage, 'alpha', [['a.txt', 'aaa', 'text/plain'], ['b.txt', 'bb', 'text/plain']]);
  await seedFolder(storage, 'alpha-two', [['c.txt', 'c', 'text/plain']]);
  await seedFolder(
    storage,
    'bulk',
    Array.from({ length: 55 }, (_, i) => [`f${String(i).padStart(2, '0')}.txt`, `${i}`, 'text/plain'])
  );
  await storage.putAsset('page', '__page.html', '<h1>x</h1>', 'text/html');
  await storage.saveMeta('page', { slug: 'page', title: 'P', lang: 'en', createdAt: new Date().toISOString(), kind: 'uploaded', assets: [] });

  const client = await connect(STATIC_TOKEN);

  const exact = await client.callTool({ name: 'list_files', arguments: { prefix: 'alpha' } });
  assert.equal(exact.isError, undefined, JSON.stringify(exact));
  assert.equal(exact.structuredContent.total_count, 3, 'prefix matches alpha and alpha-two');
  assert.deepEqual(
    exact.structuredContent.files.map((f) => f.path),
    ['alpha/a.txt', 'alpha/b.txt', 'alpha-two/c.txt']
  );
  const item = exact.structuredContent.files[0];
  assert.equal(item.size_bytes, 3);
  assert.equal(item.content_type, 'text/plain');
  assert.equal(item.url, 'https://share.example.invalid/alpha/a.txt');
  assert.equal(item.page_url, 'https://share.example.invalid/alpha');
  assert.ok(item.created_at);
  assert.equal(exact.structuredContent.next_cursor, undefined);

  assert.deepEqual(exact.structuredContent.pages, [], 'no page starts with "alpha"');

  const all = await client.callTool({ name: 'list_files', arguments: {} });
  assert.equal(all.structuredContent.total_count, 58);
  assert.equal(all.structuredContent.page_count, 1);
  assert.deepEqual(all.structuredContent.pages, [
    { prefix: 'page', title: 'P', created_at: (await storage.getMeta('page')).createdAt, url: 'https://share.example.invalid/page' },
  ]);
  assert.match(all.content[0].text, /update_page/);
  assert.equal(all.structuredContent.files.length, 50);
  assert.ok(all.structuredContent.next_cursor);
  assert.ok(all.content[0].text.includes('cursor'));

  const rest = await client.callTool({ name: 'list_files', arguments: { cursor: all.structuredContent.next_cursor } });
  assert.equal(rest.structuredContent.files.length, 8);
  assert.equal(rest.structuredContent.next_cursor, undefined);
  const seen = new Set([...all.structuredContent.files, ...rest.structuredContent.files].map((f) => f.path));
  assert.equal(seen.size, 58);

  const onlyPage = await client.callTool({ name: 'list_files', arguments: { prefix: 'page' } });
  assert.equal(onlyPage.structuredContent.total_count, 0);
  assert.equal(onlyPage.structuredContent.page_count, 1);
  assert.match(onlyPage.content[0].text, /https:\/\/share\.example\.invalid\/page/);

  const none = await client.callTool({ name: 'list_files', arguments: { prefix: 'zzz' } });
  assert.equal(none.structuredContent.total_count, 0);
  assert.equal(none.structuredContent.page_count, 0);
  assert.match(none.content[0].text, /No files/);

  const bad = await client.callTool({ name: 'list_files', arguments: { cursor: 'garbage' } });
  assert.equal(bad.isError, true);
  await client.close();
});

test('get_file_info describes a file, a folder or a page and fails clearly when missing', async () => {
  const storage = fresh();
  await seedFolder(storage, 'docs', [['guide.pdf', 'pdfpdf', 'application/pdf'], ['notes.md', '# n', 'text/markdown']], {
    expiresAt: '2030-01-01T00:00:00.000Z',
    passwordHash: 'scrypt$N=1$r=1$p=1$00$00',
  });
  const client = await connect(STATIC_TOKEN);

  const file = await client.callTool({ name: 'get_file_info', arguments: { path: 'docs/guide.pdf' } });
  assert.equal(file.isError, undefined, JSON.stringify(file));
  assert.equal(file.structuredContent.type, 'file');
  assert.equal(file.structuredContent.size_bytes, 6);
  assert.equal(file.structuredContent.content_type, 'application/pdf');
  assert.equal(file.structuredContent.expires_at, '2030-01-01T00:00:00.000Z');
  assert.equal(file.structuredContent.password_protected, true);
  assert.equal(file.structuredContent.url, 'https://share.example.invalid/docs/guide.pdf');
  assert.equal(file.structuredContent.file_count, 2);
  assert.match(file.content[0].text, /password protected/);

  const folder = await client.callTool({ name: 'get_file_info', arguments: { path: 'docs' } });
  assert.equal(folder.structuredContent.type, 'folder');
  assert.equal(folder.structuredContent.title, 'Folder docs');
  assert.equal(folder.structuredContent.size_bytes, 9);
  assert.equal(folder.structuredContent.files.length, 2);
  assert.equal(folder.structuredContent.url, 'https://share.example.invalid/docs');

  await storage.putAsset('landing', '__page.html', '<p>hola</p>', 'text/html; charset=utf-8');
  await storage.saveMeta('landing', { slug: 'landing', title: 'Landing', lang: 'es', createdAt: new Date().toISOString(), kind: 'uploaded', assets: [] });
  const page = await client.callTool({ name: 'get_file_info', arguments: { path: 'landing' } });
  assert.equal(page.isError, undefined, JSON.stringify(page));
  assert.equal(page.structuredContent.type, 'page');
  assert.equal(page.structuredContent.size_bytes, 11);
  assert.equal(page.structuredContent.content_type, 'text/html; charset=utf-8');
  assert.equal(page.structuredContent.file_count, 0);
  assert.equal(page.structuredContent.url, 'https://share.example.invalid/landing');
  assert.match(page.content[0].text, /update_page/);

  const missingFile = await client.callTool({ name: 'get_file_info', arguments: { path: 'docs/nope.txt' } });
  assert.equal(missingFile.isError, true);
  assert.match(missingFile.content[0].text, /guide\.pdf, notes\.md/);

  const missingFolder = await client.callTool({ name: 'get_file_info', arguments: { path: 'nothing-here' } });
  assert.equal(missingFolder.isError, true);
  await client.close();
});

test('delete_file needs files:delete, removes files, folds an empty folder and removes folders', async () => {
  const storage = fresh();
  await seedFolder(storage, 'trip', [['a.jpg', 'aa', 'image/jpeg'], ['b.jpg', 'bb', 'image/jpeg']]);
  await seedFolder(storage, 'old', [['x.txt', 'x', 'text/plain']]);

  const limited = await connect(STATIC_TOKEN);
  const denied = await limited.callTool({ name: 'delete_file', arguments: { path: 'trip/a.jpg' } });
  assert.equal(denied.isError, true);
  assert.match(denied.content[0].text, /files:delete/);
  assert.ok(await storage.headAsset('trip', 'a.jpg'));
  await limited.close();

  const client = await connect(await ownerToken());
  const one = await client.callTool({ name: 'delete_file', arguments: { path: 'trip/a.jpg' } });
  assert.equal(one.isError, undefined, JSON.stringify(one));
  assert.deepEqual(one.structuredContent, { path: 'trip/a.jpg', deleted: true, folder_deleted: false, remaining_files: 1 });
  assert.equal(await storage.headAsset('trip', 'a.jpg'), null);
  assert.ok(await storage.headAsset('trip', 'b.jpg'));

  const last = await client.callTool({ name: 'delete_file', arguments: { path: 'trip/b.jpg' } });
  assert.equal(last.structuredContent.folder_deleted, true);
  assert.equal(await storage.getMeta('trip'), null);
  assert.equal(await storage.headAsset('trip', 'b.jpg'), null);

  const folder = await client.callTool({ name: 'delete_file', arguments: { path: 'old' } });
  assert.equal(folder.structuredContent.folder_deleted, true);
  assert.equal(await storage.getMeta('old'), null);

  const gone = await client.callTool({ name: 'delete_file', arguments: { path: 'old' } });
  assert.equal(gone.isError, true);
  await client.close();
});

test('an OAuth token carries exactly the scopes it was granted', async () => {
  const storage = fresh();
  await seedFolder(storage, 'ro', [['x.txt', 'x', 'text/plain']]);
  const client = await connect(await ownerToken(['files:read']));
  const list = await client.callTool({ name: 'list_files', arguments: {} });
  assert.equal(list.isError, undefined);
  const upload = await client.callTool({ name: 'upload_file', arguments: { filename: 'y.txt', content: 'y', encoding: 'text' } });
  assert.equal(upload.isError, true);
  assert.match(upload.content[0].text, /files:write/);

  const publish = await client.callTool({ name: 'publish_page', arguments: { prefix: 'nueva', html: '<p>x</p>', title: 'T' } });
  assert.equal(publish.isError, true);
  assert.match(publish.content[0].text, /files:write/);
  assert.equal(await storage.getMeta('nueva'), null);

  const update = await client.callTool({ name: 'update_page', arguments: { prefix: 'ro', html: '<p>x</p>' } });
  assert.equal(update.isError, true);
  assert.match(update.content[0].text, /files:write/);
  await client.close();
});
