import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

process.env.SHARE_API_TOKEN = 'secret-test-token-xyz789';
process.env.SHARE_COOKIE_SECRET = 'cookie-secret-test-abc123';
process.env.SHARE_BASE_URL = 'https://share.example.invalid';
process.env.MCP_OAUTH_SECRET = 'test-oauth-signing-secret-with-enough-length-0123456789';
delete process.env.MCP_STATIC_TOKEN;
delete process.env.MCP_OAUTH_CLIENTS;

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { hashPassword } from '../lib/auth.ts';
import { MemoryStorage, setStorageForTesting } from '../lib/storage.ts';
import { closeMcpHandlerForTesting, serveMcp } from '../lib/mcp/server.ts';
import { loginLimiter, registrationLimiter, tokenLimiter } from '../lib/mcp/ratelimit.ts';
import { setCimdTransportForTesting } from '../lib/oauth/clients.ts';
import {
  handleAuthorizationServerMetadata,
  handleAuthorize,
  handleProtectedResourceMetadata,
  handleRegister,
  handleToken,
} from '../lib/oauth/handlers.ts';

const BASE = 'https://share.example.invalid';
const PASSPHRASE = 'correct horse battery staple';
process.env.MCP_LOGIN_PASSPHRASE_HASH = await hashPassword(PASSPHRASE);

/* ------------------------------------------------------------------------------------------ */
/* Helpers                                                                                     */
/* ------------------------------------------------------------------------------------------ */

function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

async function register(metadata) {
  const res = await handleRegister(
    new Request(`${BASE}/oauth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(metadata),
    })
  );
  return { status: res.status, body: await res.json() };
}

function authorizeUrl(params) {
  const url = new URL(`${BASE}/oauth/authorize`);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) url.searchParams.set(k, v);
  return url.toString();
}

function requestTokenFrom(html) {
  const match = html.match(/name="request" value="([^"]+)"/);
  assert.ok(match, 'the page carries the signed request');
  return match[1].replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&');
}

async function submitLogin(requestToken, passphrase, decision = 'allow', headers = {}) {
  const form = new URLSearchParams({ request: requestToken, passphrase, decision });
  return handleAuthorize(
    new Request(`${BASE}/oauth/authorize`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: form.toString(),
    })
  );
}

async function tokenRequest(params, headers = {}) {
  const res = await handleToken(
    new Request(`${BASE}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(params).toString(),
    })
  );
  return { status: res.status, body: await res.json(), headers: res.headers };
}

/** Runs the whole authorization-code flow for a public client and returns the code and the redirect. */
async function obtainCode({ clientId, redirectUri, scope, state = 'xyz', resource, extra = {} }) {
  const { verifier, challenge } = pkce();
  const page = await handleAuthorize(
    new Request(
      authorizeUrl({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        scope,
        state,
        resource,
        ...extra,
      })
    )
  );
  const html = await page.text();
  assert.equal(page.status, 200, html);
  const requestToken = requestTokenFrom(html);
  const redirect = await submitLogin(requestToken, PASSPHRASE);
  assert.equal(redirect.status, 303, await redirect.text());
  const location = new URL(redirect.headers.get('location'));
  return { verifier, location, code: location.searchParams.get('code'), html };
}

async function connectMcp(token) {
  const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`), {
    fetch: (url, init) => serveMcp(new Request(url, init)),
    authProvider: { token: async () => token },
  });
  const client = new Client({ name: 'oauth-test', version: '1.0.0' }, { versionNegotiation: { mode: 'auto' } });
  await client.connect(transport);
  return client;
}

test.beforeEach(() => {
  setStorageForTesting(new MemoryStorage());
  loginLimiter.reset();
  tokenLimiter.reset();
  registrationLimiter.reset();
  setCimdTransportForTesting(null, null);
});

test.afterEach(async () => {
  await closeMcpHandlerForTesting();
});

/* ------------------------------------------------------------------------------------------ */
/* Discovery                                                                                   */
/* ------------------------------------------------------------------------------------------ */

test('discovery: protected resource metadata points at this issuer and lists the scopes', async () => {
  const res = await handleProtectedResourceMetadata(
    new Request(`${BASE}/.well-known/oauth-protected-resource/mcp`, { headers: { origin: 'https://chatgpt.com' } })
  );
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), 'https://chatgpt.com');
  const prm = await res.json();
  assert.equal(prm.resource, `${BASE}/mcp`);
  assert.deepEqual(prm.authorization_servers, [BASE]);
  assert.deepEqual(prm.scopes_supported, ['files:read', 'files:write', 'files:delete']);
  assert.deepEqual(prm.bearer_methods_supported, ['header']);
});

test('discovery: authorization server metadata advertises PKCE S256, DCR, CIMD and iss', async () => {
  const res = await handleAuthorizationServerMetadata(new Request(`${BASE}/.well-known/oauth-authorization-server`));
  assert.equal(res.status, 200);
  const md = await res.json();
  assert.equal(md.issuer, BASE);
  assert.equal(md.authorization_endpoint, `${BASE}/oauth/authorize`);
  assert.equal(md.token_endpoint, `${BASE}/oauth/token`);
  assert.equal(md.registration_endpoint, `${BASE}/oauth/register`);
  assert.deepEqual(md.code_challenge_methods_supported, ['S256']);
  assert.deepEqual(md.response_types_supported, ['code']);
  assert.deepEqual(md.grant_types_supported, ['authorization_code', 'refresh_token']);
  assert.ok(md.token_endpoint_auth_methods_supported.includes('none'));
  assert.equal(md.client_id_metadata_document_supported, true);
  assert.equal(md.authorization_response_iss_parameter_supported, true);
  assert.ok(!md.scopes_supported.some((s) => ['openid', 'email', 'profile'].includes(s)), 'no OIDC scopes offered');

  const preflight = await handleAuthorizationServerMetadata(
    new Request(`${BASE}/.well-known/oauth-authorization-server`, { method: 'OPTIONS', headers: { origin: 'https://x.example' } })
  );
  assert.equal(preflight.status, 204);
});

/* ------------------------------------------------------------------------------------------ */
/* Dynamic Client Registration                                                                 */
/* ------------------------------------------------------------------------------------------ */

test('DCR: a public client registers and gets a self-contained client_id', async () => {
  const { status, body } = await register({
    client_name: 'Example Host',
    redirect_uris: ['https://host.example/oauth/callback', 'http://localhost:3334/callback'],
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
  });
  assert.equal(status, 201, JSON.stringify(body));
  assert.match(body.client_id, /^dcr\./);
  assert.equal(body.client_secret, undefined);
  assert.equal(body.client_name, 'Example Host');
  assert.deepEqual(body.redirect_uris, ['https://host.example/oauth/callback', 'http://localhost:3334/callback']);
  assert.equal(body.token_endpoint_auth_method, 'none');
  assert.ok(body.client_id_issued_at > 0);
});

test('DCR: a confidential client gets a secret; bad metadata is refused', async () => {
  const conf = await register({
    client_name: 'Confidential',
    redirect_uris: ['https://host.example/cb'],
    token_endpoint_auth_method: 'client_secret_post',
  });
  assert.equal(conf.status, 201);
  assert.ok(conf.body.client_secret, 'secret issued');
  assert.equal(conf.body.client_secret_expires_at, 0);

  const bad = await register({ redirect_uris: ['http://evil.example/cb'] });
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error, 'invalid_redirect_uri');

  const none = await register({ client_name: 'x' });
  assert.equal(none.status, 400);

  const method = await register({ redirect_uris: ['https://a.example/cb'], token_endpoint_auth_method: 'private_key_jwt' });
  assert.equal(method.status, 400);
  assert.equal(method.body.error, 'invalid_client_metadata');

  const notJson = await handleRegister(new Request(`${BASE}/oauth/register`, { method: 'POST', body: 'nope' }));
  assert.equal(notJson.status, 400);
});

/* ------------------------------------------------------------------------------------------ */
/* Authorization code flow                                                                     */
/* ------------------------------------------------------------------------------------------ */

test('full flow: discovery, DCR, login with the passphrase, PKCE token exchange, MCP call', async () => {
  const { body: client } = await register({ client_name: 'Flow Host', redirect_uris: ['https://host.example/cb'] });

  const { verifier, location, code, html } = await obtainCode({
    clientId: client.client_id,
    redirectUri: 'https://host.example/cb',
    scope: 'files:read files:write files:delete',
    resource: `${BASE}/mcp`,
  });
  assert.ok(html.includes('Flow Host'), 'the consent page names the client');
  assert.ok(html.includes('files:delete'), 'the consent page lists the scopes');
  assert.equal(location.origin + location.pathname, 'https://host.example/cb');
  assert.equal(location.searchParams.get('state'), 'xyz');
  assert.equal(location.searchParams.get('iss'), BASE);
  assert.ok(code);

  const wrongVerifier = await tokenRequest({
    grant_type: 'authorization_code',
    code,
    code_verifier: 'x'.repeat(43),
    client_id: client.client_id,
    redirect_uri: 'https://host.example/cb',
  });
  assert.equal(wrongVerifier.status, 400);
  assert.equal(wrongVerifier.body.error, 'invalid_grant');

  const wrongRedirect = await tokenRequest({
    grant_type: 'authorization_code',
    code,
    code_verifier: verifier,
    client_id: client.client_id,
    redirect_uri: 'https://host.example/other',
  });
  assert.equal(wrongRedirect.body.error, 'invalid_grant');

  const tokens = await tokenRequest({
    grant_type: 'authorization_code',
    code,
    code_verifier: verifier,
    client_id: client.client_id,
    redirect_uri: 'https://host.example/cb',
    resource: `${BASE}/mcp`,
  });
  assert.equal(tokens.status, 200, JSON.stringify(tokens.body));
  assert.equal(tokens.body.token_type, 'Bearer');
  assert.equal(tokens.body.expires_in, 3600);
  assert.equal(tokens.body.scope, 'files:read files:write files:delete');
  assert.ok(tokens.body.access_token);
  assert.ok(tokens.body.refresh_token);
  assert.equal(tokens.headers.get('cache-control'), 'no-store');

  const mcp = await connectMcp(tokens.body.access_token);
  const { tools } = await mcp.listTools();
  assert.equal(tools.length, 9);
  const upload = await mcp.callTool({ name: 'upload_file', arguments: { filename: 'hola.txt', content: 'hola', encoding: 'text' } });
  assert.equal(upload.isError, undefined, JSON.stringify(upload));
  const del = await mcp.callTool({ name: 'delete_file', arguments: { path: upload.structuredContent.prefix } });
  assert.equal(del.isError, undefined, JSON.stringify(del));
  await mcp.close();

  const refreshed = await tokenRequest({
    grant_type: 'refresh_token',
    refresh_token: tokens.body.refresh_token,
    client_id: client.client_id,
    scope: 'files:read',
  });
  assert.equal(refreshed.status, 200, JSON.stringify(refreshed.body));
  assert.equal(refreshed.body.scope, 'files:read');
  assert.ok(refreshed.body.refresh_token);

  const widened = await tokenRequest({
    grant_type: 'refresh_token',
    refresh_token: refreshed.body.refresh_token,
    client_id: client.client_id,
    scope: 'files:read files:delete',
  });
  assert.equal(widened.status, 400);
  assert.equal(widened.body.error, 'invalid_scope');

  const otherClient = (await register({ redirect_uris: ['https://other.example/cb'] })).body;
  const stolen = await tokenRequest({
    grant_type: 'refresh_token',
    refresh_token: tokens.body.refresh_token,
    client_id: otherClient.client_id,
  });
  assert.equal(stolen.body.error, 'invalid_grant');
});

test('the login page refuses a wrong passphrase, denies on cancel and rate-limits attempts', async () => {
  const { body: client } = await register({ redirect_uris: ['https://host.example/cb'] });
  const { challenge } = pkce();
  const page = await handleAuthorize(
    new Request(
      authorizeUrl({
        response_type: 'code',
        client_id: client.client_id,
        redirect_uri: 'https://host.example/cb',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: 's1',
      })
    )
  );
  const requestToken = requestTokenFrom(await page.text());

  const wrong = await submitLogin(requestToken, 'not it');
  assert.equal(wrong.status, 200);
  const wrongHtml = await wrong.text();
  assert.ok(wrongHtml.includes('not right'));
  assert.ok(wrongHtml.includes('name="request"'), 'the form is shown again');

  const denied = await submitLogin(requestToken, PASSPHRASE, 'deny');
  assert.equal(denied.status, 303);
  const deniedUrl = new URL(denied.headers.get('location'));
  assert.equal(deniedUrl.searchParams.get('error'), 'access_denied');
  assert.equal(deniedUrl.searchParams.get('state'), 's1');

  const expired = await submitLogin('garbage', PASSPHRASE);
  assert.equal(expired.status, 400);

  loginLimiter.reset();
  const ip = { 'x-forwarded-for': '203.0.113.9' };
  for (let i = 0; i < 5; i++) await submitLogin(requestToken, 'wrong', 'allow', ip);
  const blocked = await submitLogin(requestToken, PASSPHRASE, 'allow', ip);
  assert.equal(blocked.status, 429);
  assert.ok((await blocked.text()).includes('Too many attempts'));
});

test('authorize validates client, redirect, PKCE, scope and resource before showing a page', async () => {
  const { body: client } = await register({ redirect_uris: ['https://host.example/cb', 'https://host.example/cb2'] });
  const { challenge } = pkce();
  const base = { response_type: 'code', client_id: client.client_id, redirect_uri: 'https://host.example/cb', code_challenge: challenge, code_challenge_method: 'S256', state: 'st' };

  const unknownClient = await handleAuthorize(new Request(authorizeUrl({ ...base, client_id: 'dcr.tampered.sig' })));
  assert.equal(unknownClient.status, 400);
  assert.ok((await unknownClient.text()).includes('Unknown client'));

  const badRedirect = await handleAuthorize(new Request(authorizeUrl({ ...base, redirect_uri: 'https://evil.example/cb' })));
  assert.equal(badRedirect.status, 400);
  assert.ok((await badRedirect.text()).includes('Invalid redirect'));

  const noRedirect = await handleAuthorize(new Request(authorizeUrl({ ...base, redirect_uri: undefined })));
  assert.equal(noRedirect.status, 400, 'two registered redirects means the request must name one');

  const errorOf = async (params) => {
    const res = await handleAuthorize(new Request(authorizeUrl({ ...base, ...params })));
    assert.equal(res.status, 303);
    const url = new URL(res.headers.get('location'));
    assert.equal(url.origin + url.pathname, 'https://host.example/cb');
    assert.equal(url.searchParams.get('state'), 'st');
    assert.equal(url.searchParams.get('iss'), BASE);
    return url.searchParams.get('error');
  };
  assert.equal(await errorOf({ response_type: 'token' }), 'unsupported_response_type');
  assert.equal(await errorOf({ code_challenge: undefined }), 'invalid_request');
  assert.equal(await errorOf({ code_challenge_method: 'plain' }), 'invalid_request');
  assert.equal(await errorOf({ scope: 'files:read admin' }), 'invalid_scope');
  assert.equal(await errorOf({ resource: 'https://elsewhere.example/mcp' }), 'invalid_target');

  const ok = await handleAuthorize(new Request(authorizeUrl(base)));
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.ok((await ok.text()).includes('files:read'), 'omitted scope means every scope');
});

test('a confidential client must authenticate at the token endpoint, by header or body', async () => {
  const { body: client } = await register({ redirect_uris: ['https://host.example/cb'], token_endpoint_auth_method: 'client_secret_basic' });
  const { verifier, code } = await obtainCode({ clientId: client.client_id, redirectUri: 'https://host.example/cb' });

  const missing = await tokenRequest({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: client.client_id });
  assert.equal(missing.status, 401);
  assert.equal(missing.body.error, 'invalid_client');

  const wrong = await tokenRequest(
    { grant_type: 'authorization_code', code, code_verifier: verifier },
    { authorization: `Basic ${Buffer.from(`${client.client_id}:nope`).toString('base64')}` }
  );
  assert.equal(wrong.status, 401);
  assert.equal(wrong.headers.get('www-authenticate'), 'Basic realm="oauth"');

  const viaHeader = await tokenRequest(
    { grant_type: 'authorization_code', code, code_verifier: verifier },
    { authorization: `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64')}` }
  );
  assert.equal(viaHeader.status, 200, JSON.stringify(viaHeader.body));

  const viaBody = await tokenRequest({
    grant_type: 'authorization_code',
    code,
    code_verifier: verifier,
    client_id: client.client_id,
    client_secret: client.client_secret,
  });
  assert.equal(viaBody.status, 200, JSON.stringify(viaBody.body));
});

test('a loopback redirect may change port, as native clients do', async () => {
  const { body: client } = await register({ redirect_uris: ['http://localhost:8080/callback'] });
  const { verifier, code, location } = await obtainCode({ clientId: client.client_id, redirectUri: 'http://localhost:51234/callback' });
  assert.equal(location.port, '51234');
  const tokens = await tokenRequest({
    grant_type: 'authorization_code',
    code,
    code_verifier: verifier,
    client_id: client.client_id,
    redirect_uri: 'http://localhost:51234/callback',
  });
  assert.equal(tokens.status, 200, JSON.stringify(tokens.body));
});

/* ------------------------------------------------------------------------------------------ */
/* Client ID Metadata Documents and pre-registered clients                                     */
/* ------------------------------------------------------------------------------------------ */

test('CIMD: an https client_id is fetched, validated and usable without registration', async () => {
  const clientId = 'https://host.example/oauth/client.json';
  const fetched = [];
  setCimdTransportForTesting(
    async (url, init) => {
      fetched.push({ url: String(url), redirect: init?.redirect });
      return new Response(
        JSON.stringify({
          client_id: clientId,
          client_name: 'Metadata Host',
          redirect_uris: ['https://host.example/connector/callback'],
          token_endpoint_auth_method: 'none',
        }),
        { headers: { 'content-type': 'application/json' } }
      );
    },
    async () => ['93.184.216.34']
  );

  const { verifier, code, html } = await obtainCode({ clientId, redirectUri: 'https://host.example/connector/callback' });
  assert.ok(html.includes('Metadata Host'));
  assert.equal(fetched.length, 1);
  assert.equal(fetched[0].redirect, 'error');

  const tokens = await tokenRequest({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: clientId });
  assert.equal(tokens.status, 200, JSON.stringify(tokens.body));
  assert.equal(fetched.length, 1, 'the document is cached between authorize and token');
});

test('CIMD: a document preferring private_key_jwt but supporting "none" is accepted as a public client', async () => {
  // ChatGPT's document at https://chatgpt.com/oauth/client.json, as published.
  const clientId = 'https://chatgpt.com/oauth/client.json';
  const redirectUri = 'https://chatgpt.com/connector_platform_oauth_redirect';
  setCimdTransportForTesting(
    async () =>
      new Response(
        JSON.stringify({
          client_id: clientId,
          redirect_uris: [redirectUri],
          token_endpoint_auth_method: 'private_key_jwt',
          token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          client_name: 'ChatGPT',
          token_endpoint_auth_signing_alg: 'RS256',
          jwks_uri: 'https://chatgpt.com/oauth/jwks.json',
        }),
        { headers: { 'content-type': 'application/json' } }
      ),
    async () => ['93.184.216.34']
  );

  const { verifier, code, html } = await obtainCode({ clientId, redirectUri });
  assert.ok(html.includes('ChatGPT'));
  const tokens = await tokenRequest({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: clientId });
  assert.equal(tokens.status, 200, JSON.stringify(tokens.body));
});

test('CIMD: a document that supports only a confidential method is refused', async () => {
  const { challenge } = pkce();
  const clientId = 'https://h.example/client.json';
  setCimdTransportForTesting(
    async () =>
      new Response(
        JSON.stringify({
          client_id: clientId,
          redirect_uris: ['https://h.example/cb'],
          token_endpoint_auth_method: 'private_key_jwt',
          token_endpoint_auth_methods_supported: ['private_key_jwt'],
        }),
        { headers: { 'content-type': 'application/json' } }
      ),
    async () => ['93.184.216.34']
  );
  const response = await handleAuthorize(
    new Request(
      authorizeUrl({ response_type: 'code', client_id: clientId, redirect_uri: 'https://h.example/cb', code_challenge: challenge, code_challenge_method: 'S256' })
    )
  );
  assert.equal(response.status, 400);
});

test('CIMD: documents from private addresses, with a mismatched id, or without a path are refused', async () => {
  const { challenge } = pkce();
  const attempt = async (clientId, fetcher, resolver) => {
    setCimdTransportForTesting(fetcher, resolver);
    return handleAuthorize(
      new Request(
        authorizeUrl({ response_type: 'code', client_id: clientId, redirect_uri: 'https://h.example/cb', code_challenge: challenge, code_challenge_method: 'S256' })
      )
    );
  };
  const doc = (id) =>
    new Response(JSON.stringify({ client_id: id, redirect_uris: ['https://h.example/cb'] }), { headers: { 'content-type': 'application/json' } });

  const privateHost = await attempt('https://intranet.example/client.json', async () => doc('https://intranet.example/client.json'), async () => ['10.0.0.5']);
  assert.equal(privateHost.status, 400);

  const mismatch = await attempt('https://h.example/client.json', async () => doc('https://other.example/client.json'), async () => ['93.184.216.34']);
  assert.equal(mismatch.status, 400);

  const noPath = await attempt('https://h.example/', async () => doc('https://h.example/'), async () => ['93.184.216.34']);
  assert.equal(noPath.status, 400);

  const http = await attempt('http://h.example/client.json', async () => doc('http://h.example/client.json'), async () => ['93.184.216.34']);
  assert.equal(http.status, 400);
});

test('a pre-registered client from MCP_OAUTH_CLIENTS works with its configured secret', async () => {
  process.env.MCP_OAUTH_CLIENTS = JSON.stringify([
    { client_id: 'gemini-manual', client_secret: 'manual-secret-value', client_name: 'Manual Host', redirect_uris: ['https://manual.example/cb'] },
  ]);
  try {
    const { verifier, code, html } = await obtainCode({ clientId: 'gemini-manual', redirectUri: 'https://manual.example/cb' });
    assert.ok(html.includes('Manual Host'));
    const noSecret = await tokenRequest({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: 'gemini-manual' });
    assert.equal(noSecret.status, 401);
    const tokens = await tokenRequest({
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
      client_id: 'gemini-manual',
      client_secret: 'manual-secret-value',
    });
    assert.equal(tokens.status, 200, JSON.stringify(tokens.body));
  } finally {
    delete process.env.MCP_OAUTH_CLIENTS;
  }
});

test('the token endpoint rejects unknown grants and malformed bodies', async () => {
  const { body: client } = await register({ redirect_uris: ['https://host.example/cb'] });
  const unsupported = await tokenRequest({ grant_type: 'client_credentials', client_id: client.client_id });
  assert.equal(unsupported.status, 400);
  assert.equal(unsupported.body.error, 'unsupported_grant_type');

  const noClient = await tokenRequest({ grant_type: 'authorization_code', code: 'x', code_verifier: 'y' });
  assert.equal(noClient.status, 401);

  const wrongType = await handleToken(new Request(`${BASE}/oauth/token`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'x' }));
  assert.equal(wrongType.status, 400);
  assert.equal((await wrongType.json()).error, 'invalid_request');

  const get = await handleToken(new Request(`${BASE}/oauth/token`, { method: 'GET' }));
  assert.equal(get.status, 405);
});
