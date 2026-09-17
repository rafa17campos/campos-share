# campos-share

A lightweight Next.js service on Vercel backed by Vercel Blob, serving standalone unlisted share pages and raw files at:

`$SHARE_BASE_URL/<slug>`  
`$SHARE_BASE_URL/<slug>/<filename>`

---

## Architecture & Principles

* **Blob Storage Only (Zero Database)**:
  * Standing constraint: There is no database anywhere (no Postgres, SQLite, Redis, or ORM).
  * Storage is partitioned in Vercel Blob by slug:
    ```text
    <slug>/__meta.json
    <slug>/__page.html       (for kind: "uploaded")
    <slug>/<asset-filename>
    ```
  * `__meta.json` is the sole source of truth. Link expiry is a timestamp comparison at read time; password protection is a cryptographic hash comparison at read time.
* **Repatriation Escape Hatch**:
  * `@vercel/blob` is imported and used in **exactly one module** (`lib/storage.ts`).
  * The rest of the application interacts with a standard storage interface. Repatriating to AWS S3, MinIO, or a custom object store requires editing only `lib/storage.ts`.
  * Standard Node.js runtime only—no edge-runtime exclusives, no proprietary caching.
* **Direct Client Uploads (Bypassing Function Payload Ceilings)**:
  * Vercel Functions enforce a 4.5 MB payload ceiling (`FUNCTION_PAYLOAD_TOO_LARGE`).
  * Binary assets bypass function bodies entirely: clients request a scoped upload token (`POST /api/uploads`) and upload directly to Vercel Blob. `POST /api/shares` is called only after assets land.
  * Ceiling for all uploads is **20 MB**, enforced by token constraints.
* **HTTP Caching that survives an update**:
  * A file can be replaced in place and keep its URL, so nothing is cached as immutable. Unprotected, unexpiring shares and files: `public, max-age=0, must-revalidate` with the store's `ETag`; a browser's `If-None-Match` goes through to Blob, which answers `304` without moving the bytes when nothing changed.
  * Password-protected shares: `private, no-cache`. Shared caches never retain protected content.
  * Expiring shares: `private, max-age=0, must-revalidate`. Evaluated on every request.
  * Every read of `__meta.json` and of file bytes bypasses Blob's CDN cache (`useCache: false`), and every write asks for the shortest cache the store allows. Blob otherwise serves reads from a cache for up to a minute after a delete or an overwrite, which is how a file just deleted read as "already exists" and how a file just added could be dropped by the next write.
* **Template Invariants ("The Validator Ascends into the Template")**:
  * Metadata rules hold by construction: `<html lang="...">` matching content language, non-empty `<title>`, `<meta name="viewport">`, `<meta name="description">`, `<meta name="robots" content="noindex,nofollow">`, and Open Graph tags.
  * `og:image` is generated only for unprotected and unexpiring shares with image assets. Password-protected and expiring shares never publish `og:image` to avoid leaking content to social crawlers.
* **Security & Privacy**:
  * Obscure URLs are **not** access control.
  * Password hashing uses `crypto.scrypt` tuned to ~100ms key derivation time to defeat brute-force guessing without needing serverless state.
  * Requests attempting to unlock non-existent or unprotected slugs run dummy scrypt derivations to guarantee constant execution time and prevent slug probing.
  * Successful unlock sets an HTTP-only, `SameSite=Lax`, `Secure` cookie scoped to `Path=/[slug]` signed with `SHARE_COOKIE_SECRET` (never reusing `SHARE_API_TOKEN`).

---

## API Contract (`/api/*`)

All `/api/*` routes require `Authorization: Bearer <SHARE_API_TOKEN>`. Token validation uses constant-time comparison (`crypto.timingSafeEqual`).

### 1. `POST /api/uploads`
Issues a scoped Blob client upload token before files move.
* **Request**:
  ```json
  {
    "slug": "hotel-comparison",
    "files": [
      { "name": "informe.pdf", "contentType": "application/pdf", "sizeBytes": 481920, "overwrite": false }
    ]
  }
  ```
* **Response (`200 OK`)**:
  ```json
  {
    "clientToken": "vercel_blob_client_...",
    "prefix": "hotel-comparison/"
  }
  ```
* **Errors**: `400` (invalid or reserved slug / missing files / file > 20 MB), `401` (unauthorized), `409` (the slug already holds a file with that name, or is an uploaded page; create never overwrites).
* An existing slug accepts new file names: that is how a file joins a share. Upload it, then `PUT /api/shares/{slug}` with the full asset list. The slugs `api`, `mcp` and `oauth` are reserved for application routes.
* A file declared with `"overwrite": true` may replace one the share already holds, behind the same URL. After the `PUT` to the presigned URL, `PUT /api/shares/{slug}` with the same asset list refreshes its size and `etag` in the record. Assets in API responses carry `etag` and, once replaced, `updatedAt`.
* Wherever an asset is declared (`POST /api/shares`, `PUT /api/shares/{slug}`, `POST /api/shares/{slug}/assets`, `PUT /api/shares/{slug}/assets/{name}`) it may carry `"sha256"`, the lowercase hex SHA-256 of its bytes. The service stores and echoes it, computes it itself for content it writes (MCP `upload_file`, `update_file`), and drops it when a presigned overwrite changes the bytes without restating it, so a digest in the record always describes the current content. Callers use it to know whether bytes are already published.

### 2. `POST /api/shares`
Creates a share record after assets have been uploaded to Blob.
* **Request**:
  ```json
  {
    "slug": "hotel-comparison",
    "title": "Comparativa de hoteles",
    "description": "Precios y ubicación de tres opciones en Lisboa",
    "lang": "es",
    "kind": "generated",
    "html": null,
    "assets": [
      {
        "name": "informe.pdf",
        "originalName": "Informe final (v2).pdf",
        "contentType": "application/pdf"
      }
    ],
    "expiresAt": null,
    "password": null
  }
  ```
  * For `kind: "uploaded"`, set `html` to the inline HTML string and omit assets.
* **Response (`201 Created`)**:
  ```json
  {
    "slug": "hotel-comparison",
    "url": "$SHARE_BASE_URL/hotel-comparison",
    "createdAt": "2026-09-14T18:20:00Z",
    "assets": [
      {
        "name": "informe.pdf",
        "originalName": "Informe final (v2).pdf",
        "contentType": "application/pdf",
        "sizeBytes": 481920,
        "url": "$SHARE_BASE_URL/hotel-comparison/informe.pdf"
      }
    ]
  }
  ```
* **Errors**: `400` (validation failure or declared asset does not exist in Blob), `401`, `409` (slug exists).

### 3. `GET /api/shares`
Lists all active shares.
* **Response (`200 OK`)**: Array of share summaries (`slug`, `title`, `description`, `lang`, `kind`, `createdAt`, `url`, `assetCount`, `totalSize`, `isExpired`, `isPasswordProtected`).
* *Note: `passwordHash` is never exposed in API responses.*

### 4. `GET /api/shares/{slug}`
Retrieves full share record and asset URLs.
* **Response (`200 OK`)**: Full share metadata (excluding `passwordHash`).
* **Response (`404 Not Found`)**: If share does not exist.

### 5. `PUT /api/shares/{slug}`
Replaces metadata and asset set for an existing share, pruning obsolete blobs.
* **Request**: Same payload as `POST /api/shares`. Assets uploaded beforehand via `POST /api/uploads`.
* **Response (`200 OK`)**: Updated share record.

### 6. `DELETE /api/shares/{slug}`
Deletes `<slug>/__meta.json` and all associated blobs under `<slug>/`.
* **Response (`204 No Content`)**.

### 7. `POST /api/shares/{slug}/assets`
Adds already-uploaded files to a generated share without restating the rest. The caller names only the files that join; the record is updated with a conditional write, so two callers adding at the same time both end up in it.
* **Request**: `{ "assets": [ { "name": "mapa.png", "originalName": "Mapa (v2).png", "contentType": "image/png" } ] }` after the files were `PUT` to their presigned URLs.
* **Response (`200 OK`)**: the full share record, as `GET /api/shares/{slug}`.
* **Errors**: `400` (a declared file is not in storage, or an invalid name), `404` (unknown slug), `409` (a name the share already holds, or the share is an uploaded page).

### 8. `PUT /api/shares/{slug}/assets/{name}`
Brings the record of one file in line with the bytes in storage, after an upload with `"overwrite": true` replaced them. Idempotent.
* **Request**: optional `{ "contentType": "...", "originalName": "..." }`; an empty body keeps both.
* **Response (`200 OK`)**: the full share record with the file's new `sizeBytes`, `etag` and `updatedAt`.
* **Errors**: `404` (unknown slug or file).

### 9. `DELETE /api/shares/{slug}/assets/{name}`
Removes one file and prunes its blob. A generated share must keep at least one file, so removing the last one removes the share.
* **Response (`200 OK`)**: `{ "unpublished": false, "share": { ...full record... } }`, or `{ "unpublished": true, "share": null }` when the share went away.
* **Errors**: `404` (unknown slug or file).

`PUT /api/shares/{slug}` stays the way to change title, language, expiry, password or the whole asset set at once; the three routes above are the atomic way to touch one file. All record writes that start from a read use the store's ETag as a precondition and retry on conflict, so an update never builds on a copy another caller has already replaced.

### 10. `POST /api/shares/orphans`
Sweeps and deletes `<slug>/` prefixes older than 24 hours that contain uploaded blobs but no `__meta.json`.

---

## MCP server

The service exposes its files as tools to any MCP client at:

`$SHARE_BASE_URL/mcp`

It is a remote, client-agnostic MCP server: Streamable HTTP only (no legacy SSE), stateless so it fits Vercel Functions, serving the **2026-07-28** protocol revision natively and 2025-era clients (those that still send `initialize`) from the same endpoint. It works unchanged with claude.ai custom connectors, Claude Code, ChatGPT Developer Mode, the Gemini app (Spark connected apps), Gemini CLI, MCP Inspector and any other standard client.

Nothing in it is specific to one vendor: no UI widgets, no vendor `_meta`, only tools (no resources or prompts, which some clients ignore).

### The model the tools present

A **folder** is a share and its slug is the `prefix`. A **file** is an asset in it. A **path** is `<prefix>/<filename>`. Every file is public at `$SHARE_BASE_URL/<prefix>/<filename>` and its folder page at `$SHARE_BASE_URL/<prefix>`.

A **page** is the other kind of share (`kind: "uploaded"`): one HTML document served at `$SHARE_BASE_URL/<prefix>` with nothing around it. A page holds no files, so the file tools refuse it and say so; `publish_page` and `update_page` are its two verbs.

| Tool | Does | Scope | Annotations |
|---|---|---|---|
| `upload_file` | Publishes inline content (`text` or `base64`, up to **3 MB** decoded) and returns the public URL. Creates the folder or adds to an existing one. Never overwrites. | `files:write` | writes |
| `update_file` | Replaces the content of an existing file (inline, up to **3 MB** decoded) and keeps its URL. | `files:write` | **destructive**, idempotent |
| `create_upload_url` | Returns a presigned `PUT` URL (15 min, bound to content type and size) for files up to **20 MB**, plus the URL the file will have. For large files and for clients that can run `curl`. `overwrite: true` replaces an existing file in place. | `files:write` | writes |
| `complete_upload` | Publishes a file uploaded through `create_upload_url`, or refreshes its record after an overwrite. Idempotent. | `files:write` | idempotent |
| `publish_page` | Publishes an HTML document (inline, up to **3 MB**) as a page at `$SHARE_BASE_URL/<prefix>`. Never overwrites. | `files:write` | writes |
| `update_page` | Replaces the document of an existing page and keeps its URL. Title, description and language keep their stored value unless restated. | `files:write` | **destructive**, idempotent |
| `list_files` | Name, size, date and URL of every file, optionally under a prefix, 50 per page with a cursor, plus every page matching the prefix (not paginated). | `files:read` | read-only |
| `get_file_info` | Details of one file, one folder or one page. | `files:read` | read-only |
| `delete_file` | Deletes a file, a whole folder, or a page (by its prefix). Deleting the last file deletes its folder. | `files:delete` | **destructive** |

Every tool returns readable text and the same data as `structuredContent` with an `outputSchema`, so clients that use either work. Failures come back as tool results with `isError: true` and a message that says what to do (auth, size, duplicate name, missing upload), never as exceptions.

Schemas are the least common denominator every host's function calling accepts: flat objects, basic types, string enums, explicit `required`, a description on every field, no `anyOf`/`oneOf`/`$ref`/`additionalProperties`/`$schema`. `tests/mcp.test.mjs` asserts this on the real `tools/list` output.

**Limits.** Vercel Functions reject request bodies above 4.5 MB, so `upload_file` accepts 3 MB of decoded content and points at `create_upload_url` above that. `publish_page` and `update_page` take the same 3 MB inline, with no presigned path: a document that large should link to its images, styles and scripts as files of their own. Files go up to 20 MB through the presigned URL, which is the share service's ceiling. Tool calls are rate limited per subject (120 per minute per instance), passphrase attempts per address (5 per 15 minutes), and the token and registration endpoints per address. These counters live in the memory of the running instance; a hard ceiling belongs in the Vercel Firewall. File content and secrets are never logged.

### Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `MCP_OAUTH_SECRET` | yes | Signs every OAuth artefact (client ids, codes, access and refresh tokens). 32+ characters, e.g. `openssl rand -base64 48`. Rotating it logs every client out. |
| `MCP_LOGIN_PASSPHRASE_HASH` | yes | scrypt hash of the passphrase that authorizes clients. Generate with `npm run passphrase:hash`. |
| `MCP_STATIC_TOKEN` | no | Bearer token for terminal clients that cannot run OAuth. Off when empty. 32+ characters. |
| `MCP_STATIC_TOKEN_SCOPES` | no | Scopes of the static token. Default `files:read files:write`, never delete. |
| `MCP_OAUTH_CLIENTS` | no | JSON array of pre-registered clients (`client_id`, `client_secret`, `client_name`, `redirect_uris`) for hosts that take an id and secret instead of registering. |
| `MCP_ALLOWED_ORIGINS` | no | Browser origins allowed on `/mcp`. Default `*`: the endpoint has no ambient authority, every call carries a bearer token. A comma-separated list turns on strict `Origin` validation. |
| `SHARE_DEFAULT_LANG` | no | Language stamped on folders the tools create. Default `es`. |

The share API's own `SHARE_API_TOKEN` is not involved: the tools call `lib/shares.ts` directly, the same module the HTTP API uses.

### Authorization

The MCP endpoint is an OAuth 2.1 resource server and the app is its own authorization server, without a database:

* **Discovery.** `/.well-known/oauth-protected-resource/mcp` (and the root variant) names the authorization server; `/.well-known/oauth-authorization-server` describes it. A request without a token gets `401` with `WWW-Authenticate: Bearer resource_metadata="..."`.
* **Client registration.** Three ways, chosen by the client: Client ID Metadata Documents (an `https` URL as `client_id`, fetched and validated, never from private addresses), Dynamic Client Registration at `/oauth/register` (the `client_id` is the signed registration itself, so nothing is stored), or pre-registered clients from `MCP_OAUTH_CLIENTS`.
* **Flow.** Authorization code with PKCE S256 only, `resource` bound to `$SHARE_BASE_URL/mcp` and copied into the token audience, `iss` in the authorization response. Access tokens last 1 hour, refresh tokens 30 days from the first grant.
* **Login.** There is one resource owner. `/oauth/authorize` shows which client asks for what and takes the passphrase; entering it is the consent. The hash lives in `MCP_LOGIN_PASSPHRASE_HASH` and is checked with scrypt in constant time.
* **Scopes.** `files:read`, `files:write`, `files:delete`. Clients get all three unless they ask for less. Each tool checks its scope and answers with a tool error when it is missing.
* **Static token.** With `MCP_STATIC_TOKEN` set, `Authorization: Bearer <token>` is accepted with the scopes in `MCP_STATIC_TOKEN_SCOPES`. Meant for Gemini CLI and scripts; keep it out of shared configs.

Because tokens are stateless, an authorization code is not single-use (its 60-second life and the PKCE verifier bound to it are the protection) and a single refresh token cannot be revoked on its own: rotate `MCP_OAUTH_SECRET` to revoke everything.

### Set it up

```bash
openssl rand -base64 48            # -> MCP_OAUTH_SECRET
npm run passphrase:hash            # prompts, prints -> MCP_LOGIN_PASSPHRASE_HASH
openssl rand -base64 36            # -> MCP_STATIC_TOKEN (optional)
```

Add them in Vercel under **Settings → Environment Variables** and redeploy. The endpoint is live at `$SHARE_BASE_URL/mcp`.

### Try it with MCP Inspector

Run the app locally against in-memory storage (nothing reaches Vercel Blob):

```bash
STORAGE_PROVIDER=memory SHARE_BASE_URL=http://localhost:3000 SHARE_API_TOKEN=dev SHARE_COOKIE_SECRET=dev \
MCP_OAUTH_SECRET=$(openssl rand -base64 48) MCP_LOGIN_PASSPHRASE_HASH="$(npm run -s passphrase:hash -- 'una frase de desarrollo')" \
MCP_STATIC_TOKEN=dev-static-token-0123456789abcdefghij npm run dev
```

Then either:

* **Web UI with the full OAuth flow**: `npm run mcp:inspect`, open the URL it prints, choose transport **Streamable HTTP**, URL `http://localhost:3000/mcp`, click **Connect**. The Inspector discovers the metadata, registers itself, opens the login page; enter the passphrase. List and call the tools from the UI.
* **CLI with the static token**, which also checks schema portability across hosts:

```bash
MCP_STATIC_TOKEN=dev-static-token-0123456789abcdefghij npm run mcp:check
npx -y @modelcontextprotocol/inspector --cli --server-url http://localhost:3000/mcp --transport http \
  --header "Authorization: Bearer dev-static-token-0123456789abcdefghij" \
  --method tools/call --tool-name upload_file \
  --tool-args-json '{"filename":"hola.md","content":"# Hola","encoding":"text"}'
```

Point `MCP_URL` at production to run the same checks there.

### Connect the clients

In every case the server URL is `$SHARE_BASE_URL/mcp`. The host discovers the OAuth endpoints, registers itself, sends you to the login page, and you enter the passphrase once.

**claude.ai (custom connector).** Settings → Connectors → *Add custom connector* → name it and paste the URL → *Add* → *Connect*. The login page opens; enter the passphrase. Free plans allow one custom connector. *Advanced settings* takes a client id and secret if you prefer a pre-registered client from `MCP_OAUTH_CLIENTS` (register `https://claude.ai/api/mcp/auth_callback` as its redirect URI, or whatever URI the connector dialog shows).

**Claude Code.**

```bash
claude mcp add --transport http share https://share.example.com/mcp
claude mcp login share        # or run /mcp inside a session and choose Authenticate
```

For a script or CI, the static token instead of OAuth:

```bash
claude mcp add --transport http share https://share.example.com/mcp \
  --header "Authorization: Bearer $MCP_STATIC_TOKEN"
```

**ChatGPT (Developer Mode).** Needs Plus, Pro, Business, Enterprise or Edu on the web. Settings → Apps → *Advanced settings* → turn on **Developer mode** (on some accounts it sits under Settings → Security and login). Then Settings → Apps → *Create* (or *Add app*): name, the URL, authentication **OAuth**, save. ChatGPT registers itself through its Client ID Metadata Document and opens the login page. Tools without `readOnlyHint` ask for confirmation before each call; `list_files` and `get_file_info` do not.

**Gemini app (Spark connected apps).** Requires a personal Google account, 18+, English, *Keep Activity* on, and setup on the web at gemini.google.com: Settings → Connected apps → *Add custom app* → paste the URL. Gemini registers itself dynamically; if its dialog insists on a client id and secret, add an entry to `MCP_OAUTH_CLIENTS` with the redirect URI the dialog shows and paste those values under *Advanced features*. Google's help notes that it does not support or secure third-party servers; at the time of writing there is an open report of Spark not calling the token endpoint after the login redirect, which nothing on the server side can fix.

**Gemini CLI.** In `~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "share": {
      "httpUrl": "https://share.example.com/mcp",
      "oauth": { "enabled": true, "authProviderType": "dynamic_discovery" }
    }
  }
}
```

Then `/mcp auth share` inside the CLI. Or with the static token and no browser:

```json
{
  "mcpServers": {
    "share": {
      "httpUrl": "https://share.example.com/mcp",
      "headers": { "Authorization": "Bearer <MCP_STATIC_TOKEN>" }
    }
  }
}
```

**Any other client.** Streamable HTTP to `$SHARE_BASE_URL/mcp`; OAuth discovery does the rest. Clients that cannot run OAuth use the static token in the `Authorization` header.

---

## Local Development & Testing

```bash
# Install dependencies
npm install

# Run automated tests (100% offline using in-memory storage)
npm test

# Run Next.js development server
npm run dev

# Run production build
npm run build
```

---

## Deploying to Vercel

1. **Import the repository.** Vercel Dashboard → **Add New → Project** → pick this repository. The framework is detected as **Next.js**; leave Build Command, Output Directory and Root Directory at their defaults.
2. **Create the Blob store.** Project → **Storage** → **Create** → **Blob**, and connect it to the project. That connection is what supplies `BLOB_READ_WRITE_TOKEN`; do not paste the token by hand.
3. **Add the environment variables** under **Settings → Environment Variables**. All of them are read at request time and fail fast when missing — there are no fallback defaults.

   | Variable | Required | What it is |
   | --- | --- | --- |
   | `BLOB_READ_WRITE_TOKEN` | yes | Comes from the connected Blob store (step 2). |
   | `SHARE_API_TOKEN` | yes | Bearer token publishing clients send to `/api/*`. |
   | `SHARE_COOKIE_SECRET` | yes | Signs unlock cookies. A distinct secret, never `SHARE_API_TOKEN`. |
   | `SHARE_BASE_URL` | yes | Canonical base URL of the deployment, e.g. `https://share.example.com`. |
   | `MCP_OAUTH_SECRET` | for `/mcp` | Signs every OAuth artefact. 32+ characters. |
   | `MCP_LOGIN_PASSPHRASE_HASH` | for `/mcp` | `npm run passphrase:hash` output. |

   The optional MCP settings are listed in `.env.example` and in [MCP server](#mcp-server).
4. **Point `SHARE_BASE_URL` at the domain you will actually share.** Add the custom domain first (**Settings → Domains**), then set the variable to it. Published links, `og:` tags and the OAuth metadata are all built from it, so changing it later invalidates links already handed out.
5. **Deploy** by pushing to `main`, or with **Redeploy** from the dashboard.

### Moving an existing project to a different repository

Keep the project rather than creating a new one: the domain, the Blob store and the environment variables stay with it, so already-published links and any connected MCP client keep working.

1. **Settings → Git → Disconnect.** Deployments, domains and variables are untouched; only auto-deploy stops.
2. Make sure Vercel's GitHub App can see the new repository (GitHub → *Settings → Applications → Vercel → Repository access*).
3. **Settings → Git → Connect Git Repository**, pick the new one, and set the production branch to `main`.
4. Renaming the project changes its generated `*.vercel.app` hostname but not custom domains. If `SHARE_BASE_URL` points at the generated hostname, update both together.

---

## License

MIT. See [LICENSE](LICENSE).
