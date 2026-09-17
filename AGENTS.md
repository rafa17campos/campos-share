# AGENTS.md — Agent Operating Contract

This repository is a lightweight Next.js application on Vercel backed by Vercel Blob. It serves standalone, unlisted share pages and raw files at:

`$SHARE_BASE_URL/<slug>`  
`$SHARE_BASE_URL/<slug>/<filename>`

This document serves as the operational contract for any AI coding agent reading, maintaining, or modifying code in this repository, or publishing content to it.

---

## 1. Publishing Workflow & The API

**Shares are NO LONGER committed as static files to `public/<slug>/`.**  
The filesystem under `public/` is reserved strictly for application-level static assets (such as `robots.txt` and icons). It is no longer the share store.

### Publishing Flow for Agents / Callers:
1. **Choose a slug**: Lowercase alphanumeric characters and single hyphens (`^[a-z0-9]+(-[a-z0-9]+)*$`). `api`, `mcp` and `oauth` are reserved for application routes.
2. **For binary assets (`kind: "generated"`)**:
   - Request presigned upload URLs:
     `POST /api/uploads` with `{ "slug": "<slug>", "files": [ { "name": "...", "contentType": "...", "sizeBytes": 123 } ] }`
   - `PUT` each file to its returned URL. An existing slug accepts names it does not hold yet; a name it holds is a `409`.
3. **Publish the share**:
   - Call `POST /api/shares` with `Authorization: Bearer <SHARE_API_TOKEN>`. To touch one file of an existing share use `POST /api/shares/{slug}/assets` (add), `PUT /api/shares/{slug}/assets/{name}` (refresh after an overwrite upload) or `DELETE /api/shares/{slug}/assets/{name}` (remove); `PUT /api/shares/{slug}` replaces the whole record.
   - Pass metadata (`slug`, `title`, `description`, `lang`, `kind`, `assets`, optional `expiresAt`, optional `password`).
   - For `kind: "uploaded"`, send the HTML content in the `html` field.
4. **Result**:
   The share is immediately live at:
   `$SHARE_BASE_URL/<slug>`

### The MCP door
The same shares are exposed as MCP tools at `$SHARE_BASE_URL/mcp` (see README, "MCP server"). Rules for anyone touching it:
* **One place for share operations**: `lib/shares.ts` creates, replaces, extends and removes shares. Both the HTTP routes under `app/api/` and the MCP tools in `lib/mcp/tools.ts` call it. Never reimplement a share write in a route or a tool.
* **Least common denominator tools**: only tools (no resources, no prompts), snake_case names, flat JSON Schemas with basic types, string enums, explicit `required` and a `description` on every field; no `anyOf`/`oneOf`/`$ref`/`additionalProperties`/`$schema`. `tests/mcp.test.mjs` enforces this on the real `tools/list`; keep that test green rather than loosening it. Nothing vendor-specific in the core (no UI widgets, no vendor `_meta`).
* **Tool failures are results**: return `{ isError: true }` with an actionable message; never throw out of a tool handler.
* **Every tool carries annotations** (`readOnlyHint`, `destructiveHint`, `idempotentHint`) and an `outputSchema`, and returns both text `content` and `structuredContent`. `upload_file` never overwrites; replacing content is `update_file` (or `create_upload_url` with `overwrite`), marked destructive so hosts ask before running it.
* **A page is not a folder**: `kind: "uploaded"` stores its HTML at `<slug>/__page.html`, a reserved name no file operation can reach, so the file tools refuse a page and every such refusal names `publish_page` or `update_page` instead. Those two go through `createShare`/`replaceShare` like everything else; never write `__page.html` from a tool.
* **The authorization server keeps no state**: client ids, codes and tokens are signed with `MCP_OAUTH_SECRET` (`lib/oauth/`). Adding a store for them reopens the no-database decision. The only login is the passphrase whose scrypt hash is `MCP_LOGIN_PASSPHRASE_HASH`.
* **Static routes shadow slugs**: `app/mcp`, `app/oauth` and `app/.well-known` win over `app/[slug]`, which is why those slugs are reserved in `lib/shares.ts`.

---

## 2. Core Architectural Invariants

* **Blob Storage Only (Zero Database)**:
  * Strict standing constraint: No database (no Postgres, SQLite, Redis, or ORM).
  * Storage is partitioned in Blob under `<slug>/__meta.json` and `<slug>/<filename>`.
  * `__meta.json` is the sole source of truth. Link expiry is a date comparison at read time; password protection is a constant-time scrypt hash comparison at read time.
  * Adding a feature that requires a database requires reopening this architectural decision first.
* **Record writes are conditional**:
  * `lib/shares.ts` changes a share through `mutateShare`: read the record with its ETag, compute the new record, `saveMeta` with `ifMatch`, retry on `MetaConflictError`. Adding, replacing, syncing and removing a single file all go through it. A write that starts from a read and saves unconditionally is a bug, because Blob has no transactions and the other caller's change would vanish.
  * Prune blobs after the record is written, never before, so a write that loses the race deletes nothing.
* **Single Storage Module (Repatriation Escape Hatch)**:
  * `@vercel/blob` must ONLY be imported and called inside `lib/storage.ts`.
  * No other file in the repository may import from `@vercel/blob` or `@vercel/blob/client`.
  * Keep Next.js standard Node.js runtime only—no edge-runtime exclusives, no proprietary caching.
* **Template Invariants ("The Validator Ascends into the Template")**:
  * Metadata rules hold by construction in `lib/renderer.ts`:
    * `<html lang="...">` matching content language.
    * Non-empty, unique `<title>`.
    * `<meta name="viewport" content="...">`.
    * `<meta name="description" content="...">`.
    * `<meta name="robots" content="noindex,nofollow">`.
    * Open Graph tags (`og:title`, `og:description`, `og:type`).
  * `og:image` is generated ONLY when the share has an image asset AND is neither password-protected nor expiring.
* **Caching that survives an in-place update**:
  * Public, non-expiring share pages (`GET /[slug]`): `public, max-age=0, must-revalidate` with `ETag` and `304 Not Modified`.
  * Public, non-expiring raw assets (`GET /[slug]/<filename>`): `public, max-age=0, must-revalidate` with the store's `ETag`; `If-None-Match` is forwarded to Blob so an unchanged file is a `304` with no transfer. Never `immutable`: a file can be replaced behind the same URL (`overwrite` on `POST /api/uploads`, `update_file` in MCP).
  * Password-protected shares and assets: `private, no-cache`.
  * Expiring shares and assets: `private, max-age=0, must-revalidate`.
  * Every storage read bypasses Blob's CDN cache (`useCache: false` in `lib/storage.ts`) and every write sets the shortest `cacheControlMaxAge`. Blob serves cached reads for up to a minute after a delete or overwrite; a stale `__meta.json` makes a deleted share read as existing and drops files from the next write. Do not reintroduce cached reads of the record.
* **Zero Secrets & No Fallback Defaults (Strict)**:
  * Never commit or publish secrets, API keys, passwords, bearer tokens, private keys, or `.env` files. There are NO exceptions.
  * Required environment variables (`SHARE_API_TOKEN`, `SHARE_COOKIE_SECRET`, `SHARE_BASE_URL`, and for `/mcp` `MCP_OAUTH_SECRET` and `MCP_LOGIN_PASSPHRASE_HASH`) must fail fast if missing—never fall back to literals or silently degrade. Optional MCP settings (`MCP_STATIC_TOKEN`, `MCP_STATIC_TOKEN_SCOPES`, `MCP_OAUTH_CLIENTS`, `MCP_ALLOWED_ORIGINS`, `SHARE_DEFAULT_LANG`) are documented in `.env.example`.
  * Secret scanning should be enforced before upload. Do not add commit-time scanners to this repo.
* **Preserve Spanish Accents**:
  * Preserve characters `á`, `é`, `í`, `ó`, `ú`, `ñ` in code, content, templates, and docs.

---

## 3. Verification & Quality Gate

Before completing any task, run the test suite and verify the Next.js production build:

```bash
# 1. Run automated unit and API integration tests
npm test

# 2. Verify Next.js production build
npm run build
```

Every test must pass with zero errors, and `npm run build` must compile cleanly.

---

## 4. Final Response Contract

When completing any share creation or service change, the agent's final message to the user **must state the expected production URL**:

`$SHARE_BASE_URL/<slug>`
