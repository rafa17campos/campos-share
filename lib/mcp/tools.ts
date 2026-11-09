/**
 * lib/mcp/tools.ts
 *
 * The tools the MCP endpoint offers, on top of the share operations in lib/shares.ts. The model
 * they present is a flat one: a *folder* is a share (its slug is the `prefix`), a *file* is an
 * asset in it, and a `path` is `<prefix>/<filename>`. Every tool returns readable text and the
 * same data as `structuredContent`, except read_file, whose result is content rather than data and
 * goes out as text alone. Every failure is a tool result with `isError`, never an exception, so the
 * model can read what went wrong and try again.
 */

import crypto from 'node:crypto';
import type { AuthInfo, CallToolResult, McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod';
import type { ShareMeta, StorageProvider } from '../storage.ts';
import {
  appendAssets,
  assetUrl,
  contentVersion,
  createShare,
  deleteShare,
  hasExpired,
  isRejection,
  isValidAssetName,
  isValidSlug,
  issueUploadUrls,
  listShares,
  PAGE_ASSET_NAME,
  removeAsset,
  replaceAssetContent,
  replaceShare,
  sha256Hex,
  shareUrl,
  syncAssetFromStorage,
  toShareSummary,
  type ShareInputRejection,
} from '../shares.ts';
import { MAX_INLINE_BYTES, SCOPE_DELETE, SCOPE_READ, SCOPE_WRITE, getDefaultLang } from './config.ts';
import { lcd, mimeFromFilename } from './schema.ts';
import {
  DB_LIMITS,
  checkDbAccess,
  deleteDocument,
  getDocument,
  listCollections,
  listDocuments,
  writeDocument,
  type DbDocument,
} from '../pageDb.ts';

export type ToolDeps = { storage: StorageProvider };

type ToolContext = { http?: { authInfo?: AuthInfo }; authInfo?: AuthInfo };

/* ------------------------------------------------------------------------------------------ */
/* Results                                                                                     */
/* ------------------------------------------------------------------------------------------ */

function ok(text: string, structured: Record<string, unknown>): CallToolResult {
  return { content: [{ type: 'text', text }], structuredContent: structured };
}

function fail(message: string): CallToolResult {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function failRejection(rejection: ShareInputRejection): CallToolResult {
  if (rejection.status === 412) {
    return fail(
      `${rejection.error}. Someone changed it after you read it: call read_file again and apply your change to the current content.`
    );
  }
  return fail(rejection.error);
}

const versionInput = z
  .string()
  .max(200)
  .optional()
  .describe(
    'The "version" read_file returned for the content you edited. When given, nothing is written if the content ' +
      'changed since then; omit it to overwrite whatever is there.'
  );

/** Content types whose bytes read_file returns as text when they are valid UTF-8. */
function isTextType(contentType: string): boolean {
  const type = contentType.split(';')[0].trim().toLowerCase();
  return (
    type.startsWith('text/') ||
    /^application\/(json|xml|javascript|ecmascript|x-javascript|x-sh|x-yaml|yaml|toml|sql|graphql|ld\+json|manifest\+json)$/.test(type) ||
    type.endsWith('+json') ||
    type.endsWith('+xml')
  );
}

function scopesOf(ctx: ToolContext): string[] {
  return ctx.http?.authInfo?.scopes ?? ctx.authInfo?.scopes ?? [];
}

function requireScope(ctx: ToolContext, scope: string): CallToolResult | null {
  if (scopesOf(ctx).includes(scope)) return null;
  return fail(`This action needs the "${scope}" permission, which the current credentials do not carry.`);
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/* ------------------------------------------------------------------------------------------ */
/* Paths and names                                                                             */
/* ------------------------------------------------------------------------------------------ */

type ParsedPath = { prefix: string; filename: string | null };

function parsePath(path: string): ParsedPath | CallToolResult {
  const trimmed = path.trim().replace(/^\/+/, '');
  const slash = trimmed.indexOf('/');
  const prefix = slash < 0 ? trimmed : trimmed.slice(0, slash);
  const filename = slash < 0 ? null : trimmed.slice(slash + 1);
  if (!isValidSlug(prefix)) {
    return fail(`"${prefix}" is not a valid prefix: lowercase letters, digits and single hyphens only.`);
  }
  if (filename !== null && !isValidAssetName(filename)) {
    return fail(`"${filename}" is not a valid file name.`);
  }
  return { prefix, filename };
}

/** The bytes a tool call carries, or the tool error explaining why they could not be read. */
function decodeContent(content: string, encoding: 'text' | 'base64'): Buffer | CallToolResult {
  let bytes: Buffer;
  if (encoding === 'base64') {
    const clean = content.replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 === 1) {
      return fail('content is not valid base64. Encode the bytes with standard base64 (with or without padding).');
    }
    bytes = Buffer.from(clean, 'base64');
  } else {
    bytes = Buffer.from(content, 'utf8');
  }
  if (bytes.length === 0) return fail('content is empty; nothing to upload.');
  if (bytes.length > MAX_INLINE_BYTES) {
    return fail(
      `The content is ${formatBytes(bytes.length)}, above the ${MAX_INLINE_BYTES / (1024 * 1024)} MB limit for inline uploads. ` +
        'Call create_upload_url with the file name, content type and size, PUT the bytes to the returned URL, then call complete_upload.'
    );
  }
  return bytes;
}

/** The document a page tool carries, or the tool error explaining why it cannot be published. */
function readHtml(html: string): string | CallToolResult {
  if (html.trim().length === 0) return fail('html is empty; nothing to publish.');
  const size = Buffer.byteLength(html, 'utf8');
  if (size > MAX_INLINE_BYTES) {
    return fail(
      `The document is ${formatBytes(size)}, above the ${MAX_INLINE_BYTES / (1024 * 1024)} MB limit for a page. ` +
        'Publish its images, stylesheets and scripts as files of their own with upload_file and link to them from the page.'
    );
  }
  return html;
}

const MIN_PAGE_PASSWORD_LENGTH = 8;

/** The expiry a page tool was given, trimmed, with "" meaning none; or the tool error explaining why it cannot be used. */
function readExpiresArg(raw: string | undefined, emptyMeans: string): string | undefined | CallToolResult {
  if (raw === undefined) return undefined;
  const value = raw.trim();
  if (value === '') return '';
  const at = new Date(value).getTime();
  if (Number.isNaN(at)) {
    return fail(`"expires_at" is not a date this can read: "${value}". Use ISO 8601, or ${emptyMeans}.`);
  }
  if (at <= Date.now()) {
    return fail(`"expires_at" is in the past: "${value}". Use a future ISO 8601 date, or ${emptyMeans}.`);
  }
  return value;
}

/** The password a page tool was given, with "" meaning none; or the tool error explaining why it cannot be used. */
function readPasswordArg(raw: string | undefined, emptyMeans: string): string | undefined | CallToolResult {
  if (raw === undefined || raw === '') return raw;
  if (raw.trim() !== raw) {
    return fail(`"password" starts or ends with whitespace, which a visitor would not type. Send it without it, or ${emptyMeans}.`);
  }
  if (raw.length < MIN_PAGE_PASSWORD_LENGTH) {
    return fail(`"password" is shorter than ${MIN_PAGE_PASSWORD_LENGTH} characters. Send a longer one, or ${emptyMeans}.`);
  }
  return raw;
}

/** How a page is reached, for the text result: whether it asks for a password and when it stops being served. */
function describeAccess(meta: ShareMeta): string {
  const parts = [meta.passwordHash ? 'password protected' : 'no password'];
  parts.push(meta.expiresAt ? `expires ${meta.expiresAt}` : 'no expiry');
  if (meta.database) parts.push('with a database');
  return parts.join(', ');
}

function checkFilename(filename: string): CallToolResult | null {
  if (!isValidAssetName(filename)) {
    return fail(
      `"${filename}" is not a valid file name: no leading slash, no "..", no backslash, no segment starting with "__".`
    );
  }
  return null;
}

/** A slug derived from a file name plus a short random tail, so two uploads never collide. */
export function slugFromFilename(filename: string): string {
  const bare = (filename.split('/').pop() ?? filename).replace(/\.[^.]+$/, '');
  const base = bare
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40)
    .replace(/-+$/g, '');
  const tail = crypto.randomInt(0, 36 ** 6).toString(36).padStart(6, '0');
  return `${base || 'file'}-${tail}`;
}

async function chooseSlug(storage: StorageProvider, prefix: string | undefined, filename: string) {
  if (prefix !== undefined && prefix !== '') {
    if (!isValidSlug(prefix)) {
      return fail(`"${prefix}" is not a valid prefix: lowercase letters, digits and single hyphens only ("api", "mcp" and "oauth" are reserved).`);
    }
    return prefix;
  }
  for (let attempt = 0; attempt < 5; attempt++) {
    const candidate = slugFromFilename(filename);
    if (!(await storage.getMeta(candidate))) return candidate;
  }
  return fail('Could not find a free prefix; pass one explicitly.');
}

/* ------------------------------------------------------------------------------------------ */
/* Views                                                                                       */
/* ------------------------------------------------------------------------------------------ */

const fileItemSchema = z.object({
  path: z.string().describe('The file path, "<prefix>/<filename>". Use it with get_file_info and delete_file.'),
  prefix: z.string().describe('The folder the file lives in.'),
  filename: z.string().describe('The file name inside the folder.'),
  size_bytes: z.number().int().describe('File size in bytes.'),
  content_type: z.string().describe('The MIME type the file is served with.'),
  created_at: z.string().describe('When the folder was created, ISO 8601.'),
  url: z.string().describe('Public URL of the raw file.'),
  page_url: z.string().describe('Public URL of the folder page that lists and previews its files.'),
});

type FileItem = z.infer<typeof fileItemSchema>;

const pageItemSchema = z.object({
  prefix: z.string().describe('The page name, which is also its path on the site. Use it with get_file_info and update_page.'),
  title: z.string().describe('Title of the page.'),
  created_at: z.string().describe('When the page was published, ISO 8601.'),
  url: z.string().describe('Public URL of the page.'),
});

type PageItem = z.infer<typeof pageItemSchema>;

function fileItems(meta: ShareMeta): FileItem[] {
  return meta.assets.map((a) => ({
    path: `${meta.slug}/${a.name}`,
    prefix: meta.slug,
    filename: a.name,
    size_bytes: a.sizeBytes,
    content_type: a.contentType,
    created_at: meta.createdAt,
    url: assetUrl(meta.slug, a.name),
    page_url: shareUrl(meta.slug),
  }));
}

function describeFile(item: FileItem): string {
  return `${item.path} (${formatBytes(item.size_bytes)}, ${item.content_type})\n  file: ${item.url}\n  page: ${item.page_url}`;
}

/* ------------------------------------------------------------------------------------------ */
/* Registration                                                                                */
/* ------------------------------------------------------------------------------------------ */

export function registerShareTools(server: McpServer, deps: ToolDeps): void {
  const { storage } = deps;

  /* ---------------------------------------------------------------- upload_file ---------- */
  server.registerTool(
    'upload_file',
    {
      title: 'Upload a file',
      description:
        'Publish a file and get its public URL. Send the content inline: encoding "text" for UTF-8 text such as ' +
        'markdown, HTML, CSV or JSON, encoding "base64" for binary files such as images or PDFs. Decoded content ' +
        `must be at most ${MAX_INLINE_BYTES / (1024 * 1024)} MB; for anything larger, or when you can run a shell, use ` +
        'create_upload_url instead. Omit "prefix" to create a new folder named after the file; pass an existing ' +
        'prefix to add the file to that folder. A file name that already exists in the folder is rejected, never overwritten.',
      inputSchema: lcd(
        z.object({
          filename: z
            .string()
            .min(1)
            .max(255)
            .describe('File name including extension, e.g. "informe.pdf". May contain "/" for a subfolder.'),
          content: z.string().describe('The file content, as UTF-8 text or as base64 according to "encoding".'),
          encoding: z
            .enum(['text', 'base64'])
            .describe('"text" when content is plain UTF-8 text, "base64" when it is base64-encoded binary.'),
          content_type: z
            .string()
            .max(200)
            .optional()
            .describe('MIME type to serve the file with. Defaults to a type derived from the file extension.'),
          prefix: z
            .string()
            .max(80)
            .optional()
            .describe('Folder to put the file in: lowercase letters, digits and hyphens. Created if it does not exist. Defaults to a new folder derived from the file name.'),
          title: z
            .string()
            .max(200)
            .optional()
            .describe('Title shown on the folder page when the folder is created. Defaults to the file name.'),
        })
      ),
      outputSchema: lcd(
        z.object({
          path: z.string().describe('The file path, "<prefix>/<filename>".'),
          url: z.string().describe('Public URL of the raw file.'),
          page_url: z.string().describe('Public URL of the folder page.'),
          prefix: z.string().describe('The folder the file was stored in.'),
          filename: z.string().describe('The stored file name.'),
          size_bytes: z.number().int().describe('Size of the stored file in bytes.'),
          content_type: z.string().describe('MIME type the file is served with.'),
          folder_created: z.boolean().describe('True when the call created the folder, false when the file joined an existing one.'),
        })
      ),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async (args, ctx) => {
      const denied = requireScope(ctx as ToolContext, SCOPE_WRITE);
      if (denied) return denied;
      const bad = checkFilename(args.filename);
      if (bad) return bad;

      const bytes = decodeContent(args.content, args.encoding);
      if (!Buffer.isBuffer(bytes)) return bytes;

      const contentType =
        args.content_type?.trim() ||
        mimeFromFilename(args.filename) ||
        (args.encoding === 'text' ? 'text/plain; charset=utf-8' : 'application/octet-stream');

      const slug = await chooseSlug(storage, args.prefix, args.filename);
      if (typeof slug !== 'string') return slug;

      const existing = await storage.getMeta(slug);
      if (existing) {
        if (existing.kind !== 'generated') {
          return fail(
            `The prefix "${slug}" is a published page, not a folder, and cannot hold files. Use update_page to replace its content, or choose another prefix.`
          );
        }
        if (existing.assets.some((a) => a.name === args.filename)) {
          return fail(`"${slug}/${args.filename}" already exists. upload_file never overwrites: use update_file to replace its content, or choose another file name.`);
        }
      }

      await storage.putAsset(slug, args.filename, bytes, contentType);

      const asset = { name: args.filename, originalName: args.filename, contentType, sha256: sha256Hex(bytes) };
      const result = existing
        ? await appendAssets(storage, slug, [asset])
        : await createShare(storage, slug, {
            title: args.title?.trim() || args.filename,
            lang: getDefaultLang(),
            kind: 'generated',
            assets: [asset],
          });
      if (isRejection(result)) {
        await storage.deleteBlobs([`${slug}/${args.filename}`]).catch(() => undefined);
        return failRejection(result);
      }

      const structured = {
        path: `${slug}/${args.filename}`,
        url: assetUrl(slug, args.filename),
        page_url: shareUrl(slug),
        prefix: slug,
        filename: args.filename,
        size_bytes: bytes.length,
        content_type: contentType,
        folder_created: result.created,
      };
      return ok(
        `Uploaded ${structured.path} (${formatBytes(bytes.length)}, ${contentType}).\nFile URL: ${structured.url}\nPage URL: ${structured.page_url}`,
        structured
      );
    }
  );

  /* ---------------------------------------------------------------- update_file ---------- */
  server.registerTool(
    'update_file',
    {
      title: 'Update a file',
      description:
        'Replace the content of an existing file, keeping its URL. Send the whole new content inline, ' +
        `encoding "text" or "base64", at most ${MAX_INLINE_BYTES / (1024 * 1024)} MB decoded; for larger files use ` +
        'create_upload_url with "overwrite": true and then complete_upload. The previous content is lost. ' +
        'To edit what is there, read it first with read_file and pass the "version" it returns, so a change made ' +
        'in between is not overwritten. To publish a file that does not exist yet, use upload_file instead.',
      inputSchema: lcd(
        z.object({
          path: z.string().min(3).max(340).describe('The file to replace, "<prefix>/<filename>".'),
          content: z.string().describe('The complete new content, as UTF-8 text or as base64 according to "encoding".'),
          encoding: z
            .enum(['text', 'base64'])
            .describe('"text" when content is plain UTF-8 text, "base64" when it is base64-encoded binary.'),
          content_type: z
            .string()
            .max(200)
            .optional()
            .describe('New MIME type to serve the file with. Defaults to the type it already has.'),
          version: versionInput,
        })
      ),
      outputSchema: lcd(
        z.object({
          path: z.string().describe('The file path.'),
          url: z.string().describe('Public URL of the raw file, unchanged.'),
          page_url: z.string().describe('Public URL of the folder page.'),
          size_bytes: z.number().int().describe('Size of the new content in bytes.'),
          previous_size_bytes: z.number().int().describe('Size of the content that was replaced.'),
          content_type: z.string().describe('MIME type the file is served with.'),
          updated_at: z.string().describe('When the replacement happened, ISO 8601.'),
          version: z.string().describe('Version of the new content; pass it to the next update_file to chain edits without reading again.'),
        })
      ),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    },
    async (args, ctx) => {
      const denied = requireScope(ctx as ToolContext, SCOPE_WRITE);
      if (denied) return denied;
      const parsed = parsePath(args.path);
      if ('content' in parsed) return parsed;
      if (parsed.filename === null) return fail('path must name a file: "<prefix>/<filename>".');
      const { prefix, filename } = parsed;

      const meta = await storage.getMeta(prefix);
      if (!meta) return fail(`Nothing is published under "${prefix}". Use upload_file to publish a new file.`);
      if (meta.kind !== 'generated') {
        return fail(
          `"${prefix}" is a published page, not a folder, so it holds no files. Use update_page with prefix "${prefix}" to replace its content.`
        );
      }
      const current = meta.assets.find((a) => a.name === filename);
      if (!current) {
        const names = meta.assets.map((a) => a.name).join(', ') || '(none)';
        return fail(`"${prefix}" has no file named "${filename}" (it has: ${names}). Use upload_file to publish a new file.`);
      }

      const bytes = decodeContent(args.content, args.encoding);
      if (!Buffer.isBuffer(bytes)) return bytes;
      const contentType = args.content_type?.trim() || current.contentType;

      const result = await replaceAssetContent(storage, prefix, filename, bytes, contentType, { ifVersion: args.version?.trim() || undefined });
      if (isRejection(result)) return failRejection(result);
      const stored = result.meta.assets.find((a) => a.name === filename);

      const structured = {
        path: `${prefix}/${filename}`,
        url: assetUrl(prefix, filename),
        page_url: shareUrl(prefix),
        size_bytes: bytes.length,
        previous_size_bytes: current.sizeBytes,
        content_type: contentType,
        updated_at: stored?.updatedAt ?? new Date().toISOString(),
        version: stored?.etag ? contentVersion(stored.etag) : '',
      };
      return ok(
        `Updated ${structured.path}: ${formatBytes(current.sizeBytes)} -> ${formatBytes(bytes.length)}, ${contentType}, version ${structured.version}. The URL is unchanged: ${structured.url}`,
        structured
      );
    }
  );

  /* ---------------------------------------------------------- create_upload_url ---------- */
  server.registerTool(
    'create_upload_url',
    {
      title: 'Create an upload URL',
      description:
        'Get a short-lived signed URL to upload one file directly with an HTTP PUT, for files up to 20 MB and for ' +
        'clients that can run curl or code. The upload URL expires in 15 minutes and is bound to the exact content ' +
        'type and size you declare. After the PUT succeeds, call complete_upload with the returned path to publish ' +
        'the file; until then it is not public. Prefer upload_file for small text or binary content you already hold. ' +
        'Pass "overwrite": true to replace an existing file behind the same URL.',
      inputSchema: lcd(
        z.object({
          filename: z.string().min(1).max(255).describe('File name including extension, e.g. "video.mp4".'),
          content_type: z.string().min(1).max(200).describe('MIME type of the file, e.g. "application/pdf". The PUT must send exactly this Content-Type.'),
          size_bytes: z.number().int().min(1).describe('Exact size of the file in bytes. The PUT must send exactly this many bytes.'),
          prefix: z
            .string()
            .max(80)
            .optional()
            .describe('Folder to put the file in. Created on complete_upload if it does not exist. Defaults to a new folder derived from the file name.'),
          overwrite: z
            .boolean()
            .optional()
            .describe('Allow replacing a file that already exists at this path. Its previous content is lost once the PUT succeeds. Default false.'),
        })
      ),
      outputSchema: lcd(
        z.object({
          upload_url: z.string().describe('Signed URL to PUT the bytes to.'),
          method: z.string().describe('HTTP method to use: always "PUT".'),
          content_type_header: z.string().describe('Value the Content-Type request header must carry.'),
          expires_at: z.string().describe('When the upload URL stops working, ISO 8601.'),
          path: z.string().describe('The file path to pass to complete_upload once the PUT has succeeded.'),
          prefix: z.string().describe('The folder the file will live in.'),
          filename: z.string().describe('The file name.'),
          url: z.string().describe('Public URL the file will have after complete_upload.'),
          page_url: z.string().describe('Public URL of the folder page after complete_upload.'),
          curl_example: z.string().describe('A ready-to-run curl command for the upload.'),
        })
      ),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async (args, ctx) => {
      const denied = requireScope(ctx as ToolContext, SCOPE_WRITE);
      if (denied) return denied;
      const bad = checkFilename(args.filename);
      if (bad) return bad;

      const slug = await chooseSlug(storage, args.prefix, args.filename);
      if (typeof slug !== 'string') return slug;

      const existing = await storage.getMeta(slug);
      if (existing && existing.kind !== 'generated') {
        return fail(
          `The prefix "${slug}" is a published page, not a folder, and cannot hold files. Use update_page to replace its content, or choose another prefix.`
        );
      }

      const issued = await issueUploadUrls(storage, slug, [
        { name: args.filename, contentType: args.content_type, sizeBytes: args.size_bytes, overwrite: args.overwrite === true },
      ]);
      if (isRejection(issued)) return failRejection(issued);

      const token = issued.tokens[0];
      const structured = {
        upload_url: token.uploadUrl,
        method: 'PUT',
        content_type_header: args.content_type,
        expires_at: new Date(issued.validUntil).toISOString(),
        path: `${slug}/${args.filename}`,
        prefix: slug,
        filename: args.filename,
        url: assetUrl(slug, args.filename),
        page_url: shareUrl(slug),
        curl_example: `curl -f -X PUT -H 'Content-Type: ${args.content_type}' --data-binary @'${args.filename}' '${token.uploadUrl}'`,
      };
      return ok(
        `Upload URL ready for ${structured.path} (expires ${structured.expires_at}).\n` +
          `1. PUT exactly ${args.size_bytes} bytes with Content-Type: ${args.content_type}:\n   ${structured.curl_example}\n` +
          `2. Then call complete_upload with path "${structured.path}".\n` +
          `The file will be public at ${structured.url}`,
        structured
      );
    }
  );

  /* ------------------------------------------------------------ complete_upload ---------- */
  server.registerTool(
    'complete_upload',
    {
      title: 'Complete an upload',
      description:
        'Publish a file that was uploaded through a create_upload_url URL, making it public and returning its URL. ' +
        'Safe to call again: a file that is already published is reported as such, and one whose bytes were ' +
        'replaced with an overwrite upload has its record refreshed. Fails if the PUT has not happened yet or ' +
        'the upload URL expired unused.',
      inputSchema: lcd(
        z.object({
          path: z.string().min(3).max(340).describe('The path returned by create_upload_url, "<prefix>/<filename>".'),
          content_type: z
            .string()
            .max(200)
            .optional()
            .describe('MIME type to serve the file with. Defaults to the type declared to create_upload_url.'),
          title: z
            .string()
            .max(200)
            .optional()
            .describe('Title for the folder page when this call creates the folder. Defaults to the file name.'),
        })
      ),
      outputSchema: lcd(
        z.object({
          path: z.string().describe('The file path.'),
          url: z.string().describe('Public URL of the raw file.'),
          page_url: z.string().describe('Public URL of the folder page.'),
          prefix: z.string().describe('The folder the file lives in.'),
          filename: z.string().describe('The file name.'),
          size_bytes: z.number().int().describe('Size of the published file in bytes.'),
          content_type: z.string().describe('MIME type the file is served with.'),
          already_published: z.boolean().describe('True when the file had been published before this call.'),
        })
      ),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (args, ctx) => {
      const denied = requireScope(ctx as ToolContext, SCOPE_WRITE);
      if (denied) return denied;
      const parsed = parsePath(args.path);
      if ('content' in parsed) return parsed;
      if (parsed.filename === null) return fail('path must name a file: "<prefix>/<filename>".');
      const { prefix, filename } = parsed;

      const existing = await storage.getMeta(prefix);
      const published = existing?.assets.find((a) => a.name === filename);
      if (existing && published) {
        const synced = await syncAssetFromStorage(storage, prefix, filename, { contentType: args.content_type?.trim() || undefined });
        if (isRejection(synced)) return failRejection(synced);
        const now = synced.meta.assets.find((a) => a.name === filename) ?? published;
        const structured = {
          path: `${prefix}/${filename}`,
          url: assetUrl(prefix, filename),
          page_url: shareUrl(prefix),
          prefix,
          filename,
          size_bytes: now.sizeBytes,
          content_type: now.contentType,
          already_published: !synced.changed,
        };
        const text = synced.changed
          ? `Replaced the content of ${structured.path} (${formatBytes(now.sizeBytes)}, ${now.contentType}); the URL is unchanged.`
          : `${structured.path} was already published.`;
        return ok(`${text}\nFile URL: ${structured.url}\nPage URL: ${structured.page_url}`, structured);
      }

      const head = await storage.headAsset(prefix, filename);
      if (!head || !head.exists) {
        return fail(
          `No uploaded bytes found at "${prefix}/${filename}". Either the PUT to the upload URL has not succeeded yet, or the URL expired: call create_upload_url again.`
        );
      }
      const contentType = args.content_type?.trim() || head.contentType || mimeFromFilename(filename) || 'application/octet-stream';
      const asset = { name: filename, originalName: filename, contentType };
      const result = existing
        ? await appendAssets(storage, prefix, [asset])
        : await createShare(storage, prefix, {
            title: args.title?.trim() || filename,
            lang: getDefaultLang(),
            kind: 'generated',
            assets: [asset],
          });
      if (isRejection(result)) return failRejection(result);

      const stored = result.meta.assets.find((a) => a.name === filename);
      const structured = {
        path: `${prefix}/${filename}`,
        url: assetUrl(prefix, filename),
        page_url: shareUrl(prefix),
        prefix,
        filename,
        size_bytes: stored?.sizeBytes ?? head.size,
        content_type: contentType,
        already_published: false,
      };
      return ok(
        `Published ${structured.path} (${formatBytes(structured.size_bytes)}, ${contentType}).\nFile URL: ${structured.url}\nPage URL: ${structured.page_url}`,
        structured
      );
    }
  );

  /* --------------------------------------------------------------- publish_page ---------- */
  server.registerTool(
    'publish_page',
    {
      title: 'Publish a page',
      description:
        'Publish an HTML document as a page of its own. Its URL is the prefix and nothing else: no folder ' +
        'listing around it, no file name after it. Send the whole document inline as UTF-8 text, at most ' +
        `${MAX_INLINE_BYTES / (1024 * 1024)} MB; a missing lang attribute, title, description, viewport or robots ` +
        'tag is added to its <head> when it is served. A prefix that is already taken is rejected, never ' +
        'overwritten: use update_page to replace the content of a page that exists. Pass "password" to make ' +
        'visitors enter one before they see it, and "expires_at" to stop serving it at a date. Pass "database": true ' +
        'to give the page a small data store shared by every visitor (a poll, a sign-up sheet, a checklist): the page ' +
        'reads and writes it through window.shareDb (see the "database" field), and you through read_page_data and ' +
        'write_page_data. For an HTML file that should sit in a folder alongside other files, use upload_file instead.',
      inputSchema: lcd(
        z.object({
          prefix: z
            .string()
            .min(1)
            .max(80)
            .describe('Name the page is published under, which is also its path on the site: lowercase letters, digits and single hyphens ("api", "mcp" and "oauth" are reserved).'),
          html: z.string().describe('The complete HTML document, as UTF-8 text.'),
          title: z.string().min(1).max(200).describe('Title of the page, used for <title> and og:title when the document has none.'),
          description: z
            .string()
            .max(500)
            .optional()
            .describe('Short description, used for the description meta tag and og:description when the document has none.'),
          lang: z
            .string()
            .max(20)
            .optional()
            .describe('Content language as a BCP 47 tag, e.g. "es". Defaults to the language configured for this service.'),
          password: z
            .string()
            .max(200)
            .optional()
            .describe(
              `Password visitors must enter to open the page, at least ${MIN_PAGE_PASSWORD_LENGTH} characters with no leading or ` +
                'trailing whitespace. Omit it, or send an empty string, for a page anyone with the URL can open.'
            ),
          expires_at: z
            .string()
            .optional()
            .describe('When the page stops being served, a future ISO 8601 date. Omit it for a page with no expiry.'),
          database: z
            .boolean()
            .optional()
            .describe(
              'Give the page a shared database. Its scripts then find window.shareDb, whose methods return promises: ' +
                'collections() -> [{name, count}]; list(collection) -> [{id, data, createdAt, updatedAt}] oldest first; ' +
                'get(collection, id) -> document or null; add(collection, data) -> document with a new id; ' +
                'set(collection, id, data) creates or replaces; update(collection, id, object) shallow-merges; ' +
                'remove(collection, id) -> whether it existed. data is any JSON value. Collection names: lowercase ' +
                'letters, digits, "_" and "-"; ids: letters, digits, "_" and "-". Every visitor shares the same data; ' +
                'there are no live updates (poll list() to refresh) and no per-visitor identity. Limits: ' +
                `${DB_LIMITS.documentBytes / 1024} KB per document, ${DB_LIMITS.storeBytes / (1024 * 1024)} MB per page.`
            ),
        })
      ),
      outputSchema: lcd(
        z.object({
          prefix: z.string().describe('The name the page was published under.'),
          url: z.string().describe('Public URL of the page.'),
          page_url: z.string().describe('Public URL of the page, same as "url", for symmetry with the file tools.'),
          title: z.string().describe('Title stored for the page.'),
          size_bytes: z.number().int().describe('Size of the published document in bytes.'),
          created_at: z.string().describe('When the page was published, ISO 8601.'),
          expires_at: z.string().optional().describe('When the page stops being served, if an expiry is set.'),
          password_protected: z.boolean().describe('Whether visitors need a password to open the page.'),
          database: z.boolean().describe('Whether the page has a shared database (window.shareDb).'),
        })
      ),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async (args, ctx) => {
      const denied = requireScope(ctx as ToolContext, SCOPE_WRITE);
      if (denied) return denied;

      const prefix = args.prefix.trim().replace(/^\/+|\/+$/g, '');
      if (!isValidSlug(prefix)) {
        return fail(`"${prefix}" is not a valid page name: lowercase letters, digits and single hyphens only ("api", "mcp" and "oauth" are reserved).`);
      }
      const html = readHtml(args.html);
      if (typeof html !== 'string') return html;

      const publishExpiresAt = readExpiresArg(args.expires_at, 'omit it for no expiry');
      if (typeof publishExpiresAt === 'object') return publishExpiresAt;
      const publishPassword = readPasswordArg(args.password, 'omit it for a page anyone with the URL can open');
      if (typeof publishPassword === 'object') return publishPassword;

      const existing = await storage.getMeta(prefix);
      if (existing) {
        return fail(
          existing.kind === 'uploaded'
            ? `A page is already published at "${prefix}". publish_page never overwrites: use update_page to replace its content, or choose another prefix.`
            : `"${prefix}" is a folder of files, not a page; choose another prefix.`
        );
      }

      const result = await createShare(storage, prefix, {
        title: args.title.trim(),
        description: args.description?.trim() || undefined,
        lang: args.lang?.trim() || getDefaultLang(),
        kind: 'uploaded',
        html,
        ...(publishExpiresAt ? { expiresAt: publishExpiresAt } : {}),
        ...(publishPassword ? { password: publishPassword } : {}),
        ...(args.database ? { database: true } : {}),
      });
      if (isRejection(result)) return failRejection(result);

      const structured = {
        prefix,
        url: shareUrl(prefix),
        page_url: shareUrl(prefix),
        title: result.meta.title,
        size_bytes: Buffer.byteLength(html, 'utf8'),
        created_at: result.meta.createdAt,
        expires_at: result.meta.expiresAt ?? undefined,
        password_protected: Boolean(result.meta.passwordHash),
        database: Boolean(result.meta.database),
      };
      return ok(
        `Published the page "${structured.title}" (${formatBytes(structured.size_bytes)} of HTML; ${describeAccess(result.meta)}).\nPage URL: ${structured.url}`,
        structured
      );
    }
  );

  /* ---------------------------------------------------------------- update_page ---------- */
  server.registerTool(
    'update_page',
    {
      title: 'Update a page',
      description:
        'Replace the content of a published page, keeping its URL. Send the complete new document inline as ' +
        `UTF-8 text, at most ${MAX_INLINE_BYTES / (1024 * 1024)} MB; the previous content is lost. Title, ` +
        'description, language, expiry and password keep their stored value unless you pass a new one. To edit the page, read its ' +
        'current HTML with read_file, change it, and send it back with the "version" read_file returned, so a ' +
        'change made in between is not overwritten. To publish a page that does not exist yet use publish_page, ' +
        'and to change one file inside a folder use update_file.',
      inputSchema: lcd(
        z.object({
          prefix: z.string().min(1).max(80).describe('The page to replace, the name it is published under.'),
          html: z.string().describe('The complete new HTML document, as UTF-8 text.'),
          title: z.string().max(200).optional().describe('New title. Defaults to the one the page already has.'),
          description: z
            .string()
            .max(500)
            .optional()
            .describe('New description; an empty string removes the one it has. Defaults to the one the page already has.'),
          lang: z.string().max(20).optional().describe('New content language. Defaults to the one the page already has.'),
          expires_at: z
            .string()
            .optional()
            .describe(
              'When the page stops being served, a future ISO 8601 date; an empty string removes the expiry. Defaults to the one the ' +
                'page already has. Required when the page has already expired.'
            ),
          password: z
            .string()
            .max(200)
            .optional()
            .describe(
              `New password visitors must enter to open the page, at least ${MIN_PAGE_PASSWORD_LENGTH} characters with no ` +
                'leading or trailing whitespace; an empty string removes the password. Defaults to the ' +
                'one the page already has.'
            ),
          database: z
            .boolean()
            .optional()
            .describe(
              'true gives the page a shared database (window.shareDb; see publish_page), false turns it off. Turning it ' +
                'off keeps its data, and turning it back on brings it back. Defaults to what the page already has.'
            ),
          version: versionInput,
        })
      ),
      outputSchema: lcd(
        z.object({
          prefix: z.string().describe('The page that was replaced.'),
          url: z.string().describe('Public URL of the page, unchanged.'),
          page_url: z.string().describe('Public URL of the page, same as "url", for symmetry with the file tools.'),
          title: z.string().describe('Title stored for the page after this call.'),
          size_bytes: z.number().int().describe('Size of the new document in bytes.'),
          previous_size_bytes: z.number().int().describe('Size of the document that was replaced.'),
          updated_at: z.string().describe('When the replacement happened, ISO 8601.'),
          expires_at: z.string().optional().describe('When the page stops being served, if an expiry is set.'),
          password_protected: z.boolean().describe('Whether visitors need a password to open the page after this call.'),
          database: z.boolean().describe('Whether the page has a shared database after this call.'),
          version: z.string().describe('Version of the new document; pass it to the next update_page to chain edits without reading again.'),
        })
      ),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    },
    async (args, ctx) => {
      const denied = requireScope(ctx as ToolContext, SCOPE_WRITE);
      if (denied) return denied;

      const prefix = args.prefix.trim().replace(/^\/+|\/+$/g, '');
      if (!isValidSlug(prefix)) {
        return fail(`"${prefix}" is not a valid page name: lowercase letters, digits and single hyphens only.`);
      }
      const html = readHtml(args.html);
      if (typeof html !== 'string') return html;

      const meta = await storage.getMeta(prefix);
      if (!meta) return fail(`Nothing is published under "${prefix}". Use publish_page to publish a new page.`);
      if (meta.kind !== 'uploaded') {
        const names = meta.assets.map((a) => a.name).join(', ') || '(none)';
        return fail(
          `"${prefix}" is a folder of files, not a page. Use update_file with "${prefix}/<filename>" to replace one of its files (it has: ${names}).`
        );
      }

      const expiresAt = readExpiresArg(args.expires_at, 'an empty string to remove the expiry');
      if (typeof expiresAt === 'object') return expiresAt;
      const password = readPasswordArg(args.password, 'an empty string to remove the password');
      if (typeof password === 'object') return password;
      if (expiresAt === undefined && hasExpired(meta.expiresAt)) {
        return fail(
          `The page "${prefix}" expired at ${meta.expiresAt} and is no longer served. Call update_page again with ` +
            '"expires_at": a new ISO 8601 date to serve it until then, or an empty string to serve it with no expiry.'
        );
      }

      const before = await storage.headAsset(prefix, PAGE_ASSET_NAME);
      const result = await replaceShare(storage, prefix, {
        title: args.title?.trim() || meta.title,
        description: args.description?.trim() ?? meta.description,
        lang: args.lang?.trim() || meta.lang,
        kind: 'uploaded',
        html,
        ...(expiresAt !== undefined ? { expiresAt } : {}),
        ...(password !== undefined ? { password } : {}),
        ...(args.database !== undefined ? { database: args.database } : {}),
      }, { ifVersion: args.version?.trim() || undefined });
      if (isRejection(result)) return failRejection(result);

      const size = Buffer.byteLength(html, 'utf8');
      const previous = before?.exists ? before.size : 0;
      const structured = {
        prefix,
        url: shareUrl(prefix),
        page_url: shareUrl(prefix),
        title: result.meta.title,
        size_bytes: size,
        previous_size_bytes: previous,
        updated_at: new Date().toISOString(),
        expires_at: result.meta.expiresAt ?? undefined,
        password_protected: Boolean(result.meta.passwordHash),
        database: Boolean(result.meta.database),
        version: result.pageVersion ?? '',
      };
      return ok(
        `Updated the page "${structured.title}": ${formatBytes(previous)} -> ${formatBytes(size)} of HTML, version ${structured.version}; ${describeAccess(result.meta)}. The URL is unchanged: ${structured.url}`,
        structured
      );
    }
  );

  /* ------------------------------------------------------------------ list_files --------- */
  const PAGE_SIZE = 50;
  server.registerTool(
    'list_files',
    {
      title: 'List files',
      description:
        'List published files with their size, date and public URL, oldest folder first, and alongside them every ' +
        'published page. Pass "prefix" to list one folder or page (exact match) or everything whose name starts ' +
        'with it. Files come in pages of results; when "next_cursor" is present, call again with it as "cursor" ' +
        'to get the next one. Pages hold no files and are listed in full every time.',
      inputSchema: lcd(
        z.object({
          prefix: z
            .string()
            .max(80)
            .optional()
            .describe('Folder name, or the beginning of one, to restrict the listing. Omit for every file.'),
          cursor: z.string().max(200).optional().describe('The "next_cursor" value from a previous call, to continue listing.'),
        })
      ),
      outputSchema: lcd(
        z.object({
          files: z.array(fileItemSchema).describe('The files in this page of results.'),
          total_count: z.number().int().describe('Total number of files matching the prefix across all pages of results.'),
          pages: z.array(pageItemSchema).describe('Every published page matching the prefix. Not paginated: the full list comes with each page of results.'),
          page_count: z.number().int().describe('Number of published pages matching the prefix.'),
          next_cursor: z.string().optional().describe('Pass as "cursor" to get the next page of files. Absent on the last one.'),
        })
      ),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (args, ctx) => {
      const denied = requireScope(ctx as ToolContext, SCOPE_READ);
      if (denied) return denied;

      const prefix = args.prefix?.trim().replace(/^\/+|\/+$/g, '') ?? '';
      let offset = 0;
      if (args.cursor) {
        try {
          const parsed = JSON.parse(Buffer.from(args.cursor, 'base64url').toString('utf8'));
          if (typeof parsed?.o !== 'number' || parsed.o < 0) throw new Error('bad cursor');
          offset = parsed.o;
        } catch {
          return fail('cursor is not one this server issued; call list_files without a cursor to start over.');
        }
      }

      const matching = (await listShares(storage)).filter(
        (m) => prefix === '' || m.slug === prefix || m.slug.startsWith(prefix)
      );
      const all = matching.filter((m) => m.kind === 'generated').flatMap(fileItems);
      const pages: PageItem[] = matching
        .filter((m) => m.kind === 'uploaded')
        .map((m) => ({ prefix: m.slug, title: m.title, created_at: m.createdAt, url: shareUrl(m.slug) }));
      const page = all.slice(offset, offset + PAGE_SIZE);
      const nextOffset = offset + PAGE_SIZE;
      const structured: {
        files: FileItem[];
        total_count: number;
        pages: PageItem[];
        page_count: number;
        next_cursor?: string;
      } = {
        files: page,
        total_count: all.length,
        pages,
        page_count: pages.length,
      };
      if (nextOffset < all.length) {
        structured.next_cursor = Buffer.from(JSON.stringify({ o: nextOffset })).toString('base64url');
      }
      const heading =
        all.length === 0
          ? prefix
            ? `No files under "${prefix}".`
            : 'No files published yet.'
          : `${all.length} file${all.length === 1 ? '' : 's'}${prefix ? ` under "${prefix}"` : ''}, showing ${offset + 1}-${offset + page.length}:`;
      const lines = page.map(describeFile);
      const pageLines = pages.length
        ? [
            `${pages.length} published page${pages.length === 1 ? '' : 's'}${prefix ? ` under "${prefix}"` : ''} (HTML documents, not folders; replace one with update_page):`,
            ...pages.map((p) => `${p.prefix} ("${p.title}")\n  page: ${p.url}`),
          ]
        : [];
      const tail = structured.next_cursor ? `\nMore files available: call again with cursor "${structured.next_cursor}".` : '';
      return ok([heading, ...lines, ...pageLines].join('\n') + tail, structured);
    }
  );

  /* --------------------------------------------------------------- get_file_info --------- */
  server.registerTool(
    'get_file_info',
    {
      title: 'Get file or folder info',
      description:
        'Describe one file ("<prefix>/<filename>"), one folder ("<prefix>") or one published page ("<prefix>"): ' +
        'size, type, dates, public URLs, and for a folder the files it holds. Use it to check that a path exists ' +
        'before deleting it, to recover the URL of something published earlier, or to tell a folder of files from ' +
        'a page, which is replaced with update_page rather than update_file.',
      inputSchema: lcd(
        z.object({
          path: z.string().min(1).max(340).describe('A file path "<prefix>/<filename>" or a folder name "<prefix>".'),
        })
      ),
      outputSchema: lcd(
        z.object({
          path: z.string().describe('The path that was looked up.'),
          type: z.enum(['file', 'folder', 'page']).describe('Whether the path is a file, a folder of files, or a published HTML page.'),
          prefix: z.string().describe('The folder name.'),
          filename: z.string().optional().describe('The file name, for a file.'),
          title: z.string().describe('Title of the folder page.'),
          content_type: z.string().optional().describe('MIME type, for a file or a page.'),
          size_bytes: z.number().int().describe('Size in bytes: the file, or the sum of the folder.'),
          created_at: z.string().describe('When the folder was created, ISO 8601.'),
          expires_at: z.string().optional().describe('When the folder stops being served, if an expiry is set.'),
          password_protected: z.boolean().describe('Whether visitors need a password to open it.'),
          database: z.boolean().optional().describe('For a page, whether it has a shared database (read it with read_page_data).'),
          url: z.string().describe('Public URL: the raw file, or the folder page.'),
          page_url: z.string().describe('Public URL of the folder page.'),
          file_count: z.number().int().describe('Number of files in the folder; always 0 for a page.'),
          files: z.array(fileItemSchema).optional().describe('The files in the folder, for a folder.'),
        })
      ),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (args, ctx) => {
      const denied = requireScope(ctx as ToolContext, SCOPE_READ);
      if (denied) return denied;
      const parsed = parsePath(args.path);
      if ('content' in parsed) return parsed;
      const { prefix, filename } = parsed;

      const meta = await storage.getMeta(prefix);
      if (!meta) return fail(`Nothing is published under "${prefix}".`);
      const summary = toShareSummary(meta);

      if (filename !== null) {
        const asset = meta.assets.find((a) => a.name === filename);
        if (!asset) {
          const names = meta.assets.map((a) => a.name).join(', ') || '(none)';
          return fail(`"${prefix}" has no file named "${filename}". Files in it: ${names}.`);
        }
        const structured = {
          path: `${prefix}/${filename}`,
          type: 'file' as const,
          prefix,
          filename,
          title: meta.title,
          content_type: asset.contentType,
          size_bytes: asset.sizeBytes,
          created_at: meta.createdAt,
          expires_at: summary.expiresAt ?? undefined,
          password_protected: summary.isPasswordProtected,
          url: assetUrl(prefix, filename),
          page_url: shareUrl(prefix),
          file_count: meta.assets.length,
        };
        return ok(
          `${structured.path}: ${formatBytes(asset.sizeBytes)}, ${asset.contentType}, created ${meta.createdAt}` +
            (structured.expires_at ? `, expires ${structured.expires_at}` : '') +
            (structured.password_protected ? ', password protected' : '') +
            `\nFile URL: ${structured.url}\nPage URL: ${structured.page_url}`,
          structured
        );
      }

      if (meta.kind === 'uploaded') {
        const head = await storage.headAsset(prefix, PAGE_ASSET_NAME);
        const structured = {
          path: prefix,
          type: 'page' as const,
          prefix,
          title: meta.title,
          content_type: 'text/html; charset=utf-8',
          size_bytes: head?.exists ? head.size : 0,
          created_at: meta.createdAt,
          expires_at: summary.expiresAt ?? undefined,
          password_protected: summary.isPasswordProtected,
          database: summary.hasDatabase,
          url: shareUrl(prefix),
          page_url: shareUrl(prefix),
          file_count: 0,
          files: [],
        };
        return ok(
          `Page "${prefix}": "${meta.title}", ${formatBytes(structured.size_bytes)} of HTML, published ${meta.createdAt}` +
            (structured.expires_at ? `, expires ${structured.expires_at}` : '') +
            (structured.password_protected ? ', password protected' : '') +
            (structured.database ? ', with a database (read_page_data)' : '') +
            `\nPage URL: ${structured.url}` +
            '\nIt is a page, not a folder: it holds no files, and its content is replaced with update_page.',
          structured
        );
      }

      const items = fileItems(meta);
      const structured = {
        path: prefix,
        type: 'folder' as const,
        prefix,
        title: meta.title,
        size_bytes: summary.totalSize,
        created_at: meta.createdAt,
        expires_at: summary.expiresAt ?? undefined,
        password_protected: summary.isPasswordProtected,
        url: shareUrl(prefix),
        page_url: shareUrl(prefix),
        file_count: meta.assets.length,
        files: items,
      };
      return ok(
        `Folder "${prefix}": "${meta.title}", ${items.length} file${items.length === 1 ? '' : 's'}, ${formatBytes(summary.totalSize)}, created ${meta.createdAt}` +
          (structured.expires_at ? `, expires ${structured.expires_at}` : '') +
          (structured.password_protected ? ', password protected' : '') +
          `\nPage URL: ${structured.page_url}` +
          (items.length ? `\n${items.map(describeFile).join('\n')}` : ''),
        structured
      );
    }
  );

  /* ------------------------------------------------------------------- read_file --------- */
  server.registerTool(
    'read_file',
    {
      title: 'Read a file or page',
      description:
        'Return the current content of one file ("<prefix>/<filename>") or the HTML of one published page ' +
        '("<prefix>"), read straight from storage, so it works for password-protected and expired content and ' +
        'without network access to the public URL. Text comes back as UTF-8, anything else as base64, up to ' +
        `${MAX_INLINE_BYTES / (1024 * 1024)} MB. Read before editing: change the content and send it back with ` +
        'update_page or update_file together with the "version" returned here.',
      inputSchema: lcd(
        z.object({
          path: z.string().min(1).max(340).describe('A file path "<prefix>/<filename>", or a page name "<prefix>".'),
        })
      ),
      // No outputSchema: a host that sees structuredContent reads only that (ChatGPT) and one that
      // does not reads only the text, so the file would have to go out twice. As text alone it goes
      // out once and every host reads it.
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (args, ctx) => {
      const denied = requireScope(ctx as ToolContext, SCOPE_READ);
      if (denied) return denied;
      const parsed = parsePath(args.path);
      if ('content' in parsed) return parsed;
      const { prefix, filename } = parsed;

      const meta = await storage.getMeta(prefix);
      if (!meta) return fail(`Nothing is published under "${prefix}".`);

      let blobName: string;
      if (filename === null) {
        if (meta.kind !== 'uploaded') {
          const names = meta.assets.map((a) => `${prefix}/${a.name}`).join(', ') || '(none)';
          return fail(`"${prefix}" is a folder of files, not a page. Read one of its files by path: ${names}.`);
        }
        blobName = PAGE_ASSET_NAME;
      } else {
        if (meta.kind !== 'generated') {
          return fail(`"${prefix}" is a published page, not a folder, so it holds no files. Read its HTML with path "${prefix}".`);
        }
        if (!meta.assets.some((a) => a.name === filename)) {
          const names = meta.assets.map((a) => a.name).join(', ') || '(none)';
          return fail(`"${prefix}" has no file named "${filename}". Files in it: ${names}.`);
        }
        blobName = filename;
      }

      const url = filename === null ? shareUrl(prefix) : assetUrl(prefix, filename);
      const head = await storage.headAsset(prefix, blobName);
      if (!head || !head.exists) return fail(`The content of "${args.path.trim()}" is missing from storage.`);
      if (head.size > MAX_INLINE_BYTES) {
        return fail(
          `"${args.path.trim()}" is ${formatBytes(head.size)}, above the ${MAX_INLINE_BYTES / (1024 * 1024)} MB that fits in one ` +
            `tool result. Download it from ${url} instead.`
        );
      }
      const read = await storage.getAsset(prefix, blobName);
      if (!read || !read.stream) return fail(`The content of "${args.path.trim()}" is missing from storage.`);
      const bytes = Buffer.from(await new Response(read.stream).arrayBuffer());

      const contentType = filename === null ? 'text/html; charset=utf-8' : read.contentType;
      let content: string | null = null;
      if (isTextType(contentType)) {
        try {
          content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
        } catch {
          content = null;
        }
      }
      const encoding = content === null ? 'base64' : 'text';
      const path = filename === null ? prefix : `${prefix}/${filename}`;
      const version = contentVersion(read.etag);
      const next = filename === null ? 'update_page' : 'update_file';
      return {
        content: [
          {
            type: 'text',
            text:
              `path: ${path}\ntype: ${filename === null ? 'page' : 'file'}\ncontent_type: ${contentType}\n` +
              `encoding: ${encoding}\nsize_bytes: ${bytes.length}\nversion: ${version}\nurl: ${url}\n` +
              `To change it, send the whole new content to ${next} with "version": "${version}". ` +
              `The content follows in the next block${encoding === 'base64' ? ', base64-encoded' : ''}.`,
          },
          { type: 'text', text: content ?? bytes.toString('base64') },
        ],
      };
    }
  );

  /* ----------------------------------------------------------------- delete_file --------- */
  server.registerTool(
    'delete_file',
    {
      title: 'Delete a file, folder or page',
      description:
        'Permanently delete one file ("<prefix>/<filename>"), a whole folder with everything in it ("<prefix>"), ' +
        'or a published page ("<prefix>"). Deleting the last file of a folder deletes the folder. Public URLs stop ' +
        'working immediately and there is no undo. Check the path with get_file_info first when in doubt.',
      inputSchema: lcd(
        z.object({
          path: z.string().min(1).max(340).describe('A file path "<prefix>/<filename>", or a name "<prefix>" alone to delete a folder with all its files, or a published page.'),
        })
      ),
      outputSchema: lcd(
        z.object({
          path: z.string().describe('The path that was deleted.'),
          deleted: z.boolean().describe('Always true on success.'),
          folder_deleted: z.boolean().describe('True when the folder itself is gone, either because it was the target or because its last file was removed.'),
          remaining_files: z.number().int().describe('Files still in the folder after the deletion; 0 when the folder is gone.'),
        })
      ),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    },
    async (args, ctx) => {
      const denied = requireScope(ctx as ToolContext, SCOPE_DELETE);
      if (denied) return denied;
      const parsed = parsePath(args.path);
      if ('content' in parsed) return parsed;
      const { prefix, filename } = parsed;

      const meta = await storage.getMeta(prefix);
      if (!meta) return fail(`Nothing is published under "${prefix}"; nothing to delete.`);

      if (filename === null) {
        const count = meta.assets.length;
        await deleteShare(storage, prefix);
        return ok(`Deleted folder "${prefix}" and its ${count} file${count === 1 ? '' : 's'}.`, {
          path: prefix,
          deleted: true,
          folder_deleted: true,
          remaining_files: 0,
        });
      }

      if (meta.kind !== 'generated') {
        return fail(`"${prefix}" is a published page, not a folder. Delete it by passing "${prefix}" alone.`);
      }
      const result = await removeAsset(storage, prefix, filename);
      if (isRejection(result)) return failRejection(result);
      const remaining = result.meta?.assets.length ?? 0;
      return ok(
        result.shareDeleted
          ? `Deleted ${prefix}/${filename}; it was the last file, so folder "${prefix}" is gone too.`
          : `Deleted ${prefix}/${filename}; ${remaining} file${remaining === 1 ? '' : 's'} remain in "${prefix}".`,
        { path: `${prefix}/${filename}`, deleted: true, folder_deleted: result.shareDeleted, remaining_files: remaining }
      );
    }
  );
  /* ------------------------------------------------------------- page database --------- */
  /** Serialised documents per read_page_data result; the result carries them twice (text and structured). */
  const DATA_PAGE_BYTES = 512 * 1024;
  const documentSchema = z.object({
    id: z.string().describe('The document id.'),
    data: z.unknown().describe('The stored JSON value.'),
    created_at: z.string().describe('When the document was first written, ISO 8601.'),
    updated_at: z.string().describe('When the document was last written, ISO 8601.'),
  });
  const toDocumentItem = (d: DbDocument) => ({ id: d.id, data: d.data, created_at: d.createdAt, updated_at: d.updatedAt });

  /** The page a database tool names, or the tool error explaining why it cannot be used. */
  async function pageForDb(rawPrefix: string, mode: 'read' | 'write'): Promise<ShareMeta | CallToolResult> {
    const prefix = rawPrefix.trim().replace(/^\/+|\/+$/g, '');
    if (!isValidSlug(prefix)) return fail(`"${prefix}" is not a valid page name.`);
    const meta = await storage.getMeta(prefix);
    const denied = checkDbAccess(prefix, meta, mode, 'owner');
    if (denied) return fail(denied.error);
    return meta as ShareMeta;
  }

  server.registerTool(
    'read_page_data',
    {
      title: 'Read page data',
      description:
        'Read the shared database of a published page (one published with "database": true): with only "prefix", ' +
        'its collections and how many documents each holds; with "collection", every document in it, oldest first; ' +
        'with "collection" and "id", one document. This is the data visitors wrote through window.shareDb. It reads ' +
        'straight from storage, so it works on password-protected and expired pages, and on a page whose database ' +
        'was turned off (the data is kept). A large collection comes in pages of results: when "next_cursor" is ' +
        'present, call again with it as "cursor".',
      inputSchema: lcd(
        z.object({
          prefix: z.string().min(1).max(80).describe('The page whose data to read, the name it is published under.'),
          collection: z.string().max(64).optional().describe('A collection to list. Omit to list the collections.'),
          id: z.string().max(128).optional().describe('One document to read from "collection". Omit to list the whole collection.'),
          cursor: z.string().max(200).optional().describe('The "next_cursor" value from a previous call, to continue listing a collection.'),
        })
      ),
      outputSchema: lcd(
        z.object({
          prefix: z.string().describe('The page read.'),
          database: z.boolean().describe('Whether the page currently has its database turned on.'),
          collections: z
            .array(z.object({ name: z.string().describe('Collection name.'), count: z.number().int().describe('Documents in it.') }))
            .optional()
            .describe('The collections, when no collection was given.'),
          collection: z.string().optional().describe('The collection read, when one was given.'),
          documents: z.array(documentSchema).optional().describe('The documents of the collection in this page of results, when no id was given.'),
          total_count: z.number().int().optional().describe('Documents in the collection across all pages of results.'),
          next_cursor: z.string().optional().describe('Pass as "cursor" to get the next page of documents. Absent on the last one.'),
          document: documentSchema.optional().describe('The document, when an id was given and it exists.'),
          found: z.boolean().optional().describe('When an id was given, whether that document exists.'),
        })
      ),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (args, ctx) => {
      const denied = requireScope(ctx as ToolContext, SCOPE_READ);
      if (denied) return denied;
      const meta = await pageForDb(args.prefix, 'read');
      if ('content' in meta) return meta;
      const prefix = meta.slug;
      const database = Boolean(meta.database);
      const off = database ? '' : ' (its database is turned off; this is the data it kept)';
      const collection = args.collection?.trim() || undefined;
      const id = args.id?.trim() || undefined;

      if (collection === undefined) {
        if (id !== undefined) return fail('"id" needs a "collection" to look in.');
        const collections = await listCollections(storage, prefix);
        const text = collections.length
          ? `Page "${prefix}" has ${collections.length} collection${collections.length === 1 ? '' : 's'}${off}:\n` +
            collections.map((c) => `${c.name}: ${c.count} document${c.count === 1 ? '' : 's'}`).join('\n')
          : `Page "${prefix}" has no data yet${off}.`;
        return ok(text, { prefix, database, collections });
      }

      if (id === undefined) {
        const docs = await listDocuments(storage, prefix, collection);
        if (isRejection(docs)) return fail(docs.error);
        // The cursor names the last document returned, not a position, so documents deleted or added
        // between calls never make the next page skip or repeat one. The order is (createdAt, id),
        // and a document keeps its createdAt when it is rewritten.
        let offset = 0;
        if (args.cursor) {
          let after: { c: string; i: string };
          try {
            after = JSON.parse(Buffer.from(args.cursor, 'base64url').toString('utf8'));
            if (typeof after?.c !== 'string' || typeof after?.i !== 'string') throw new Error('bad cursor');
          } catch {
            return fail('cursor is not one this server issued; call read_page_data without a cursor to start over.');
          }
          const next = docs.findIndex((d) => d.createdAt > after.c || (d.createdAt === after.c && d.id > after.i));
          offset = next < 0 ? docs.length : next;
        }
        // Each page of results stays well under the response ceiling, counting both copies of it.
        const documents: ReturnType<typeof toDocumentItem>[] = [];
        let budget = DATA_PAGE_BYTES;
        for (let i = offset; i < docs.length; i++) {
          const item = toDocumentItem(docs[i]);
          const size = Buffer.byteLength(JSON.stringify(item), 'utf8');
          if (documents.length > 0 && size > budget) break;
          documents.push(item);
          budget -= size;
        }
        const nextOffset = offset + documents.length;
        const structured: Record<string, unknown> = { prefix, database, collection, documents, total_count: docs.length };
        if (nextOffset < docs.length && documents.length > 0) {
          const last = documents[documents.length - 1];
          structured.next_cursor = Buffer.from(JSON.stringify({ c: last.created_at, i: last.id })).toString('base64url');
        }
        const text = docs.length
          ? `${docs.length} document${docs.length === 1 ? '' : 's'} in "${prefix}" / "${collection}"${off}, showing ${documents.length ? `${offset + 1}-${nextOffset}` : 'none after the cursor'}, ` +
            'one JSON object per line:\n' +
            documents.map((d) => JSON.stringify(d)).join('\n') +
            (structured.next_cursor ? `\nMore documents available: call again with cursor "${structured.next_cursor}".` : '')
          : `Collection "${collection}" of "${prefix}" is empty or does not exist${off}.`;
        return ok(text, structured);
      }

      const doc = await getDocument(storage, prefix, collection, id);
      if (isRejection(doc)) {
        if (doc.missing) return ok(`No document "${id}" in "${prefix}" / "${collection}"${off}.`, { prefix, database, collection, found: false });
        return fail(doc.error);
      }
      const document = toDocumentItem(doc);
      // Compact JSON everywhere: indentation grows with nesting depth, not with the data.
      return ok(`"${prefix}" / "${collection}" / "${id}"${off}:\n${JSON.stringify(document)}`, {
        prefix,
        database,
        collection,
        document,
        found: true,
      });
    }
  );

  server.registerTool(
    'write_page_data',
    {
      title: 'Write page data',
      description:
        'Change one document in the shared database of a published page, the same data its visitors see through ' +
        'window.shareDb. "add" stores data under a new random id; "set" creates or replaces the document "id"; ' +
        '"update" shallow-merges a JSON object into the document "id", creating it when absent; "delete" removes the ' +
        'document "id". The page must have its database turned on (update_page with "database": true). Changes are ' +
        'immediate and visible to every visitor; there is no undo.',
      inputSchema: lcd(
        z.object({
          prefix: z.string().min(1).max(80).describe('The page whose data to change, the name it is published under.'),
          collection: z
            .string()
            .min(1)
            .max(64)
            .describe('Collection name: lowercase letters, digits, "_" and "-", starting with a letter or digit. Created on first write.'),
          action: z.enum(['add', 'set', 'update', 'delete']).describe('What to do with the document.'),
          id: z
            .string()
            .max(128)
            .optional()
            .describe('Document id (letters, digits, "_" and "-"). Required for set, update and delete; ignored for add.'),
          data_json: z
            .string()
            .optional()
            .describe(
              'The value to store, as JSON text (e.g. "{\"choice\": \"b\"}"). Any JSON value for add and set; a JSON object ' +
                `for update. Required except for delete. At most ${DB_LIMITS.documentBytes / 1024} KB.`
            ),
        })
      ),
      outputSchema: lcd(
        z.object({
          prefix: z.string().describe('The page changed.'),
          collection: z.string().describe('The collection changed.'),
          action: z.string().describe('The action performed.'),
          id: z.string().describe('The document id; for add, the new id.'),
          created: z.boolean().optional().describe('For add, set and update, whether the document is new.'),
          deleted: z.boolean().optional().describe('For delete, whether the document existed.'),
          document: documentSchema.optional().describe('The document as stored, for add, set and update.'),
        })
      ),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    },
    async (args, ctx) => {
      const denied = requireScope(ctx as ToolContext, args.action === 'delete' ? SCOPE_DELETE : SCOPE_WRITE);
      if (denied) return denied;
      const meta = await pageForDb(args.prefix, 'write');
      if ('content' in meta) return meta;
      const prefix = meta.slug;
      const collection = args.collection.trim();
      const id = args.id?.trim() || undefined;
      if (args.action !== 'add' && id === undefined) return fail(`"${args.action}" needs the "id" of the document.`);

      if (args.action === 'delete') {
        const result = await deleteDocument(storage, prefix, collection, id as string);
        if (isRejection(result)) return fail(result.error);
        return ok(
          result.deleted
            ? `Deleted "${prefix}" / "${collection}" / "${id}".`
            : `"${prefix}" / "${collection}" has no document "${id}"; nothing to delete.`,
          { prefix, collection, action: 'delete', id: id as string, deleted: result.deleted }
        );
      }

      if (args.data_json === undefined) return fail(`"${args.action}" needs "data_json", the value to store as JSON text.`);
      let data: unknown;
      try {
        data = JSON.parse(args.data_json);
      } catch (err) {
        return fail(`"data_json" is not valid JSON: ${(err as Error).message}. Send the value as JSON text, e.g. {"choice": "b"}.`);
      }
      const result = await writeDocument(storage, prefix, collection, args.action, id, data);
      if (isRejection(result)) return fail(result.error);
      const document = toDocumentItem(result.document);
      const verb = args.action === 'add' ? 'Added' : args.action === 'set' ? (result.created ? 'Created' : 'Replaced') : result.created ? 'Created' : 'Updated';
      return ok(`${verb} "${prefix}" / "${collection}" / "${document.id}":\n${JSON.stringify(document.data)}`, {
        prefix,
        collection,
        action: args.action,
        id: document.id,
        created: result.created,
        document,
      });
    }
  );
}
