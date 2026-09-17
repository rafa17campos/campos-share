/**
 * lib/mcp/schema.ts
 *
 * Tool schemas are the least common denominator of what every MCP host's function calling accepts:
 * flat objects, basic types, string enums, explicit `required`, a description on every field.
 * Zod produces exactly that from the schemas in tools.ts, with one addition the hosts do not all
 * tolerate: a top-level `$schema` keyword. `lcd` wraps a Zod schema so validation stays Zod's and
 * the advertised JSON Schema loses that keyword.
 */

import type { StandardSchemaWithJSON } from '@modelcontextprotocol/server';
import type * as z from 'zod';

type JsonConverter = StandardSchemaWithJSON['~standard']['jsonSchema'];

function strip(schema: Record<string, unknown>): Record<string, unknown> {
  const { $schema: _ignored, ...rest } = schema;
  if (rest.type === 'object' && rest.properties && !Array.isArray(rest.required)) {
    // An object whose fields are all optional still says so explicitly.
    rest.required = [];
  }
  return rest;
}

export function lcd<T extends z.ZodType>(
  schema: T
): StandardSchemaWithJSON<z.input<T>, z.output<T>> {
  const inner = schema['~standard'] as StandardSchemaWithJSON<z.input<T>, z.output<T>>['~standard'];
  const jsonSchema: JsonConverter = {
    input: (options) => strip(inner.jsonSchema.input(options)),
    output: (options) => strip(inner.jsonSchema.output(options)),
  };
  return {
    '~standard': {
      ...inner,
      jsonSchema,
    },
  };
}

const MIME_BY_EXTENSION: Record<string, string> = {
  txt: 'text/plain; charset=utf-8',
  md: 'text/markdown; charset=utf-8',
  markdown: 'text/markdown; charset=utf-8',
  html: 'text/html; charset=utf-8',
  htm: 'text/html; charset=utf-8',
  css: 'text/css; charset=utf-8',
  js: 'text/javascript; charset=utf-8',
  mjs: 'text/javascript; charset=utf-8',
  ts: 'text/plain; charset=utf-8',
  json: 'application/json; charset=utf-8',
  csv: 'text/csv; charset=utf-8',
  xml: 'application/xml; charset=utf-8',
  yaml: 'application/x-yaml; charset=utf-8',
  yml: 'application/x-yaml; charset=utf-8',
  svg: 'image/svg+xml',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  ico: 'image/x-icon',
  pdf: 'application/pdf',
  zip: 'application/zip',
  gz: 'application/gzip',
  mp3: 'audio/mpeg',
  wav: 'audio/wav',
  mp4: 'video/mp4',
  webm: 'video/webm',
  woff2: 'font/woff2',
  wasm: 'application/wasm',
};

/** The content type a file name implies, or null when the extension says nothing. */
export function mimeFromFilename(filename: string): string | null {
  const bare = filename.split('/').pop() ?? filename;
  const dot = bare.lastIndexOf('.');
  if (dot < 0) return null;
  return MIME_BY_EXTENSION[bare.slice(dot + 1).toLowerCase()] ?? null;
}
