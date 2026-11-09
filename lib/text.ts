/**
 * lib/text.ts
 *
 * Turns a text asset into the HTML a share page shows inline, so a note or a recipe reads as
 * itself rather than as a download card.
 */

import { Marked } from 'marked';

/** Largest text asset rendered into the page; bigger ones stay a download. */
export const MAX_INLINE_TEXT_BYTES = 256 * 1024;

const MARKDOWN_TYPES = ['text/markdown', 'text/x-markdown'];
const MARKDOWN_EXTENSIONS = ['md', 'markdown', 'mdown'];

const PLAIN_TEXT_TYPES = [
  'text/plain',
  'text/csv',
  'application/json',
  'application/xml',
  'text/xml',
  'application/javascript',
  'text/javascript',
  'application/x-yaml',
  'text/yaml',
];

const PLAIN_TEXT_EXTENSIONS = [
  'txt',
  'csv',
  'json',
  'xml',
  'yml',
  'yaml',
  'js',
  'ts',
  'py',
  'sh',
  'sql',
  'kt',
  'java',
  'css',
  'log',
  'ini',
  'toml',
];

// Raw HTML inside a source file is dropped rather than passed through: a markdown asset is not an
// uploaded page, and letting one emit <script> would give it the reach we deliberately took away
// from pages by sandboxing them.
const marked = new Marked({ gfm: true, breaks: false });
marked.use({
  renderer: {
    html: () => '',
  },
  // A share page is not sandboxed, so a link or image is limited to schemes that cannot run code:
  // `javascript:` would run on this origin, next to every other share, and `data:` / `vbscript:`
  // and the rest have no business in a note. Anything else becomes an inert "#".
  walkTokens(token) {
    if (token.type === 'link' || token.type === 'image') {
      token.href = safeHref(token.href);
    }
  },
});

const SAFE_SCHEMES = new Set(['http:', 'https:', 'mailto:', 'tel:']);

/** `href` if it is relative or uses a scheme in SAFE_SCHEMES, otherwise "#". */
export function safeHref(href: string): string {
  // Browsers ignore ASCII whitespace and control characters inside a scheme ("java\tscript:").
  const compact = href.replace(/[\u0000-\u0020\u007f]/g, '');
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(compact);
  if (!scheme) return href;
  return SAFE_SCHEMES.has(scheme[1].toLowerCase() + ':') ? href : '#';
}

function extensionOf(name: string): string {
  const bare = name.split('/').pop() ?? name;
  if (!bare.includes('.')) return '';
  return (bare.split('.').pop() ?? '').toLowerCase();
}

export function isMarkdown(name: string, contentType: string): boolean {
  const ct = contentType.toLowerCase();
  return (
    MARKDOWN_TYPES.some((t) => ct.startsWith(t)) ||
    MARKDOWN_EXTENSIONS.includes(extensionOf(name))
  );
}

export function isPlainText(name: string, contentType: string): boolean {
  const ct = contentType.toLowerCase();
  return (
    PLAIN_TEXT_TYPES.some((t) => ct.startsWith(t)) ||
    ct.startsWith('text/') ||
    PLAIN_TEXT_EXTENSIONS.includes(extensionOf(name))
  );
}

export function isInlineText(name: string, contentType: string, sizeBytes: number): boolean {
  if (sizeBytes > MAX_INLINE_TEXT_BYTES) return false;
  return isMarkdown(name, contentType) || isPlainText(name, contentType);
}

export function renderMarkdown(source: string): string {
  return marked.parse(source, { async: false }) as string;
}
