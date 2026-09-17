/**
 * lib/renderer.ts
 *
 * Pure HTML rendering engine.
 * The former scripts/validate.mjs ascends into this template, guaranteeing
 * metadata, accessibility, and SEO invariants by construction.
 */

import type { ShareMeta, ShareAsset } from './storage.ts';
import { isMarkdown, renderMarkdown } from './text.ts';

export function escapeHtml(str: string): string {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Base stylesheet embedded directly into rendered pages for zero-dependency autonomy.
 */
const BASE_STYLES = `
:root {
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --color-bg: #f8fafc;
  --color-surface: #ffffff;
  --color-text: #0f172a;
  --color-muted: #64748b;
  --color-border: #e2e8f0;
  --color-primary: #2563eb;
  --color-primary-hover: #1d4ed8;
  --radius-md: 0.5rem;
  --radius-lg: 0.75rem;
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1);
}

@media (prefers-color-scheme: dark) {
  :root {
    --color-bg: #0b0f19;
    --color-surface: #111827;
    --color-text: #f9fafb;
    --color-muted: #94a3b8;
    --color-border: #1f2937;
    --color-primary: #3b82f6;
    --color-primary-hover: #60a5fa;
    --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.3);
    --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.4);
  }
}

*, *::before, *::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html {
  color-scheme: light dark;
  font-family: var(--font-sans);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
  background-color: var(--color-bg);
  color: var(--color-text);
}

body {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  padding: 2rem 1rem;
}

.container {
  max-width: 52rem;
  width: 100%;
  margin: 0 auto;
}

header {
  margin-bottom: 2rem;
  padding-bottom: 1.5rem;
  border-bottom: 1px solid var(--color-border);
}

.badge {
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--color-muted);
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  padding: 0.25rem 0.625rem;
  border-radius: 9999px;
  margin-bottom: 0.75rem;
}

h1 {
  font-size: 1.75rem;
  font-weight: 700;
  margin-bottom: 0.5rem;
  line-height: 1.25;
}

.description {
  color: var(--color-muted);
  font-size: 1rem;
  line-height: 1.6;
}

.asset-list {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.asset-card {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  padding: 1.25rem;
  box-shadow: var(--shadow-sm);
}

.asset-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  margin-bottom: 1rem;
  gap: 1rem;
}

.asset-title {
  font-weight: 600;
  font-size: 1.05rem;
  word-break: break-word;
}

.asset-meta {
  font-size: 0.8125rem;
  color: var(--color-muted);
  white-space: nowrap;
}

.asset-media {
  border-radius: var(--radius-md);
  overflow: hidden;
  background: var(--color-bg);
}

.asset-media img,
.asset-media video {
  width: 100%;
  height: auto;
  max-height: 80vh;
  object-fit: contain;
  display: block;
}

.asset-media audio {
  width: 100%;
  padding: 0.5rem;
}

.asset-prose { line-height: 1.6; }
.asset-prose > *:first-child { margin-top: 0; }
.asset-prose > *:last-child { margin-bottom: 0; }
.asset-prose p { margin: 0 0 1em; }
.asset-prose h1, .asset-prose h2, .asset-prose h3,
.asset-prose h4, .asset-prose h5, .asset-prose h6 {
  margin: 1.4em 0 0.5em;
  line-height: 1.25;
  font-weight: 600;
}
.asset-prose h1 { font-size: 1.5rem; }
.asset-prose h2 { font-size: 1.25rem; }
.asset-prose h3 { font-size: 1.0625rem; }
.asset-prose h4 { font-size: 1rem; }
.asset-prose h5, .asset-prose h6 { font-size: 0.9375rem; }
.asset-prose h6 { color: var(--color-muted); }
.asset-prose a { color: var(--color-primary); text-decoration: underline; }
.asset-prose ul, .asset-prose ol { margin: 0 0 1em; padding-left: 1.5rem; }
.asset-prose ul { list-style: disc; }
.asset-prose ol { list-style: decimal; }
.asset-prose li { margin: 0.25em 0; }
.asset-prose li > ul, .asset-prose li > ol { margin: 0.25em 0; }
.asset-prose blockquote {
  margin: 0 0 1em;
  padding: 0.25em 0 0.25em 1rem;
  border-left: 3px solid var(--color-border);
  color: var(--color-muted);
}
.asset-prose hr { margin: 1.5em 0; border: 0; border-top: 1px solid var(--color-border); }
.asset-prose code, .asset-prose pre { font-family: var(--font-mono); }
.asset-prose code {
  font-size: 0.9em;
  padding: 0.1em 0.3em;
  border-radius: 4px;
  background: var(--color-bg);
  border: 1px solid var(--color-border);
}
.asset-prose pre {
  margin: 0 0 1em;
  padding: 0.75rem;
  font-size: 0.875rem;
  border-radius: var(--radius-md);
  background: var(--color-bg);
  border: 1px solid var(--color-border);
}
.asset-prose pre code { font-size: inherit; padding: 0; background: none; border: 0; }
.asset-prose img { max-width: 100%; height: auto; }
.asset-prose pre { overflow-x: auto; }
.asset-prose table {
  display: block;
  width: fit-content;
  max-width: 100%;
  margin: 0 0 1em;
  overflow-x: auto;
  border-collapse: collapse;
}
.asset-prose td, .asset-prose th { border: 1px solid var(--color-border); padding: 0.375rem 0.625rem; }
.asset-prose th { text-align: left; font-weight: 600; background: var(--color-bg); }
.asset-actions:not(:first-child) { margin-top: 1rem; }
.asset-code {
  white-space: pre-wrap;
  word-break: break-word;
  overflow-x: auto;
  line-height: 1.45;
}
.pdf-preview-tall { height: 80vh; }
.pdf-preview {
  width: 100%;
  height: 600px;
  border: none;
  display: block;
}

.code-block {
  font-family: var(--font-mono);
  font-size: 0.875rem;
  padding: 1rem;
  overflow-x: auto;
  background: var(--color-bg);
  border-radius: var(--radius-md);
  border: 1px solid var(--color-border);
  line-height: 1.45;
}

.button-link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0.5rem 1rem;
  font-size: 0.875rem;
  font-weight: 500;
  border-radius: var(--radius-md);
  background: var(--color-primary);
  color: #ffffff;
  text-decoration: none;
  transition: background-color 0.15s ease;
}

.button-link:hover {
  background: var(--color-primary-hover);
  text-decoration: none;
}

:focus-visible {
  outline: 2px solid var(--color-primary);
  outline-offset: 2px;
}

footer {
  margin-top: 3rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--color-border);
  text-align: center;
  font-size: 0.8125rem;
  color: var(--color-muted);
}
`;

/**
 * Renders individual asset element based on MIME type
 */
function renderAssetBody(
  asset: ShareAsset,
  assetUrl: string,
  inlineText?: string,
  onlyAsset = false,
): string {
  const ct = asset.contentType.toLowerCase();

  if (inlineText !== undefined) {
    const body = isMarkdown(asset.name, asset.contentType)
      ? `<div class="asset-prose">${renderMarkdown(inlineText)}</div>`
      : `<pre class="asset-code">${escapeHtml(inlineText)}</pre>`;
    return `
      ${body}
      <div class="asset-actions">
        <a href="${escapeHtml(assetUrl)}" download="${escapeHtml(asset.originalName)}" class="button-link">Descargar (${formatFileSize(asset.sizeBytes)})</a>
      </div>
    `;
  }

  if (ct.startsWith('image/')) {
    return `
      <div class="asset-media">
        <a href="${escapeHtml(assetUrl)}" target="_blank" rel="noopener">
          <img src="${escapeHtml(assetUrl)}" alt="${escapeHtml(asset.originalName || asset.name)}" loading="lazy" />
        </a>
      </div>
      <div class="asset-actions">
        <a href="${escapeHtml(assetUrl)}" download="${escapeHtml(asset.originalName)}" class="button-link">Descargar imagen</a>
      </div>
    `;
  }

  if (ct === 'application/pdf') {
    return `
      <div class="asset-media">
        <object data="${escapeHtml(assetUrl)}" type="application/pdf" class="pdf-preview${onlyAsset ? ' pdf-preview-tall' : ''}">
          <p style="padding: 1rem;">Tu navegador no puede mostrar este PDF directamente. <a href="${escapeHtml(assetUrl)}" target="_blank" rel="noopener">Abrir en nueva pestaña</a>.</p>
        </object>
      </div>
      <div class="asset-actions">
        <a href="${escapeHtml(assetUrl)}" download="${escapeHtml(asset.originalName)}" class="button-link">Descargar PDF (${formatFileSize(asset.sizeBytes)})</a>
      </div>
    `;
  }

  if (ct.startsWith('video/')) {
    return `
      <div class="asset-media">
        <video controls playsinline preload="metadata" src="${escapeHtml(assetUrl)}"></video>
      </div>
      <div class="asset-actions">
        <a href="${escapeHtml(assetUrl)}" download="${escapeHtml(asset.originalName)}" class="button-link">Descargar video (${formatFileSize(asset.sizeBytes)})</a>
      </div>
    `;
  }

  if (ct.startsWith('audio/')) {
    return `
      <div class="asset-media">
        <audio controls preload="metadata" src="${escapeHtml(assetUrl)}"></audio>
      </div>
      <div class="asset-actions">
        <a href="${escapeHtml(assetUrl)}" download="${escapeHtml(asset.originalName)}" class="button-link">Descargar audio (${formatFileSize(asset.sizeBytes)})</a>
      </div>
    `;
  }

  // Fallback download card for general binaries, zip, docx, etc.
  return `
    <div class="asset-actions">
      <a href="${escapeHtml(assetUrl)}" download="${escapeHtml(asset.originalName)}" class="button-link">
        Descargar archivo (${formatFileSize(asset.sizeBytes)})
      </a>
    </div>
  `;
}

/**
 * Pure HTML rendering function for a share
 */
export function renderSharePage(
  meta: ShareMeta,
  baseUrl: string,
  inlineText: Record<string, string> = {},
): string {
  const lang = escapeHtml(meta.lang || 'en');
  const title = escapeHtml(meta.title);
  const description = escapeHtml(meta.description || '');
  // An absent description omits the tag rather than emitting an empty one: a blank preview
  // subtitle reads as a mistake, while no subtitle reads as a page that did not need one.
  const descriptionTag = description
    ? `\n  <meta name="description" content="${description}">`
    : '';
  const ogDescriptionTag = description
    ? `\n  <meta property="og:description" content="${description}">`
    : '';

  let hostLabel = 'campos-share';
  try {
    hostLabel = new URL(baseUrl).hostname;
  } catch {
    hostLabel = baseUrl;
  }

  // Determine og:image:
  // ONLY if share is NOT password-protected and NOT expiring,
  // AND there is an image asset.
  let ogImageTag = '';
  const isProtected = Boolean(meta.passwordHash);
  const isExpiring = Boolean(meta.expiresAt);

  if (!isProtected && !isExpiring) {
    const firstImage = meta.assets.find((a) => a.contentType.toLowerCase().startsWith('image/'));
    if (firstImage) {
      const ogImageUrl = `${baseUrl}/${encodeURIComponent(meta.slug)}/${encodeURIComponent(firstImage.name)}`;
      ogImageTag = `\n  <meta property="og:image" content="${escapeHtml(ogImageUrl)}">`;
    }
  }

  const assetCards = meta.assets
    .map((asset) => {
      const assetUrl = `${baseUrl}/${encodeURIComponent(meta.slug)}/${encodeURIComponent(asset.name)}`;
      return `
    <article class="asset-card">
      <div class="asset-header">
        <h2 class="asset-title">${escapeHtml(asset.originalName || asset.name)}</h2>
        <span class="asset-meta">${formatFileSize(asset.sizeBytes)}</span>
      </div>
      ${renderAssetBody(asset, assetUrl, inlineText[asset.name], meta.assets.length === 1)}
    </article>
      `;
    })
    .join('\n');

  return `<!DOCTYPE html>
<html lang="${lang}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex,nofollow">${descriptionTag}
  <title>${title}</title>
  <meta property="og:title" content="${title}">${ogDescriptionTag}
  <meta property="og:type" content="website">${ogImageTag}
  <style>${BASE_STYLES}</style>
</head>
<body>
  <div class="container">
    <header>
      <div class="badge">Compartido</div>
      <h1>${title}</h1>
      <p class="description">${description}</p>
    </header>

    <main class="asset-list">
      ${assetCards}
    </main>

    <footer>
      <p>${escapeHtml(hostLabel)} &bull; Documento no indexado</p>
    </footer>
  </div>
</body>
</html>`;
}

/**
 * Injects missing mandatory head tags into uploaded HTML files
 */
export function injectUploadedHtml(rawHtml: string, meta: ShareMeta): string {
  let html = rawHtml;

  // Ensure <html lang="...">
  if (!/<html\b[^>]*\blang=/i.test(html)) {
    html = html.replace(/<html\b/i, `<html lang="${escapeHtml(meta.lang || 'en')}"`);
  }

  // Ensure <head>
  if (!/<head\b/i.test(html)) {
    html = `<head></head>${html}`;
  }

  const headInjections: string[] = [];

  // Robots meta
  if (!/<meta\b[^>]*name=["']robots["']/i.test(html)) {
    headInjections.push('<meta name="robots" content="noindex,nofollow">');
  }

  // Viewport
  if (!/<meta\b[^>]*name=["']viewport["']/i.test(html)) {
    headInjections.push('<meta name="viewport" content="width=device-width, initial-scale=1.0">');
  }

  // Title
  if (!/<title\b/i.test(html)) {
    headInjections.push(`<title>${escapeHtml(meta.title)}</title>`);
  }

  // Description
  if (meta.description && !/<meta\b[^>]*name=["']description["']/i.test(html)) {
    headInjections.push(`<meta name="description" content="${escapeHtml(meta.description)}">`);
  }

  // Open Graph
  if (!/<meta\b[^>]*property=["']og:title["']/i.test(html)) {
    headInjections.push(`<meta property="og:title" content="${escapeHtml(meta.title)}">`);
  }
  if (meta.description && !/<meta\b[^>]*property=["']og:description["']/i.test(html)) {
    headInjections.push(`<meta property="og:description" content="${escapeHtml(meta.description)}">`);
  }
  if (!/<meta\b[^>]*property=["']og:type["']/i.test(html)) {
    headInjections.push('<meta property="og:type" content="website">');
  }

  if (headInjections.length > 0) {
    html = html.replace(/<head\b[^>]*>/i, (match) => `${match}\n  ${headInjections.join('\n  ')}`);
  }

  return html;
}

/**
 * Renders the password unlock prompt screen
 */
export function renderPasswordPrompt(slug: string, hasError: boolean = false): string {
  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex,nofollow">
  <meta name="description" content="Este enlace está protegido por contraseña.">
  <title>Acceso protegido</title>
  <style>
    ${BASE_STYLES}
    body {
      align-items: center;
      justify-content: center;
    }
    .auth-card {
      background: var(--color-surface);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-lg);
      padding: 2.25rem;
      max-width: 26rem;
      width: 100%;
      box-shadow: var(--shadow-md);
      text-align: center;
    }
    .input-field {
      width: 100%;
      padding: 0.625rem 0.75rem;
      border: 1px solid var(--color-border);
      border-radius: var(--radius-md);
      margin: 1rem 0 0.5rem;
      font-size: 1rem;
      background: var(--color-bg);
      color: var(--color-text);
    }
    .input-field:focus {
      outline: 2px solid var(--color-primary);
      outline-offset: 1px;
    }
    .submit-btn {
      width: 100%;
      padding: 0.625rem;
      background: var(--color-primary);
      color: white;
      border: none;
      border-radius: var(--radius-md);
      font-weight: 600;
      cursor: pointer;
      margin-top: 0.75rem;
      transition: background-color 0.15s ease;
    }
    .submit-btn:hover {
      background: var(--color-primary-hover);
    }
    .error-msg {
      color: #ef4444;
      font-size: 0.875rem;
      margin-top: 0.5rem;
    }
  </style>
</head>
<body>
  <main class="auth-card">
    <div class="badge">Protegido</div>
    <h1>Acceso protegido</h1>
    <p class="description">Introduce la contraseña para ver este contenido.</p>

    <form method="POST" action="/${encodeURIComponent(slug)}/unlock">
      <input type="password" name="password" placeholder="Contraseña" required autofocus class="input-field" />
      <button type="submit" class="submit-btn">Desbloquear</button>
      ${hasError ? '<p class="error-msg">Contraseña incorrecta.</p>' : ''}
    </form>
  </main>
</body>
</html>`;
}
