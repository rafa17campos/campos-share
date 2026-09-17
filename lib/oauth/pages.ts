/**
 * lib/oauth/pages.ts
 *
 * The two pages the authorization server shows a person: the login-and-consent form, and an error
 * that could not be sent back to the client because the client or its redirect could not be
 * trusted. Everything user-controlled is escaped; the pages carry no script.
 */

import { escapeHtml } from '../renderer.ts';

const STYLE = `
  :root { color-scheme: light; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
         background: #f8fafc; color: #0f172a; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  main { background: #fff; border: 1px solid #e2e8f0; border-radius: .75rem; padding: 2rem; width: 100%; max-width: 26rem; box-sizing: border-box; margin: 1rem; }
  h1 { font-size: 1.25rem; margin: 0 0 .5rem; }
  p { color: #475569; line-height: 1.5; margin: .5rem 0; }
  code { background: #f1f5f9; padding: .1rem .3rem; border-radius: .25rem; font-size: .9em; word-break: break-all; }
  ul { padding-left: 1.2rem; color: #475569; }
  label { display: block; font-weight: 600; margin: 1rem 0 .35rem; }
  input[type=password] { width: 100%; box-sizing: border-box; padding: .6rem .7rem; border: 1px solid #cbd5e1; border-radius: .5rem; font-size: 1rem; }
  .actions { display: flex; gap: .5rem; margin-top: 1.25rem; }
  button { flex: 1; padding: .65rem; border-radius: .5rem; border: 1px solid #cbd5e1; background: #fff; font-size: 1rem; cursor: pointer; }
  button.primary { background: #2563eb; border-color: #2563eb; color: #fff; }
  .error { background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; padding: .6rem .8rem; border-radius: .5rem; }
`;

const SCOPE_TEXT: Record<string, string> = {
  'files:read': 'List files and read their details',
  'files:write': 'Upload new files',
  'files:delete': 'Delete files and folders',
};

function page(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<main>
${body}
</main>
</body>
</html>`;
}

export function renderAuthorizePage(input: {
  action: string;
  clientName: string;
  clientId: string;
  scopes: string[];
  requestToken: string;
  error?: string;
}): string {
  const scopeItems = input.scopes
    .map((s) => `<li>${escapeHtml(SCOPE_TEXT[s] ?? s)} <code>${escapeHtml(s)}</code></li>`)
    .join('\n');
  const error = input.error ? `<p class="error">${escapeHtml(input.error)}</p>` : '';
  return page(
    'Authorize access',
    `<h1>Authorize ${escapeHtml(input.clientName)}</h1>
<p>An application identified as <code>${escapeHtml(input.clientId)}</code> asks for access to your shared files. Only you can grant it: enter the passphrase to continue.</p>
<ul>
${scopeItems}
</ul>
${error}
<form method="post" action="${escapeHtml(input.action)}">
  <input type="hidden" name="request" value="${escapeHtml(input.requestToken)}">
  <label for="passphrase">Passphrase</label>
  <input id="passphrase" name="passphrase" type="password" autocomplete="current-password" required autofocus>
  <div class="actions">
    <button type="submit" name="decision" value="deny">Cancel</button>
    <button type="submit" name="decision" value="allow" class="primary">Authorize</button>
  </div>
</form>`
  );
}

export function renderErrorPage(title: string, message: string): string {
  return page(title, `<h1>${escapeHtml(title)}</h1>\n<p>${escapeHtml(message)}</p>`);
}
