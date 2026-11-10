/**
 * lib/sandbox.ts
 *
 * The Content-Security-Policy every piece of content we did not write is served under: uploaded
 * pages, and HTML, SVG or XML files in a folder. `sandbox` gives it an opaque origin, so it cannot
 * read this origin's cookies or storage or call its API with the visitor's credentials.
 *
 * What it may do inside that box:
 * - allow-scripts: ordinary pages need JavaScript (and window.shareDb needs it).
 * - allow-forms: submitting a form. A script can already send data anywhere with fetch, so a form
 *   adds no reach; without it a plain <form> silently does nothing.
 * - allow-modals: alert, confirm and prompt, which only ever block the page's own tab.
 *
 * Never allow-same-origin. This origin also serves OAuth, MCP, /api and the unlock cookie of every
 * protected share: with allow-same-origin and allow-scripts together, one page could reach other
 * shares the visitor unlocked and read every other page's storage.
 */
export const UNTRUSTED_CONTENT_POLICY = 'sandbox allow-scripts allow-forms allow-modals';
