/**
 * lib/config.ts
 *
 * Central configuration helpers.
 * Canonical URLs are derived strictly from environment configuration (SHARE_BASE_URL)
 * and never from the incoming Host header, preventing Host header poisoning.
 */

export function getBaseUrl(): string {
  const url = process.env.SHARE_BASE_URL;
  if (!url || url.trim().length === 0) {
    throw new Error(
      'SHARE_BASE_URL environment variable is required and must not be empty. ' +
      'Refusing to run without explicit base URL configuration.'
    );
  }
  return url.trim().replace(/\/+$/, '');
}
