/**
 * lib/conflictRetry.ts
 *
 * The wait between attempts of an optimistic write (read with an ETag, write with ifMatch, start
 * over on a conflict). Writers that collided and retried at once would collide again: each waits a
 * random time up to a cap that doubles per attempt (exponential backoff with full jitter), so they
 * fall into line. The cap starts near one Blob read-modify-write cycle and stops at two seconds.
 */

const BASE_MS = 100;
const CAP_MS = 2000;

export function backoffBeforeRetry(attempt: number): Promise<void> {
  const cap = Math.min(CAP_MS, BASE_MS * 2 ** attempt);
  return new Promise((resolve) => setTimeout(resolve, Math.random() * cap));
}
