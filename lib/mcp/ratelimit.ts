/**
 * lib/mcp/ratelimit.ts
 *
 * A fixed-window counter per key, held in the memory of the running instance. On serverless that
 * is a best-effort limit: every instance counts on its own and a cold start counts from zero. It
 * slows a scripted guess at the passphrase and a runaway tool loop, which is what it is for; a
 * hard ceiling belongs at the edge (the platform firewall).
 */

export type RateDecision = { allowed: boolean; retryAfterSeconds: number };

export class RateLimiter {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();
  private readonly limit: number;
  private readonly windowMs: number;

  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }

  hit(key: string, now: number = Date.now()): RateDecision {
    this.prune(now);
    const entry = this.hits.get(key);
    if (!entry || entry.resetAt <= now) {
      this.hits.set(key, { count: 1, resetAt: now + this.windowMs });
      return { allowed: true, retryAfterSeconds: 0 };
    }
    entry.count += 1;
    if (entry.count > this.limit) {
      return { allowed: false, retryAfterSeconds: Math.ceil((entry.resetAt - now) / 1000) };
    }
    return { allowed: true, retryAfterSeconds: 0 };
  }

  reset(): void {
    this.hits.clear();
  }

  private prune(now: number): void {
    if (this.hits.size < 1000) return;
    for (const [key, entry] of this.hits) {
      if (entry.resetAt <= now) this.hits.delete(key);
    }
  }
}

/** The caller's address as the platform reports it; "unknown" when nothing reports it. */
export function clientAddress(request: Request): string {
  const forwarded = request.headers.get('x-forwarded-for');
  if (forwarded) return forwarded.split(',')[0].trim() || 'unknown';
  return request.headers.get('x-real-ip')?.trim() || 'unknown';
}

/** Tool calls per authenticated subject. */
export const toolCallLimiter = new RateLimiter(120, 60 * 1000);
/** Passphrase attempts per address. */
export const loginLimiter = new RateLimiter(5, 15 * 60 * 1000);
/** Token endpoint requests per address. */
export const tokenLimiter = new RateLimiter(60, 60 * 1000);
/** Client registrations per address. */
export const registrationLimiter = new RateLimiter(20, 60 * 60 * 1000);
