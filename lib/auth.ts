/**
 * lib/auth.ts
 *
 * Authentication, cryptographic hashing, and session unlock utilities.
 * Uses Node.js native crypto for timing-safe comparison and scrypt hashing.
 */

import crypto from 'node:crypto';

/**
 * Constant-time comparison for API Bearer tokens
 */
export function verifyApiToken(request: Request): boolean {
  const expectedToken = process.env.SHARE_API_TOKEN;
  if (!expectedToken) {
    return false;
  }

  const authHeader = request.headers.get('authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return false;
  }

  const receivedToken = authHeader.slice(7).trim();
  const expectedBuffer = Buffer.from(expectedToken, 'utf-8');
  const receivedBuffer = Buffer.from(receivedToken, 'utf-8');

  if (expectedBuffer.length !== receivedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuffer, receivedBuffer);
}

/**
 * Derives a password hash using scrypt with random salt.
 * Tuned to ~100ms verification time on serverless runtime (N=32768) to defeat offline brute force.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16);
  const costN = 32768;
  const costR = 8;
  const costP = 1;
  const keyLen = 32;
  const maxmem = 64 * 1024 * 1024;

  const derivedKey = await new Promise<Buffer>((resolve, reject) => {
    crypto.scrypt(
      password,
      salt,
      keyLen,
      { N: costN, r: costR, p: costP, maxmem },
      (err, progress) => {
        if (err) reject(err);
        else resolve(progress as Buffer);
      }
    );
  });

  return `scrypt$N=${costN}$r=${costR}$p=${costP}$${salt.toString('hex')}$${derivedKey.toString('hex')}`;
}

/**
 * Verifies a password against a stored scrypt hash using constant-time comparison.
 */
export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const parts = storedHash.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') {
    return false;
  }

  const n = parseInt(parts[1].replace('N=', ''), 10);
  const r = parseInt(parts[2].replace('r=', ''), 10);
  const p = parseInt(parts[3].replace('p=', ''), 10);
  const salt = Buffer.from(parts[4], 'hex');
  const expectedKey = Buffer.from(parts[5], 'hex');
  const maxmem = 64 * 1024 * 1024;

  const derivedKey = await new Promise<Buffer>((resolve, reject) => {
    crypto.scrypt(
      password,
      salt,
      expectedKey.length,
      { N: n, r: r, p: p, maxmem },
      (err, progress) => {
        if (err) reject(err);
        else resolve(progress as Buffer);
      }
    );
  });

  if (derivedKey.length !== expectedKey.length) {
    return false;
  }

  return crypto.timingSafeEqual(derivedKey, expectedKey);
}

/**
 * Executes a dummy scrypt verification so that requests for non-existent
 * or unprotected slugs take the exact same ~100ms execution time,
 * eliminating timing-based slug probing.
 */
export async function runDummyPasswordCheck(): Promise<void> {
  const dummySalt = Buffer.alloc(16, 0x42);
  const maxmem = 64 * 1024 * 1024;
  await new Promise<Buffer>((resolve, reject) => {
    crypto.scrypt(
      'dummy_password_timing_defense',
      dummySalt,
      32,
      { N: 32768, r: 8, p: 1, maxmem },
      (err, progress) => {
        if (err) reject(err);
        else resolve(progress as Buffer);
      }
    );
  });
}

function getCookieSecret(): string {
  const secret = process.env.SHARE_COOKIE_SECRET;
  if (!secret || secret.trim().length === 0) {
    throw new Error(
      'SHARE_COOKIE_SECRET environment variable is required and must not be empty. ' +
      'Refusing to run with missing or fallback cookie secret.'
    );
  }
  return secret.trim();
}

/**
 * Generates an HMAC-signed session unlock token for a slug.
 * Signed strictly with SHARE_COOKIE_SECRET, never SHARE_API_TOKEN.
 * Throws immediately if SHARE_COOKIE_SECRET is missing.
 */
export function createUnlockCookieValue(slug: string): string {
  const secret = getCookieSecret();
  const timestamp = Date.now();
  const payload = `${slug}:${timestamp}`;
  const hmac = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return `${payload}:${hmac}`;
}

/**
 * Verifies that the provided cookie value is valid, unexpired, and matches the slug.
 * Throws immediately if SHARE_COOKIE_SECRET is missing.
 */
export function verifyUnlockCookieValue(cookieValue: string | null | undefined, slug: string): boolean {
  if (!cookieValue) return false;

  const parts = cookieValue.split(':');
  if (parts.length !== 3) return false;

  const [cookieSlug, timestampStr, signature] = parts;
  if (cookieSlug !== slug || !/^[0-9a-f]{64}$/i.test(signature)) return false;

  const timestamp = parseInt(timestampStr, 10);
  if (isNaN(timestamp)) return false;

  // Max unlock session duration: 7 days
  const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
  if (Date.now() - timestamp > MAX_AGE_MS || timestamp > Date.now() + 60000) {
    return false;
  }

  const secret = getCookieSecret();
  const payload = `${cookieSlug}:${timestampStr}`;
  const expectedHmac = crypto.createHmac('sha256', secret).update(payload).digest('hex');

  const expectedBuffer = Buffer.from(expectedHmac, 'hex');
  const signatureBuffer = Buffer.from(signature, 'hex');

  if (expectedBuffer.length !== signatureBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuffer, signatureBuffer);
}

/**
 * Helper to extract the unlock cookie for a specific slug from Cookie header
 */
export function getUnlockCookieFromRequest(request: Request, slug: string): string | null {
  const cookieHeader = request.headers.get('cookie');
  if (!cookieHeader) return null;

  const cookieName = `share_unlock_${slug}`;
  const cookies = cookieHeader.split(';');
  for (const c of cookies) {
    const [key, value] = c.trim().split('=');
    if (key === cookieName) {
      return decodeURIComponent(value || '');
    }
  }
  return null;
}
