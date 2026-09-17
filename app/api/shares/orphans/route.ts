import { getStorage } from '../../../../lib/storage.ts';
import { verifyApiToken } from '../../../../lib/auth.ts';

export async function POST(request: Request) {
  if (!verifyApiToken(request)) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const storage = getStorage();
  // Only sweep prefixes older than 24 hours (86,400,000 ms)
  const orphanPrefixes = await storage.listOrphanPrefixes(24 * 60 * 60 * 1000);

  for (const prefix of orphanPrefixes) {
    await storage.deleteShare(prefix);
  }

  return new Response(
    JSON.stringify({
      sweptPrefixes: orphanPrefixes,
      count: orphanPrefixes.length,
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }
  );
}
