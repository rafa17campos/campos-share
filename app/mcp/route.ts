import { serveMcp } from '../../lib/mcp/server.ts';

export const dynamic = 'force-dynamic';
// Every tool call finishes in well under a second; cap a stuck request at 60 s, not the 300 s default.
export const maxDuration = 60;

export { serveMcp as GET, serveMcp as POST, serveMcp as DELETE, serveMcp as OPTIONS };
