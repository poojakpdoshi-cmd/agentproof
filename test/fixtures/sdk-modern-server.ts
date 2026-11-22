import { Server } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { appendFileSync } from 'node:fs';

const journal = process.argv[2];
serveStdio(() => {
  const server = new Server({ name: 'official-sdk-modern', version: '1.0.0' },
    { capabilities: { tools: {} }, supportedProtocolVersions: ['2026-07-28'] });
  server.setRequestHandler('tools/list', async () => ({ tools: [
    { name: 'read_file', inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } },
  ] }));
  server.setRequestHandler('tools/call', async request => {
    appendFileSync(journal, JSON.stringify({ event: 'executed', params: request.params }) + '\n');
    return { content: [{ type: 'text', text: 'DUMMY_MODERN' }], isError: false };
  });
  return server;
}, { legacy: 'reject' });
