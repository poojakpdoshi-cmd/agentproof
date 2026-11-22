// Official MCP SDK transport and server; tool side effects use dummy memory only.
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, ListResourcesRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { appendFileSync } from 'node:fs';

const journal = process.argv[2];
const log = (value: unknown) => appendFileSync(journal, JSON.stringify(value) + '\n');
const server = new Server({ name: 'official-sdk-dummy', version: '1.0.0' },
  { capabilities: { tools: {}, resources: {}, prompts: {}, logging: {} } });
const files = new Map([['docs/dummy.txt', 'DUMMY_PUBLIC'], ['private/secret.txt', 'DUMMY_SECRET'],
  ['docs/café.txt', 'DUMMY_UNICODE'], ['docs/.config', 'DUMMY_HIDDEN']]);
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [
  { name: 'read_file', inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } },
  { name: 'write_file', inputSchema: { type: 'object', properties: { path: { type: 'string' }, data: { type: 'string' } }, required: ['path', 'data'] } },
  { name: 'network_request', inputSchema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] } },
] }));
server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: [] }));
server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
  log({ event: 'executed', id: extra.requestId, params: request.params });
  const args = request.params.arguments!;
  if (request.params._meta?.progressToken !== undefined) {
    await server.notification({ method: 'notifications/progress', params: {
      progressToken: request.params._meta.progressToken, progress: 1, total: 1,
    } });
  }
  let data: string;
  if (request.params.name === 'write_file') { files.set(args.path as string, args.data as string); data = 'DUMMY_WRITE_OK'; }
  else if (request.params.name === 'read_file') {
    if (!files.has(args.path as string)) return { isError: true, content: [{ type: 'text', text: 'DUMMY_NOT_FOUND' }] };
    data = files.get(args.path as string)!;
  } else data = 'DUMMY_NETWORK_OK';
  return { content: [{ type: 'text', text: data }], structuredContent: { data }, isError: false };
});
const transport = new StdioServerTransport();
await server.connect(transport);
const receive = transport.onmessage!;
transport.onmessage = (message, extra) => { log({ event: 'received', message }); receive(message, extra); };
