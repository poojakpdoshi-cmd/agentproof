#!/usr/bin/env node
// Deliberately no policy enforcement: integration tests must prove the proxy blocks calls.
import { appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';

const args = process.argv.slice(2);
const option = (name: string) => args.includes(name) ? args[args.indexOf(name) + 1] : undefined;
const journal = option('--journal');
const fault = option('--fault');
const log = (value: unknown) => { if (journal) appendFileSync(journal, JSON.stringify(value) + '\n'); };
const output = (value: unknown) => process.stdout.write(JSON.stringify(value) + '\n');
const files = new Map([['docs/dummy.txt', 'DUMMY_PUBLIC'], ['private/secret.txt', 'DUMMY_SECRET']]);
const schema = (properties: Record<string, unknown>, required: string[]) =>
  ({ type: 'object', properties, required, additionalProperties: false });
const text = { type: 'string' };
const reordered: unknown[] = [];
log({ event: 'started' });

for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  const request = JSON.parse(line);
  log(request);
  if (!request.method || !Object.hasOwn(request, 'id')) continue;
  const reply = (result: unknown) => output({ jsonrpc: '2.0', id: request.id, result });
  const error = (code: number, message: string) => output({ jsonrpc: '2.0', id: request.id, error: { code, message } });
  switch (request.method) {
    case 'initialize':
      if (args.includes('--ping-client')) output({ jsonrpc: '2.0', id: request.id, method: 'ping' });
      reply({ protocolVersion: '2025-11-25', capabilities: { tools: {} },
        serverInfo: { name: 'agentproof-dummy', version: '0.0.0' } });
      break;
    case 'ping': reply({}); break;
    case 'tools/list':
      reply({ tools: [
        { name: 'read_file', inputSchema: schema({ path: text }, ['path']) },
        { name: 'write_file', inputSchema: schema({ path: text, data: text }, ['path', 'data']) },
        { name: 'network_request', inputSchema: schema({ url: text, method: { enum: ['GET', 'HEAD'] } }, ['url']) },
      ] });
      break;
    case 'tools/call': {
      if (fault === 'exit') process.exit(3);
      if (fault === 'invalid') { process.stdout.write('NOT_JSON\n'); break; }
      if (fault === 'wrong-id') { output({ jsonrpc: '2.0', id: 'unsolicited', result: {} }); break; }
      if (fault === 'rpc-error') { error(-32603, 'DUMMY upstream error'); break; }
      if (fault === 'server-request') output({ jsonrpc: '2.0', id: 'server-action', method: 'sampling/createMessage', params: {} });
      const { name, arguments: input, _meta } = request.params;
      if (_meta && Object.hasOwn(_meta, 'progressToken')) output({ jsonrpc: '2.0', method: 'notifications/progress',
        params: { progressToken: _meta.progressToken, progress: 1, total: 1 } });
      let result: string;
      if (name === 'write_file') { files.set(input.path, input.data); result = 'DUMMY_WRITE_OK'; }
      else if (name === 'read_file') {
        if (!files.has(input.path)) { reply({ isError: true, content: [{ type: 'text', text: 'DUMMY_NOT_FOUND' }] }); break; }
        result = files.get(input.path)!;
      } else if (name === 'network_request') result = 'DUMMY_NETWORK_OK';
      else { error(-32602, 'Unknown tool'); break; }
      log({ event: 'executed', id: request.id, tool: name });
      const response = { jsonrpc: '2.0', id: request.id,
        result: { content: [{ type: 'text', text: result }], isError: false } };
      if (fault === 'reorder') {
        reordered.push(response);
        if (reordered.length === 2) for (const queued of reordered.splice(0).reverse()) output(queued);
      } else output(response);
      break;
    }
    default: error(-32601, 'Method not found');
  }
}
