import assert from 'node:assert/strict';
import test from 'node:test';
import type { TestContext } from 'node:test';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { JSONRPCMessageSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { Client as ModernClient } from '@modelcontextprotocol/client';
import { StdioClientTransport as ModernTransport } from '@modelcontextprotocol/client/stdio';
import { message, rpcError } from '../src/mcp-protocol.ts';
import { toolGate } from '../src/mcp-policy.ts';

const proxy = fileURLToPath(new URL('../src/mcp-proxy.ts', import.meta.url));
const legacyServer = fileURLToPath(new URL('./fixtures/sdk-server.ts', import.meta.url));
const modernServer = fileURLToPath(new URL('./fixtures/sdk-modern-server.ts', import.meta.url));

function setup(t: TestContext, modern = false, proxied = true) {
  const root = mkdtempSync(path.join(tmpdir(), 'agentproof-sdk-'));
  const policy = path.join(root, 'policy.json');
  const journal = path.join(root, 'journal.jsonl');
  writeFileSync(policy, JSON.stringify({ read: ['docs/', 'out/'], write: ['out/'], network: ['https://api.example.test/health'] }));
  const server = modern ? modernServer : legacyServer;
  const args = proxied ? [proxy, '--policy', policy, '--', process.execPath, server, journal] : [server, journal];
  const transport = modern
    ? new ModernTransport({ command: process.execPath, args, stderr: 'pipe' })
    : new StdioClientTransport({ command: process.execPath, args, stderr: 'pipe' });
  const client = modern
    ? new ModernClient({ name: 'agentproof-audit', version: '0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } })
    : new Client({ name: 'agentproof-audit', version: '0' }, { capabilities: { roots: { listChanged: true } } });
  const sent: any[] = [];
  const received: any[] = [];
  const errors: Error[] = [];
  client.onerror = error => { errors.push(error); };
  const send = transport.send.bind(transport);
  transport.send = async (value: any, ...rest: any[]) => { sent.push(structuredClone(value)); return send(value, ...rest); };
  const records = (): any[] => existsSync(journal) ? readFileSync(journal, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) : [];
  t.after(async () => { await client.close(); await transport.close(); rmSync(root, { recursive: true, force: true }); });
  async function connect() {
    await client.connect(transport, { timeout: 3000 });
    const receive = transport.onmessage!;
    transport.onmessage = (value: any, ...rest: any[]) => { received.push(structuredClone(value)); receive(value, ...rest); };
  }
  return { client, transport, connect, sent, received, records, errors };
}

test('official legacy SDK client/server: allow executes, deny never reaches handler or transport', { timeout: 15000 }, async t => {
  const s = setup(t);
  await s.connect();
  assert.equal(s.client.getServerVersion()?.name, 'official-sdk-dummy');
  assert.equal((await s.client.listTools()).tools.length, 3);
  const progress: unknown[] = [];
  const write = await s.client.callTool({ name: 'write_file', arguments: { path: 'out/dummy.txt', data: 'DUMMY_SDK' } });
  assert.equal(write.isError, false);
  const read = await s.client.callTool({ name: 'read_file', arguments: { path: 'out/dummy.txt' } }, undefined,
    { onprogress: value => progress.push(value) });
  assert.deepEqual(read.structuredContent, { data: 'DUMMY_SDK' });
  // The proxy must relay the progress notification (checked at the transport). The SDK's own
  // callback can miss it when notification and response share one pipe chunk: notifications
  // are dispatched on a microtask while _onresponse deletes the handler synchronously.
  assert.equal(s.received.filter(v => v.method === 'notifications/progress').length, 1);
  assert.ok(progress.length <= 1);
  const denied = [
    { name: 'read_file', arguments: { path: 'private/secret.txt' } },
    { name: 'write_file', arguments: { path: 'docs/dummy.txt', data: 'DUMMY_ATTACK' } },
    { name: 'read_file', arguments: { path: 'docs/../private/secret.txt' } },
    { name: 'network_request', arguments: { url: 'https://api.example.test/health', body: 'DUMMY_SECRET' } },
  ];
  for (const params of denied) assert.equal((await s.client.callTool(params)).isError, true);
  assert.equal((await s.client.callTool({ name: 'network_request', arguments: { url: 'https://api.example.test/health' } })).isError, false);
  await s.client.ping();
  const executed = s.records().filter(v => v.event === 'executed');
  assert.equal(executed.length, 3);
  assert.equal(s.records().filter(v => v.event === 'received' && v.message.method === 'tools/call').length, 3);
  for (const call of s.sent.filter(v => v.method === 'tools/call')) {
    assert.equal(s.received.filter(v => v.id === call.id && !v.method).length, 1);
  }
  // Only the SDK client race described above may surface here (late progress after response).
  assert.equal(s.errors.filter(e => !/progress notification for an unknown token/.test(e.message)).length, 0);
});

test('official SDK negotiated capabilities do not advertise methods the proxy blocks', { timeout: 15000 }, async t => {
  const s = setup(t);
  await s.connect();
  assert.deepEqual(s.client.getServerCapabilities(), { tools: {} });
  const init = s.records().find(v => v.event === 'received' && v.message.method === 'initialize');
  assert.deepEqual(init.message.params.capabilities, {});
});

test('official modern SDK works directly against its 2026-only server', { timeout: 15000 }, async t => {
  const s = setup(t, true, false);
  await s.connect();
  assert.equal((await s.client.listTools()).tools.length, 1);
  const result = await s.client.callTool({ name: 'read_file', arguments: { path: 'docs/dummy.txt' } });
  assert.equal(result.isError, false);
  assert.equal(s.records().filter(v => v.event === 'executed').length, 1);
  assert.equal((s.client as ModernClient).getNegotiatedProtocolVersion(), '2026-07-28');
});

test('official modern SDK confirms 2026-only server is incompatible through legacy proxy', { timeout: 15000 }, async t => {
  const s = setup(t, true, true);
  let failure: unknown;
  try {
    await s.connect();
    await s.client.listTools();
  } catch (error) { failure = error; }
  assert.ok(failure, 'Modern discovery/requests must not be reported as supported');
  t.diagnostic('Confirmed 2026 incompatibility: ' + String(failure));
  assert.equal(s.records().filter(v => v.event === 'executed').length, 0);
});

test('MCP envelopes agree with official legacy SDK schemas', () => {
  assert.equal(JSONRPCMessageSchema.safeParse(rpcError(null, -32700, 'Parse error')).success, true);
  for (const result of [null, 42, 'DUMMY', []]) assert.equal(message({ jsonrpc: '2.0', id: 1, result }), false);
});

test('fractional progress tokens agree with official SDK rejection', () => {
  const params = { name: 'read_file', arguments: { path: 'docs/dummy.txt' }, _meta: { progressToken: 0.5 } };
  assert.equal(CallToolRequestSchema.safeParse({ method: 'tools/call', params }).success, false);
  assert.equal(toolGate({ read: ['docs/'] })(params).allowed, false);
});

test('measure deliberate false denials: valid tracing metadata, Unicode and dotfiles', { timeout: 15000 }, async t => {
  const direct = setup(t, false, false);
  const guarded = setup(t);
  await direct.connect();
  await guarded.connect();
  const calls = [
    { name: 'read_file', arguments: { path: 'docs/dummy.txt' },
      _meta: { traceparent: '00-11111111111111111111111111111111-2222222222222222-01' } },
    { name: 'read_file', arguments: { path: 'docs/café.txt' } },
    { name: 'read_file', arguments: { path: 'docs/.config' } },
  ];
  for (const call of calls) {
    assert.equal((await direct.client.callTool(call)).isError, false);
    assert.equal((await guarded.client.callTool(call)).isError, true);
  }
  assert.equal(direct.records().filter(v => v.event === 'executed').length, 3);
  assert.equal(guarded.records().filter(v => v.event === 'executed').length, 0);
});
