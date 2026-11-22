import assert from 'node:assert/strict';
import test from 'node:test';
import type { TestContext } from 'node:test';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { toolGate } from '../src/mcp-policy.ts';

const proxy = fileURLToPath(new URL('../src/mcp-proxy.ts', import.meta.url));
const dummy = fileURLToPath(new URL('../examples/dummy-mcp-server.ts', import.meta.url));
const policy = { read: ['docs/', 'out/'], write: ['out/'], network: ['https://api.example.test/health'] };
const call = (id: string | number, name: string, args: unknown) =>
  ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

function session(t: TestContext, configuration: unknown = policy, flags: string[] = []) {
  const root = mkdtempSync(path.join(tmpdir(), 'agentproof-mcp-dummy-'));
  const config = path.join(root, 'policy.json');
  const journal = path.join(root, 'server.jsonl');
  writeFileSync(config, typeof configuration === 'string' ? configuration : JSON.stringify(configuration));
  const child = spawn(process.execPath, [proxy, '--policy', config, '--', process.execPath, dummy, '--journal', journal, ...flags],
    { stdio: ['pipe', 'pipe', 'pipe'] });
  const messages: any[] = [];
  let stderr = '';
  let ended = false;
  const waiters = new Set<() => void>();
  const wake = () => { for (const resolve of waiters) resolve(); waiters.clear(); };
  child.stdin.on('error', () => {});
  child.stderr.on('data', chunk => { stderr += chunk; });
  createInterface({ input: child.stdout }).on('line', line => {
    messages.push(JSON.parse(line));
    wake();
  });
  const done = new Promise<number | null>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', code => { ended = true; wake(); resolve(code); });
  });
  const watchdog = setTimeout(() => { child.kill(); }, 10000);
  t.after(async () => {
    clearTimeout(watchdog);
    if (!ended) { child.stdin.end(); child.kill(); }
    await done;
    rmSync(root, { recursive: true, force: true });
  });
  async function wait(predicate: (value: any) => boolean): Promise<any> {
    while (true) {
      const found = messages.find(predicate);
      if (found) return found;
      if (ended) throw new Error('Proxy exited before expected response: ' + stderr);
      await new Promise<void>(resolve => { waiters.add(resolve); });
    }
  }
  const send = (value: unknown) => child.stdin.write(JSON.stringify(value) + '\n');
  const response = (id: string | number) => wait(value => value.id === id && !value.method);
  const request = async (value: any) => { send(value); return response(value.id); };
  async function initialize(id: string | number = 'init') {
    const pending = request({ jsonrpc: '2.0', id, method: 'initialize', params: {
      protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'dummy-test', version: '0' },
    } });
    if (flags.includes('--ping-client')) {
      const ping = await wait(value => value.method === 'ping');
      send({ jsonrpc: '2.0', id: ping.id, result: {} });
    }
    const reply = await pending;
    assert.equal(reply.id, id);
    assert.equal(reply.result.serverInfo.name, 'agentproof-dummy');
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    return reply;
  }
  const records = (): any[] => existsSync(journal)
    ? readFileSync(journal, 'utf8').trim().split('\n').map(line => JSON.parse(line)) : [];
  return { child, messages, done, send, request, response, initialize, wait, records,
    stderr: () => stderr, close: async () => { child.stdin.end(); return done; } };
}

test('MCP approved calls execute in a separate server and preserve typed IDs', { timeout: 15000 }, async t => {
  const s = session(t);
  await s.initialize(0);
  assert.equal((await s.request({ jsonrpc: '2.0', id: 'list', method: 'tools/list' })).result.tools.length, 3);
  assert.equal((await s.request(call(1, 'write_file', { path: 'OUT\\RESULT.TXT', data: 'DUMMY_WRITTEN' }))).result.isError, false);
  assert.equal((await s.request(call('1', 'read_file', { path: 'out/result.txt' }))).result.content[0].text, 'DUMMY_WRITTEN');
  assert.equal((await s.request(call('', 'network_request', { url: policy.network[0] }))).result.content[0].text, 'DUMMY_NETWORK_OK');
  assert.equal(await s.close(), 0);
  assert.deepEqual(s.records().filter(v => v.event === 'executed').map(v => v.id), [1, '1', '']);
  assert.equal(s.records().find(v => v.id === 1 && v.method === 'tools/call').params.arguments.path, 'out/result.txt');
});

test('MCP denied calls never reach the dummy server; denied writes cannot mutate it', { timeout: 15000 }, async t => {
  const s = session(t);
  await s.initialize();
  const attempts = [
    call('secret', 'read_file', { path: 'private/secret.txt' }),
    call('write', 'write_file', { path: 'docs/dummy.txt', data: 'DUMMY_ATTACK' }),
    call('traversal', 'read_file', { path: 'docs/../private/secret.txt' }),
    call('unc', 'read_file', { path: '\\\\server\\share\\dummy.txt' }),
    call('ads', 'write_file', { path: 'out/dummy.txt:stream', data: 'DUMMY' }),
    call('host', 'network_request', { url: 'https://attacker.example.test/' }),
    call('exfil', 'network_request', { url: policy.network[0], body: 'DUMMY_SECRET' }),
    call('query', 'network_request', { url: policy.network[0] + '?data=DUMMY_SECRET' }),
    call('unknown', 'shell', { command: 'DUMMY' }),
    call('override', 'read_file', { type: 'write', path: 'docs/dummy.txt' }),
    { ...call('task', 'read_file', { path: 'docs/dummy.txt' }), params: { name: 'read_file', arguments: { path: 'docs/dummy.txt' }, task: {} } },
    { ...call('meta', 'read_file', { path: 'docs/dummy.txt' }), params: { name: 'read_file', arguments: { path: 'docs/dummy.txt' }, _meta: { bypass: true } } },
  ];
  for (const attempt of attempts) {
    const reply = await s.request(attempt);
    assert.equal(reply.id, attempt.id);
    assert.equal(reply.result.isError, true);
  }
  assert.equal((await s.request(call('verify', 'read_file', { path: 'docs/dummy.txt' }))).result.content[0].text, 'DUMMY_PUBLIC');
  assert.equal(await s.close(), 0);
  assert.deepEqual(s.records().filter(v => v.method === 'tools/call').map(v => v.id), ['verify']);
  const audits = s.stderr().trim().split('\n').map(line => JSON.parse(line));
  assert.equal(audits.filter(v => v.decision === 'deny').length, attempts.length);
  assert.equal(s.stderr().includes('DUMMY_SECRET'), false);
});

test('MCP empty policy denies every tool', { timeout: 15000 }, async t => {
  const s = session(t, {});
  await s.initialize();
  for (const [id, name, args] of [[1, 'read_file', { path: 'docs/dummy.txt' }],
    [2, 'write_file', { path: 'out/dummy.txt', data: 'DUMMY' }], [3, 'network_request', { url: policy.network[0] }]] as const) {
    assert.equal((await s.request(call(id, name, args))).result.isError, true);
  }
  await s.close();
  assert.equal(s.records().some(v => v.method === 'tools/call'), false);
});

for (const [name, config] of [['malformed JSON', '{'], ['invalid grants', { read: ['../'] }], ['null', null]] as const) {
  test(`MCP ${name} policy fails before upstream startup`, { timeout: 15000 }, async t => {
    const s = session(t, config);
    assert.equal(await s.done, 2);
    assert.deepEqual(s.records(), []);
    assert.deepEqual(s.messages, []);
  });
}

test('MCP lifecycle, bidirectional IDs, progress and cancellation preserve envelopes', { timeout: 15000 }, async t => {
  const s = session(t, policy, ['--ping-client']);
  assert.equal((await s.request(call('early', 'read_file', { path: 'docs/dummy.txt' }))).error.code, -32000);
  await s.initialize(5);
  const request = call('progress', 'read_file', { path: 'docs/dummy.txt' });
  Object.assign(request.params, { _meta: { progressToken: 'dummy-token' } });
  await s.request(request);
  assert.deepEqual((await s.wait(v => v.method === 'notifications/progress')).params,
    { progressToken: 'dummy-token', progress: 1, total: 1 });
  s.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 'progress' } });
  await s.request({ jsonrpc: '2.0', id: 'barrier', method: 'ping' });
  assert.equal(await s.close(), 0);
  assert.equal(s.records().some(v => v.id === 'early'), false);
  assert.ok(s.records().some(v => v.id === 5 && v.result));
  assert.ok(s.records().some(v => v.method === 'notifications/cancelled'));
});

test('MCP tool notifications, batches and alternate methods cannot bypass interception', { timeout: 15000 }, async t => {
  const s = session(t);
  await s.initialize();
  s.send({ jsonrpc: '2.0', method: 'tools/call', params: { name: 'write_file', arguments: { path: 'docs/dummy.txt', data: 'DUMMY' } } });
  s.send([call('batch', 'read_file', { path: 'private/secret.txt' })]);
  assert.equal((await s.wait(v => !Object.hasOwn(v, 'id'))).error.code, -32600);
  for (const method of ['resources/read', 'prompts/get', 'tasks/get', 'Tools/call']) {
    assert.equal((await s.request({ jsonrpc: '2.0', id: method, method, params: {} })).error.code, -32601);
  }
  await s.request({ jsonrpc: '2.0', id: 'barrier', method: 'ping' });
  await s.close();
  assert.equal(s.records().some(v => v.method === 'tools/call' || Array.isArray(v)), false);
});

test('MCP framing supports split UTF-8 and coalesced CRLF messages; malformed JSON is isolated', { timeout: 15000 }, async t => {
  const s = session(t);
  await s.initialize();
  s.child.stdin.write('NOT_JSON\n');
  assert.equal((await s.wait(v => !Object.hasOwn(v, 'id'))).error.code, -32700);
  const bytes = Buffer.from(JSON.stringify(call('unicode', 'write_file', { path: 'out/data.txt', data: 'DUMMY_é' })) + '\r\n');
  const split = bytes.indexOf(0xc3) + 1;
  s.child.stdin.write(bytes.subarray(0, split));
  s.child.stdin.write(Buffer.concat([bytes.subarray(split), Buffer.from(JSON.stringify(call('read', 'read_file', { path: 'out/data.txt' })) + '\n')]));
  assert.equal((await s.response('unicode')).result.isError, false);
  assert.equal((await s.response('read')).result.content[0].text, 'DUMMY_é');
  assert.equal(await s.close(), 0);
});

test('MCP duplicate IDs terminate the session before the duplicate reaches upstream', { timeout: 15000 }, async t => {
  const s = session(t);
  await s.initialize();
  await s.request(call('same', 'read_file', { path: 'docs/dummy.txt' }));
  s.send(call('same', 'write_file', { path: 'out/dummy.txt', data: 'DUMMY' }));
  assert.equal(await s.done, 2);
  assert.equal(s.records().filter(v => v.id === 'same' && v.method).length, 1);
});

for (const fault of ['exit', 'invalid', 'wrong-id']) {
  test(`MCP upstream ${fault} fails closed and resolves the pending ID`, { timeout: 15000 }, async t => {
    const s = session(t, policy, ['--fault', fault]);
    await s.initialize();
    const reply = await s.request(call('pending', 'read_file', { path: 'docs/dummy.txt' }));
    assert.equal(reply.error.code, -32002);
    assert.equal(await s.done, 2);
    assert.equal(s.messages.some(v => v.id === 'unsolicited'), false);
    assert.equal(s.messages.filter(v => v.id === 'pending').length, 1);
  });
}

test('MCP upstream JSON-RPC errors pass through unchanged', { timeout: 15000 }, async t => {
  const s = session(t, policy, ['--fault', 'rpc-error']);
  await s.initialize();
  assert.deepEqual(await s.request(call(7, 'read_file', { path: 'docs/dummy.txt' })),
    { jsonrpc: '2.0', id: 7, error: { code: -32603, message: 'DUMMY upstream error' } });
  assert.equal(await s.close(), 0);
});

test('MCP upstream sampling requests are refused, not relayed to the client', { timeout: 15000 }, async t => {
  const s = session(t, policy, ['--fault', 'server-request']);
  await s.initialize();
  await s.request(call('read', 'read_file', { path: 'docs/dummy.txt' }));
  await s.request({ jsonrpc: '2.0', id: 'barrier', method: 'ping' });
  await s.close();
  assert.equal(s.messages.some(v => v.method === 'sampling/createMessage'), false);
  assert.equal(s.records().find(v => v.id === 'server-action' && v.error).error.code, -32601);
});

for (const [name, frame] of [['UTF-8', Buffer.from([0xff, 10])], ['oversize', Buffer.alloc(1024 * 1024 + 1, 65)] ] as const) {
  test(`MCP invalid ${name} transport closes without forwarding a call`, { timeout: 15000 }, async t => {
    const s = session(t);
    await s.initialize();
    s.child.stdin.write(frame);
    assert.equal(await s.done, 2);
    assert.equal(s.records().some(v => v.method === 'tools/call'), false);
  });
}

test('MCP gate rejects hostile in-process inputs without executing getters', () => {
  const gate = toolGate(policy);
  let reads = 0;
  const result = gate({ get name() { reads++; throw new Error('DUMMY'); }, arguments: {} });
  assert.equal(result.allowed, false);
  assert.equal(reads, 0);
  assert.equal(gate({ name: 'read_file', arguments: { path: 'docs/dummy.txt' }, _meta: { progressToken: {} } }).allowed, false);
});

test('MCP unexpected policy-evaluation exceptions become denials', t => {
  const gate = toolGate(policy);
  const replacement = t.mock.method(String.prototype, 'replaceAll', () => { throw new Error('DUMMY evaluator failure'); });
  const result = gate({ name: 'read_file', arguments: { path: 'docs/dummy.txt' } });
  replacement.mock.restore();
  assert.equal(result.allowed, false);
  assert.equal(result.reason, 'policy-error');
});

test('MCP concurrent out-of-order responses retain numeric versus string IDs', { timeout: 15000 }, async t => {
  const s = session(t, policy, ['--fault', 'reorder']);
  await s.initialize();
  const replies = await Promise.all([
    s.request(call(9, 'read_file', { path: 'docs/dummy.txt' })),
    s.request(call('9', 'network_request', { url: policy.network[0] })),
  ]);
  assert.equal(replies[0].id, 9);
  assert.equal(replies[0].result.content[0].text, 'DUMMY_PUBLIC');
  assert.equal(replies[1].id, '9');
  assert.equal(replies[1].result.content[0].text, 'DUMMY_NETWORK_OK');
  assert.deepEqual(s.messages.filter(v => v.id === 9 || v.id === '9').map(v => v.id), ['9', 9]);
  assert.equal(await s.close(), 0);
});

test('MCP malformed envelopes and IDs never reach upstream', { timeout: 15000 }, async t => {
  const s = session(t);
  await s.initialize();
  const allowed = call('invalid', 'read_file', { path: 'docs/dummy.txt' });
  for (const input of [
    { ...allowed, jsonrpc: '1.0' }, { ...allowed, id: null }, { ...allowed, id: 1.5 },
    { ...allowed, id: Number.MAX_SAFE_INTEGER + 1 }, { ...allowed, result: {} },
    { ...allowed, params: [] }, { ...allowed, extra: 'DUMMY' },
  ]) s.send(input);
  await s.request({ jsonrpc: '2.0', id: 'barrier', method: 'ping' });
  assert.equal(await s.close(), 0);
  assert.equal(s.messages.filter(v => !Object.hasOwn(v, 'id') && v.error.code === -32600).length, 7);
  assert.equal(s.records().some(v => v.method === 'tools/call'), false);
});

test('MCP truncated frame is never treated as an executable request', { timeout: 15000 }, async t => {
  const s = session(t);
  await s.initialize();
  s.child.stdin.end(JSON.stringify(call('truncated', 'write_file', { path: 'out/dummy.txt', data: 'DUMMY' })));
  assert.equal(await s.done, 2);
  assert.equal(s.records().some(v => v.method === 'tools/call'), false);
});
