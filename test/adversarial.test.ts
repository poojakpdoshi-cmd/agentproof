import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, lstatSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Simulator } from '../src/simulator.ts';

const url = 'https://api.example.test/health';
const seed = { 'out/dummy.txt': 'DUMMY_OLD' };
const make = () => new Simulator({ read: ['out/'], write: ['out/'], network: [url] }, seed);

test('accessor actions deny without evaluating getters or changing files', () => {
  const sim = make();
  let evaluations = 0;
  const inputs = [
    { get type() { evaluations++; throw new Error('DUMMY'); }, path: 'out/dummy.txt' },
    { type: 'write', path: 'out/dummy.txt', get data() { return ++evaluations === 1 ? 'DUMMY' : {}; } },
    { type: 'read', get path() { evaluations++; return 'out/dummy.txt'; } },
  ];
  for (const input of inputs) assert.equal(sim.execute(input).audit.decision, 'deny');
  assert.equal(evaluations, 0);
  assert.equal(sim.audit.length, inputs.length);
  assert.equal(sim.execute({ type: 'read', path: 'out/dummy.txt' }).data, 'DUMMY_OLD');
});

test('revoked and trap-bearing proxies deny without running traps', () => {
  const sim = make();
  let traps = 0;
  const proxy = new Proxy({}, { getPrototypeOf() { traps++; throw new Error('DUMMY'); } });
  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  for (const input of [proxy, revoked.proxy]) assert.equal(sim.execute(input).audit.decision, 'deny');
  assert.equal(traps, 0);
  assert.equal(sim.audit.length, 2);
});

test('hidden fields and symbols cannot bypass the action schema', () => {
  for (const extra of ['body', Symbol('body')]) {
    const input = { type: 'network', url };
    Object.defineProperty(input, extra, { value: 'DUMMY_SECRET' });
    assert.equal(make().execute(input).audit.decision, 'deny');
  }
});

test('required action fields cannot come from Object.prototype', () => {
  const sim = make();
  const inherited = { type: 'write', path: 'out/dummy.txt', data: 'DUMMY_CHANGED', url };
  const saved = Object.getOwnPropertyDescriptors(Object.prototype);
  try {
    for (const [key, value] of Object.entries(inherited)) {
      Object.defineProperty(Object.prototype, key, { value, configurable: true });
    }
    for (const action of [{}, { type: 'read' }, { type: 'write', path: 'out/dummy.txt' }, { type: 'network' }]) {
      assert.equal(sim.execute(action).audit.decision, 'deny');
    }
  } finally {
    for (const key of Object.keys(inherited)) {
      if (Object.hasOwn(saved, key)) Object.defineProperty(Object.prototype, key, saved[key]);
      else Reflect.deleteProperty(Object.prototype, key);
    }
  }
  assert.equal(sim.execute({ type: 'read', path: 'out/dummy.txt' }).data, 'DUMMY_OLD');
});

test('policy accessors, proxies and non-JSON arrays reject before executing code', () => {
  let calls = 0;
  const array = ['out/'];
  Object.defineProperty(array, 'map', { value() { calls++; return ['private/']; } });
  const accessorArray = ['out/'];
  Object.defineProperty(accessorArray, '0', { get() { calls++; return 'private/'; } });
  const revoked = Proxy.revocable([], {});
  revoked.revoke();
  for (const policy of [
    { get read() { calls++; return ['private/']; } },
    { read: array }, { read: accessorArray }, { read: new Array(1) }, { read: revoked.proxy },
  ]) assert.throws(() => new Simulator(policy), /Invalid policy/);
  assert.equal(calls, 0);
});

test('seed accessors reject without reading values; null-prototype JSON records work', () => {
  let calls = 0;
  assert.throws(() => new Simulator({}, { get dummy() { calls++; return 'DUMMY'; } }), /Invalid files/);
  assert.equal(calls, 0);
  const input = Object.assign(Object.create(null), { type: 'read', path: 'out/dummy.txt' });
  assert.equal(make().execute(input).data, 'DUMMY_OLD');
});

test('extended UNC, NT device, short-name, control and Unicode aliases deny everywhere', () => {
  const invalid = [
    '\\\\?\\UNC\\server\\share\\dummy.txt', '//?/UNC/server/share/dummy.txt',
    '\\\\server@SSL\\DavWWWRoot\\dummy.txt', '\\\\.\\GLOBALROOT\\Device\\dummy.txt',
    '\\Device\\HarddiskVolume1\\dummy.txt', 'out\\\\dummy.txt', 'out/PROGRA~1/dummy.txt',
    'out/CONIN$', 'out/CONOUT$', 'out/LPT².txt', 'out/dummy.txt\n', 'out/dummy.txt\r',
    'out/dummy.txt\u2028', 'out/dummy.txt\u00a0', 'out/\uff0e\uff0e/dummy.txt',
  ];
  for (const name of invalid) {
    const sim = make();
    assert.equal(sim.execute({ type: 'read', path: name }).audit.reason, 'invalid-path', name);
    assert.equal(sim.execute({ type: 'write', path: name, data: 'DUMMY' }).audit.reason, 'invalid-path', name);
    assert.throws(() => new Simulator({ read: [name] }), /Invalid policy/);
    assert.throws(() => new Simulator({}, { [name]: 'DUMMY' }), /Invalid files/);
  }
});

test('Windows aliases use identical permissions and cannot widen exact grants', () => {
  const sim = new Simulator({ read: ['OUT\\DUMMY.TXT'], write: ['OUT/'] }, seed);
  assert.equal(sim.execute({ type: 'read', path: 'Out/Dummy.txt' }).data, 'DUMMY_OLD');
  for (const name of ['out/dummy.txt.bak', 'outside/dummy.txt', 'out/dummy.txt/child']) {
    assert.equal(sim.execute({ type: 'read', path: name }).audit.decision, 'deny');
  }
});

test('malformed URLs and extra transport options deny even beside a valid grant', () => {
  const sim = make();
  for (const target of [
    url + '?', url + '#', url + '\r\nX-Dummy: dummy', 'https://api.example.test./health',
    'https://api.example.test@evil.example.test/health', 'https://2130706433/health',
    'https://0x7f000001/health', 'https://[::ffff:127.0.0.1]/health',
    'https://api.example.test/%2e%2e/health', 'https://api.example.test/health%3fdata=DUMMY',
  ]) assert.equal(sim.execute({ type: 'network', url: target }).audit.decision, 'deny');
  for (const extra of ['redirect', 'agent', 'lookup', 'hostname', 'port', 'socketPath', 'signal']) {
    assert.equal(sim.execute({ type: 'network', url, [extra]: 'DUMMY' }).audit.decision, 'deny');
  }
});

test('symlink metadata and link-creation actions are unsupported and deny', () => {
  assert.throws(() => new Simulator({}, { 'out/link': { symlink: '../private' } }), /Invalid files/);
  for (const type of ['symlink', 'junction', 'hardlink']) {
    assert.equal(make().execute({ type, path: 'out/link', target: '../private' }).audit.decision, 'deny');
  }
});

test('host symlink or junction is never followed by simulated reads or writes', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'agentproof-dummy-'));
  try {
    const outside = path.join(root, 'outside');
    const sandbox = path.join(root, 'sandbox');
    mkdirSync(outside);
    mkdirSync(sandbox);
    writeFileSync(path.join(outside, 'dummy.txt'), 'DUMMY_HOST');
    symlinkSync(outside, path.join(sandbox, 'link'), process.platform === 'win32' ? 'junction' : 'dir');
    assert.equal(lstatSync(path.join(sandbox, 'link')).isSymbolicLink(), true);
    // Use the directory containing the real link as cwd, exposing any accidental relative disk I/O.
    const before = process.cwd();
    try {
      process.chdir(sandbox);
      const sim = new Simulator({ read: ['link/'], write: ['link/'] });
      assert.equal(sim.execute({ type: 'read', path: 'link/dummy.txt' }).audit.reason, 'missing-file');
      assert.equal(sim.execute({ type: 'write', path: 'link/dummy.txt', data: 'DUMMY_VIRTUAL' }).audit.decision, 'allow');
      assert.equal(sim.execute({ type: 'read', path: 'link/dummy.txt' }).data, 'DUMMY_VIRTUAL');
      assert.equal(readFileSync(path.join(outside, 'dummy.txt'), 'utf8'), 'DUMMY_HOST');
    } finally { process.chdir(before); }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('network allow is a simulation, including explicitly granted local endpoints', t => {
  const fetch = t.mock.method(globalThis, 'fetch', () => { throw new Error('Unexpected real fetch'); });
  const sim = new Simulator({ network: [url, 'https://127.0.0.1/health'] });
  for (const target of [url, 'https://127.0.0.1/health']) {
    assert.equal(sim.execute({ type: 'network', url: target }).status, 204);
  }
  assert.equal(fetch.mock.callCount(), 0);
});
