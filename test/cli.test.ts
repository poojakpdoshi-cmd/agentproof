import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const run = (input: string | Buffer, args: string[] = []) => spawnSync(process.execPath, [cli, ...args], {
  input, encoding: 'utf8', timeout: 10000, maxBuffer: 2 * 1024 * 1024,
});

test('CLI emits reproducible audit JSONL for the documented dummy scenario', () => {
  const input = readFileSync(new URL('../examples/scenario.json', import.meta.url), 'utf8');
  const first = run(input);
  assert.equal(first.error, undefined);
  assert.equal(first.status, 1);
  assert.equal(first.stderr, '');
  assert.equal(first.stdout, run(input).stdout);
  const logs = first.stdout.trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual(logs.map(log => log.decision), ['allow', 'allow', 'allow', 'allow', 'deny', 'deny', 'deny']);
  assert.deepEqual(logs.map(log => log.sequence), [1, 2, 3, 4, 5, 6, 7]);
  assert.equal(first.stdout.includes('DUMMY'), false);
});

test('CLI allow-only scenario exits zero; absent policy denies', () => {
  const allowed = run(JSON.stringify({ policy: { network: ['https://api.example.test/health'] },
    actions: [{ type: 'network', url: 'https://api.example.test/health' }] }));
  assert.equal(allowed.status, 0);
  const denied = run(JSON.stringify({ actions: [{ type: 'read', path: 'data.txt' }] }));
  assert.equal(denied.status, 1);
  assert.equal(JSON.parse(denied.stdout).reason, 'not-granted');
});

test('CLI invalid configuration fails before processing actions without echoing input', () => {
  for (const input of ['DUMMY_SECRET', '', 'null', '{}', '{"actions":{}}',
    '{"policy":null,"actions":[]}', '{"policy":{"read":"*"},"actions":[{"type":"read"}]}',
    '{"actions":[],"unexpected":"DUMMY_SECRET"}', ' '.repeat(1024 * 1024 + 1)]) {
    const result = run(input);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'Invalid scenario or arguments. Use --help.\n');
  }
});

test('CLI help and invalid flags have explicit exit codes', () => {
  const help = run('', ['--help']);
  assert.equal(help.status, 0);
  assert.match(help.stdout, /Usage:/);
  assert.equal(run('', ['--unknown']).status, 2);
});

test('invalid UTF-8 fails closed before any action is processed', () => {
  const input = Buffer.concat([
    Buffer.from('{"policy":{"write":["out/"]},"actions":[{"type":"write","path":"out/dummy.txt","data":"'),
    Buffer.from([0xff]), Buffer.from('"}]}'),
  ]);
  const result = run(input);
  assert.equal(result.status, 2);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, 'Invalid scenario or arguments. Use --help.\n');
});
