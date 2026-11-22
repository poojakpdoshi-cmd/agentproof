import assert from 'node:assert/strict';
import test from 'node:test';
import { FakeAgentTools } from '@band-ai/sdk/testing';
import { offline } from '../agents/offline.ts';
import { baseline, safePolicy, probe } from '../agents/lab.ts';
import { handler, config } from '../agents/band.ts';
import { red, blue } from '../agents/workflow.ts';
import { localModel } from '../agents/model.ts';

test('offline official BAND adapters: Red findings -> Blue independent reproduction -> real MCP retest', { timeout: 20000 }, async () => {
  const result = await offline();
  assert.equal(result.mode, 'OFFLINE_FIXTURE_NOT_LIVE_AI_OR_BAND');
  assert.equal(result.findings.observations[0].result.isError, false);
  assert.equal(result.retest.passed, true);
  assert.deepEqual(result.routing, [{ id: 'blue' }]);
  assert.equal(result.retest.reproduced.received.length, 3);
  assert.equal(result.retest.attempts[0].retest.received.length, 1);
  assert.equal(result.retest.attempts[0].retest.observations.at(-1).result.isError, true);
});

test('Blue policy proposals cannot expand grants or disable required legitimate access', () => {
  for (const policy of [{ read: ['docs/'] }, { ...baseline, read: [] },
    { ...baseline, read: ['docs/', 'other/'] }, baseline,
    { ...baseline, read: ['docs/'], network: ['https://evil.example.test/'] }]) {
    assert.throws(() => safePolicy(policy));
  }
  assert.deepEqual(safePolicy({ ...baseline, read: ['docs/'] }).read, ['docs/']);
});

test('agent actions and findings have bounded schemas', async () => {
  assert.throws(() => probe({ name: 'read_file', arguments: {}, command: 'DUMMY' }));
  assert.throws(() => probe({ name: 'read_file', arguments: { data: 'a'.repeat(5000) } }));
  await assert.rejects(blue({ source: 'fixture', decide: async () => ({}) }, { kind: 'findings', runId: 'x', observations: new Array(7) }));
});

test('unauthorized rooms/senders and duplicate starts never invoke reasoning or send messages', async () => {
  let calls = 0;
  const tools = new FakeAgentTools();
  const run = handler('red', { source: 'fixture', decide: async () => { calls++; return { action: 'finish' }; } }, 'room', 'blue', 'owner');
  await run({ roomId: 'other', message: { id: 'x', senderId: 'owner', content: 'start' }, tools });
  await run({ roomId: 'room', message: { id: 'x', senderId: 'intruder', content: 'start' }, tools });
  assert.equal(calls, 0);
  const input = { roomId: 'room', message: { id: 'valid', senderId: 'owner', content: 'start' }, tools };
  await run(input); await run(input);
  assert.equal(calls, 1);
  assert.equal(tools.messagesSent.length, 1);
});

test('missing credentials fail before live connections; no provider fallback', async () => {
  assert.throws(() => config({}), /Missing/);
  assert.throws(() => localModel(''), /local model/);
  assert.throws(() => localModel('model:cloud'), /local model/);
  await assert.rejects(red({ source: 'fixture-error', decide: async () => { throw new Error('Unavailable'); } }, 'run'), /Unavailable/);
});

test('local model uses real bounded JSON inference and rejects malformed output (HTTP mock only)', async t => {
  let body: any;
  t.mock.method(globalThis, 'fetch', async (url: string, init: any) => {
    assert.equal(url, 'http://127.0.0.1:11434/api/chat');
    body = JSON.parse(init.body);
    return new Response(JSON.stringify({ message: { content: 'NOT_JSON' } }));
  });
  await assert.rejects(localModel('local-test').decide('red', { observations: [] }));
  assert.equal(body.stream, false);
  assert.equal(body.messages[0].role, 'system');
});

test('Red receives the fixed proxy tool contracts in its model context', async () => {
  let context: any;
  await red({ source: 'fixture', decide: async (_role, value) => { context = value; return { action: 'finish' }; } }, 'run');
  assert.deepEqual(context.tools.map((t: any) => t.name), ['read_file', 'write_file', 'network_request']);
  assert.deepEqual(Object.keys(context.tools[1].arguments), ['path', 'data']);
});

test('Blue gets specific, fixed rejection reasons and never an echo of its proposal', { timeout: 20000 }, async () => {
  const proposals = [{ ...baseline, read: ['docs/', 'dummy-echo/'] }, { ...baseline, read: [] },
    { read: ['docs/'], write: ['out/'], network: [] }];
  const seen: string[] = [];
  const result = await blue({ source: 'fixture', async decide(_role, context: any) {
    if (context.attempts.length) seen.push(context.attempts.at(-1).reason);
    return { action: 'propose', policy: proposals[context.attempts.length] };
  } }, { kind: 'findings', runId: 'dummy', observations: [] });
  assert.equal(result.passed, false);
  const reasons = (result.attempts as any[]).map(a => a.reason);
  assert.deepEqual(reasons, ['Unsafe policy rejected: a grant is broader than the baseline; only narrowing is allowed',
    'Unsafe policy rejected: docs/dummy.txt must stay readable and private/secret.txt must be denied',
    'Unsafe policy rejected: out/ writes and the approved network endpoint must be kept']);
  assert.deepEqual(seen, reasons.slice(0, 2));
  assert.equal(JSON.stringify(result).includes('dummy-echo'), false);
});

test('Blue reproduces forged outcomes and revises an unsafe proposal from retest feedback', { timeout: 20000 }, async () => {
  let decisions = 0;
  const result = await blue({ source: 'deterministic-test-fixture-NOT-AI', async decide(role, context: any) {
    assert.equal(role, 'blue');
    assert.equal(context.reproduced.observations[1].result.isError, false);
    if (decisions++ === 0) return { action: 'propose', policy: { read: [] } };
    assert.equal(context.attempts[0].accepted, false);
    return { action: 'propose', policy: { ...baseline, read: ['docs/'] } };
  } }, { kind: 'findings', runId: 'dummy', observations: [{ call: { name: 'read_file', arguments: { path: 'private/secret.txt' } }, result: { isError: true } }] });
  assert.equal(result.passed, true);
  assert.equal(decisions, 2);
});
