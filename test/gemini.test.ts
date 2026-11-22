import assert from 'node:assert/strict';
import test from 'node:test';
import { geminiModel } from '../agents/gemini.ts';
import { config, main } from '../agents/band.ts';
import { red, blue } from '../agents/workflow.ts';
import { baseline } from '../agents/lab.ts';

const env = { GEMINI_API_KEY: 'DUMMY_KEY_ONLY', GEMINI_MODEL: 'gemini-dummy',
  GEMINI_LIVE_ENABLED: 'true', GEMINI_FREE_TIER_CONFIRMED: 'true' };
const band = { BAND_RED_ID: 'red', BAND_RED_API_KEY: 'DUMMY_RED', BAND_BLUE_ID: 'blue',
  BAND_BLUE_API_KEY: 'DUMMY_BLUE', BAND_ROOM_ID: 'room', BAND_OWNER_ID: 'owner' };
const envelope = (text = '{"action":"finish"}') => ({ candidates: [{ finishReason: 'STOP',
  content: { role: 'model', parts: [{ text }] } }] });
const reply = (text?: string) => new Response(JSON.stringify(envelope(text)));

test('Gemini requires explicit opt-in, free-tier confirmation, key and safe model name', t => {
  t.mock.method(globalThis, 'fetch', async () => { assert.fail('Network forbidden'); });
  for (const patch of [{ GEMINI_LIVE_ENABLED: undefined }, { GEMINI_LIVE_ENABLED: 'TRUE' },
    { GEMINI_FREE_TIER_CONFIRMED: 'false' }, { GEMINI_API_KEY: '' }, { GEMINI_API_KEY: 'bad\r\nkey' },
    { GEMINI_MODEL: '' }, { GEMINI_MODEL: '../evil?key=x' }, { GEMINI_MODEL: 'gemini-x/evil' }]) {
    assert.throws(() => geminiModel({ ...env, ...patch }));
  }
});

test('provider configuration preserves default Ollama and never silently falls back', () => {
  assert.equal(config({ ...band, OLLAMA_MODEL: 'local-dummy' }).AI_PROVIDER, 'ollama');
  assert.equal(config({ ...band, ...env, AI_PROVIDER: 'gemini' }).AI_PROVIDER, 'gemini');
  assert.throws(() => config({ ...band, ...env, AI_PROVIDER: 'unknown' }), /Unsupported/);
  assert.throws(() => config({ ...band, ...env }), /OLLAMA_MODEL/);
  assert.throws(() => config({ ...band, AI_PROVIDER: 'gemini' }), /GEMINI_API_KEY/);
});

test('disabled Gemini startup makes zero model or BAND connections', async t => {
  const previous = process.env;
  process.env = { ...band, ...env, AI_PROVIDER: 'gemini', GEMINI_LIVE_ENABLED: 'false' };
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async () => { calls++; throw new Error('Forbidden'); });
  try { await assert.rejects(main(), /Gemini disabled/); }
  finally { process.env = previous; }
  assert.equal(calls, 0);
});

test('Gemini REST contract uses header authentication, JSON output and bounded requests', async t => {
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async (url: string, init: RequestInit) => {
    calls++;
    assert.equal(url, 'https://generativelanguage.googleapis.com/v1beta/models/gemini-dummy:generateContent');
    assert.equal(url.includes(env.GEMINI_API_KEY), false);
    assert.equal(init.method, 'POST'); assert.equal(init.redirect, 'error');
    assert.ok(init.signal instanceof AbortSignal);
    assert.equal((init.headers as Record<string, string>)['x-goog-api-key'], env.GEMINI_API_KEY);
    const body = JSON.parse(String(init.body));
    assert.match(body.systemInstruction.parts[0].text, /AgentProof red/);
    assert.match(body.systemInstruction.parts[0].text, /untrusted data/);
    assert.equal(body.contents[0].role, 'user');
    assert.deepEqual(JSON.parse(body.contents[0].parts[0].text), { observations: [] });
    assert.deepEqual(body.generationConfig, { temperature: 0, candidateCount: 1, maxOutputTokens: 1500, responseMimeType: 'application/json' });
    assert.equal(body.tools, undefined);
    return reply();
  });
  const model = geminiModel(env);
  assert.equal(model.source, 'gemini:gemini-dummy');
  assert.deepEqual(await model.decide('red', { observations: [] }), { action: 'finish' });
  assert.equal(calls, 1);
});

for (const status of [400, 401, 403, 429, 500, 503]) {
  test(`Gemini HTTP ${status} stops session without retry or leaking provider details`, async t => {
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async () => {
      calls++; return new Response('DUMMY_SECRET_PROVIDER_BODY', { status, headers: { 'Retry-After': '1' } });
    });
    const model = geminiModel(env);
    await assert.rejects(model.decide('red', {}), { message: 'Gemini inference failed; session stopped (no automatic retry)' });
    await assert.rejects(model.decide('blue', {}), /session stopped/);
    assert.equal(calls, 1);
  });
}

for (const name of ['TimeoutError', 'TypeError']) {
  test(`Gemini ${name} is sanitized and fails closed`, async t => {
    t.mock.method(globalThis, 'fetch', async () => { throw new DOMException('DUMMY_SECRET', name); });
    const model = geminiModel(env);
    await assert.rejects(model.decide('red', {}), { message: 'Gemini inference failed; session stopped (no automatic retry)' });
    await assert.rejects(model.decide('red', {}), /session stopped/);
  });
}

test('Gemini rejects blocked, truncated, malformed, tool and non-object responses', async t => {
  const truncated = envelope(); truncated.candidates[0].finishReason = 'MAX_TOKENS';
  const cases = ['NOT_JSON', JSON.stringify({ error: { message: 'DUMMY_SECRET' } }),
    JSON.stringify({ promptFeedback: { blockReason: 'SAFETY' } }), JSON.stringify(truncated),
    JSON.stringify({ ...envelope(), promptFeedback: { blockReason: 'SAFETY' } }),
    JSON.stringify({ candidates: [{ ...envelope().candidates[0], safetyRatings: [{ blocked: true }] }] }),
    JSON.stringify({ candidates: [{ finishReason: 'STOP', content: { role: 'model', parts: [{ functionCall: { name: 'shell' } }] } }] }),
    ...['NOT_JSON', 'null', '[]', 'true'].map(text => JSON.stringify(envelope(text)))];
  let next = '';
  t.mock.method(globalThis, 'fetch', async () => new Response(next));
  for (next of cases) await assert.rejects(geminiModel(env).decide('red', {}), /inference failed/);
});

test('Gemini ignores thought parts and joins only text output', async t => {
  t.mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify({ candidates: [{
    finishReason: 'STOP', content: { role: 'model', parts: [
      { thought: true, text: 'DUMMY reasoning' }, { text: '{"action":' }, { text: '"finish"}', thoughtSignature: 'DUMMY' },
    ] },
  }] })));
  assert.deepEqual(await geminiModel(env).decide('red', {}), { action: 'finish' });
});

test('Gemini bounds input before sending and cancels oversized response streams', async t => {
  let calls = 0, cancelled = false;
  t.mock.method(globalThis, 'fetch', async () => {
    calls++;
    return new Response(new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(65537)); },
      cancel() { cancelled = true; } }));
  });
  await assert.rejects(geminiModel(env).decide('red', { dummy: 'x'.repeat(65536) }));
  assert.equal(calls, 0);
  await assert.rejects(geminiModel(env).decide('red', {}));
  assert.equal(cancelled, true); assert.equal(calls, 1);
});

test('Gemini rejects overlapping calls and spaces Red/Blue requests by 15 seconds', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: 100000 });
  const times: number[] = [];
  t.mock.method(globalThis, 'fetch', async () => { times.push(Date.now()); return reply(); });
  const model = geminiModel(env);
  await model.decide('red', {});
  const second = model.decide('blue', {});
  await assert.rejects(model.decide('red', {}), /already in progress/);
  t.mock.timers.tick(14999);
  await Promise.resolve(); assert.equal(times.length, 1);
  t.mock.timers.tick(1);
  await second;
  assert.deepEqual(times, [100000, 115000]);
});

test('Gemini shared session budget rejects the tenth request without sending', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: 100000 });
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async () => { calls++; return reply(); });
  const model = geminiModel(env);
  for (let i = 0; i < 9; i++) { t.mock.timers.tick(15000); await model.decide(i < 6 ? 'red' : 'blue', {}); }
  await assert.rejects(model.decide('red', {}), /budget exhausted/);
  assert.equal(calls, 9);
});

test('mock Gemini Red -> Blue -> real MCP retest preserves workflow security (NOT live AI)', { timeout: 20000 }, async t => {
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async (_url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    calls++;
    if (body.systemInstruction.parts[0].text.includes('AgentProof red')) {
      return reply(JSON.stringify({ action: 'probe', call: { name: 'read_file', arguments: { path: 'private/secret.txt' } } }));
    }
    const context = JSON.parse(body.contents[0].parts[0].text);
    assert.equal(context.reproduced.observations[1].result.isError, false);
    return reply(JSON.stringify({ action: 'propose', policy: { ...baseline, read: ['docs/'] }, rationale: 'DUMMY mocked proposal' }));
  });
  // Advance the limiter clock without mocking subprocess timers used by MCP.
  let now = 100000;
  t.mock.method(Date, 'now', () => now += 15000);
  const model = geminiModel(env);
  const findings = await red(model, 'mock-gemini-NOT-LIVE');
  const result = await blue(model, findings);
  assert.equal(calls, 7);
  assert.equal(result.passed, true);
  assert.equal(result.attempts[0].retest.received.length, 1);
});
