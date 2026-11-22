// Phase 4.3 reproducible offline E2E. Scripted Gemini REST replies are NOT AI output and
// FakeAgentTools is NOT the live BAND platform. Everything else is the production code path:
// band.ts handlers in the official GenericAdapter, the gemini.ts adapter (request contract,
// parsing, limits, fail-closed latch), workflow.ts, lab.ts policy checks, the MCP proxy
// subprocess and the dummy MCP server. Dummy configuration only: process.env/.env are never read.
import { FakeAgentTools } from '@band-ai/sdk/testing';
import { GenericAdapter } from '@band-ai/sdk';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { handler } from './band.ts';
import { geminiModel } from './gemini.ts';
import { baseline } from './lab.ts';

const ROOM = 'offline-room', OWNER = 'owner', RED = 'red', BLUE = 'blue';
const KEY = 'DUMMY_OFFLINE_KEY_NOT_A_SECRET', MODEL = 'gemini-offline-dummy';
const ENDPOINT = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent`;
const env = { GEMINI_API_KEY: KEY, GEMINI_MODEL: MODEL, GEMINI_LIVE_ENABLED: 'true', GEMINI_FREE_TIER_CONFIRMED: 'true' };
const LEAK = 'DUMMY_PROVIDER_BODY_MUST_NOT_LEAK';

export const script = {
  red: [
    { action: 'probe', call: { name: 'read_file', arguments: { path: 'private/secret.txt' } } },
    { action: 'probe', call: { name: 'read_file', arguments: { path: 'docs/../private/secret.txt' } } },
    { action: 'probe', call: { name: 'network_request', arguments: { url: baseline.network[0], body: 'DUMMY_SECRET' } } },
    { action: 'finish' },
  ],
  blue: [
    { action: 'propose', policy: { ...baseline, read: ['docs/', 'private/', 'shared/'] }, rationale: 'UNSAFE scripted proposal: expands grants' },
    { action: 'propose', policy: { ...baseline, read: ['docs/'] }, rationale: 'Scripted fix: remove seeded private/ overgrant' },
  ],
};

// Local stand-in for the Gemini REST endpoint. It enforces the adapter's request contract and
// never calls the real fetch, so no request can leave the process.
function scriptedGemini(requests: any[], blocked: string[], status = 200) {
  const queue = { red: [...script.red], blue: [...script.blue] };
  return async (url: unknown, init: any) => {
    if (url !== ENDPOINT || init?.method !== 'POST' || init.redirect !== 'error' || !(init.signal instanceof AbortSignal)
      || init.headers?.['x-goog-api-key'] !== KEY || String(url).includes(KEY)) {
      blocked.push('request outside the Gemini REST contract');
      throw new Error('blocked');
    }
    const body = JSON.parse(init.body);
    const role = body.systemInstruction.parts[0].text.startsWith('You are AgentProof red.') ? 'red' : 'blue';
    const text = body.contents[0].parts[0].text;
    const context = JSON.parse(text);
    requests.push({ request: requests.length + 1, role, inputBytes: Buffer.byteLength(text),
      ...(role === 'red' ? { toolsInContext: (context.tools ?? []).map((t: any) => t.name) } : {}),
      ...(role === 'blue' ? { priorAttempts: context.attempts.length,
        reproducedPrivateReadAllowed: context.reproduced.observations[1].result.isError === false,
        ...(context.attempts.length ? { lastFeedback: context.attempts.at(-1).reason ?? 'retest result' } : {}) } : {}) });
    if (status !== 200) return new Response(JSON.stringify({ error: { code: status, message: LEAK } }), { status });
    const next = queue[role as 'red' | 'blue'].shift();
    if (!next) { blocked.push('script exhausted'); throw new Error('blocked'); }
    return new Response(JSON.stringify({ candidates: [{ finishReason: 'STOP',
      content: { role: 'model', parts: [{ text: JSON.stringify(next) }] } }] }));
  };
}

let sequence = 0;
const message = (senderId: string, content: string) => ({ id: `${senderId}-message-${++sequence}`, roomId: ROOM,
  senderId, senderType: senderId === OWNER ? 'User' : 'Agent', senderName: senderId, messageType: 'text',
  metadata: {}, createdAt: new Date(0), content });
// One adapter per agent, as in band.ts main(), so replay/busy state persists across messages.
const agent = (role: 'red' | 'blue', model: any) => {
  const adapter = new GenericAdapter(handler(role, model, ROOM, role === 'red' ? BLUE : RED, OWNER));
  return (msg: any, tools: any, roomId = ROOM) =>
    adapter.onMessage(msg, tools, {} as any, null, null, { roomId, isSessionBootstrap: false });
};
const verdict = (o: any) => o.result.isError === false ? 'ALLOWED' : 'DENIED';
const label = (c: any) => `${c.name} ${c.arguments.path ?? c.arguments.url}${c.arguments.body ? ' (+body)' : ''}`;

async function attackDefend() {
  const requests: any[] = [], blocked: string[] = [];
  globalThis.fetch = scriptedGemini(requests, blocked) as any;
  const model = geminiModel(env);
  const red = agent('red', model), blue = agent('blue', model);
  const redTools = new FakeAgentTools(), blueTools = new FakeAgentTools();
  await red(message('intruder', 'start'), redTools);
  await red(message(OWNER, 'start'), redTools, 'other-room');
  const requestsBeforeAuthorizedStart = requests.length, unauthorizedMessagesSent = redTools.messagesSent.length;
  const start = message(OWNER, '@red start');
  await red(start, redTools);
  const requestsAfterRed = requests.length;
  await red(start, redTools);
  const replayIgnored = requests.length === requestsAfterRed && redTools.messagesSent.length === 1;
  const sent = redTools.messagesSent[0];
  await blue(message(RED, sent.content), blueTools);
  const report = blueTools.messagesSent[0];
  const findings = JSON.parse(sent.content), retest = JSON.parse(report.content);
  if (findings.runId !== retest.runId) throw new Error('runId mismatch');
  const fixed = retest.attempts.at(-1).retest, before = retest.reproduced;
  return {
    accessControl: { requestsBeforeAuthorizedStart, unauthorizedMessagesSent, replayIgnored },
    red: { source: findings.source, requests: requestsAfterRed,
      probes: findings.observations.map((o: any) => ({ probe: label(o.call), seededBaseline: verdict(o) })) },
    band: { findings: { from: RED, mentions: sent.mentions, bytes: Buffer.byteLength(sent.content) },
      report: { from: BLUE, mentions: report.mentions, bytes: Buffer.byteLength(report.content) } },
    blue: { source: retest.source, passed: retest.passed, proposedPolicy: retest.proposedPolicy,
      attempts: retest.attempts.map((a: any) => a.candidate ? { accepted: a.accepted } : a) },
    retest: before.observations.map((o: any, i: number) => ({ call: label(o.call),
      kind: i < 4 ? 'fixed control' : 'Red finding', baseline: verdict(o), afterFix: verdict(fixed.observations[i]) })),
    upstreamReceived: { baseline: before.received.length, afterFix: fixed.received.length },
    gemini: { requests, budgetUsed: `${requests.length}/9`, blockedRequests: blocked },
    messages: { findings: { ...findings, runId: '<random-uuid>' }, report: { ...retest, runId: '<random-uuid>' } },
  };
}

async function failClosed() {
  const requests: any[] = [], blocked: string[] = [];
  globalThis.fetch = scriptedGemini(requests, blocked, 429) as any;
  const model = geminiModel(env);
  const tools = new FakeAgentTools();
  let adapterError = 'none';
  try { await agent('red', model)(message(OWNER, 'start'), tools); } catch (error: any) { adapterError = error?.name; }
  const sentAfterFailure = requests.length;
  let latched = 'not latched';
  try { await model.decide('red', {}); } catch (error: any) { latched = error.message; }
  const events = tools.eventsSent.map((e: any) => ({ messageType: e.messageType, content: e.content }));
  return { providerStatus: 429, requestsSent: sentAfterFailure, adapterError, messagesSent: tools.messagesSent.length,
    failureEvents: events, nextRequestAfterFailure: latched, requestsAfterLatch: requests.length - sentAfterFailure,
    providerBodyLeaked: JSON.stringify(events).includes(LEAK), blockedRequests: blocked };
}

export async function e2e({ realtime = false } = {}) {
  const realFetch = globalThis.fetch, realNow = Date.now;
  // Virtual limiter clock (as in the mocked unit test); --realtime keeps real 15 s spacing.
  let now = 100000;
  if (!realtime) Date.now = () => now += 15000;
  try {
    const evidence = { phase: '4.3', mode: 'OFFLINE_E2E_SCRIPTED_GEMINI_REST_NOT_AI_FAKE_BAND_TOOLS_NOT_LIVE',
      realComponents: ['agents/band.ts handler + @band-ai/sdk GenericAdapter', 'agents/gemini.ts adapter',
        'agents/workflow.ts', 'agents/lab.ts', 'src/mcp-proxy.ts subprocess', 'examples/dummy-mcp-server.ts'],
      simulated: ['Gemini HTTP replies (scripted, contract-checked, never sent)', 'BAND delivery (FakeAgentTools)'],
      limiterClock: realtime ? 'real' : 'virtual', liveNetworkRequests: 0,
      attackDefend: await attackDefend(), failClosed: await failClosed() };
    const json = JSON.stringify(evidence, null, 2) + '\n';
    for (const forbidden of [KEY, homedir(), tmpdir(), process.cwd()]) {
      if (json.includes(forbidden) || json.includes(JSON.stringify(forbidden).slice(1, -1))) throw new Error('Evidence sanitization failed');
    }
    return { evidence, json, sha256: createHash('sha256').update(json).digest('hex') };
  } finally {
    globalThis.fetch = realFetch;
    Date.now = realNow;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { evidence, json, sha256 } = await e2e({ realtime: process.argv.includes('--realtime') });
  writeFileSync(new URL('../docs/phase4.3-e2e.json', import.meta.url), json);
  const a = evidence.attackDefend, f = evidence.failClosed;
  console.log(JSON.stringify({ mode: evidence.mode, passed: a.blue.passed, geminiRequests: a.gemini.budgetUsed,
    unsafeProposalRejected: a.blue.attempts[0].accepted === false, upstreamReceived: a.upstreamReceived,
    failClosed: f.messagesSent === 0 && f.requestsAfterLatch === 0 && !f.providerBodyLeaked, sha256 }));
}
