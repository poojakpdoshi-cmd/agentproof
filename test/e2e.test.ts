import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { e2e } from '../agents/e2e.ts';

test('Phase 4.3 offline E2E: Gemini adapter -> BAND adapters -> real MCP retest, fail-closed, no network (NOT live AI)', { timeout: 30000 }, async () => {
  let networkCalls = 0;
  const sentinel = async () => { networkCalls++; throw new Error('Network forbidden'); };
  const realNow = Date.now;
  globalThis.fetch = sentinel as any;
  const { evidence, json } = await e2e();
  assert.equal(globalThis.fetch, sentinel);
  assert.equal(Date.now, realNow);
  assert.equal(networkCalls, 0);

  const a = evidence.attackDefend;
  assert.match(evidence.mode, /NOT_AI.*NOT_LIVE/);
  assert.deepEqual(a.accessControl, { requestsBeforeAuthorizedStart: 0, unauthorizedMessagesSent: 0, replayIgnored: true });
  assert.equal(a.gemini.budgetUsed, '6/9');
  assert.deepEqual(a.gemini.blockedRequests, []);
  assert.deepEqual(a.band.findings.mentions, [{ id: 'blue' }]);
  assert.deepEqual(a.band.report.mentions, [{ id: 'owner' }]);
  assert.equal(a.red.probes[0].seededBaseline, 'ALLOWED');
  const expansion = 'Unsafe policy rejected: a grant is broader than the baseline; only narrowing is allowed';
  assert.deepEqual(a.blue.attempts, [{ accepted: false, reason: expansion }, { accepted: true }]);
  assert.ok(a.gemini.requests.filter((r: any) => r.role === 'red')
    .every((r: any) => r.toolsInContext.join() === 'read_file,write_file,network_request'));
  assert.equal(a.gemini.requests.at(-1).lastFeedback, expansion);
  assert.equal(a.blue.passed, true);
  assert.deepEqual(a.blue.proposedPolicy.read, ['docs/']);
  assert.equal(a.retest[0].afterFix, 'ALLOWED');
  assert.ok(a.retest.slice(1).every((r: any) => r.afterFix === 'DENIED'));
  assert.deepEqual(a.upstreamReceived, { baseline: 3, afterFix: 1 });

  const f = evidence.failClosed;
  assert.equal(f.requestsSent, 1);
  assert.equal(f.messagesSent, 0);
  assert.equal(f.requestsAfterLatch, 0);
  assert.equal(f.providerBodyLeaked, false);
  assert.match(f.nextRequestAfterFailure, /session stopped/);
  assert.equal(json.includes('DUMMY_OFFLINE_KEY'), false);

  // Committed evidence must match a fresh deterministic run (parsed, so line endings do not matter).
  assert.deepEqual(JSON.parse(readFileSync(new URL('../docs/phase4.3-e2e.json', import.meta.url), 'utf8')), evidence);
});
