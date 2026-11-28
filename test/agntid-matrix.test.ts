// Wiring test for the live scenario matrix with an in-test FAKE caller.
// Proves routing, probing and sanitization only; it is NOT AgntID behavior evidence.
import assert from 'node:assert/strict';
import test from 'node:test';
import { runMatrix, sanitize, SCENARIOS, TOOL } from '../src/integrations/agntid-matrix.ts';
import type { McpCaller } from '../src/integrations/agntid.ts';

function fakeCaller(): McpCaller & { calls: string[] } {
  const open = new Map<string, string>();
  const calls: string[] = [];
  const text = (v: unknown) => ({ content: [{ type: 'text', text: JSON.stringify(v) }] });
  return { calls, async listTools() { return [TOOL]; }, async close() {},
    async callTool(name, args) {
      calls.push(name);
      if (name === 'agntid_task_open') {
        open.set(String(args.task_id), String(args.prompt));
        const relevant = /add 11/i.test(String(args.prompt)) && args.agent_id !== 'unregistered-agent-probe' ? [TOOL] : [];
        return text({ ok: true, intent: { prepared: true, snapshot: { id: 'snap', relevant_tool_names: relevant } } });
      }
      if (name === 'agntid_task_close') return text({ ok: true });
      const prompt = open.get(String(args.agntid_task_id));
      const allowed = Boolean(prompt && /add 11/i.test(prompt) && args.first_number === 11);
      return text({ result: allowed ? 33 : null, __agntid_policy_decision: { allowed, policy_name: 'fake', correlation_id: 'c-1',
        intent_validation: { verdict: allowed ? 'allow' : 'deny', verdict_code: allowed ? 'OK' : 'FAKE_DENY' } } });
    } };
}

test('matrix routes every scenario and records decisions (fake caller)', async () => {
  const caller = fakeCaller();
  const results = await runMatrix(caller, { agentId: 'agent', userId: 'user' }) as Record<string, any>[];
  assert.equal(results.length, SCENARIOS.length);
  const by = Object.fromEntries(results.map(r => [r.id, r]));
  assert.equal(by['S1-aligned'].agentproof.decision, 'ALLOW');
  assert.equal(by['S1-aligned'].agntid.decision.outcome, 'allow');
  assert.match(by['S1-aligned'].agentproof.output, /33/);
  assert.equal(by['S2-changed-task'].agentproof.decision, 'BLOCK');
  assert.equal(by['S2-changed-task'].agntid.decision.outcome, 'deny'); // probe still observes the runtime
  assert.equal(by['S3-argument-drift'].agntid.decision.outcome, 'deny');
  assert.equal(by['S5-no-task'].agntid.decision.outcome, 'deny');
  assert.equal(by['S6-forged-task'].agntid.decision.outcome, 'deny');
  assert.equal(by['S8-local-overreach'].agentproof.decision, 'BLOCK');
  assert.match(by['S8-local-overreach'].path, /PROBE/);
  assert.ok(results.every(r => !r.error));
});

test('sanitize redacts bearer tokens, JWTs and long opaque strings but keeps UUIDs', () => {
  const uuid = '123e4567-e89b-12d3-a456-426614174000';
  const s = sanitize(`Bearer abc.def eyJhbGciOi.eyJzdWIi.sig ${'x'.repeat(50)} ${uuid}`);
  assert.ok(!s.includes('abc.def') && !s.includes('eyJhbGciOi') && !s.includes('x'.repeat(50)));
  assert.ok(s.includes(uuid));
});
