// Tests the AgntID adapter against a MOCK runtime (test/fixtures/mock-agntid-runtime.ts).
// Passing here proves adapter logic and fail-closed handling, NOT live AgntID behavior.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AgntidRuntime, connectRuntime, parseAgntidDecision, parseTaskOpen, stripPlatformFields, validateRuntimeUrl } from '../src/integrations/agntid.ts';
import { Firewall } from '../src/guard/firewall.ts';
import { startMockAgntid } from './fixtures/mock-agntid-runtime.ts';

const mandate = { id: 'q3', subject: { agent: 'report-agent', user: 'analyst' }, objective: 'Summarize reports/q3.md and save it to out/q3.md',
  expiresAt: '2099-01-01T00:00:00Z',
  // Deliberately over-broad local grant on secrets/ to show the second layer catching it.
  allow: [{ tools: ['read_file'], resources: ['reports/', 'secrets/'] }, { tools: ['write_file'], resources: ['out/'] }, { tools: ['send_email'], resources: ['@corp.test'] }] };
const user = [{ source: 'user' as const, text: mandate.objective + ' and email dana@corp.test' }];

test('decision parser mirrors agntid-python parse_decision', () => {
  assert.equal(parseAgntidDecision({ __agntid_policy_decision: { allowed: true } })?.outcome, 'allow');
  assert.equal(parseAgntidDecision({ __agntid_error: 'denied', __agntid_policy_decision: { allowed: false, policy_name: 'p' } })?.outcome, 'deny');
  assert.equal(parseAgntidDecision({ __agntid_policy_decision: { allowed: false, intent_validation: { verdict: 'hitl' } } })?.outcome, 'review_required');
  assert.equal(parseAgntidDecision({ __agntid_policy_decision: { allowed: true }, __agntid_execution_flow: { review: { outcome: 'deny' } } })?.outcome, 'deny');
  assert.equal(parseAgntidDecision({ result: 'plain tool output' }), null);
  assert.equal(parseTaskOpen({ structuredContent: { ok: true, intent: { prepared: false } } }).intentPrepared, false);
  assert.equal(parseTaskOpen(null).ok, false);
  assert.deepEqual(stripPlatformFields({ a: 1, __agntid_result: 2, n: [{ __agntid_x: 1, b: 2 }] }), { a: 1, n: [{ b: 2 }] });
});

test('runtime URL policy: loopback http or https only, no credentials', () => {
  assert.ok(validateRuntimeUrl('http://localhost:8082/mcp'));
  assert.ok(validateRuntimeUrl('https://runtime.example.test/mcp'));
  for (const url of ['http://runtime.example.test/mcp', 'https://u:p@h.test/mcp', 'https://h.test/mcp?token=x', 'file:///etc/passwd']) {
    assert.throws(() => validateRuntimeUrl(url), url);
  }
});

test('AgntID adapter (MOCK runtime): intent shortlist + runtime policy layered on AgentProof', { timeout: 20000 }, async () => {
  const mock = await startMockAgntid({ files: { 'reports/q3.md': 'Revenue grew 12%.', 'secrets/prod.env': 'DUMMY' }, requireToken: 'DUMMY_ACCESS_TOKEN' });
  const caller = await connectRuntime(mock.url, { accessToken: 'DUMMY_ACCESS_TOKEN' });
  try {
    const runtime = new AgntidRuntime(caller, { agentId: 'report-agent', userId: 'analyst' });
    const opened = await runtime.openTask(mandate.objective);
    assert.ok(opened.ok && opened.intentPrepared);
    assert.deepEqual(opened.relevantTools, ['read_file', 'write_file']);
    const fw = new Firewall({ mandates: [mandate], authorizer: runtime.authorizer(), executor: runtime.executor() });
    const run = async (tool: string, args: Record<string, unknown>) => {
      const verdict = await fw.decide({ agent: 'report-agent', mandate: 'q3', action: { tool, arguments: args }, context: user });
      return { verdict, result: verdict.token ? await fw.execute(verdict.token, { tool, arguments: args }) : null };
    };
    const ok = await run('read_file', { path: 'reports/q3.md' });
    assert.equal(ok.verdict.decision, 'ALLOW');
    assert.ok(ok.result?.ok && JSON.stringify(ok.result.output).includes('Revenue'));
    assert.ok(!JSON.stringify(ok.result.output).includes('__agntid'), 'platform fields stripped');
    const secret = await run('read_file', { path: 'secrets/prod.env' });
    assert.equal(secret.verdict.decision, 'ALLOW', 'local over-grant');
    assert.deepEqual(secret.result, { ok: false, actionId: secret.verdict.actionId, code: 'EXTERNAL_DENY' }, 'runtime policy denies');
    const mail = await run('send_email', { to: 'dana@corp.test', subject: 'Q3', body: 'x' });
    assert.equal(mail.verdict.decision, 'BLOCK');
    assert.ok(mail.verdict.reasons.includes('EXTERNAL_DENY'), 'tool not in task intent shortlist');
    assert.equal(mock.calls.filter(c => c.name === 'send_email').length, 0, 'blocked call never reached runtime');
    // Every protected call carried the task correlation id; agents cannot inject their own.
    assert.ok(mock.calls.filter(c => c.name === 'read_file').every(c => c.args.agntid_task_id === runtime.taskId));
    await assert.rejects(runtime.callTool({ tool: 'read_file', arguments: { path: 'reports/q3.md', agntid_task_id: 'forged' } }), /EXTERNAL_DENY/);
    const evidence = fw.ledger.entries.map(e => e.type);
    assert.ok(evidence.includes('external-authorization') && evidence.includes('execution'));
    await runtime.closeTask();
  } finally { await caller.close(); await mock.close(); }
});

test('AgntID adapter fails closed: intent not prepared, runtime down, no task', { timeout: 20000 }, async () => {
  const mock = await startMockAgntid({ prepareIntent: false });
  const caller = await connectRuntime(mock.url);
  const runtime = new AgntidRuntime(caller, { agentId: 'report-agent', userId: 'analyst' });
  const noTask = new Firewall({ mandates: [mandate], authorizer: runtime.authorizer() });
  assert.ok((await noTask.decide({ agent: 'report-agent', mandate: 'q3', action: { tool: 'read_file', arguments: { path: 'reports/q3.md' } }, context: user })).reasons.includes('AUTHZ_UNAVAILABLE'));
  await runtime.openTask(mandate.objective);
  const fw = new Firewall({ mandates: [mandate], authorizer: runtime.authorizer(), executor: runtime.executor() });
  const verdict = await fw.decide({ agent: 'report-agent', mandate: 'q3', action: { tool: 'read_file', arguments: { path: 'reports/q3.md' } }, context: user });
  assert.equal(verdict.decision, 'BLOCK');
  assert.ok(verdict.reasons.includes('AUTHZ_UNAVAILABLE'));
  await caller.close();
  await mock.close();
  // Runtime gone: the executor reports unavailability; nothing is treated as allowed.
  const local = new Firewall({ mandates: [mandate], executor: runtime.executor() });
  const allowed = local.evaluate({ agent: 'report-agent', mandate: 'q3', action: { tool: 'read_file', arguments: { path: 'reports/q3.md' } }, context: user });
  const result = await local.execute(allowed.token, { tool: 'read_file', arguments: { path: 'reports/q3.md' } });
  assert.equal(result.ok, false);
  assert.equal(result.ok ? '' : result.code, 'AUTHZ_UNAVAILABLE');
});
