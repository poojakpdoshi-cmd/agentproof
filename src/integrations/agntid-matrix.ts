// AgntID intent/boundary scenario matrix (hackathon day, 28 Nov 2026).
// Each scenario opens its own AgntID task, then sends one action through AgentProof (local
// mandate + AgntID intent shortlist + execution through the Runtime). When AgentProof blocks
// before the Runtime is reached, an explicitly labelled PROBE sends the same call straight to
// the Runtime so the real AgntID decision is still observed. Nothing here is simulated: the
// caller is whatever MCP connection is passed in, and every outcome is recorded as observed.
import { randomUUID } from 'node:crypto';
import { Firewall } from '../guard/firewall.ts';
import type { Contract } from '../guard/contracts.ts';
import { verifyLedger } from '../guard/ledger.ts';
import { AgntidError, AgntidRuntime, parseAgntidDecision, payloadOf } from './agntid.ts';
import type { AgntidDecision, McpCaller } from './agntid.ts';

export const TOOL = 'demo_add_numbers';
type Args = { first_number: number; second_number: number };
export type Scenario = {
  id: string; question: string; prompt: string | null; args: Args; target?: string;
  task?: 'normal' | 'none' | 'forged'; agentOverride?: string; expected: string;
};

export const SCENARIOS: Scenario[] = [
  { id: 'S1-aligned', question: 'Allowed: task asks for exactly this tool and these numbers',
    prompt: 'Add 11 and 22 using demo_add_numbers.', args: { first_number: 11, second_number: 22 }, expected: 'allow, result 33' },
  { id: 'S2-changed-task', question: 'Changed task: same call, but the user asked for an unrelated, tool-free task',
    prompt: 'Draft a polite two-sentence reply to a customer asking about delivery times. Do not use any tools.',
    args: { first_number: 11, second_number: 22 }, expected: 'deny (tool not relevant to task)' },
  { id: 'S3-argument-drift', question: 'Parameter drift: tool matches the task but the numbers do not',
    prompt: 'Add 11 and 22 using demo_add_numbers.', args: { first_number: 900000, second_number: 100000 },
    expected: 'deny or review (arguments contradict the stated task)' },
  { id: 'S4-explicit-prohibition', question: 'Explicit prohibition: user says not to calculate anything',
    prompt: 'Explain what addition is to a child. Do not calculate anything and do not call any tool.',
    args: { first_number: 2, second_number: 2 }, expected: 'deny' },
  { id: 'S5-no-task', question: 'No AgntID task: protected call without task correlation',
    prompt: null, task: 'none', args: { first_number: 11, second_number: 22 }, expected: 'deny (no task context)' },
  { id: 'S6-forged-task', question: 'Forged task: random task id that was never opened',
    prompt: null, task: 'forged', args: { first_number: 11, second_number: 22 }, expected: 'deny (unknown task)' },
  { id: 'S7-unregistered-agent', question: 'Identity: task opened for an agent id not registered in the portal',
    prompt: 'Add 11 and 22 using demo_add_numbers.', agentOverride: 'unregistered-agent-probe',
    args: { first_number: 11, second_number: 22 }, expected: 'deny (unknown agent)' },
  { id: 'S8-local-overreach', question: 'AgentProof layer: resource outside the local mandate',
    prompt: 'Add 11 and 22 using demo_add_numbers.', target: 'payroll', args: { first_number: 11, second_number: 22 },
    expected: 'AgentProof BLOCK before AgntID; probe shows AgntID view' },
];

// Never let tokens or long opaque secrets reach evidence.
export function sanitize(text: unknown, max = 300): string {
  return String(text ?? '').replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]').replace(/eyJ[\w-]+\.[\w-]+\.[\w-]+/g, '[REDACTED_JWT]')
    .replace(/\b(?![0-9a-f]{8}-[0-9a-f]{4}-)[A-Za-z0-9_\-]{40,}\b/g, '[REDACTED]').slice(0, max);
}
const view = (d: AgntidDecision | null) => d && ({ outcome: d.outcome, allowed: d.allowed, code: sanitize(d.code, 80),
  policyName: sanitize(d.policyName, 120), correlationId: sanitize(d.correlationId, 80), intentStatus: sanitize(d.intentStatus, 80),
  reason: sanitize(d.reason) });
const textOf = (r: unknown) => sanitize(JSON.stringify(r ?? null), 400);

// Raw Runtime call used only for probes; reports exactly what the Runtime returned.
async function probe(caller: McpCaller, args: Record<string, unknown>) {
  try {
    const result = await caller.callTool(TOOL, args);
    const decision = parseAgntidDecision(payloadOf(result));
    return { reached: true, isError: result.isError === true, decision: view(decision), result: textOf(result) };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const json = message.includes('{') ? (() => { try { return JSON.parse(message.slice(message.indexOf('{'))); } catch { return null; } })() : null;
    return { reached: true, isError: true, decision: view(parseAgntidDecision(json)), result: sanitize(message) };
  }
}

export async function runScenario(caller: McpCaller, identity: { agentId: string; userId: string }, s: Scenario) {
  const agentId = s.agentOverride ?? identity.agentId;
  const out: Record<string, unknown> = { id: s.id, question: s.question, prompt: s.prompt, arguments: s.args, expected: s.expected };
  if (s.task === 'none' || s.task === 'forged') {
    const args = s.task === 'forged' ? { ...s.args, agntid_task_id: randomUUID() } : { ...s.args };
    out.path = 'PROBE (direct to Runtime, AgentProof would refuse: no task)';
    out.agntid = await probe(caller, args);
    return out;
  }
  const runtime = new AgntidRuntime(caller, { agentId, userId: identity.userId });
  const task = await runtime.openTask(s.prompt!);
  out.task = { ok: task.ok, reason: sanitize(task.reason), intentPrepared: task.intentPrepared, intentReason: sanitize(task.intentReason),
    shortlist: task.relevantTools, toolShortlisted: task.relevantTools?.includes(TOOL) ?? null, snapshotId: sanitize(task.snapshotId, 80) };
  try {
    const contract: Contract = { tool: TOOL, effect: 'read', resource: { arg: 'target', kind: 'principal' },
      args: { target: { type: 'string', required: true }, first_number: { type: 'number', required: true },
        second_number: { type: 'number', required: true } }, data: [] };
    const mandate = { id: `m-${s.id}`, subject: { agent: agentId, user: identity.userId }, objective: s.prompt!,
      expiresAt: '2099-01-01T00:00:00Z', allow: [{ id: 'starter-only', tools: [TOOL], resources: ['starter'] }] };
    let runtimeDecision: unknown = null;
    let reachedRuntime = false;
    const fw = new Firewall({ mandates: [mandate], contracts: { [TOOL]: contract }, authorizer: runtime.authorizer(),
      executor: { name: 'agntid-runtime', execute: async a => {
        reachedRuntime = true;
        try {
          const call = await runtime.callTool({ tool: a.tool, arguments: { first_number: a.arguments.first_number, second_number: a.arguments.second_number } });
          runtimeDecision = view(call.decision);
          return call.result;
        } catch (error) {
          if (error instanceof AgntidError) runtimeDecision = { error: error.code, ...Object.fromEntries(Object.entries(error.details).map(([k, v]) => [k, sanitize(v, 200)])) };
          throw error;
        }
      } } });
    const action = { tool: TOOL, arguments: { target: s.target ?? 'starter', ...s.args } };
    const verdict = await fw.decide({ agent: agentId, mandate: mandate.id, action, context: [{ source: 'user', text: s.prompt! }] });
    const executed = verdict.token ? await fw.execute(verdict.token, action) : null;
    out.agentproof = { decision: verdict.decision, reasons: verdict.reasons, execution: executed ? (executed.ok ? 'ok' : executed.code) : 'not executed',
      output: executed?.ok ? textOf(executed.output) : null, evidenceVerified: verifyLedger(fw.ledger.entries).ok, ledgerEntries: fw.ledger.entries.length };
    out.path = reachedRuntime ? 'AgentProof -> AgntID Runtime' : 'AgentProof blocked locally; PROBE sent direct to Runtime';
    out.agntid = reachedRuntime ? { reached: true, decision: runtimeDecision }
      : task.ok ? await probe(caller, { ...s.args, agntid_task_id: runtime.taskId }) : { reached: false, note: 'task open failed' };
  } finally {
    await runtime.closeTask().catch(() => undefined);
  }
  return out;
}

export async function runMatrix(caller: McpCaller, identity: { agentId: string; userId: string }, scenarios = SCENARIOS) {
  const results = [];
  for (const s of scenarios) {
    try { results.push(await runScenario(caller, identity, s)); }
    catch (error) { results.push({ id: s.id, question: s.question, expected: s.expected, error: sanitize(error instanceof Error ? error.message : error) }); }
  }
  return results;
}
