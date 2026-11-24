import { Firewall } from '../guard/firewall.ts';
import { EvidenceLedger } from '../guard/ledger.ts';
import { canonical, digest } from '../guard/canonical.ts';
import type { Environment, PatchOp, ReplayResult, StepOutcome, Trace } from './types.ts';

const CLOCK = Date.parse('2026-11-24T12:00:00.000Z');

// Deterministic counterfactual replay of one trace under one policy. Tool outputs come from the
// environment (read_file returns the asset), so the same inputs always give the same decisions.
// Steps flagged `approved` are approved by a (simulated) human when the policy asks; nothing else is.
export function replay(env: Environment, mandate: Record<string, unknown>, trace: Trace, ledger?: EvidenceLedger): ReplayResult {
  let n = 0;
  const fw = new Firewall({ mandates: [mandate], clock: () => new Date(CLOCK), ids: () => `${trace.id}#${++n}`,
    ledger: ledger ?? new EvidenceLedger({ clock: () => new Date(CLOCK) }) });
  const id = String(mandate.id);
  const agent = String((mandate.subject as { agent: string }).agent);
  const steps: StepOutcome[] = [];
  let stopped = false;
  for (const step of trace.steps) {
    if (stopped) break;
    const action = { tool: step.tool, arguments: step.arguments };
    const v = fw.evaluate({ agent, mandate: id, session: 'replay', action, context: trace.context });
    let token = v.token, humanApproved = false;
    if (v.decision === 'REQUIRE_APPROVAL' && step.approved) { token = fw.approve(v.actionId, 'replay-approver', true).token; humanApproved = true; }
    let executed = false;
    if (token && fw.consume(token, action).ok) {
      const output = step.tool === 'read_file' ? env.assets.find(a => a.path === step.arguments.path)?.content ?? 'not found' : 'ok';
      fw.verifyOutput(v.actionId, 'replay', { content: [{ type: 'text', text: output }] }, 'replay', fw.mandate(id), action);
      executed = true;
    }
    steps.push({ tool: step.tool, resource: v.resource ?? null, decision: v.decision, reasons: [...v.reasons], ruleId: v.ruleId ?? null,
      score: v.risk.score, factors: v.risk.factors.map(f => f.code), executed, humanApproved });
    if (!executed) stopped = true;
  }
  const blocked = steps.some(s => s.decision === 'BLOCK');
  return { traceId: trace.id, steps, completed: steps.length === trace.steps.length && steps.every(s => s.executed), blocked,
    held: !blocked && steps.some(s => s.decision === 'REQUIRE_APPROVAL' && !s.humanApproved) };
}

// Minimal JSON-patch subset over the mandate document ('add' appends with '/-').
export function applyPatch(mandate: Record<string, unknown>, patch: PatchOp[]): Record<string, unknown> {
  const out = structuredClone(mandate);
  for (const { op, path, value } of patch) {
    const parts = path.split('/').slice(1);
    let node: any = out;
    for (const key of parts.slice(0, -1)) {
      if (node[key] === undefined) node[key] = /^\d+$/.test(key) ? [] : (parts.at(-1) === '-' ? [] : {});
      node = node[key];
    }
    const last = parts.at(-1)!;
    if (op === 'add' && last === '-') { if (!Array.isArray(node)) throw new Error('Patch target is not a list'); node.push(structuredClone(value)); }
    else if (op === 'replace' || op === 'add') node[last] = structuredClone(value);
  }
  return out;
}

export const traceDigest = (trace: Trace) => digest(trace);
export const decisionVector = (r: ReplayResult) => r.steps.map(s => `${s.decision}${s.executed ? '' : '!'}`).join(' ');
export const policyDigest = (m: Record<string, unknown>) => digest(m);
export { canonical };
