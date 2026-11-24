import type { Entry, VerifyResult } from '../guard/ledger.ts';

// Derives dashboard state from evidence entries only. No numbers are invented: every count,
// latency and timeline row comes from a ledger entry, and integrity comes from re-verification.
type Row = {
  seq: number; ts: string; actionId: string; agent: string | null; tool: string; resource: string | null; decision: string; final: string;
  score: number; level: string; reasons: string[]; threats: string[]; factors: Array<{ code: string; points: number; detail: string }>;
  policyId: string; latencyMs: number | null; external: string | null; approval: string | null; execution: string | null; objective: string | null;
};
const quantile = (values: number[], q: number) => {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return Math.round(sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))] * 1000) / 1000;
};

export function summarize(entries: readonly Entry[], verification: VerifyResult, source: { file: string; mode: string }) {
  const rows = new Map<string, Row>();
  const mandates: Array<Record<string, unknown>> = [];
  let bindingViolations = 0;
  for (const e of entries) {
    const d = (e.data ?? {}) as Record<string, any>;
    if (e.type === 'mandate') mandates.push({ id: d.mandate, agent: d.agent, user: d.user, objective: d.objective, expiresAt: d.expiresAt, version: d.version });
    if (e.type === 'decision' && typeof d.actionId === 'string') {
      rows.set(d.actionId, { seq: e.seq, ts: e.ts, actionId: d.actionId, agent: d.agent ?? null, tool: d.action?.tool ?? 'unknown',
        resource: typeof d.action?.resource === 'string' ? d.action.resource : null, decision: d.decision, final: d.decision,
        score: d.risk?.score ?? 0, level: d.risk?.level ?? 'LOW', reasons: d.reasons ?? [], threats: d.threats ?? [], factors: d.risk?.factors ?? [],
        policyId: d.policyId, latencyMs: typeof d.latencyMs === 'number' ? d.latencyMs : null, external: null, approval: null, execution: null, objective: d.objective ?? null });
    }
    const row = typeof d.actionId === 'string' ? rows.get(d.actionId) : undefined;
    if (e.type === 'external-authorization' && row) {
      row.external = `${d.authorizer}: ${d.outcome}${d.code ? ' (' + d.code + ')' : ''}`;
      if (d.outcome === 'review_required' && row.final === 'ALLOW') row.final = 'REQUIRE_APPROVAL';
      if (d.outcome === 'deny' || d.outcome === 'unknown') row.final = 'BLOCK';
    }
    if (e.type === 'approval' && row) { row.approval = d.approved ? `approved by ${d.approver}` : `rejected by ${d.approver}`; if (!d.approved) row.final = 'BLOCK'; }
    if (e.type === 'execution' && row) row.execution = d.status === 'ok' ? `executed${d.secretsRedacted ? `, ${d.secretsRedacted} secret(s) redacted` : ''}${d.injectionSignals?.length ? ', injection flagged in output' : ''}` : `failed: ${d.code}`;
    if (e.type === 'binding-violation') bindingViolations++;
  }
  const all = [...rows.values()];
  const count = (f: (r: Row) => boolean) => all.filter(f).length;
  const threats: Record<string, number> = {};
  const reasons: Record<string, number> = {};
  for (const r of all) {
    if (r.final !== 'ALLOW') for (const t of r.threats) threats[t] = (threats[t] ?? 0) + 1;
    for (const c of r.reasons) reasons[c] = (reasons[c] ?? 0) + 1;
  }
  const latencies = all.map(r => r.latencyMs).filter((v): v is number => v !== null);
  return {
    source, generatedAt: new Date().toISOString(),
    integrity: { ok: verification.ok, entries: verification.entries, head: verification.head, macVerified: verification.macVerified, issues: verification.issues.slice(0, 50) },
    totals: { evaluated: all.length, allowed: count(r => r.final === 'ALLOW'), blocked: count(r => r.final === 'BLOCK'),
      approval: count(r => r.final === 'REQUIRE_APPROVAL' && !r.approval), approvedByHuman: count(r => r.approval?.startsWith('approved') ?? false),
      executed: count(r => r.execution?.startsWith('executed') ?? false), executionFailures: count(r => r.execution?.startsWith('failed') ?? false), bindingViolations },
    threats, reasons,
    latency: { decisions: latencies.length, p50: quantile(latencies, 0.5), p95: quantile(latencies, 0.95), max: latencies.length ? Math.max(...latencies) : null },
    mandates, timeline: all.sort((a, b) => a.seq - b.seq),
  };
}
