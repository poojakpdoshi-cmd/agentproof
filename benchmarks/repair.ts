// Phase 2 benchmark: automatic repair vs manual expert policy vs naive strategies on the FROZEN
// evaluation set. Attacks used for scoring are regenerated with a different salt (fresh
// destination names) from the ORIGINAL policy, so repairs are not scored on the traces they were
// built from; legitimate tasks include a held-out suite the engine never saw.
// Run: node benchmarks/repair.ts   (writes docs/benchmark/repair-results.json)
import { mkdirSync, writeFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { generateAttacks } from '../src/repair/discover.ts';
import { repair } from '../src/repair/engine.ts';
import { replay } from '../src/repair/replay.ts';
import type { Environment, Trace } from '../src/repair/types.ts';
import { EVAL } from './repair/eval-envs.ts';
import { env as devEnv, H_A13 } from './repair/dev-report.ts';

const pct = (a: number, b: number) => b === 0 ? null : Math.round(1000 * a / b) / 10;
const strict = (d: string) => d === 'BLOCK' ? 2 : d === 'REQUIRE_APPROVAL' ? 1 : 0;

function score(env: Environment, policy: Record<string, unknown>, attacks: Trace[], legit: Trace[], baseVuln: Set<string>) {
  const vulnerable = attacks.filter(a => replay(env, policy, a).completed);
  let unattended = 0, notBlocked = 0, stricter = 0;
  for (const t of legit) {
    const r = replay(env, policy, t), b = replay(env, env.mandate, t);
    if (r.completed && !r.held) unattended++;
    if (!r.blocked) notBlocked++;
    r.steps.forEach((s, i) => { if (b.steps[i] && strict(s.decision) > strict(b.steps[i].decision)) stricter++; });
  }
  const legitSteps = legit.reduce((n, t) => n + t.steps.length, 0);
  return { vulnerable: vulnerable.length, prevented: pct(baseVuln.size - vulnerable.filter(a => baseVuln.has(a.id)).length, baseVuln.size),
    securityRegressions: vulnerable.filter(a => !baseVuln.has(a.id)).length,
    legitUnattended: pct(unattended, legit.length), legitNotBlocked: pct(notBlocked, legit.length), falsePositiveSteps: pct(stricter, legitSteps) };
}

const rows: Record<string, unknown>[] = [];
const totals: Record<string, { vulnPrevented: number; vulnTotal: number; legitOk: number; legitAny: number; legitTotal: number; fpSteps: number; steps: number; regressions: number }> = {};
let seededFound = 0, seededTotal = 0, repairMs = 0, proposals = 0;
for (const { env, legitHoldout, manual } of EVAL) {
  const t0 = performance.now();
  const report = repair(env);
  const ms = performance.now() - t0;
  repairMs += ms; proposals += report.proposals.length;
  // Discovery rate: seeded weaknesses the engine's own discovery exposed as vulnerabilities.
  const vulnAtStart = report.attacks.filter(a => replay(env, env.mandate, a).completed);
  const found = (env.seeded ?? []).map(s => ({ ...s, found: vulnAtStart.some(a => a.violation!.family === s.family && a.violation!.sink === s.sink && a.violation!.asset === s.asset) }));
  seededFound += found.filter(f => f.found).length; seededTotal += found.length;
  const evalAttacks = generateAttacks(env, env.mandate, { salt: 'eval' });
  const baseVuln = new Set(evalAttacks.filter(a => replay(env, env.mandate, a).completed).map(a => a.id));
  const sinks = [...new Set(evalAttacks.filter(a => baseVuln.has(a.id)).map(a => a.violation!.sink).filter(s => s !== 'read_file'))];
  const strategies: Record<string, Record<string, unknown>> = {
    baseline: env.mandate, auto: report.finalPolicy, manual,
    'deny-all': { ...env.mandate, deny: [{ tools: ['*'], resources: ['*'] }] },
    'deny-sinks': { ...env.mandate, deny: [...((env.mandate.deny as unknown[]) ?? []), ...sinks.map(tool => ({ tools: [tool], resources: ['*'] }))] },
  };
  const legit = [...env.legit, ...legitHoldout];
  const result: Record<string, unknown> = {};
  for (const [name, policy] of Object.entries(strategies)) {
    const s = score(env, policy, evalAttacks, legit, baseVuln);
    result[name] = s;
    const t = totals[name] ??= { vulnPrevented: 0, vulnTotal: 0, legitOk: 0, legitAny: 0, legitTotal: 0, fpSteps: 0, steps: 0, regressions: 0 };
    t.vulnTotal += baseVuln.size; t.vulnPrevented += Math.round((s.prevented ?? 100) * baseVuln.size / 100);
    t.legitTotal += legit.length; t.legitOk += Math.round((s.legitUnattended ?? 0) * legit.length / 100); t.legitAny += Math.round((s.legitNotBlocked ?? 0) * legit.length / 100);
    const steps = legit.reduce((n, x) => n + x.steps.length, 0);
    t.steps += steps; t.fpSteps += Math.round((s.falsePositiveSteps ?? 0) * steps / 100); t.regressions += s.securityRegressions;
  }
  rows.push({ environment: env.id, evalAttacks: evalAttacks.length, baselineVulnerabilities: baseVuln.size, discoveredAttacks: report.discovered,
    seeded: found, proposals: report.proposals.map(p => ({ id: p.id, operator: p.chosen.candidate.operator, summary: p.chosen.candidate.summary,
      fixes: p.chosen.vulnerabilitiesFixed, legitBlocked: p.chosen.legitBlocked, legitHeld: p.chosen.legitHeld, causes: p.rootCause.causes, latencyMs: p.latencyMs })),
    residualDuringRepair: report.residual.length, repairLatencyMs: Math.round(ms), strategies: result });
}
const summary = Object.fromEntries(Object.entries(totals).map(([k, t]) => [k, { vulnerabilitiesPrevented: pct(t.vulnPrevented, t.vulnTotal),
  legitCompletedUnattended: pct(t.legitOk, t.legitTotal), legitNotBlocked: pct(t.legitAny, t.legitTotal), falsePositiveSteps: pct(t.fpSteps, t.steps), securityRegressions: t.regressions }]));
const dev = repair(devEnv);
const output = { measuredOn: new Date().toISOString().slice(0, 10), node: process.version,
  disclaimer: 'Synthetic environments authored by the engine author. Frozen eval set committed before its first run. Attacks scored here use fresh destination names; legit includes a held-out suite.',
  discoveryRate: pct(seededFound, seededTotal), seededFound, seededTotal, meanRepairLatencyMsPerEnvironment: Math.round(repairMs / EVAL.length),
  meanLatencyMsPerProposal: Math.round(repairMs / Math.max(1, proposals)), summary, environments: rows,
  regressionCase: { id: 'H-A13', vulnerableBefore: replay(devEnv, devEnv.mandate, H_A13).completed, vulnerableAfter: replay(devEnv, dev.finalPolicy, H_A13).completed,
    proposals: dev.proposals.map(p => p.chosen.candidate.summary) } };
mkdirSync(new URL('../docs/benchmark/', import.meta.url), { recursive: true });
writeFileSync(new URL('../docs/benchmark/repair-results.json', import.meta.url), JSON.stringify(output, null, 2) + '\n');
console.log(JSON.stringify({ discoveryRate: output.discoveryRate, seeded: `${seededFound}/${seededTotal}`, latency: output.meanRepairLatencyMsPerEnvironment, perProposal: output.meanLatencyMsPerProposal, summary, regressionCase: output.regressionCase,
  envs: rows.map(r => ({ env: r.environment, vulns: r.baselineVulnerabilities, proposals: (r.proposals as Array<{ summary: string }>).map(p => p.summary), seededMissed: (r.seeded as Array<{ found: boolean; note: string }>).filter(s => !s.found).map(s => s.note) })) }, null, 1));
