// Phase 3 benchmark. The holdout definition was frozen at commit 0509c8d before its first run.
// Phase 2 cases are synthesis/development data; only PHASE3_EVAL holdouts and attack salts score.
import { mkdirSync, writeFileSync } from 'node:fs';
import { generateAttacks } from '../src/repair/discover.ts';
import { repair, verifyCertificate } from '../src/repair/engine.ts';
import { replay } from '../src/repair/replay.ts';
import type { Environment, Trace } from '../src/repair/types.ts';
import { EVAL } from './repair/eval-envs.ts';
import { PHASE3_EVAL } from './repair/phase3-eval.ts';

const pct = (a: number, b: number) => b === 0 ? null : Math.round(1000 * a / b) / 10;
const strict = (d: string) => d === 'BLOCK' ? 2 : d === 'REQUIRE_APPROVAL' ? 1 : 0;
type Counts = { prevented: number; vulnerable: number; unattended: number; notBlocked: number; legit: number; stricter: number; steps: number; regressions: number };

function score(env: Environment, policy: Record<string, unknown>, attacks: Trace[], legit: readonly Trace[], baseVulnerable: Set<string>): Counts {
  let unattended = 0, notBlocked = 0, stricter = 0;
  for (const trace of legit) {
    const now = replay(env, policy, trace), base = replay(env, env.mandate, trace);
    if (now.completed && !now.held) unattended++;
    if (!now.blocked) notBlocked++;
    now.steps.forEach((step, i) => { if (base.steps[i] && strict(step.decision) > strict(base.steps[i].decision)) stricter++; });
  }
  const vulnerableNow = attacks.filter(a => replay(env, policy, a).completed);
  return { prevented: baseVulnerable.size - vulnerableNow.filter(a => baseVulnerable.has(a.id)).length, vulnerable: baseVulnerable.size,
    unattended, notBlocked, legit: legit.length, stricter, steps: legit.reduce((n, t) => n + t.steps.length, 0),
    regressions: vulnerableNow.filter(a => !baseVulnerable.has(a.id)).length };
}

const totals = new Map<string, Counts>();
const rows: Record<string, unknown>[] = [];
let certificates = 0, certificatesVerified = 0;
for (let i = 0; i < PHASE3_EVAL.length; i++) {
  const c = PHASE3_EVAL[i], env = c.development;
  const phase2 = repair(EVAL[i].env, { strategy: 'phase2' });
  const phase3 = repair(env);
  for (const proposal of phase3.proposals) {
    const suite = phase3.attacks.filter(a => Object.hasOwn(proposal.certificate.security.before, a.id));
    certificates++;
    if (verifyCertificate(proposal.certificate, env, proposal.before, suite).ok) certificatesVerified++;
  }
  const attacks = generateAttacks(env, env.mandate, { salt: c.attackSalt });
  const baseVulnerable = new Set(attacks.filter(a => replay(env, env.mandate, a).completed).map(a => a.id));
  const sinks = [...new Set(attacks.filter(a => baseVulnerable.has(a.id)).map(a => a.violation!.sink).filter(s => s !== 'read_file'))];
  const strategies: Record<string, Record<string, unknown>> = {
    original: env.mandate,
    'phase2-auto': phase2.finalPolicy,
    'phase3-optimized': phase3.finalPolicy,
    'manual-expert': c.manual,
    'deny-all': { ...env.mandate, deny: [{ tools: ['*'], resources: ['*'] }] },
    'deny-sinks': { ...env.mandate, deny: [...((env.mandate.deny as unknown[]) ?? []), ...sinks.map(tool => ({ tools: [tool], resources: ['*'] }))] },
  };
  const results: Record<string, unknown> = {};
  for (const [name, policy] of Object.entries(strategies)) {
    const value = score(env, policy, attacks, c.holdout, baseVulnerable);
    results[name] = { vulnerabilitiesPrevented: pct(value.prevented, value.vulnerable), legitCompletedUnattended: pct(value.unattended, value.legit),
      legitNotBlocked: pct(value.notBlocked, value.legit), falsePositiveSteps: pct(value.stricter, value.steps), securityRegressions: value.regressions };
    const total = totals.get(name) ?? { prevented: 0, vulnerable: 0, unattended: 0, notBlocked: 0, legit: 0, stricter: 0, steps: 0, regressions: 0 };
    for (const key of Object.keys(total) as Array<keyof Counts>) total[key] += value[key];
    totals.set(name, total);
  }
  rows.push({ environment: env.id, baselineVulnerabilities: baseVulnerable.size, holdoutLegitimateTasks: c.holdout.length,
    phase2Operators: phase2.proposals.map(p => p.chosen.candidate.operator), phase3Operators: phase3.proposals.map(p => p.chosen.candidate.operator),
    phase3Residual: phase3.residual.length, strategies: results });
}

const summary = Object.fromEntries([...totals].map(([name, value]) => [name, {
  vulnerabilitiesPrevented: pct(value.prevented, value.vulnerable), legitCompletedUnattended: pct(value.unattended, value.legit),
  legitNotBlocked: pct(value.notBlocked, value.legit), falsePositiveSteps: pct(value.stricter, value.steps), securityRegressions: value.regressions,
}]));
const output = { measuredOn: new Date().toISOString().slice(0, 10), node: process.version, frozenAtCommit: '0509c8d',
  disclaimer: 'Synthetic, self-authored frozen holdout. Phase 2 evaluation cases are development data. No independent cases were available.',
  certificates: { verified: certificatesVerified, total: certificates }, summary, environments: rows };
mkdirSync(new URL('../docs/benchmark/', import.meta.url), { recursive: true });
writeFileSync(new URL('../docs/benchmark/phase3-repair-results.json', import.meta.url), JSON.stringify(output, null, 2) + '\n');
console.log(JSON.stringify(output, null, 2));
