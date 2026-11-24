import { performance } from 'node:perf_hooks';
import { writeFileSync } from 'node:fs';
import { repair, verifyCertificate } from '../../src/repair/engine.ts';
import { replay } from '../../src/repair/replay.ts';
import type { Environment, Trace } from '../../src/repair/types.ts';
import { PHASE5_CASES } from './phase5-cases.ts';

const scenarios: Array<{ environment: string; attacks: number; prevented: number; legitimate: number; completed: number;
  blocked: number; approvalSteps: number; falsePositiveSteps: number; repairProposals: string[]; certificatesVerified: number; certificates: number }> = [];
const durations: number[] = [];
for (const { env, legitHoldout, attacks } of PHASE5_CASES) {
  const report = repair(env);
  const policy = report.finalPolicy;
  const legit = [...env.legit, ...legitHoldout];
  const legitimateResults = legit.map(t => replay(env, policy, t));
  const attackResults = attacks.map(t => replay(env, policy, t));
  let certified = 0;
  for (const proposal of report.proposals) {
    const suite = report.attacks.filter(a => Object.hasOwn(proposal.certificate.security.before, a.id));
    if (verifyCertificate(proposal.certificate, env, proposal.before, suite).ok) certified++;
  }
  let stricter = 0;
  legitimateResults.forEach((result, i) => {
    const before = replay(env, env.mandate, legit[i]);
    result.steps.forEach((s, j) => { if (s.decision !== before.steps[j]?.decision && s.decision !== 'ALLOW') stricter++; });
  });
  scenarios.push({ environment: env.id, attacks: attacks.length, prevented: attackResults.filter(r => !r.completed).length,
    legitimate: legit.length, completed: legitimateResults.filter(r => r.completed && !r.held).length,
    blocked: legitimateResults.filter(r => r.blocked).length,
    approvalSteps: legitimateResults.flatMap(r => r.steps).filter(s => s.decision === 'REQUIRE_APPROVAL').length,
    falsePositiveSteps: stricter, repairProposals: report.proposals.map(p => p.chosen.candidate.operator),
    certificatesVerified: certified, certificates: report.proposals.length });
  for (const t of [...legit, ...attacks]) for (let i = 0; i < 30; i++) {
    const start = performance.now();
    replay(env, policy, t);
    durations.push(performance.now() - start);
  }
}
durations.sort((a, b) => a - b);
const sum = (key: 'attacks' | 'prevented' | 'legitimate' | 'completed' | 'blocked' | 'approvalSteps' | 'falsePositiveSteps' | 'certificates' | 'certificatesVerified') =>
  scenarios.reduce((n, s) => n + s[key], 0);
const output = { measuredOn: new Date().toISOString().slice(0, 10), node: process.version, freezeCommit: '808ecf0',
  note: 'Synthetic self-authored frozen cases. Latency is full in-process deterministic replay, including firewall setup and evidence; not per-decision production latency.',
  totals: { attacksPrevented: `${sum('prevented')}/${sum('attacks')}`, legitimateUnattended: `${sum('completed')}/${sum('legitimate')}`,
    legitimateBlocked: sum('blocked'), approvalSteps: sum('approvalSteps'), newlyStricterLegitimateSteps: sum('falsePositiveSteps'),
    certificatesVerified: `${sum('certificatesVerified')}/${sum('certificates')}` },
  latencyMs: { p50: Number(durations[Math.floor(durations.length * .5)].toFixed(3)), p95: Number(durations[Math.floor(durations.length * .95)].toFixed(3)), samples: durations.length },
  scenarios };
writeFileSync(new URL('../../docs/benchmark/phase5-results.json', import.meta.url), JSON.stringify(output, null, 2) + '\n');
console.log(JSON.stringify(output, null, 2));
