import { mkdirSync, writeFileSync } from 'node:fs';
import { repair, verifyCertificate } from '../../src/repair/engine.ts';
import { generateAttacks } from '../../src/repair/discover.ts';
import { replay } from '../../src/repair/replay.ts';
import { CASES } from './phase6_3-cases.ts';

const cases = CASES.map(selected => {
  const { env } = selected;
  const report = repair(env);
  const measure = (policy: Record<string, unknown>, traces: typeof selected.authorized) => traces.map(trace => {
    const result = replay(env, policy, trace);
    return { id: trace.id, completed: result.completed, decisions: result.steps.map(step => step.decision) };
  });
  const strictDirectory = { ...env.mandate, trustedTargets: ['write_file'] };
  return { id: selected.id, discoveredPublicDestinations: generateAttacks(env, env.mandate).filter(t => t.violation?.property === 'unauthorized-destination').length,
    initialVulnerabilities: report.initialVulnerabilities, proposals: report.proposals.map(p => ({ id: p.id, operator: p.chosen.candidate.operator,
      certificate: p.certificate.digest, verified: verifyCertificate(p.certificate, env, p.before,
        report.attacks.filter(a => Object.hasOwn(p.certificate.security.before, a.id))).ok })), residual: report.residual.length,
    unauthorized: { before: measure(env.mandate, selected.unauthorized), after: measure(report.finalPolicy, selected.unauthorized) },
    authorized: { before: measure(env.mandate, selected.authorized), after: measure(report.finalPolicy, selected.authorized),
      strictDirectory: selected.id === 'directory-wide' ? measure(strictDirectory, selected.authorized) : undefined } };
});
const output = { frozenCasesCommit: 'c517e1e', cases };
mkdirSync(new URL('../../docs/benchmark/', import.meta.url), { recursive: true });
writeFileSync(new URL('../../docs/benchmark/phase6.3-destinations.json', import.meta.url), JSON.stringify(output, null, 2) + '\n');
console.log(JSON.stringify(cases.map(c => ({ id: c.id, discovered: c.discoveredPublicDestinations, proposals: c.proposals.map(p => p.operator),
  unauthorizedBefore: c.unauthorized.before.map(x => x.completed), unauthorizedAfter: c.unauthorized.after.map(x => x.completed),
  authorizedAfter: c.authorized.after.map(x => x.completed), strictDirectory: c.authorized.strictDirectory?.map(x => x.completed) })), null, 2));
