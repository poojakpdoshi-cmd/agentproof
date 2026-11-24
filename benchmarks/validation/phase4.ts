import { mkdirSync, writeFileSync } from 'node:fs';
import { repair, verifyCertificate } from '../../src/repair/engine.ts';
import { replay } from '../../src/repair/replay.ts';
import type { Environment, Trace } from '../../src/repair/types.ts';
import { AGENTDOJO_ACTION_CASES, SYNTHETIC_CASES, UNSUPPORTED_AGENTDOJO } from './phase4-cases.ts';

type Policy = Record<string, unknown>;
const decision = (env: Environment, policy: Policy, trace: Trace) => {
  const result = replay(env, policy, trace);
  return { completed: result.completed, blocked: result.blocked, held: result.held,
    vector: result.steps.map(s => s.decision).join(' ') };
};
const denyAll = (env: Environment): Policy => ({ ...env.mandate, deny: [{ tools: ['*'], resources: ['*'] }] });
const denySinks = (env: Environment): Policy => ({ ...env.mandate,
  deny: [{ tools: ['send_email', 'write_file', 'network_request', 'execute_command'], resources: ['*'] }] });

function measure(env: Environment, policy: Policy, legit: readonly Trace[], attacks: readonly Trace[]) {
  const legitimate = legit.map(t => ({ id: t.id, ...decision(env, policy, t) }));
  const adversarial = attacks.map(t => ({ id: t.id, ...decision(env, policy, t) }));
  return { legitimate, adversarial, unattended: legitimate.filter(x => x.completed && !x.held).length,
    notBlocked: legitimate.filter(x => !x.blocked).length, attackPrevented: adversarial.filter(x => !x.completed).length,
    attackBlocked: adversarial.filter(x => x.blocked).length };
}

const externalEnv = AGENTDOJO_ACTION_CASES[0].env;
const externalAttacks = AGENTDOJO_ACTION_CASES.map(x => x.trace);
const originalExternal: Policy = { ...externalEnv.mandate, trustedTargets: [] };
const external = {
  source: 'ethz-spylab/agentdojo@089ed468cf3ed0322acc66b0211f26d9d90dbf60',
  scope: 'Two mapped v1 workspace injection goals; deterministic proposed-action replay only, not an official AgentDojo score.',
  mappings: AGENTDOJO_ACTION_CASES.map(({ id, sourceTask, mapping }) => ({ id, sourceTask, mapping })),
  unsupported: UNSUPPORTED_AGENTDOJO,
  strategies: {
    original: measure(externalEnv, originalExternal, externalEnv.legit, externalAttacks),
    agentproof: measure(externalEnv, externalEnv.mandate, externalEnv.legit, externalAttacks),
    'deny-all': measure(externalEnv, denyAll(externalEnv), externalEnv.legit, externalAttacks),
    'deny-sinks': measure(externalEnv, denySinks(externalEnv), externalEnv.legit, externalAttacks),
  },
};

const synthetic = [];
for (const { env, legitHoldout, attacks } of SYNTHETIC_CASES) {
  const report = repair(env);
  let certified = 0;
  for (const proposal of report.proposals) {
    const suite = report.attacks.filter(a => Object.hasOwn(proposal.certificate.security.before, a.id));
    if (verifyCertificate(proposal.certificate, env, proposal.before, suite).ok) certified++;
  }
  const legit = [...env.legit, ...legitHoldout];
  synthetic.push({ environment: env.id, classification: env.assets.map(a => ({ path: a.path, class: a.class })),
    proposals: report.proposals.map(p => p.chosen.candidate.operator), certificatesVerified: certified,
    certificatesTotal: report.proposals.length, residualDiscoveryVulnerabilities: report.residual.length,
    strategies: { original: measure(env, env.mandate, legit, attacks), agentproof: measure(env, report.finalPolicy, legit, attacks),
      'deny-all': measure(env, denyAll(env), legit, attacks), 'deny-sinks': measure(env, denySinks(env), legit, attacks) } });
}

const output = { measuredOn: new Date().toISOString().slice(0, 10), node: process.version,
  implementationCommit: '93f0893', frozenCasesCommit: '80d727a', external, synthetic };
mkdirSync(new URL('../../docs/benchmark/', import.meta.url), { recursive: true });
writeFileSync(new URL('../../docs/benchmark/phase4-validation.json', import.meta.url), JSON.stringify(output, null, 2) + '\n');
console.log(JSON.stringify({ external: Object.fromEntries(Object.entries(external.strategies).map(([k, v]) => [k, {
  attacksPrevented: `${v.attackPrevented}/${externalAttacks.length}`, legitUnattended: `${v.unattended}/${externalEnv.legit.length}` }])),
  synthetic: synthetic.map(s => ({ env: s.environment, proposals: s.proposals, certificates: `${s.certificatesVerified}/${s.certificatesTotal}`,
    original: [s.strategies.original.attackPrevented, s.strategies.original.unattended],
    agentproof: [s.strategies.agentproof.attackPrevented, s.strategies.agentproof.unattended],
    denyAll: [s.strategies['deny-all'].attackPrevented, s.strategies['deny-all'].unattended],
    denySinks: [s.strategies['deny-sinks'].attackPrevented, s.strategies['deny-sinks'].unattended] })) }, null, 2));
