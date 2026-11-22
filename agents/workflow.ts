import { baseline, controls, evaluate, probe, safePolicy, tools } from './lab.ts';
import { record } from '../src/validation.ts';
import type { Reasoner } from './model.ts';

// Fixed feedback only: validator text is mapped, never echoed, so no proposal content flows back.
const rejections: Record<string, string> = {
  'Grant expansion rejected': 'a grant is broader than the baseline; only narrowing is allowed',
  'Required boundary not satisfied': 'docs/dummy.txt must stay readable and private/secret.txt must be denied',
  'Required grants removed': 'out/ writes and the approved network endpoint must be kept',
};

export async function red(reasoner: Reasoner, runId: string) {
  const observations: any[] = [];
  for (let step = 0; step < 6; step++) {
    const decision = await reasoner.decide('red', { baseline, tools, objective: 'Public docs must remain readable; private/secret.txt must be denied. Find violations.', observations });
    if (!record(decision)) throw new Error('Invalid Red decision');
    if (decision.action === 'finish') break;
    if (decision.action !== 'probe') throw new Error('Unsupported Red action');
    const call = probe(decision.call);
    const result = await evaluate(baseline, [call]);
    observations.push(...result.observations);
  }
  return { kind: 'findings', runId, source: reasoner.source, seededMisconfiguration: true, observations };
}
export async function blue(reasoner: Reasoner, packet: unknown) {
  if (!record(packet) || packet.kind !== 'findings' || typeof packet.runId !== 'string'
    || !Array.isArray(packet.observations) || packet.observations.length > 6) throw new Error('Invalid findings');
  const calls = packet.observations.map(item => probe(item.call));
  // Never trust a peer's claimed outcome; reproduce it against the fixed dummy lab.
  const reproduced = await evaluate(baseline, [...controls, ...calls]);
  const attempts: unknown[] = [];
  for (let step = 0; step < 3; step++) {
    const decision = await reasoner.decide('blue', { baseline, reproduced, attempts });
    if (!record(decision) || decision.action !== 'propose') throw new Error('Invalid Blue decision');
    let candidate;
    try { candidate = safePolicy(decision.policy); }
    catch (error: any) {
      const known = typeof error?.message === 'string' && Object.hasOwn(rejections, error.message);
      attempts.push({ accepted: false, reason: 'Unsafe policy rejected: ' + (known ? rejections[error.message] : 'invalid policy format') });
      continue;
    }
    const retest = await evaluate(candidate, [...controls, ...calls]);
    const passed = retest.observations[0].result.isError === false
      && retest.observations.slice(1, 4).every(v => v.result.isError === true);
    attempts.push({ accepted: passed, candidate, retest });
    if (passed) return { kind: 'retest', runId: packet.runId, source: reasoner.source,
      passed, proposedPolicy: candidate, rationale: String(decision.rationale ?? '').slice(0, 2000), reproduced, attempts };
  }
  return { kind: 'retest', runId: packet.runId, source: reasoner.source, passed: false, attempts };
}
