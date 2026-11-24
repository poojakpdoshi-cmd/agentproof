import { performance } from 'node:perf_hooks';
import { BUILTIN_CONTRACTS } from '../guard/contracts.ts';
import { digest } from '../guard/canonical.ts';
import { parseMandate } from '../guard/mandate.ts';
import { analyze, candidates, legitUsage, signature } from './analyze.ts';
import { generateAttacks } from './discover.ts';
import type { DiscoveryOptions } from './discover.ts';
import { applyPatch, decisionVector, replay } from './replay.ts';
import type { Candidate, Environment, Evaluation, ReplayResult, RootCause, Trace } from './types.ts';

// Ranking weights (documented, fixed). Eligibility first: the candidate must be a valid policy,
// stop the vulnerable trace, and re-enable no attack the current policy already stops.
export const RANK = Object.freeze({ base: 100, perFixedShare: 40, legitBlockedShare: -60, legitHeldShare: -25, complexity: -2, blocksTarget: 5 });

type Suite = { attacks: Trace[]; attackBase: Map<string, ReplayResult>; legit: Trace[]; legitBase: Map<string, ReplayResult> };
const strict = (d: string) => d === 'BLOCK' ? 2 : d === 'REQUIRE_APPROVAL' ? 1 : 0;

export function evaluate(env: Environment, mandate: Record<string, unknown>, candidate: Candidate, target: Trace, suite: Suite): Evaluation & { after: Record<string, unknown> } {
  const fail = (error: string) => ({ candidate, valid: false, error, fixesTarget: false, targetDecision: 'n/a', vulnerabilitiesFixed: 0,
    securityRegressions: 0, legitBlocked: 0, legitHeld: 0, stricterLegitSteps: 0, score: -Infinity, after: mandate });
  let after: Record<string, unknown>;
  try { after = applyPatch(mandate, candidate.patch); parseMandate(after, BUILTIN_CONTRACTS); } catch (e) { return fail(e instanceof Error ? e.message : 'invalid'); }
  const t = replay(env, after, target);
  const stop = t.steps.find(s => !s.executed);
  let fixed = 0, regressions = 0, blocked = 0, held = 0, stricter = 0;
  const vulnerable = suite.attacks.filter(a => suite.attackBase.get(a.id)!.completed).length;
  for (const attack of suite.attacks) {
    const before = suite.attackBase.get(attack.id)!.completed, now = replay(env, after, attack).completed;
    if (before && !now) fixed++;
    if (!before && now) regressions++;
  }
  for (const trace of suite.legit) {
    const base = suite.legitBase.get(trace.id)!, now = replay(env, after, trace);
    if (now.blocked && !base.blocked) blocked++;
    else if (now.held && !base.held) held++;
    now.steps.forEach((s, i) => { if (base.steps[i] && strict(s.decision) > strict(base.steps[i].decision)) stricter++; });
  }
  const fixesTarget = !t.completed;
  const n = Math.max(1, suite.legit.length);
  const score = RANK.base + RANK.perFixedShare * (fixed / Math.max(1, vulnerable)) + RANK.legitBlockedShare * (blocked / n)
    + RANK.legitHeldShare * (held / n) + RANK.complexity * candidate.complexity + (stop?.decision === 'BLOCK' ? RANK.blocksTarget : 0);
  return { candidate, valid: true, fixesTarget, targetDecision: stop ? stop.decision : 'ALLOW', vulnerabilitiesFixed: fixed, securityRegressions: regressions,
    legitBlocked: blocked, legitHeld: held, stricterLegitSteps: stricter, score: Math.round(score * 100) / 100, after };
}

export type Proposal = {
  id: string; iteration: number; rootCause: RootCause; group: number; chosen: Evaluation; alternatives: Evaluation[];
  before: Record<string, unknown>; after: Record<string, unknown>; certificate: Certificate; latencyMs: number;
};
export type Certificate = {
  v: 1; engine: 'agentproof-repair/1'; environment: string; environmentDigest: string;
  policyBefore: string; patch: Candidate['patch']; policyAfter: string;
  target: { trace: Trace; before: string; after: string };
  regression: { legitDigest: string; before: Record<string, string>; after: Record<string, string> };
  security: { attackDigest: string; before: Record<string, boolean>; after: Record<string, boolean> };
  digest?: string;
};

const vectors = (env: Environment, mandate: Record<string, unknown>, traces: Trace[]) => Object.fromEntries(traces.map(t => [t.id, decisionVector(replay(env, mandate, t))]));
const outcomes = (env: Environment, mandate: Record<string, unknown>, traces: Trace[]) => Object.fromEntries(traces.map(t => [t.id, replay(env, mandate, t).completed]));
const envDigest = (env: Environment) => digest({ id: env.id, mandate: env.mandate, assets: env.assets, legit: env.legit });

export function certify(env: Environment, before: Record<string, unknown>, after: Record<string, unknown>, patch: Candidate['patch'], target: Trace, attacks: Trace[]): Certificate {
  const cert: Certificate = { v: 1, engine: 'agentproof-repair/1', environment: env.id, environmentDigest: envDigest(env),
    policyBefore: digest(before), patch, policyAfter: digest(after),
    target: { trace: target, before: decisionVector(replay(env, before, target)), after: decisionVector(replay(env, after, target)) },
    regression: { legitDigest: digest(env.legit), before: vectors(env, before, env.legit), after: vectors(env, after, env.legit) },
    security: { attackDigest: digest(attacks), before: outcomes(env, before, attacks), after: outcomes(env, after, attacks) } };
  return { ...cert, digest: digest(cert) };
}

// Independent re-verification: recompute every digest and re-run every replay from scratch.
export function verifyCertificate(cert: Certificate, env: Environment, before: Record<string, unknown>, attacks: Trace[]): { ok: boolean; mismatches: string[] } {
  const m: string[] = [];
  const { digest: claimed, ...body } = cert;
  if (digest(body) !== claimed) m.push('certificate digest');
  if (envDigest(env) !== cert.environmentDigest) m.push('environment digest');
  if (digest(before) !== cert.policyBefore) m.push('policy before');
  let after: Record<string, unknown>;
  try { after = applyPatch(before, cert.patch); } catch { return { ok: false, mismatches: [...m, 'patch'] }; }
  if (digest(after) !== cert.policyAfter) m.push('policy after');
  if (digest(attacks) !== cert.security.attackDigest) m.push('attack suite digest');
  if (decisionVector(replay(env, before, cert.target.trace)) !== cert.target.before) m.push('target before');
  if (decisionVector(replay(env, after, cert.target.trace)) !== cert.target.after) m.push('target after');
  for (const [mandate, side] of [[before, 'before'], [after, 'after']] as const) {
    const legit = vectors(env, mandate, env.legit), sec = outcomes(env, mandate, attacks);
    for (const [id, v] of Object.entries(cert.regression[side])) if (legit[id] !== v) m.push(`legit ${id} ${side}`);
    for (const [id, v] of Object.entries(cert.security[side])) if (sec[id] !== v) m.push(`attack ${id} ${side}`);
  }
  return { ok: m.length === 0, mismatches: m };
}

export type RepairReport = {
  environment: string; iterations: number; discovered: number; initialVulnerabilities: number; residual: Trace[];
  proposals: Proposal[]; finalPolicy: Record<string, unknown>; attacks: Trace[]; latencyMs: number;
};

// Iterative discover -> analyze -> propose -> verify -> rank loop. Each iteration rediscovers
// attacks against the *current* (simulated, not yet applied) policy, so a repair that opens or
// leaves new sinks is probed again. Proposals are applied only by a human (see store.ts).
export function repair(env: Environment, options: { discovery?: DiscoveryOptions; maxIterations?: number } = {}): RepairReport {
  const started = performance.now();
  let current = structuredClone(env.mandate);
  const attacks = new Map<string, Trace>();
  const proposals: Proposal[] = [];
  let initial = -1;
  for (let iteration = 1; iteration <= (options.maxIterations ?? 8); iteration++) {
    const t0 = performance.now();
    for (const t of generateAttacks(env, current, { ...options.discovery, salt: (options.discovery?.salt ?? 'a') + iteration })) if (!attacks.has(t.id)) attacks.set(t.id, t);
    const all = [...attacks.values()];
    const attackBase = new Map(all.map(t => [t.id, replay(env, current, t)]));
    const vulns = all.filter(t => attackBase.get(t.id)!.completed);
    if (initial < 0) initial = vulns.length;
    if (vulns.length === 0) break;
    const legitBase = new Map(env.legit.map(t => [t.id, replay(env, current, t)]));
    const suite: Suite = { attacks: all, attackBase, legit: env.legit, legitBase };
    const usage = legitUsage(env, current);
    const groups = new Map<string, RootCause>();
    for (const t of vulns) { const rc = analyze(env, current, t, attackBase.get(t.id)!); if (!groups.has(signature(rc))) groups.set(signature(rc), rc); }
    const seen = new Set<string>();
    const evaluated: Array<Evaluation & { after: Record<string, unknown>; rc: RootCause; group: number }> = [];
    [...groups.values()].forEach((rc, group) => {
      const target = attacks.get(rc.traceId)!;
      for (const c of candidates(rc, current, usage)) {
        const key = digest(c.patch);
        if (seen.has(key)) continue;
        seen.add(key);
        evaluated.push({ ...evaluate(env, current, c, target, suite), rc, group });
      }
    });
    const eligible = evaluated.filter(e => e.valid && e.fixesTarget && e.securityRegressions === 0)
      .sort((a, b) => b.score - a.score || a.candidate.complexity - b.candidate.complexity || a.candidate.id.localeCompare(b.candidate.id));
    if (eligible.length === 0) break;
    const best = eligible[0];
    const target = attacks.get(best.rc.traceId)!;
    const { after, rc, group, ...chosen } = best;
    proposals.push({ id: `P${iteration}-${best.candidate.id}`, iteration, rootCause: rc, group, chosen,
      alternatives: eligible.slice(1, 6).map(({ after: _a, rc: _r, group: _g, ...e }) => e),
      before: current, after, certificate: certify(env, current, after, best.candidate.patch, target, all), latencyMs: Math.round(performance.now() - t0) });
    current = after;
  }
  const residual = [...attacks.values()].filter(t => replay(env, current, t).completed);
  return { environment: env.id, iterations: proposals.length, discovered: attacks.size, initialVulnerabilities: Math.max(0, initial),
    residual, proposals, finalPolicy: current, attacks: [...attacks.values()], latencyMs: Math.round(performance.now() - started) };
}
