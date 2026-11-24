import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { Firewall } from '../src/guard/firewall.ts';
import { generateAttacks } from '../src/repair/discover.ts';
import { repair, verifyCertificate } from '../src/repair/engine.ts';
import { replay } from '../src/repair/replay.ts';
import type { Trace } from '../src/repair/types.ts';
import { CASES } from '../benchmarks/validation/phase6_3-cases.ts';
import { CASES as LIVE_CASES } from '../demo/live-validation-cases.ts';

test('archived Phase 6.2 public write is blocked after intent repair; old certificate remains valid', () => {
  const selected = LIVE_CASES.find(c => c.id === 'injecagent')!;
  const archive = JSON.parse(readFileSync(new URL('../docs/demo/phase6.2/suite.json', import.meta.url), 'utf8'));
  const oldReport = JSON.parse(readFileSync(new URL('../docs/demo/phase6.2/injecagent/repair-report.json', import.meta.url), 'utf8'));
  const actions = archive.results.find((c: { id: string }) => c.id === selected.id).modes.repaired.events;
  const trace: Trace = { id: 'archived-live-write', kind: 'attack', context: [{ source: 'user', text: String(selected.environment.mandate.objective) }],
    steps: actions.map((e: { action: { tool: string; arguments: Record<string, unknown> } }) => e.action),
    violation: { property: 'unauthorized-destination', family: 'destination-hijack', sink: 'write_file', target: selected.unauthorizedWrite } };
  assert.equal(replay(selected.environment, oldReport.finalPolicy, trace).completed, true);
  for (const p of oldReport.proposals) {
    const suite = oldReport.attacks.filter((a: { id: string }) => Object.hasOwn(p.certificate.security.before, a.id));
    assert.equal(verifyCertificate(p.certificate, selected.environment, p.before, suite).ok, true);
  }
  const fixed = repair(selected.environment);
  const after = replay(selected.environment, fixed.finalPolicy, trace);
  assert.equal(after.completed, false);
  assert.ok(after.steps.some(step => step.reasons.includes('UNTRUSTED_TARGET')));
  assert.equal(replay(selected.environment, fixed.finalPolicy, selected.environment.legit[0]).completed, true);
});

test('fresh public-data destinations are discovered, repaired, and certified without narrowing legitimate files', () => {
  for (const selected of CASES.filter(c => c.unauthorized.length > 0)) {
    const discovered = generateAttacks(selected.env, selected.env.mandate);
    assert.ok(discovered.some(t => t.violation?.property === 'unauthorized-destination'));
    const report = repair(selected.env);
    assert.ok((report.finalPolicy.trustedTargets as string[]).includes('write_file'));
    assert.equal(report.residual.length, 0);
    for (const trace of selected.unauthorized) {
      assert.equal(replay(selected.env, selected.env.mandate, trace).completed, true);
      assert.equal(replay(selected.env, report.finalPolicy, trace).completed, false);
    }
    for (const trace of selected.authorized) assert.equal(replay(selected.env, report.finalPolicy, trace).completed, true);
    for (const p of report.proposals) {
      const suite = report.attacks.filter(a => Object.hasOwn(p.certificate.security.before, a.id));
      assert.equal(verifyCertificate(p.certificate, selected.env, p.before, suite).ok, true);
    }
  }
});

test('trusted directory intent permits multiple writes; untrusted scopes and path-prefix tricks do not', () => {
  const selected = CASES.find(c => c.id === 'directory-wide')!;
  const strict = { ...selected.env.mandate, trustedTargets: ['write_file'] };
  for (const trace of selected.authorized) assert.equal(replay(selected.env, strict, trace).completed, true);
  assert.equal(generateAttacks(selected.env, strict).some(t => t.violation?.property === 'unauthorized-destination'), false);
  assert.throws(() => new Firewall({ mandates: [{ ...strict, intentScopes: [{ tools: ['write_file'], resources: ['reports/'], authority: 'agent' }] }] }));
  const exact = CASES.find(c => c.id === 'market-note')!;
  const expected = String(exact.authorized[0].steps[1].arguments.path);
  const suffix: Trace = { id: 'suffix', kind: 'attack', context: exact.authorized[0].context,
    steps: [{ tool: 'write_file', arguments: { path: `${expected}.bak`, data: 'public' } }] };
  assert.equal(replay(exact.env, { ...exact.env.mandate, trustedTargets: ['write_file'] }, suffix).completed, false);
});
