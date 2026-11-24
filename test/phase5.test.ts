import assert from 'node:assert/strict';
import test from 'node:test';
import { Firewall } from '../src/guard/firewall.ts';
import { repair, verifyCertificate } from '../src/repair/engine.ts';
import { replay } from '../src/repair/replay.ts';
import type { Environment } from '../src/repair/types.ts';
import { PHASE5_CASES } from '../benchmarks/validation/phase5-cases.ts';

test('frozen classification and lineage cases stop attacks and complete authorized tasks', () => {
  for (const c of PHASE5_CASES) {
    for (const trace of c.attacks) assert.equal(replay(c.env, c.env.mandate, trace).completed, false, trace.id);
    for (const trace of [...c.env.legit, ...c.legitHoldout]) assert.equal(replay(c.env, c.env.mandate, trace).completed, true, trace.id);
  }
});

test('classification and declassification metadata is operator controlled and exact', () => {
  const base = PHASE5_CASES[1].env.mandate;
  assert.throws(() => new Firewall({ mandates: [{ ...base, classifications: [{ resource: 'private/staff.txt', class: 'public', confidence: 2, authority: 'operator' }] }] }));
  assert.throws(() => new Firewall({ mandates: [{ ...base, classifications: [{ resource: 'private/staff.txt', class: 'public', confidence: 1, authority: 'agent' }] }] }));
  assert.throws(() => new Firewall({ mandates: [{ ...base, declassifications: [{ from: ['private/staff.txt'], tools: ['write_file'], resources: ['out/'], effect: 'allow' }] }] }));
});

test('repair composes classification and lineage without losing a legitimate summary; certificate replays', () => {
  const objective = 'Read private/a.txt and summarize to out/summary.md';
  const env: Environment = { id: 'phase5-repair-dev', description: 'Development integration case',
    mandate: { id: 'phase5-repair-dev', subject: { agent: 'a', user: 'u' }, objective, expiresAt: '2099-01-01T00:00:00Z',
      allow: [{ tools: ['read_file'], resources: ['private/a.txt'] }, { tools: ['write_file'], resources: ['out/'] }] },
    assets: [{ path: 'private/a.txt', content: 'Strategic hiring decisions will change the west-region team next year.', class: 'confidential' }],
    legit: [{ id: 'summary', kind: 'legit', context: [{ source: 'user', text: objective }],
      steps: [{ tool: 'read_file', arguments: { path: 'private/a.txt' }, approved: true },
        { tool: 'write_file', arguments: { path: 'out/summary.md', data: 'Staff planning is underway.' } }] }] };
  const result = repair(env);
  assert.ok(result.proposals.some(p => p.chosen.candidate.patch.some(op => op.path === '/enforceLineage')));
  assert.ok(result.proposals.some(p => p.chosen.candidate.patch.some(op => op.path === '/classifications')));
  assert.equal(replay(env, result.finalPolicy, env.legit[0]).completed, true);
  for (const proposal of result.proposals) {
    const attacks = result.attacks.filter(a => Object.hasOwn(proposal.certificate.security.before, a.id));
    assert.equal(verifyCertificate(proposal.certificate, env, proposal.before, attacks).ok, true);
  }
});
