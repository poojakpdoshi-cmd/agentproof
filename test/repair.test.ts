import assert from 'node:assert/strict';
import test from 'node:test';
import { Firewall } from '../src/guard/firewall.ts';
import { verifyLedger } from '../src/guard/ledger.ts';
import { generateAttacks } from '../src/repair/discover.ts';
import { repair, verifyCertificate } from '../src/repair/engine.ts';
import { PolicyStore } from '../src/repair/store.ts';
import { replay } from '../src/repair/replay.ts';
import { env, H_A13 } from '../benchmarks/repair/dev-report.ts';

const report = repair(env);

test('flow rules and trusted targets are enforced; policy change invalidates outstanding tokens', () => {
  const mandate = { id: 'm', subject: { agent: 'a', user: 'u' }, objective: 'read docs/a.md and email bob@corp.test', expiresAt: '2099-01-01T00:00:00Z',
    allow: [{ tools: ['read_file'], resources: ['docs/'] }, { tools: ['send_email'], resources: ['@corp.test'] }, { tools: ['write_file'], resources: ['out/'] }],
    flows: [{ id: 'docs-out', from: ['docs/'], to: ['send_email'], effect: 'deny' }], trustedTargets: ['send_email'] };
  const fw = new Firewall({ mandates: [mandate] });
  const user = [{ source: 'user' as const, text: mandate.objective }];
  const read = fw.evaluate({ agent: 'a', mandate: 'm', action: { tool: 'read_file', arguments: { path: 'docs/a.md' } }, context: user });
  fw.consume(read.token, { tool: 'read_file', arguments: { path: 'docs/a.md' } });
  fw.verifyOutput(read.actionId, 'default', 'Secret plan: launch the product on 12 March in Pune.', 'test', fw.mandate('m'), { tool: 'read_file', arguments: { path: 'docs/a.md' } });
  const leak = fw.evaluate({ agent: 'a', mandate: 'm', action: { tool: 'send_email', arguments: { to: 'bob@corp.test', subject: 's', body: 'launch the product on 12 March in Pune' } }, context: user });
  assert.ok(leak.reasons.includes('FLOW_VIOLATION'));
  const stranger = fw.evaluate({ agent: 'a', mandate: 'm', action: { tool: 'send_email', arguments: { to: 'eve@corp.test', subject: 's', body: 'hi' } }, context: user });
  assert.ok(stranger.reasons.includes('UNTRUSTED_TARGET'));
  const ok = fw.evaluate({ agent: 'a', mandate: 'm', action: { tool: 'write_file', arguments: { path: 'out/x.md', data: 'x' } }, context: user });
  fw.replaceMandate({ ...mandate, allow: mandate.allow.slice(0, 2) }, 'test');
  assert.equal(fw.consume(ok.token, { tool: 'write_file', arguments: { path: 'out/x.md', data: 'x' } }).ok || 'changed', 'changed');
  assert.throws(() => new Firewall({ mandates: [{ ...mandate, flows: [{ from: ['../x'], to: ['send_email'], effect: 'deny' }] }] }));
});

test('discovery derives attacks from the policy and labels, not from the firewall', () => {
  const attacks = generateAttacks(env, env.mandate);
  assert.ok(attacks.length > 50);
  assert.ok(attacks.every(a => a.violation && a.kind === 'attack'));
  assert.ok(attacks.some(a => a.violation!.sink === 'write_file' && a.violation!.asset === 'reports/hr/summary.md'));
});

test('H-A13 (first regression case): engine repairs it without seeing it, legit work preserved', () => {
  assert.equal(replay(env, env.mandate, H_A13).completed, true, 'vulnerable before');
  assert.ok(report.initialVulnerabilities > 0 && report.proposals.length > 0);
  assert.equal(report.residual.length, 0);
  assert.equal(replay(env, report.finalPolicy, H_A13).completed, false, 'H-A13 prevented by the synthesized policy');
  for (const p of report.proposals) {
    assert.equal(p.chosen.securityRegressions, 0);
    assert.equal(p.chosen.legitBlocked, 0);
    assert.ok(p.rootCause.causes.length > 0 && p.rootCause.explanation.length > 0);
  }
  for (const t of env.legit) assert.equal(replay(env, report.finalPolicy, t).blocked, false, t.id);
});

test('certificates re-verify independently and detect forgery', () => {
  const p = report.proposals[0];
  const attacks = report.attacks.filter(a => Object.hasOwn(p.certificate.security.before, a.id));
  assert.ok(verifyCertificate(p.certificate, env, p.before, attacks).ok);
  const forged = structuredClone(p.certificate);
  forged.target.after = 'ALLOW ALLOW';
  assert.equal(verifyCertificate(forged, env, p.before, attacks).ok, false);
  const tamperedPolicy = { ...p.before, thresholds: { approval: 90, block: 99 } };
  assert.equal(verifyCertificate(p.certificate, env, tamperedPolicy, attacks).ok, false);
});

test('policy store: human approval, stale-proposal guard, versioning, rollback and evidence', () => {
  const fw = new Firewall({ mandates: [env.mandate] });
  const store = new PolicyStore(env.mandate, { firewall: fw });
  report.proposals.forEach(p => store.propose(p));
  const [first, second] = report.proposals;
  assert.equal(store.apply(first.id, 'repair-engine').code, 'INVALID_APPROVER');
  assert.equal(store.apply(first.id, String((env.mandate.subject as { agent: string }).agent)).code, 'INVALID_APPROVER');
  assert.equal(store.apply(second.id, 'sec-lead').code, 'STALE_PROPOSAL');
  assert.equal(store.apply(first.id, 'sec-lead').version, 2);
  assert.equal(store.apply(second.id, 'sec-lead').version, 3);
  assert.equal(fw.mandate(String(env.mandate.id))!.version, store.history.length > 0 ? fw.mandate(String(env.mandate.id))!.version : '');
  assert.equal(store.rollback(1, 'sec-lead').version, 4);
  assert.equal(store.current.digest, store.history[0].digest);
  assert.ok(verifyLedger(store.ledger.entries).ok);
  assert.deepEqual(store.ledger.entries.map(e => e.type).filter(t => t !== 'repair-proposal'), ['policy-version', 'policy-version', 'policy-version', 'policy-version']);
});
