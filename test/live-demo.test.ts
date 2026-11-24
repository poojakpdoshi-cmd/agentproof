import assert from 'node:assert/strict';
import test from 'node:test';
import { LocalAgent } from '../demo/local-agent.ts';
import { env } from '../demo/live-env.ts';
import { repair, verifyCertificate } from '../src/repair/engine.ts';
import { replay } from '../src/repair/replay.ts';
import { PolicyStore } from '../src/repair/store.ts';

test('live demo synthetic environment discovers and certifies a repair; only an operator applies it', () => {
  const report = repair(env);
  assert.ok(report.initialVulnerabilities > 0);
  assert.ok(report.proposals.length > 0);
  const store = new PolicyStore(env.mandate);
  for (const proposal of report.proposals) {
    const suite = report.attacks.filter(a => Object.hasOwn(proposal.certificate.security.before, a.id));
    assert.equal(verifyCertificate(proposal.certificate, env, proposal.before, suite).ok, true);
    store.propose(proposal);
    assert.equal(store.apply(proposal.id, 'live-agent').code, 'INVALID_APPROVER');
    assert.equal(store.apply(proposal.id, 'demo-operator').ok, true);
  }
  const attack = report.attacks.find(a => a.violation?.sink === 'write_file' && replay(env, env.mandate, a).completed);
  assert.ok(attack);
  assert.equal(replay(env, store.current.mandate, attack).completed, false);
  assert.equal(replay(env, store.current.mandate, env.legit[0]).completed, true);
});

test('local agent adapter fails closed without a model and rejects unsupported proposals (mock HTTP only)', async () => {
  const unavailable = new LocalAgent('local-test', async () => { throw new Error('offline'); });
  await assert.rejects(unavailable.preflight(), /not reachable/);
  const mock = new LocalAgent('local-test', async (url) => new Response(JSON.stringify(String(url).endsWith('/api/tags')
    ? { models: [{ name: 'local-test' }] }
    : { message: { content: JSON.stringify({ tool: 'send_email', arguments: { to: 'a@test.local', subject: 'x', body: 'x' } }) } }), { status: 200 }));
  await mock.preflight();
  await assert.rejects(mock.next('task', []), /unsupported tool action/);
});
