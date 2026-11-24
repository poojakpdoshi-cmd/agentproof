import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { EvidenceLedger, parseJsonl, verifyLedger } from '../src/guard/ledger.ts';
import { summarize } from '../src/dashboard/summary.ts';
import type { Entry } from '../src/guard/ledger.ts';

const root = fileURLToPath(new URL('..', import.meta.url));
const run = (args: string[], env: Record<string, string> = {}) => spawnSync(process.execPath, args, { cwd: root, encoding: 'utf8', env: { ...process.env, ...env } });

test('A/B demo: unprotected run leaks, protected run blocks, legit work completes, evidence verifies', { timeout: 30000 }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'agentproof-demo-'));
  try {
    const out = run(['demo/attack-demo.ts', '--out', dir]);
    assert.equal(out.status, 0, out.stderr);
    assert.match(out.stdout, /SCENARIO A[\s\S]*1 email\(s\) carried the synthetic Stripe key/);
    assert.match(out.stdout, /BLOCK\s+send_email\s+audit-backup@evil-mail\.test/);
    assert.match(out.stdout, /0 exfiltration email\(s\); summary written: true; email to dana@corp\.test sent: true/);
    assert.match(out.stdout, /DECISION_EXECUTION_MISMATCH/);
    assert.match(out.stdout, /TAMPER TEST: .* DETECTED/);
    const evidence = readFileSync(path.join(dir, 'evidence.jsonl'), 'utf8');
    assert.ok(!evidence.includes('DEMO0SYNTHETIC'), 'synthetic key never enters evidence');
    const anchor = readFileSync(path.join(dir, 'anchor.txt'), 'utf8').trim();
    const key = Buffer.from('agentproof-demo-key-NOT-A-SECRET-0001'.slice(0, 32)).toString('hex');
    const verified = run(['src/verify-evidence.ts', path.join(dir, 'evidence.jsonl'), '--anchor', anchor, '--require-mac'], { AGENTPROOF_EVIDENCE_KEY: key });
    assert.equal(verified.status, 0, verified.stdout);
    writeFileSync(path.join(dir, 'evidence.jsonl'), evidence.replace('"decision":"BLOCK"', '"decision":"ALLOW"'));
    assert.equal(run(['src/verify-evidence.ts', path.join(dir, 'evidence.jsonl')]).status, 1);
    writeFileSync(path.join(dir, 'evidence.jsonl'), evidence.split('\n').slice(0, -3).join('\n') + '\n');
    assert.equal(run(['src/verify-evidence.ts', path.join(dir, 'evidence.jsonl')]).status, 0, 'truncation is invisible without an anchor');
    assert.equal(run(['src/verify-evidence.ts', path.join(dir, 'evidence.jsonl'), '--anchor', anchor]).status, 1, 'anchor exposes truncation');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('dashboard summary derives every figure from evidence and applies overrides', () => {
  const ledger = new EvidenceLedger({ clock: () => new Date('2026-11-24T00:00:00Z') });
  ledger.append('mandate', { mandate: 'm', agent: 'a', user: 'u', objective: 'o', expiresAt: 'x' });
  ledger.append('decision', { actionId: 'a1', decision: 'ALLOW', action: { tool: 'read_file', resource: 'r' }, risk: { score: 0, level: 'LOW', factors: [] }, reasons: [], threats: [], latencyMs: 0.2 });
  ledger.append('decision', { actionId: 'a2', decision: 'ALLOW', action: { tool: 'send_email' }, risk: { score: 15, level: 'LOW', factors: [] }, reasons: ['EXTERNAL_EGRESS'], threats: ['DATA_EXFILTRATION'], latencyMs: 0.4 });
  ledger.append('external-authorization', { actionId: 'a2', authorizer: 'ext', outcome: 'deny', code: 'X' });
  ledger.append('decision', { actionId: 'a3', decision: 'REQUIRE_APPROVAL', action: { tool: 'delete_file' }, risk: { score: 50, level: 'HIGH', factors: [] }, reasons: [], threats: [], latencyMs: 0.3 });
  ledger.append('approval', { actionId: 'a3', approver: 'h', approved: true });
  ledger.append('execution', { actionId: 'a3', status: 'ok' });
  ledger.append('binding-violation', { code: 'TOKEN_REPLAY' });
  const s = summarize(ledger.entries as Entry[], verifyLedger(ledger.entries), { file: 'e.jsonl', mode: 'TEST' });
  assert.deepEqual(s.totals, { evaluated: 3, allowed: 1, blocked: 1, approval: 0, approvedByHuman: 1, executed: 1, executionFailures: 0, bindingViolations: 1 });
  assert.deepEqual(s.threats, { DATA_EXFILTRATION: 1 });
  assert.equal(s.latency.decisions, 3);
  assert.equal(s.integrity.ok, true);
});

test('dashboard export cannot be broken out of by evidence content', { timeout: 15000 }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'agentproof-dash-'));
  try {
    const ledger = new EvidenceLedger({ file: path.join(dir, 'e.jsonl') });
    ledger.append('mandate', { mandate: 'm', agent: 'a', user: 'u', objective: '</script><script>alert(1)</script> ', expiresAt: 'x' });
    const out = run(['src/dashboard/server.ts', '--evidence', path.join(dir, 'e.jsonl'), '--export', path.join(dir, 'd.html')]);
    assert.equal(out.status, 0, out.stderr);
    const html = readFileSync(path.join(dir, 'd.html'), 'utf8');
    assert.ok(!html.includes('</script><script>alert'));
    const json = html.match(/<script type="application\/json" id="state">([\s\S]*?)<\/script>/)![1];
    assert.equal(JSON.parse(json).mandates[0].objective, '</script><script>alert(1)</script> ');
    assert.ok(verifyLedger(parseJsonl(readFileSync(path.join(dir, 'e.jsonl'), 'utf8')).values).ok);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
