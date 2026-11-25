#!/usr/bin/env node
// Live-only starter smoke. No mock fallback and no model-provider call.
import { AgntidError, AgntidRuntime, connectRuntime } from '../src/integrations/agntid.ts';
import type { AgntidDecision } from '../src/integrations/agntid.ts';
import { mkdirSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Firewall } from '../src/guard/firewall.ts';
import type { Contract } from '../src/guard/contracts.ts';
import { verifyLedger } from '../src/guard/ledger.ts';
import { repair, verifyCertificate } from '../src/repair/engine.ts';
import { replay } from '../src/repair/replay.ts';
import { env } from './live-env.ts';

const url = process.env.AGNTID_MCP_URL;
const agentId = process.env.AGNTID_AGENT_ID;
const userId = process.env.AGNTID_USER_ID;
const outIndex = process.argv.indexOf('--out');
const out = outIndex >= 0 && process.argv[outIndex + 1] ? path.resolve(process.argv[outIndex + 1]) : undefined;
if (!url || !agentId || !userId) {
  console.error('Set AGNTID_MCP_URL, AGNTID_AGENT_ID and AGNTID_USER_ID for a registered live runtime. See PHASE7_AGNTID_READINESS.md.');
  process.exit(2);
}

const objective = 'Add 11 and 22 using demo_add_numbers.';
const contract: Contract = { tool: 'demo_add_numbers', effect: 'read', resource: { arg: 'target', kind: 'principal' },
  args: { target: { type: 'string', required: true }, first_number: { type: 'number', required: true },
    second_number: { type: 'number', required: true } }, data: [] };
const mandate = { id: 'agntid-starter', subject: { agent: agentId, user: userId }, objective,
  expiresAt: '2099-01-01T00:00:00Z', allow: [{ id: 'starter-only', tools: ['demo_add_numbers'], resources: ['starter'] }] };
const action = { tool: 'demo_add_numbers', arguments: { target: 'starter', first_number: 11, second_number: 22 } };

async function main() {
  const report = repair(env);
  const certificatesVerified = report.proposals.length > 0 && report.proposals.every(p => verifyCertificate(p.certificate, env, p.before,
    report.attacks.filter(a => Object.hasOwn(p.certificate.security.before, a.id))).ok);
  const attack = report.attacks.find(a => a.violation?.sink === 'write_file' && replay(env, env.mandate, a).completed);
  const attackBefore = attack ? replay(env, env.mandate, attack).completed : false;
  const attackAfter = attack ? replay(env, report.finalPolicy, attack).completed : true;
  const legitimateAfter = replay(env, report.finalPolicy, env.legit[0]).completed;
  const discoveryVerified = report.initialVulnerabilities > 0 && certificatesVerified && report.residual.length === 0
    && attackBefore && !attackAfter && legitimateAfter;
  const caller = await connectRuntime(url!, { accessToken: process.env.AGNTID_ACCESS_TOKEN });
  const runtime = new AgntidRuntime(caller, { agentId: agentId!, userId: userId! });
  try {
    const tools = await caller.listTools();
    if (!tools.includes('demo_add_numbers')) throw new Error('Official starter tool demo_add_numbers is not visible; enable and approve it in the runtime portal');
    const task = await runtime.openTask(objective);
    if (!task.ok || !task.intentPrepared || !task.relevantTools?.includes('demo_add_numbers')) {
      throw new Error(`AgntID task intent unavailable: ${task.reason || task.intentReason || 'starter tool not shortlisted'}`);
    }
    let runtimeDecision: Pick<AgntidDecision, 'outcome' | 'code' | 'policyName' | 'correlationId'> | null = null;
    const summarize = (decision: AgntidDecision) => ({ outcome: decision.outcome, code: decision.code,
      policyName: decision.policyName, correlationId: decision.correlationId });
    const firewall = new Firewall({ mandates: [mandate], contracts: { demo_add_numbers: contract },
      authorizer: runtime.authorizer(), executor: { name: 'agntid-starter', execute: async proposed => {
        // `target` is the local reviewed contract resource; only the official tool schema reaches AgntID.
        try {
          const call = await runtime.callTool({ tool: proposed.tool,
            arguments: { first_number: proposed.arguments.first_number, second_number: proposed.arguments.second_number } });
          runtimeDecision = call.decision ? summarize(call.decision) : null;
          if (!call.decision) throw new AgntidError('AUTHZ_UNAVAILABLE', { reason: 'missing structured runtime decision' });
          return call.result;
        } catch (error) {
          if (error instanceof AgntidError && typeof error.details.outcome === 'string') {
            runtimeDecision = { outcome: error.details.outcome as AgntidDecision['outcome'],
              code: String(error.details.code ?? ''), policyName: String(error.details.policyName ?? ''),
              correlationId: String(error.details.correlationId ?? '') };
          }
          throw error;
        }
      } } });
    const verdict = await firewall.decide({ agent: agentId!, mandate: mandate.id, action,
      context: [{ source: 'user', text: objective }] });
    const executed = verdict.token ? await firewall.execute(verdict.token, action) : null;
    const observedDecision = runtimeDecision as Pick<AgntidDecision, 'outcome' | 'code' | 'policyName' | 'correlationId'> | null;
    const returnedText = executed?.ok ? JSON.stringify(executed.output) : '';
    let dashboardExported: boolean | null = null;
    if (out) {
      mkdirSync(out, { recursive: true });
      const evidence = path.join(out, 'evidence.jsonl');
      writeFileSync(evidence, firewall.ledger.toJsonl());
      writeFileSync(path.join(out, 'certificates.json'), JSON.stringify(report.proposals.map(p => p.certificate), null, 2) + '\n');
      const dashboard = spawnSync(process.execPath,
        [fileURLToPath(new URL('../src/dashboard/server.ts', import.meta.url)), '--evidence', evidence,
          '--export', path.join(out, 'dashboard.html'), '--mode', 'LIVE AGNTID RUNTIME'], { encoding: 'utf8' });
      dashboardExported = dashboard.status === 0;
    }
    const result = { kind: 'LIVE AGNTID RUNTIME', discovery: { initialVulnerabilities: report.initialVulnerabilities,
      proposals: report.proposals.length, certificateDigests: report.proposals.map(p => p.certificate.digest), certificatesVerified, residual: report.residual.length,
      attackBefore, attackAfter, legitimateAfter, discoveryVerified },
    agntid: { taskId: runtime.taskId, intentSnapshot: task.snapshotId, taskPrepared: task.intentPrepared,
      relevantTool: true, localDecision: verdict.decision, localReasons: verdict.reasons,
      runtimeDecision: observedDecision, execution: executed?.ok ? 'ok' : executed?.code ?? 'not attempted',
      sum33Observed: /\b33\b/.test(returnedText), evidenceVerified: verifyLedger(firewall.ledger.entries).ok,
      dashboardExported } };
    console.log(JSON.stringify(result, null, 2));
    if (out) writeFileSync(path.join(out, 'result.json'), JSON.stringify(result, null, 2) + '\n');
    if (!discoveryVerified || !executed?.ok || observedDecision?.outcome !== 'allow' || !result.agntid.sum33Observed
      || dashboardExported === false) process.exitCode = 1;
  } finally {
    await runtime.closeTask();
    await caller.close();
  }
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : 'Live AgntID check failed');
  process.exitCode = 1;
});
