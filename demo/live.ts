#!/usr/bin/env node
// Real local-model agent, synthetic in-memory tools. Requires an installed Ollama model and
// a human terminal approval. No model responses or approvals are scripted.
import { mkdirSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { Firewall } from '../src/guard/firewall.ts';
import type { ToolAction } from '../src/guard/firewall.ts';
import { EvidenceLedger, verifyLedger } from '../src/guard/ledger.ts';
import { repair, verifyCertificate } from '../src/repair/engine.ts';
import { replay } from '../src/repair/replay.ts';
import { PolicyStore } from '../src/repair/store.ts';
import { env, OBJECTIVE, PRIVATE } from './live-env.ts';
import { LocalAgent } from './local-agent.ts';
import type { Observation } from './local-agent.ts';

const option = (key: string) => process.argv.includes(key) ? process.argv[process.argv.indexOf(key) + 1] : undefined;
const modelName = option('--model') ?? process.env.AGENTPROOF_OLLAMA_MODEL;
if (!modelName || process.argv.includes('--help')) {
  console.log('Usage: npm run demo:live -- --model INSTALLED_OLLAMA_MODEL [--out DIR]');
  process.exit(modelName ? 0 : 2);
}

type Workspace = Map<string, string>;
const workspace = (): Workspace => new Map(env.assets.map(a => [a.path, a.content]));
function tool(ws: Workspace, action: ToolAction): string {
  if (action.tool === 'read_file') return ws.get(String(action.arguments.path)) ?? 'not found';
  if (action.tool === 'write_file') { ws.set(String(action.arguments.path), String(action.arguments.data)); return 'written'; }
  throw new Error('Unsupported demo tool');
}
const firewall = (ws: Workspace, ledger: EvidenceLedger) => new Firewall({ mandates: [env.mandate], ledger,
  executor: { name: 'synthetic-memory', execute: async action => ({ content: [{ type: 'text', text: tool(ws, action) }] }) } });

async function run(agent: LocalAgent, ws: Workspace, fw?: Firewall): Promise<{ observations: Observation[]; modelTurns: Array<{ response: string; latencyMs: number }>; elapsedMs: number; stopped: string; summary: boolean; exactPrivateCopy: boolean }> {
  const started = performance.now();
  const observations: Observation[] = [];
  const modelTurns: Array<{ response: string; latencyMs: number }> = [];
  let stopped = 'step limit';
  for (let i = 0; i < 8; i++) {
    const next = await agent.next(OBJECTIVE, observations);
    modelTurns.push({ response: next.response, latencyMs: next.latencyMs });
    if (next.done) { stopped = 'model finished'; break; }
    const action = next.action;
    let result: string, decision: string;
    if (fw) {
      const verdict = fw.evaluate({ agent: 'live-agent', mandate: String(env.mandate.id), session: 'live-agent', action,
        context: [{ source: 'user', text: OBJECTIVE }] });
      decision = verdict.decision;
      if (verdict.token) {
        const execution = await fw.execute(verdict.token, action);
        result = execution.ok ? String((execution.output as { content: Array<{ text: string }> }).content[0].text) : `AgentProof execution refused: ${execution.code}`;
      } else result = `AgentProof ${verdict.decision}: action not executed`;
    } else { decision = 'UNPROTECTED'; result = tool(ws, action); }
    observations.push({ action, decision, result: result.slice(0, 4096) });
  }
  return { observations, modelTurns, elapsedMs: Math.round(performance.now() - started), stopped, summary: ws.has('out/summary.md'),
    exactPrivateCopy: [...ws].some(([name, value]) => name.startsWith('out/') && name !== 'out/summary.md' && value.includes(PRIVATE)) };
}

try {
  const agent = new LocalAgent(modelName);
  await agent.preflight();
  const report = repair(env);
  if (report.proposals.length === 0 || report.residual.length) throw new Error('Demo environment did not produce a complete repair');
  const certificates = report.proposals.map(p => verifyCertificate(p.certificate, env, p.before,
    report.attacks.filter(a => Object.hasOwn(p.certificate.security.before, a.id))));
  if (certificates.some(c => !c.ok)) throw new Error('Repair certificate verification failed');
  console.log(`Model: ${agent.source}; discovered ${report.initialVulnerabilities} controlled vulnerabilities; proposed ${report.proposals.length} repair(s).`);
  const plain = await run(agent, workspace());
  const beforeWs = workspace(), beforeLedger = new EvidenceLedger();
  const baseline = await run(agent, beforeWs, firewall(beforeWs, beforeLedger));

  if (!process.stdin.isTTY) throw new Error('An interactive operator terminal is required to approve the repair');
  const fixedWs = workspace(), fixedLedger = new EvidenceLedger();
  const fixedFirewall = firewall(fixedWs, fixedLedger);
  const store = new PolicyStore(env.mandate, { firewall: fixedFirewall, ledger: fixedLedger });
  report.proposals.forEach(p => store.propose(p));
  const input = createInterface({ input: process.stdin, output: process.stdout });
  try {
    for (const proposal of report.proposals) {
      console.log(`Repair ${proposal.id}: ${proposal.chosen.candidate.summary}`);
      console.log(`Certificate ${proposal.certificate.digest}; fixes ${proposal.chosen.vulnerabilitiesFixed}, legitimate blocked ${proposal.chosen.legitBlocked}.`);
      const answer = await input.question(`Type APPROVE ${proposal.id} to apply as demo-operator: `);
      if (answer.trim() !== `APPROVE ${proposal.id}`) throw new Error('Operator did not approve the repair');
      const applied = store.apply(proposal.id, 'demo-operator');
      if (!applied.ok) throw new Error(`Repair application failed: ${applied.code}`);
    }
  } finally { input.close(); }
  const protectedRun = await run(agent, fixedWs, fixedFirewall);
  const attack = report.attacks.find(a => a.violation?.sink === 'write_file' && replay(env, env.mandate, a).completed);
  if (!attack) throw new Error('No replayable vulnerable attack found');
  const replayBefore = replay(env, env.mandate, attack), replayAfter = replay(env, store.current.mandate, attack);
  const legitimateBefore = replay(env, env.mandate, env.legit[0]), legitimateAfter = replay(env, store.current.mandate, env.legit[0]);
  const evidenceOk = verifyLedger(fixedLedger.entries).ok;
  if (!evidenceOk) throw new Error('Live evidence verification failed');

  const out = path.resolve(option('--out') ?? 'docs/demo/live');
  mkdirSync(out, { recursive: true });
  writeFileSync(path.join(out, 'baseline-evidence.jsonl'), beforeLedger.toJsonl());
  const evidence = path.join(out, 'repaired-evidence.jsonl');
  writeFileSync(evidence, fixedLedger.toJsonl());
  const result = { kind: 'REAL LOCAL LLM; SYNTHETIC IN-MEMORY TOOLS', model: agent.source, objective: OBJECTIVE,
    discovered: report.initialVulnerabilities, proposals: report.proposals.map(p => ({ id: p.id, operator: p.chosen.candidate.operator, certificate: p.certificate.digest })),
    certificatesVerified: certificates.length, operator: 'demo-operator', policyVersion: store.current.n,
    runs: { unprotected: plain, baselineGuard: baseline, repairedGuard: protectedRun },
    replay: { attackId: attack.id, attackCompletedBefore: replayBefore.completed, attackCompletedAfter: replayAfter.completed,
      legitimateCompletedBefore: legitimateBefore.completed, legitimateCompletedAfter: legitimateAfter.completed }, evidenceVerified: evidenceOk };
  writeFileSync(path.join(out, 'result.json'), JSON.stringify(result, null, 2) + '\n');
  writeFileSync(path.join(out, 'repair-report.json'), JSON.stringify(report, null, 2) + '\n');
  const exportPath = path.join(out, 'dashboard.html');
  const exportRun = spawnSync(process.execPath, [fileURLToPath(new URL('../src/dashboard/server.ts', import.meta.url)), '--evidence', evidence,
    '--export', exportPath, '--mode', 'LIVE LOCAL LLM · SYNTHETIC TOOLS'], { encoding: 'utf8' });
  if (exportRun.status !== 0) throw new Error('Dashboard export failed');
  console.log(JSON.stringify({ model: agent.source, discovered: report.initialVulnerabilities, certificatesVerified: certificates.length,
    unprotected: { exactPrivateCopy: plain.exactPrivateCopy, summary: plain.summary, actions: plain.observations.length },
    baselineGuard: { exactPrivateCopy: baseline.exactPrivateCopy, summary: baseline.summary, actions: baseline.observations.length },
    repairedGuard: { exactPrivateCopy: protectedRun.exactPrivateCopy, summary: protectedRun.summary, actions: protectedRun.observations.length },
    replay: result.replay, evidenceVerified: evidenceOk, dashboard: exportPath }, null, 2));
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Live demo failed');
  process.exitCode = 1;
}
