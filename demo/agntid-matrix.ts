#!/usr/bin/env node
// Live-only AgntID scenario matrix. No mock fallback, no model-provider call.
// Usage: AGNTID_MCP_URL=http://localhost:8082/mcp AGNTID_AGENT_ID=... AGNTID_USER_ID=... \
//        node demo/agntid-matrix.ts --out docs/agntid-live/run-1
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { connectRuntime } from '../src/integrations/agntid.ts';
import { runMatrix, sanitize, TOOL } from '../src/integrations/agntid-matrix.ts';

const url = process.env.AGNTID_MCP_URL ?? 'http://localhost:8082/mcp';
const agentId = process.env.AGNTID_AGENT_ID;
const userId = process.env.AGNTID_USER_ID;
const health = process.env.AGNTID_HEALTH_URL ?? 'http://localhost:8080/health';
const i = process.argv.indexOf('--out');
const out = i >= 0 && process.argv[i + 1] ? path.resolve(process.argv[i + 1]) : undefined;
if (!agentId || !userId) {
  console.error('Set AGNTID_AGENT_ID and AGNTID_USER_ID (and AGNTID_ACCESS_TOKEN if the runtime requires OAuth).');
  process.exit(2);
}

async function main() {
  const startedAt = new Date().toISOString();
  const healthStatus = await fetch(health).then(r => r.status).catch(() => 0);
  const caller = await connectRuntime(url, { accessToken: process.env.AGNTID_ACCESS_TOKEN, timeoutMs: 30_000 });
  try {
    const tools = await caller.listTools();
    const results = await runMatrix(caller, { agentId: agentId!, userId: userId! });
    const run = { kind: 'LIVE AGNTID RUNTIME (observed, not simulated)', startedAt, finishedAt: new Date().toISOString(),
      runtime: { mcpUrl: url, healthStatus, toolsVisible: tools.map(t => sanitize(t, 80)), starterVisible: tools.includes(TOOL),
        oauthTokenUsed: Boolean(process.env.AGNTID_ACCESS_TOKEN) },
      identity: { agentId: sanitize(agentId, 80), userId: sanitize(userId, 80) }, results };
    const json = JSON.stringify(run, null, 2) + '\n';
    if (out) { mkdirSync(out, { recursive: true }); writeFileSync(path.join(out, 'matrix.json'), json); }
    console.log(json);
    console.log('\nSUMMARY  id | expected | AgentProof | AgntID outcome (code) | correlation');
    for (const r of results as Record<string, any>[]) {
      const d = r.agntid?.decision;
      console.log(`${r.id} | ${r.expected} | ${r.agentproof?.decision ?? '-'} | ${r.error ? 'ERROR ' + r.error : (d ? `${d.outcome ?? d.error} (${d.code || d.reason || ''})` : (r.agntid?.isError ? 'error ' + r.agntid.result : 'no decision'))} | ${d?.correlationId ?? ''}`);
    }
  } finally { await caller.close(); }
}

main().catch(error => { console.error(sanitize(error instanceof Error ? error.message : error)); process.exitCode = 1; });
