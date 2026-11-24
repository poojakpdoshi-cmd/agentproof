import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const root = mkdtempSync(path.join(tmpdir(), 'agentproof-latency-'));
const proxy = fileURLToPath(new URL('../src/mcp-proxy.ts', import.meta.url));
const server = fileURLToPath(new URL('../test/fixtures/sdk-server.ts', import.meta.url));
const policy = path.join(root, 'policy.json');
writeFileSync(policy, JSON.stringify({ read: ['docs/'] }));
const clients: Client[] = [];
try {
  for (const name of ['direct', 'proxied']) {
    const args = [server, path.join(root, name + '.jsonl')];
    const transport = new StdioClientTransport({ command: process.execPath, stderr: 'pipe',
      args: name === 'direct' ? args : [proxy, '--policy', policy, '--', process.execPath, ...args] });
    (transport.stderr as NodeJS.ReadableStream | null)?.resume();
    const client = new Client({ name: 'dummy-benchmark', version: '0' });
    clients.push(client);
    await client.connect(transport, { timeout: 5000 });
  }
  const call = async (client: Client) => {
    const result = await client.callTool({ name: 'read_file', arguments: { path: 'docs/dummy.txt' } });
    assert.equal(result.isError, false);
  };
  for (const client of clients) for (let i = 0; i < 10; i++) await call(client);
  const samples: number[][] = [[], []];
  for (let i = 0; i < 100; i++) for (let j = 0; j < 2; j++) {
    const index = (i + j) % 2;
    const start = performance.now();
    await call(clients[index]);
    samples[index].push(performance.now() - start);
  }
  const stats = samples.map(values => {
    const sorted = [...values].sort((a, b) => a - b);
    return { medianMs: (sorted[49] + sorted[50]) / 2, p95Ms: sorted[94], minMs: sorted[0], maxMs: sorted[99], samplesMs: values };
  });
  const result = { measuredOn: '2026-11-22', node: process.version, sdk: '1.32.2',
    methodology: '100 sequential reads per route after 10 warmups; paired alternating order; same official SDK server and dummy journal; startup excluded; not a Microsoft transport comparison',
    direct: stats[0], proxied: stats[1], medianDeltaMs: stats[1].medianMs - stats[0].medianMs };
  mkdirSync(new URL('../docs/', import.meta.url), { recursive: true });
  writeFileSync(new URL('../docs/phase3-stdio.json', import.meta.url), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({ directMedianMs: stats[0].medianMs, proxyMedianMs: stats[1].medianMs, medianDeltaMs: result.medianDeltaMs,
    directP95Ms: stats[0].p95Ms, proxyP95Ms: stats[1].p95Ms }));
} finally {
  for (const client of clients) await client.close();
  rmSync(root, { recursive: true, force: true });
}
