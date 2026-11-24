import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { parseJsonl, verifyLedger } from '../src/guard/ledger.ts';

const proxy = fileURLToPath(new URL('../src/mcp-proxy.ts', import.meta.url));
const dummy = fileURLToPath(new URL('../examples/dummy-mcp-server.ts', import.meta.url));
const FAKE_TOKEN = 'ghp_' + 'Q9w8E7r6'.repeat(5);

test('MCP proxy --mandate mode: intercepts, filters tool list, redacts output, writes verifiable evidence', { timeout: 20000 }, async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'agentproof-guard-proxy-'));
  const mandate = path.join(root, 'mandate.json'), evidence = path.join(root, 'evidence.jsonl'), journal = path.join(root, 'journal.jsonl');
  writeFileSync(mandate, JSON.stringify({ id: 'docs-task', subject: { agent: 'docs-agent', user: 'u1' }, objective: 'Read docs/dummy.txt and write notes to out/',
    expiresAt: '2099-01-01T00:00:00Z', allow: [{ tools: ['read_file'], resources: ['docs/', 'out/'] }, { tools: ['write_file'], resources: ['out/'] }],
    deny: [{ tools: ['*'], resources: ['private/'] }] }));
  const transport = new StdioClientTransport({ command: process.execPath, stderr: 'pipe',
    args: [proxy, '--mandate', mandate, '--evidence', evidence, '--', process.execPath, dummy, '--journal', journal] });
  transport.stderr?.resume();
  const client = new Client({ name: 'guard-test', version: '0' });
  try {
    await client.connect(transport, { timeout: 5000 });
    assert.deepEqual((await client.listTools()).tools.map(t => t.name).sort(), ['read_file', 'write_file'], 'network_request hidden');
    const read = await client.callTool({ name: 'read_file', arguments: { path: 'DOCS\\dummy.txt' } });
    assert.equal(read.isError, false);
    const denied = await client.callTool({ name: 'read_file', arguments: { path: 'private/secret.txt' } });
    assert.equal(denied.isError, true);
    assert.match(JSON.stringify(denied.content), /blocked EXPLICIT_DENY/);
    assert.equal((await client.callTool({ name: 'network_request', arguments: { url: 'https://api.example.test/health' } })).isError, true);
    assert.equal((await client.callTool({ name: 'write_file', arguments: { path: 'out/creds.txt', data: 'token ' + FAKE_TOKEN } })).isError, false);
    const leaked = await client.callTool({ name: 'read_file', arguments: { path: 'out/creds.txt' } });
    assert.ok(!JSON.stringify(leaked).includes(FAKE_TOKEN), 'secret redacted in relayed output');
    assert.match(JSON.stringify(leaked.content), /REDACTED:github-token/);
    await client.ping();
    const forwarded = readFileSync(journal, 'utf8').trim().split('\n').map(l => JSON.parse(l)).filter(v => v.method === 'tools/call').map(v => v.params.arguments.path ?? v.params.name);
    assert.deepEqual(forwarded, ['docs/dummy.txt', 'out/creds.txt', 'out/creds.txt'], 'only authorized calls reach upstream, in canonical form');
  } finally {
    await client.close();
    await transport.close();
  }
  const text = readFileSync(evidence, 'utf8');
  assert.ok(!text.includes(FAKE_TOKEN), 'evidence is redacted');
  const result = verifyLedger(parseJsonl(text).values);
  assert.ok(result.ok, JSON.stringify(result.issues));
  const decisions = parseJsonl(text).values.filter((e: any) => e.type === 'decision').map((e: any) => e.data.decision);
  assert.deepEqual(decisions, ['ALLOW', 'BLOCK', 'BLOCK', 'ALLOW', 'ALLOW']);
  rmSync(root, { recursive: true, force: true });
});

test('MCP proxy --mandate mode rejects invalid mandates before launching upstream', { timeout: 10000 }, async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'agentproof-guard-bad-'));
  const mandate = path.join(root, 'mandate.json'), marker = path.join(root, 'launched');
  writeFileSync(mandate, JSON.stringify({ id: 'x', subject: { agent: 'a', user: 'u' }, objective: 'o', expiresAt: 'never', allow: [] }));
  const { spawnSync } = await import('node:child_process');
  const run = spawnSync(process.execPath, [proxy, '--mandate', mandate, '--', process.execPath, '-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, '1')`], { input: '' });
  assert.equal(run.status, 2);
  assert.throws(() => readFileSync(marker));
  rmSync(root, { recursive: true, force: true });
});
