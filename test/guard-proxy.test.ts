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
    deny: [{ tools: ['*'], resources: ['private/'] }],
    // Default approval threshold (40) would hold the credential write for review; this test
    // raises it so the write reaches upstream and output redaction can be observed.
    thresholds: { approval: 45, block: 70 } }));
  const transport = new StdioClientTransport({ command: process.execPath, stderr: 'pipe',
    args: [proxy, '--mandate', mandate, '--evidence', evidence, '--', process.execPath, dummy, '--journal', journal] });
  (transport.stderr as NodeJS.ReadableStream | null)?.resume();
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

test('MCP proxy --approvals: REQUIRE_APPROVAL calls are held until a human approves or rejects', { timeout: 20000 }, async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'agentproof-approvals-'));
  const mandate = path.join(root, 'mandate.json'), journal = path.join(root, 'journal.jsonl');
  const port = 41000 + Math.floor(Math.random() * 2000);
  writeFileSync(mandate, JSON.stringify({ id: 'held', subject: { agent: 'a', user: 'u' }, objective: 'write notes to out/', expiresAt: '2099-01-01T00:00:00Z',
    allow: [{ tools: ['write_file'], resources: ['out/'], approval: true }] }));
  const transport = new StdioClientTransport({ command: process.execPath, stderr: 'pipe',
    args: [proxy, '--mandate', mandate, '--approvals', String(port), '--approval-timeout', '10', '--', process.execPath, dummy, '--journal', journal] });
  let stderr = '';
  (transport.stderr as NodeJS.ReadableStream | null)?.on('data', (c: Buffer) => { stderr += c; });
  const client = new Client({ name: 'held-test', version: '0' });
  try {
    await client.connect(transport, { timeout: 5000 });
    const token = JSON.parse(stderr.split('\n').find(l => l.includes('"approvals"'))!).token;
    const api = (p: string, body?: unknown) => fetch(`http://127.0.0.1:${port}${p}`, { method: body ? 'POST' : 'GET',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) }).then(r => r.json());
    const pendingCall = client.callTool({ name: 'write_file', arguments: { path: 'out/a.md', data: 'ok' } });
    let pending: Array<{ actionId: string }> = [];
    for (let i = 0; i < 50 && pending.length === 0; i++) { pending = await api('/pending'); if (!pending.length) await new Promise(r => setTimeout(r, 50)); }
    assert.equal((await fetch(`http://127.0.0.1:${port}/pending`)).status, 403, 'token required');
    assert.equal((await api('/decide', { actionId: pending[0].actionId, approver: 'a', approved: true })).code, 'INVALID_APPROVER', 'agent cannot self-approve');
    assert.deepEqual(await api('/decide', { actionId: pending[0].actionId, approver: 'ops-lead', approved: true }), { ok: true });
    assert.equal((await pendingCall).isError, false);
    const rejected = client.callTool({ name: 'write_file', arguments: { path: 'out/b.md', data: 'no' } });
    for (let i = 0; i < 50 && (pending = await api('/pending')).length === 0; i++) await new Promise(r => setTimeout(r, 50));
    await api('/decide', { actionId: pending[0].actionId, approver: 'ops-lead', approved: false });
    assert.equal((await rejected).isError, true);
    await client.ping();
    const forwarded = readFileSync(journal, 'utf8').trim().split('\n').map(l => JSON.parse(l)).filter(v => v.method === 'tools/call').map(v => v.params.arguments.path);
    assert.deepEqual(forwarded, ['out/a.md'], 'only the approved call reached upstream');
  } finally { await client.close(); await transport.close(); rmSync(root, { recursive: true, force: true }); }
});
