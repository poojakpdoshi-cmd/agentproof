// Local decision-only comparison. No API calls, actual files or sockets are exercised.
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { cpus, platform, release } from 'node:os';
import { mkdirSync, writeFileSync } from 'node:fs';
import { PolicyEngine } from '@microsoft/agent-governance-sdk';
import { toolGate } from '../src/mcp-policy.ts';
import { canonicalPath } from '../src/paths.ts';
import { endpoint } from '../src/policy.ts';
import { keys, record } from '../src/validation.ts';

const url = 'https://api.example.test/health';
const grant = { read: ['docs/dummy.txt'], write: ['out/dummy.txt'], network: [url] };
type Case = { name: string; params: { name: string; arguments: Record<string, unknown> }; expected: boolean };
const cases: Case[] = [];
const add = (name: string, tool: string, args: Record<string, unknown>, expected = false) =>
  cases.push({ name, params: { name: tool, arguments: args }, expected });
add('allowed read', 'read_file', { path: 'docs/dummy.txt' }, true);
add('allowed write', 'write_file', { path: 'out/dummy.txt', data: 'DUMMY' }, true);
add('allowed GET', 'network_request', { url }, true);
add('allowed HEAD', 'network_request', { url, method: 'HEAD' }, true);
add('Windows slash alias', 'read_file', { path: 'docs\\dummy.txt' }, true);
add('Windows case alias', 'read_file', { path: 'DOCS/DUMMY.TXT' }, true);
add('unauthorized read', 'read_file', { path: 'private/dummy.txt' });
add('unauthorized write', 'write_file', { path: 'docs/dummy.txt', data: 'DUMMY' });
for (const [name, path] of [
  ['traversal', 'docs/../private/dummy.txt'], ['mixed traversal', 'docs/..\\private/dummy.txt'],
  ['UNC', '\\\\server\\share\\dummy.txt'], ['device UNC', '\\\\?\\UNC\\server\\share\\dummy.txt'],
  ['drive relative', 'C:dummy.txt'], ['absolute', '/docs/dummy.txt'], ['ADS', 'docs/dummy.txt:stream'],
  ['reserved name', 'docs/NUL.txt'], ['trailing dot', 'docs/dummy.txt.'], ['encoded traversal', 'docs/%2e%2e/dummy.txt'],
]) add(name, 'read_file', { path });
add('different origin', 'network_request', { url: 'https://evil.example.test/health' });
add('body exfiltration', 'network_request', { url, body: 'DUMMY_SECRET' });
add('header exfiltration', 'network_request', { url, headers: { 'X-Dummy': 'DUMMY_SECRET' } });
add('query exfiltration', 'network_request', { url: url + '?secret=DUMMY' });
add('URL credentials', 'network_request', { url: 'https://DUMMY@api.example.test/health' });
add('POST forbidden', 'network_request', { url, method: 'POST' });
add('extra file argument', 'read_file', { path: 'docs/dummy.txt', followSymlinks: true });
add('non-string write', 'write_file', { path: 'out/dummy.txt', data: 42 });
add('unknown tool', 'shell', { command: 'DUMMY' });

const rules = [
  { action: 'read_file', effect: 'allow' as const, conditions: { path: 'docs/dummy.txt' } },
  { action: 'write_file', effect: 'allow' as const, conditions: { path: 'out/dummy.txt' } },
  ...['GET', 'HEAD'].map(method => ({ action: 'network_request', effect: 'allow' as const, conditions: { url, method } })),
];
const native = new PolicyEngine(rules);
const adapted = new PolicyEngine(rules.map(rule => ({ ...rule, conditions: { ...rule.conditions, contractValid: true } })));
const gate = toolGate(grant);

function rawContext(params: Case['params']): Record<string, unknown> {
  return { ...params.arguments, method: params.arguments.method ?? 'GET' };
}

// Explicit adapter supplied by this benchmark, NOT a Microsoft built-in feature.
// Reuse AgentProof's primitives to hold schema and Windows/URL semantics constant;
// Microsoft still independently makes the grant decision using its own rules.
function contractContext(params: Case['params']): Record<string, unknown> {
  const args = params.arguments;
  if (!record(args)) return { contractValid: false };
  if (params.name === 'network_request') {
    const target = endpoint(args.url);
    const method = args.method ?? 'GET';
    return { url: target, method, contractValid: target !== null && keys(args, ['url', 'method'], ['url'])
      && (method === 'GET' || method === 'HEAD') };
  }
  const fields = params.name === 'read_file' ? ['path'] : ['path', 'data'];
  const target = canonicalPath(args.path);
  return { path: target, contractValid: ['read_file', 'write_file'].includes(params.name) && target !== null
    && keys(args, fields, fields) && (params.name === 'read_file' || typeof args.data === 'string') };
}

const evaluators = {
  agentproof: (params: Case['params']) => gate(params).allowed,
  microsoftRawExactRules: (params: Case['params']) => native.evaluate(params.name, rawContext(params)) === 'allow',
  microsoftWithContractAdapter: (params: Case['params']) => adapted.evaluate(params.name, contractContext(params)) === 'allow',
};
const results = cases.map(item => ({ ...item, decisions: Object.fromEntries(
  Object.entries(evaluators).map(([name, evaluate]) => [name, evaluate(item.params)])),
}));
for (const row of results) {
  assert.equal(row.decisions.agentproof, row.expected, row.name);
  assert.equal(row.decisions.microsoftWithContractAdapter, row.expected, row.name);
}
const scores = Object.fromEntries(Object.keys(evaluators).map(name => [name, {
  correct: results.filter(row => row.decisions[name] === row.expected).length,
  total: results.length,
  falseAllows: results.filter(row => row.decisions[name] && !row.expected).length,
  falseDenials: results.filter(row => !row.decisions[name] && row.expected).length,
}]));
const timing: Record<string, unknown> = {};
let checksum = 0;
for (const evaluate of Object.values(evaluators)) {
  for (let i = 0; i < 5000; i++) checksum += Number(evaluate(cases[i % cases.length].params));
}
const batches: Record<string, number[]> = Object.fromEntries(Object.keys(evaluators).map(name => [name, []]));
// Rotate evaluation order per round to reduce order/JIT bias; same raw cases each time.
for (let round = 0; round < 7; round++) {
  const entries = Object.entries(evaluators);
  for (let j = 0; j < entries.length; j++) {
    const [name, evaluate] = entries[(j + round) % entries.length];
    const start = performance.now();
    for (let i = 0; i < 10000; i++) checksum += Number(evaluate(cases[i % cases.length].params));
    batches[name].push((performance.now() - start) * 1000 / 10000);
  }
}
for (const [name, samples] of Object.entries(batches)) {
  const ordered = [...samples].sort((a, b) => a - b);
  timing[name] = { medianMicrosecondsPerDecision: ordered[3], min: ordered[0], max: ordered[6], samples };
}
const output = {
  measuredOn: '2026-11-22', node: process.version, os: `${platform()} ${release()}`, cpu: cpus()[0]?.model,
  microsoftPackage: '@microsoft/agent-governance-sdk@5.0.0',
  scope: 'In-process PolicyEngine.evaluate exact-resource profile; not full toolkit or MCP transport comparison',
  caveat: 'Raw rule conditions are not an argument validator. Adapter shares AgentProof primitives; equal outcomes are expected, not independent security validation.',
  methodology: { warmupPerEngine: 5000, rounds: 7, decisionsPerRound: 10000, transportAndAuditIncluded: false },
  scores, timing, checksum, results,
};
mkdirSync(new URL('../docs/', import.meta.url), { recursive: true });
writeFileSync(new URL('../docs/phase3-benchmark.json', import.meta.url), JSON.stringify(output, null, 2) + '\n');
console.log(JSON.stringify({ scores, timing }, null, 2));
