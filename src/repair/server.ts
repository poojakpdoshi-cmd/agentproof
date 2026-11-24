#!/usr/bin/env node
// Interactive repair dashboard (127.0.0.1 only).
//   node src/repair/server.ts ENV_MODULE [--port 8790]            interactive: approve / reject / rollback
//   node src/repair/server.ts ENV_MODULE --export OUT.html         read-only static snapshot
// Writes need the per-process token (delivered only inside the same-origin page), an exact Host
// header and a custom request header, so other origins and DNS-rebinding pages cannot act.
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { verifyLedger } from '../guard/ledger.ts';
import { repair, verifyCertificate } from './engine.ts';
import { PolicyStore } from './store.ts';
import type { Environment } from './types.ts';

const args = process.argv.slice(2);
const opt = (n: string) => args.includes(n) ? args[args.indexOf(n) + 1] : undefined;
if (!args[0] || args[0].startsWith('--')) { process.stderr.write('Usage: node src/repair/server.ts ENV_MODULE [--port 8790] [--export OUT.html]\n'); process.exit(2); }
const env: Environment = (await import(pathToFileURL(path.resolve(args[0])).href)).env;
const report = repair(env);
const store = new PolicyStore(env.mandate);
report.proposals.forEach(p => store.propose(p));
const status = new Map(report.proposals.map(p => [p.id, 'pending']));
const verified = new Map(report.proposals.map(p => [p.id, verifyCertificate(p.certificate, env, p.before,
  report.attacks.filter(a => Object.hasOwn(p.certificate.security.before, a.id))).ok]));

// Line diff (LCS) between pretty-printed policies.
function diff(a: unknown, b: unknown): Array<[string, string]> {
  const x = JSON.stringify(a, null, 2).split('\n'), y = JSON.stringify(b, null, 2).split('\n');
  const L = Array.from({ length: x.length + 1 }, () => new Array<number>(y.length + 1).fill(0));
  for (let i = x.length - 1; i >= 0; i--) for (let j = y.length - 1; j >= 0; j--) L[i][j] = x[i] === y[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  const out: Array<[string, string]> = [];
  let i = 0, j = 0;
  while (i < x.length && j < y.length) {
    if (x[i] === y[j]) { out.push([' ', x[i]]); i++; j++; } else if (L[i + 1][j] >= L[i][j + 1]) out.push(['-', x[i++]]); else out.push(['+', y[j++]]);
  }
  while (i < x.length) out.push(['-', x[i++]]);
  while (j < y.length) out.push(['+', y[j++]]);
  // Keep changed lines with two lines of context.
  return out.filter((_, k) => out.slice(Math.max(0, k - 2), k + 3).some(([t]) => t !== ' '));
}

export function state() {
  const integrity = verifyLedger(store.ledger.entries);
  return {
    environment: { id: env.id, description: env.description },
    summary: { attacksGenerated: report.discovered, initialVulnerabilities: report.initialVulnerabilities, residual: report.residual.length, latencyMs: report.latencyMs, currentVersion: store.current.n },
    proposals: report.proposals.map(p => ({ id: p.id, status: status.get(p.id), applicable: store.current.digest === p.certificate.policyBefore && status.get(p.id) === 'pending',
      violation: p.rootCause.violation, causes: p.rootCause.causes, explanation: p.rootCause.explanation, repair: p.chosen.candidate.summary, operator: p.chosen.candidate.operator,
      verification: { fixesTarget: p.chosen.fixesTarget, targetBefore: p.certificate.target.before, targetAfter: p.certificate.target.after, vulnerabilitiesFixed: p.chosen.vulnerabilitiesFixed,
        securityRegressions: p.chosen.securityRegressions, legitBlocked: p.chosen.legitBlocked, legitHeld: p.chosen.legitHeld, score: p.chosen.score, certificate: p.certificate.digest, reverified: verified.get(p.id) },
      diff: diff(p.before, p.after), alternatives: p.alternatives.map(a => ({ operator: a.candidate.operator, summary: a.candidate.summary, score: a.score, fixes: a.vulnerabilitiesFixed, blocked: a.legitBlocked, held: a.legitHeld })),
      latencyMs: p.latencyMs })),
    versions: store.history.map(v => ({ n: v.n, digest: v.digest.slice(0, 16), change: v.change, by: v.by, proposal: v.proposal ?? null })),
    evidence: { entries: integrity.entries, ok: integrity.ok, head: integrity.head },
  };
}

const html = readFileSync(new URL('../dashboard/repair.html', import.meta.url), 'utf8');
const js = readFileSync(new URL('../dashboard/repair.js', import.meta.url), 'utf8');
const css = readFileSync(new URL('../dashboard/style.css', import.meta.url), 'utf8');
const out = opt('--export');
if (out) {
  const json = JSON.stringify(state()).replace(/</g, '\\u003c').replace(/[\u2028\u2029]/g, c => '\\u' + c.charCodeAt(0).toString(16));
  writeFileSync(out, html.replace('<link rel="stylesheet" href="style.css">', () => `<style>${css}</style>`).replace('__TOKEN__', '')
    .replace('<script src="repair.js"></script>', () => `<script type="application/json" id="state">${json}</script>\n<script>${js}</script>`));
  console.log(`Wrote ${out}`);
} else {
  const token = randomBytes(24).toString('hex');
  const port = Number(opt('--port') ?? 8790);
  const hosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  const headers = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'" };
  createServer(async (req, res) => {
    const send = (code: number, body: unknown, type = 'application/json') => res.writeHead(code, { ...headers, 'Content-Type': type }).end(typeof body === 'string' ? body : JSON.stringify(body));
    if (!hosts.has(req.headers.host ?? '')) return send(421, { error: 'host' });
    const url = (req.url ?? '/').split('?')[0];
    if (req.method === 'GET') {
      if (url === '/') return send(200, html.replace('__TOKEN__', token), 'text/html; charset=utf-8');
      if (url === '/repair.js') return send(200, js, 'text/javascript; charset=utf-8');
      if (url === '/style.css') return send(200, css, 'text/css; charset=utf-8');
      if (url === '/api/state') return send(200, state());
      return send(404, { error: 'not found' });
    }
    if (req.method !== 'POST' || req.headers['x-agentproof-token'] !== token || !String(req.headers['content-type']).startsWith('application/json')) return send(403, { error: 'forbidden' });
    let raw = '';
    for await (const chunk of req) { raw += chunk; if (raw.length > 4096) return send(413, { error: 'too large' }); }
    let body: { id?: string; version?: number; approver?: string };
    try { body = JSON.parse(raw); } catch { return send(400, { error: 'json' }); }
    const approver = String(body.approver ?? '');
    if (url === '/api/apply') { const r = store.apply(String(body.id), approver); if (r.ok) status.set(String(body.id), 'applied'); return send(r.ok ? 200 : 409, r); }
    if (url === '/api/reject') { const ok = store.reject(String(body.id), approver); if (ok) status.set(String(body.id), 'rejected'); return send(ok ? 200 : 409, { ok }); }
    if (url === '/api/rollback') { const r = store.rollback(Number(body.version), approver); return send(r.ok ? 200 : 409, r); }
    return send(404, { error: 'not found' });
  }).listen(port, '127.0.0.1', () => console.log(`AgentProof repair dashboard: http://127.0.0.1:${port}/ (${env.id})`));
}
