#!/usr/bin/env node
// Read-only security dashboard over an AgentProof evidence file.
//   node src/dashboard/server.ts --evidence FILE [--port 8787] [--mode LABEL]
//   node src/dashboard/server.ts --evidence FILE --export OUT.html [--mode LABEL]
// Optional AGENTPROOF_EVIDENCE_KEY (hex) enables HMAC verification; AGENTPROOF_ANCHOR="seq:hash"
// enables truncation detection. Binds to 127.0.0.1 only; no state-changing endpoints.
import { createServer } from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
import { parseJsonl, verifyLedger } from '../guard/ledger.ts';
import type { Anchor, Entry } from '../guard/ledger.ts';
import { summarize } from './summary.ts';

const args = process.argv.slice(2);
const opt = (name: string) => args.includes(name) ? args[args.indexOf(name) + 1] : undefined;
const evidence = opt('--evidence');
if (!evidence || args.includes('--help')) {
  process.stdout.write('Usage: node src/dashboard/server.ts --evidence FILE [--port 8787] [--mode LABEL] [--export OUT.html]\n');
  process.exit(evidence ? 0 : 2);
}
const mode = (opt('--mode') ?? 'LIVE EVIDENCE FILE').slice(0, 80);
const keyHex = process.env.AGENTPROOF_EVIDENCE_KEY;
const key = keyHex && /^[0-9a-f]{64}$/i.test(keyHex) ? Buffer.from(keyHex, 'hex') : undefined;
const anchorRaw = process.env.AGENTPROOF_ANCHOR?.match(/^(\d+):([0-9a-f]{64})$/);
const anchor: Anchor | undefined = anchorRaw ? { seq: Number(anchorRaw[1]), hash: anchorRaw[2] } : undefined;
const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
const app = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
export const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');

export function state() {
  const parsed = parseJsonl(readFileSync(evidence!, 'utf8'));
  const verification = verifyLedger(parsed.values, { key, anchor });
  if (parsed.errors.length) { verification.ok = false; verification.issues.unshift(...parsed.errors); }
  const entries = parsed.values.filter((v): v is Entry => v !== null && typeof v === 'object') as Entry[];
  return summarize(entries, verification, { file: evidence!.split(/[\\/]/).pop()!, mode });
}

const out = opt('--export');
if (out) {
  // Self-contained snapshot; JSON is escaped so evidence text cannot close the script element.
  const json = JSON.stringify(state()).replace(/</g, '\\u003c').replace(/[\u2028\u2029]/g, c => '\\u' + c.charCodeAt(0).toString(16));
  writeFileSync(out, html.replace('<link rel="stylesheet" href="style.css">', () => `<style>${css}</style>`).replace('<script src="app.js"></script>', () => `<script type="application/json" id="state">${json}</script>\n<script>${app}</script>`));
  process.stdout.write(`Wrote ${out}\n`);
} else {
  const port = Number(opt('--port') ?? 8787);
  const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  const headers = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'" };
  createServer((req, res) => {
    // Host check blocks DNS-rebinding pages from reading the API.
    if (req.method !== 'GET' || !allowedHosts.has(req.headers.host ?? '')) { res.writeHead(req.method !== 'GET' ? 405 : 421, headers).end(); return; }
    const path = (req.url ?? '/').split('?')[0];
    try {
      if (path === '/') res.writeHead(200, { ...headers, 'Content-Type': 'text/html; charset=utf-8' }).end(html);
      else if (path === '/style.css') res.writeHead(200, { ...headers, 'Content-Type': 'text/css; charset=utf-8' }).end(css);
      else if (path === '/app.js') res.writeHead(200, { ...headers, 'Content-Type': 'text/javascript; charset=utf-8' }).end(app);
      else if (path === '/api/state') res.writeHead(200, { ...headers, 'Content-Type': 'application/json' }).end(JSON.stringify(state()));
      else res.writeHead(404, headers).end();
    } catch {
      res.writeHead(500, headers).end(JSON.stringify({ error: 'evidence unavailable' }));
    }
  }).listen(port, '127.0.0.1', () => process.stdout.write(`AgentProof dashboard: http://127.0.0.1:${port}/ (evidence: ${evidence})\n`));
}
