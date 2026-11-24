#!/usr/bin/env node
// Independent evidence verifier: recomputes every hash from canonical content.
//   node src/verify-evidence.ts FILE [--anchor SEQ:HASH] [--require-mac]
// HMAC key (hex) is read from AGENTPROOF_EVIDENCE_KEY, never from arguments (shell history).
// Exit codes: 0 intact, 1 tampered/invalid, 2 usage or unreadable file.
import { readFileSync } from 'node:fs';
import { parseJsonl, verifyLedger } from './guard/ledger.ts';

const args = process.argv.slice(2);
const file = args[0];
if (!file || file.startsWith('--')) {
  process.stderr.write('Usage: node src/verify-evidence.ts FILE [--anchor SEQ:HASH] [--require-mac]\n');
  process.exit(2);
}
const anchorArg = args.includes('--anchor') ? args[args.indexOf('--anchor') + 1] : undefined;
const anchorMatch = anchorArg?.match(/^(\d+):([0-9a-f]{64})$/);
const keyHex = process.env.AGENTPROOF_EVIDENCE_KEY;
if ((anchorArg && !anchorMatch) || (keyHex && !/^[0-9a-f]{64}$/i.test(keyHex))) {
  process.stderr.write('Invalid anchor or AGENTPROOF_EVIDENCE_KEY (expected 64 hex chars).\n');
  process.exit(2);
}
let text: string;
try { text = readFileSync(file, 'utf8'); } catch { process.stderr.write('Cannot read evidence file.\n'); process.exit(2); }
const parsed = parseJsonl(text);
const result = verifyLedger(parsed.values, { key: keyHex ? Buffer.from(keyHex, 'hex') : undefined,
  anchor: anchorMatch ? { seq: Number(anchorMatch[1]), hash: anchorMatch[2] } : undefined, requireMac: args.includes('--require-mac') });
const ok = result.ok && parsed.errors.length === 0;
process.stdout.write(JSON.stringify({ ok, entries: result.entries, head: result.head, macVerified: result.macVerified,
  anchorChecked: anchorMatch !== undefined && anchorMatch !== null, issues: [...parsed.errors, ...result.issues] }, null, 2) + '\n');
process.exitCode = ok ? 0 : 1;
