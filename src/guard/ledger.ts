import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { canonical, hmac, safeEqual, sha256 } from './canonical.ts';
import { redactValue } from './redact.ts';

// Hash-chained, append-only evidence. Each entry commits to its predecessor's hash, so any
// in-place edit, reorder, insertion or middle deletion is detectable. Without an HMAC key
// anyone can recompute a fully rewritten chain, and without an external anchor (the last
// seq+hash recorded elsewhere) tail truncation is undetectable. Tamper-evident, not tamper-proof.
export type Entry = { v: 1; seq: number; ts: string; type: string; data: unknown; prev: string; hash: string; mac?: string };
export type Anchor = { seq: number; hash: string };
export type VerifyIssue = { seq: number | null; line: number; code: 'PARSE_ERROR' | 'SCHEMA' | 'SEQUENCE' | 'CHAIN' | 'HASH' | 'MAC_MISSING' | 'MAC' | 'ANCHOR' | 'EMPTY' };
export type VerifyResult = { ok: boolean; entries: number; head: Anchor | null; macVerified: boolean; issues: VerifyIssue[] };

export const GENESIS = '0'.repeat(64);
const body = (e: Pick<Entry, 'v' | 'seq' | 'ts' | 'type' | 'data' | 'prev'>) => canonical({ v: e.v, seq: e.seq, ts: e.ts, type: e.type, data: e.data, prev: e.prev });

export class EvidenceLedger {
  #entries: Entry[] = [];
  #key?: Buffer;
  #file?: string;
  #clock: () => Date;

  constructor(options: { key?: Buffer; file?: string; clock?: () => Date } = {}) {
    this.#key = options.key;
    this.#file = options.file;
    this.#clock = options.clock ?? (() => new Date());
    if (this.#file && existsSync(this.#file)) {
      // Refuse to extend a chain that does not verify: appending would launder tampering.
      const existing = parseJsonl(readFileSync(this.#file, 'utf8'));
      if (existing.errors.length > 0 || (existing.values.length > 0 && !verifyLedger(existing.values, { key: this.#key }).ok)) {
        throw new Error('Existing evidence file failed verification');
      }
      this.#entries = existing.values as Entry[];
    }
  }

  append(type: string, data: unknown): Entry {
    const last = this.#entries.at(-1);
    const entry: Entry = { v: 1, seq: (last?.seq ?? 0) + 1, ts: this.#clock().toISOString(), type,
      data: redactValue(data), prev: last?.hash ?? GENESIS, hash: '' };
    entry.hash = sha256(body(entry));
    if (this.#key) entry.mac = hmac(this.#key, entry.hash);
    if (this.#file) appendFileSync(this.#file, JSON.stringify(entry) + '\n');
    this.#entries.push(Object.freeze(entry) as Entry);
    return entry;
  }

  get entries(): readonly Entry[] { return this.#entries.slice(); }
  head(): Anchor | null { const last = this.#entries.at(-1); return last ? { seq: last.seq, hash: last.hash } : null; }
  toJsonl(): string { return this.#entries.map(e => JSON.stringify(e)).join('\n') + (this.#entries.length ? '\n' : ''); }
}

export function parseJsonl(text: string): { values: unknown[]; errors: VerifyIssue[] } {
  const values: unknown[] = [], errors: VerifyIssue[] = [];
  text.split('\n').forEach((line, i) => {
    if (line.trim() === '') return;
    try { values.push(JSON.parse(line)); } catch { errors.push({ seq: null, line: i + 1, code: 'PARSE_ERROR' }); }
  });
  return { values, errors };
}

// Independent verification: recomputes every hash from canonical content; does not trust
// stored hashes, sequence numbers or the producer's code path.
export function verifyLedger(values: readonly unknown[], options: { key?: Buffer; anchor?: Anchor; requireMac?: boolean } = {}): VerifyResult {
  const issues: VerifyIssue[] = [];
  let prev = GENESIS, expected = 1, macVerified = options.key !== undefined;
  values.forEach((value, i) => {
    const line = i + 1;
    const e = value as Entry;
    if (value === null || typeof value !== 'object' || e.v !== 1 || !Number.isSafeInteger(e.seq) || typeof e.ts !== 'string'
      || typeof e.type !== 'string' || typeof e.prev !== 'string' || typeof e.hash !== 'string' || !/^[0-9a-f]{64}$/.test(e.hash)) {
      issues.push({ seq: null, line, code: 'SCHEMA' }); macVerified = false; return;
    }
    if (e.seq !== expected) issues.push({ seq: e.seq, line, code: 'SEQUENCE' });
    if (e.prev !== prev) issues.push({ seq: e.seq, line, code: 'CHAIN' });
    let recomputed = '';
    try { recomputed = sha256(body(e)); } catch { /* non-canonical data */ }
    if (!safeEqual(recomputed, e.hash)) issues.push({ seq: e.seq, line, code: 'HASH' });
    if (options.key) {
      if (typeof e.mac !== 'string') { issues.push({ seq: e.seq, line, code: 'MAC_MISSING' }); macVerified = false; }
      else if (!safeEqual(hmac(options.key, e.hash), e.mac)) { issues.push({ seq: e.seq, line, code: 'MAC' }); macVerified = false; }
    } else if (options.requireMac) { issues.push({ seq: e.seq, line, code: 'MAC_MISSING' }); }
    prev = e.hash;
    expected = e.seq + 1;
  });
  const last = values.at(-1) as Entry | undefined;
  const head = last && typeof last === 'object' && Number.isSafeInteger(last.seq) && typeof last.hash === 'string' ? { seq: last.seq, hash: last.hash } : null;
  if (options.anchor) {
    // The anchor must still be present, unchanged, at its recorded position.
    const anchored = values.find(v => (v as Entry)?.seq === options.anchor!.seq) as Entry | undefined;
    if (!anchored || anchored.hash !== options.anchor.hash) issues.push({ seq: options.anchor.seq, line: 0, code: 'ANCHOR' });
  }
  if (values.length === 0) issues.push({ seq: null, line: 0, code: 'EMPTY' });
  return { ok: issues.length === 0, entries: values.length, head, macVerified: macVerified && issues.length === 0, issues };
}
