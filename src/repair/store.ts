import { digest } from '../guard/canonical.ts';
import { EvidenceLedger } from '../guard/ledger.ts';
import type { Firewall } from '../guard/firewall.ts';
import type { Proposal } from './engine.ts';
import { applyPatch } from './replay.ts';

// Versioned policy store. Repairs are proposals until a human (never the engine or the agent)
// approves them. Every proposal, application and rollback is a hash-chained evidence entry, and
// an attached live Firewall is hot-swapped (outstanding tokens become invalid: POLICY_CHANGED).
export type Version = { n: number; digest: string; parent: string | null; change: 'initial' | 'repair' | 'rollback'; by: string; proposal?: string; certificate?: string; mandate: Record<string, unknown> };

export class PolicyStore {
  #versions: Version[] = [];
  #proposals = new Map<string, Proposal>();
  readonly ledger: EvidenceLedger;
  #firewall?: Firewall;
  #forbidden: Set<string>;

  constructor(mandate: Record<string, unknown>, options: { ledger?: EvidenceLedger; firewall?: Firewall } = {}) {
    this.ledger = options.ledger ?? new EvidenceLedger();
    this.#firewall = options.firewall;
    this.#forbidden = new Set(['repair-engine', String((mandate.subject as { agent?: string } | undefined)?.agent ?? '')]);
    this.#push({ mandate: structuredClone(mandate), change: 'initial', by: 'operator' });
  }

  #push(v: Omit<Version, 'n' | 'digest' | 'parent'>): Version {
    const version: Version = { ...v, n: this.#versions.length + 1, digest: digest(v.mandate), parent: this.#versions.at(-1)?.digest ?? null };
    this.#versions.push(version);
    this.ledger.append('policy-version', { n: version.n, digest: version.digest, parent: version.parent, change: version.change, by: version.by,
      proposal: version.proposal ?? null, certificate: version.certificate ?? null });
    if (this.#firewall && version.change !== 'initial') this.#firewall.replaceMandate(version.mandate, `${version.change} v${version.n}`);
    return version;
  }

  get current(): Version { return this.#versions.at(-1)!; }
  get history(): readonly Version[] { return this.#versions.slice(); }
  get proposals(): Proposal[] { return [...this.#proposals.values()]; }

  propose(p: Proposal): void {
    this.#proposals.set(p.id, p);
    this.ledger.append('repair-proposal', { id: p.id, base: digest(p.before), patch: p.chosen.candidate.patch, summary: p.chosen.candidate.summary,
      rootCause: p.rootCause.causes, certificate: p.certificate.digest, fixes: p.chosen.vulnerabilitiesFixed, legitBlocked: p.chosen.legitBlocked, legitHeld: p.chosen.legitHeld });
  }

  apply(id: string, approver: string): { ok: boolean; code?: string; version?: number } {
    const p = this.#proposals.get(id);
    if (!p) return { ok: false, code: 'UNKNOWN_PROPOSAL' };
    if (!/^[A-Za-z0-9._@:-]{1,128}$/.test(approver) || this.#forbidden.has(approver)) return { ok: false, code: 'INVALID_APPROVER' };
    // A proposal is only valid against the exact policy it was verified on.
    if (digest(p.before) !== this.current.digest) return { ok: false, code: 'STALE_PROPOSAL' };
    const next = applyPatch(this.current.mandate, p.chosen.candidate.patch);
    if (digest(next) !== p.certificate.policyAfter) return { ok: false, code: 'CERTIFICATE_MISMATCH' };
    this.#proposals.delete(id);
    return { ok: true, version: this.#push({ mandate: next, change: 'repair', by: approver, proposal: id, certificate: p.certificate.digest }).n };
  }

  reject(id: string, approver: string): boolean {
    if (!this.#proposals.delete(id)) return false;
    this.ledger.append('repair-rejected', { id, by: approver });
    return true;
  }

  rollback(n: number, approver: string): { ok: boolean; code?: string; version?: number } {
    const target = this.#versions.find(v => v.n === n);
    if (!target || n === this.current.n) return { ok: false, code: 'INVALID_VERSION' };
    if (!/^[A-Za-z0-9._@:-]{1,128}$/.test(approver) || this.#forbidden.has(approver)) return { ok: false, code: 'INVALID_APPROVER' };
    return { ok: true, version: this.#push({ mandate: structuredClone(target.mandate), change: 'rollback', by: approver, proposal: `rollback-to-v${n}` }).n };
  }
}
