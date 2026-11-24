import { findSecrets } from './redact.ts';
import { normalize } from './injection.ts';
import { normalizePattern, patternMatches } from './mandate.ts';
import type { Mandate } from './mandate.ts';
import type { ParsedAction } from './contracts.ts';

// Context segments carry an origin label. Only the mandate, the user and the operator/system
// are trusted sources of instructions; everything an agent reads from tools, web pages,
// email, files or its own reasoning is data that may contain attacker-chosen text.
export type Source = 'user' | 'system' | 'operator' | 'tool' | 'web' | 'email' | 'file' | 'retrieval' | 'agent';
export type Segment = Readonly<{ source: Source; text: string; id?: string }>;
export const SOURCES: readonly Source[] = ['user', 'system', 'operator', 'tool', 'web', 'email', 'file', 'retrieval', 'agent'];
export const trusted = (source: Source) => source === 'user' || source === 'system' || source === 'operator';

export type Origin = 'trusted' | 'untrusted' | 'unattributed';

function ancestors(path: string): string[] {
  const parts = path.split('/');
  return parts.slice(0, -1).map((_, i) => parts.slice(0, i + 1).join('/'));
}
const mentions = (text: string, value: string) => value.length > 0 && text.includes(value.toLowerCase());
const mentionsWord = (text: string, word: string) => new RegExp(`(?:^|[^a-z0-9_.-])${word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:$|[^a-z0-9_-])`).test(text);

// Who chose this target? A destination, recipient, command or path that appears only in
// untrusted content (and not in the user's objective or the mandate) was most likely
// selected by injected text rather than by the principal.
export function targetOrigin(action: ParsedAction, mandate: Mandate, segments: readonly Segment[]): Origin {
  const trustedText = normalize([mandate.objective, ...segments.filter(s => trusted(s.source)).map(s => s.text)].join('\n'));
  // Include decoded (base64/hex/percent) views: encoded instructions still choose targets.
  const untrustedText = normalize(segments.filter(s => !trusted(s.source)).flatMap(s => decodedViews(s.text)).join('\n'));
  const kind = action.contract.resource.kind;
  const exactInMandate = mandate.allow.some(rule => (rule.tools.includes(action.tool) || rule.tools.includes('*')) && rule.resources.some(raw => {
    const pattern = normalizePattern(raw, kind);
    if (pattern === null || pattern === '*') return false;
    if (kind === 'url') return action.host !== undefined && new URL(pattern).hostname === action.host;
    if (kind === 'command') return patternMatches(pattern, action.resource, kind);
    return pattern === action.resource;
  }));
  if (exactInMandate) return 'trusted';
  let isTrusted = false, inUntrusted = false;
  switch (kind) {
    case 'path': {
      const broad = action.effect === 'read' || action.effect === 'write';
      const candidates = broad ? [action.resource, ...ancestors(action.resource)] : [action.resource, ancestors(action.resource).at(-1) ?? ''];
      isTrusted = candidates.some(c => c && (mentions(trustedText, c) && (c === action.resource || mentionsWord(trustedText, c))));
      inUntrusted = mentions(untrustedText, action.resource);
      break;
    }
    case 'url': case 'email':
      isTrusted = mentions(trustedText, kind === 'url' ? action.host! : action.resource);
      inUntrusted = mentions(untrustedText, kind === 'url' ? action.host! : action.resource);
      break;
    default:
      isTrusted = mentions(trustedText, action.resource);
      inUntrusted = mentions(untrustedText, action.resource);
  }
  return isTrusted ? 'trusted' : inUntrusted ? 'untrusted' : 'unattributed';
}

// Session data-flow tracking: content read from protected resources, and any credential
// found in tool output, is fingerprinted. Outbound arguments are checked for that content,
// including base64/hex/percent-encoded copies. Fingerprints live in memory only.
const SHINGLE = 24;
const squash = (text: string) => text.toLowerCase().replace(/\s+/g, ' ');

export function decodedViews(text: string): string[] {
  const views = [text];
  for (const blob of text.match(/[A-Za-z0-9+/_-]{16,}={0,2}/g) ?? []) {
    const decoded = Buffer.from(blob.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    if (/^[\x09\x0a\x0d\x20-\x7e]{8,}$/.test(decoded)) views.push(decoded);
  }
  for (const blob of text.match(/(?:[0-9a-fA-F]{2}){8,}/g) ?? []) {
    const decoded = Buffer.from(blob, 'hex').toString('utf8');
    if (/^[\x09\x0a\x0d\x20-\x7e]{8,}$/.test(decoded)) views.push(decoded);
  }
  if (/%[0-9a-f]{2}/i.test(text)) { try { views.push(decodeURIComponent(text.replace(/\+/g, ' '))); } catch { /* malformed */ } }
  return views;
}

export class TaintTracker {
  // Fingerprint -> source labels (a canonical resource path, or 'credential').
  #exact = new Map<string, Set<string>>();
  #shingles = new Map<string, Set<string>>();
  #labels = new Set<string>();
  static readonly LIMIT = 200_000;

  // Coarse label: protected content or a credential has entered this session's context.
  get confidential(): boolean { return this.#labels.size > 0; }
  // Every source label that has entered this session (for session-level flow rules).
  get labels(): ReadonlySet<string> { return this.#labels; }
  get size(): number { return this.#exact.size + this.#shingles.size; }

  #put(map: Map<string, Set<string>>, key: string, label: string): void {
    let set = map.get(key);
    if (!set) { if (map.size >= TaintTracker.LIMIT) return; set = new Set(); map.set(key, set); }
    set.add(label);
  }

  addSensitive(content: string, label = 'protected'): void {
    this.#labels.add(label);
    const text = squash(content);
    if (text.length >= 8 && text.length <= SHINGLE) this.#put(this.#exact, text, label);
    for (let i = 0; i + SHINGLE <= text.length; i += 4) this.#put(this.#shingles, text.slice(i, i + SHINGLE), label);
    this.addSecrets(content);
  }

  addSecrets(content: string): number {
    const found = findSecrets(content);
    if (found.length > 0) this.#labels.add('credential');
    for (const f of found) {
      const secret = content.slice(f.start, f.end);
      // Store the credential value itself; for KEY=value forms, also the value part.
      for (const value of [secret, secret.split(/[:=]\s*["']?/).slice(1).join('=')]) {
        // Trailing punctuation is usually prose around the secret, not part of it.
        const trimmed = value.replace(/[)\]}>.,;:!?'"]+$/, '');
        if (trimmed.length >= 8) this.#put(this.#exact, squash(trimmed), 'credential');
      }
    }
    return found.length;
  }

  // Labels whose content appears in outbound text, including decoded views.
  matchLabels(outbound: string): Set<string> {
    const found = new Set<string>();
    if (this.size === 0 || !outbound) return found;
    for (const view of decodedViews(outbound)) {
      const text = squash(view);
      for (const [value, labels] of this.#exact) if (text.includes(value)) labels.forEach(l => found.add(l));
      // Shingles were sampled every 4 characters, so test every offset.
      for (let i = 0; i + SHINGLE <= text.length; i++) this.#shingles.get(text.slice(i, i + SHINGLE))?.forEach(l => found.add(l));
    }
    return found;
  }

  matches(outbound: string): boolean { return this.matchLabels(outbound).size > 0; }
}
