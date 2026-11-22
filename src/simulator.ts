import { canonicalPath } from './paths.ts';
import { endpoint, parsePolicy, permits } from './policy.ts';
import type { Grants } from './policy.ts';
import { record, keys } from './validation.ts';

export type Action = { type: 'read'; path: string }
  | { type: 'write'; path: string; data: string }
  | { type: 'network'; url: string; method?: 'GET' | 'HEAD' };
export type Audit = Readonly<{
  sequence: number;
  action: 'read' | 'write' | 'network' | 'unknown';
  decision: 'allow' | 'deny';
  reason: 'authorized' | 'invalid-action' | 'invalid-path' | 'not-granted'
    | 'missing-file' | 'outbound-data-forbidden' | 'invalid-endpoint';
}>;
export type Result = { audit: Audit; data?: string; status?: number };

export class Simulator {
  #grants: Grants;
  #files = new Map<string, string>();
  #log: Audit[] = [];

  constructor(policy: unknown = {}, files: unknown = {}) {
    this.#grants = parsePolicy(policy);
    if (!record(files)) throw new Error('Invalid files');
    for (const [name, data] of Object.entries(files)) {
      const normalized = canonicalPath(name);
      if (normalized === null || typeof data !== 'string' || this.#files.has(normalized)) {
        throw new Error('Invalid files');
      }
      this.#files.set(normalized, data);
    }
  }

  get audit(): readonly Audit[] { return this.#log.slice(); }

  execute(input: unknown): Result {
    const type = record(input) && Object.hasOwn(input, 'type') && ['read', 'write', 'network'].includes(input.type as string)
      ? input.type as Audit['action'] : 'unknown';
    const finish = (decision: Audit['decision'], reason: Audit['reason'], data?: string, status?: number): Result => {
      const audit = Object.freeze({ sequence: this.#log.length + 1, action: type, decision, reason });
      this.#log.push(audit);
      return { audit, ...(data === undefined ? {} : { data }), ...(status === undefined ? {} : { status }) };
    };
    const deny = (reason: Audit['reason']) => finish('deny', reason);
    if (!record(input) || type === 'unknown') return deny('invalid-action');
    if (type === 'network') {
      // No user-controlled outbound body, headers, query, credentials or fragments.
      if (!keys(input, ['type', 'url', 'method'], ['type', 'url'])
        || (Object.hasOwn(input, 'method') && input.method !== 'GET' && input.method !== 'HEAD')) {
        return deny('outbound-data-forbidden');
      }
      const target = endpoint(input.url);
      if (target === null) return deny('invalid-endpoint');
      if (!this.#grants.network.includes(target)) return deny('not-granted');
      return finish('allow', 'authorized', undefined, 204);
    }
    const fields = type === 'read' ? ['type', 'path'] : ['type', 'path', 'data'];
    if (!keys(input, fields, fields)
      || (type === 'write' && typeof input.data !== 'string')) return deny('invalid-action');
    const target = canonicalPath(input.path);
    if (target === null) return deny('invalid-path');
    if (!permits(this.#grants[type], target)) return deny('not-granted');
    if (type === 'read') {
      if (!this.#files.has(target)) return deny('missing-file');
      return finish('allow', 'authorized', this.#files.get(target));
    }
    this.#files.set(target, input.data as string);
    return finish('allow', 'authorized');
  }
}
