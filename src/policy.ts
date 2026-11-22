import { canonicalPath } from './paths.ts';
import { record, keys, stringList } from './validation.ts';

export type Policy = { read?: string[]; write?: string[]; network?: string[] };
export type Grants = { read: string[]; write: string[]; network: string[] };

export function endpoint(input: unknown): string | null {
  if (typeof input !== 'string' || /[%?#\\]/.test(input)) return null;
  try {
    const url = new URL(input);
    return url.protocol === 'https:' && !url.username && !url.password
      && url.href === input ? url.href : null;
  } catch { return null; }
}

export function parsePolicy(input: unknown): Grants {
  if (!record(input) || !keys(input, ['read', 'write', 'network'])) throw new Error('Invalid policy');
  const grants: Grants = { read: [], write: [], network: [] };
  for (const kind of ['read', 'write', 'network'] as const) {
    if (!Object.hasOwn(input, kind)) continue;
    const values = input[kind];
    if (!stringList(values)) throw new Error('Invalid policy');
    grants[kind] = values.map(value => {
      const directory = kind !== 'network' && typeof value === 'string' && value.endsWith('/');
      const normalized = kind === 'network' ? endpoint(value)
        : canonicalPath(directory ? value.slice(0, -1) : value);
      if (normalized === null) throw new Error('Invalid policy');
      return normalized + (directory ? '/' : '');
    });
  }
  return grants;
}

export function permits(grants: string[], target: string): boolean {
  return grants.some(grant => grant.endsWith('/') ? target.startsWith(grant) : target === grant);
}
