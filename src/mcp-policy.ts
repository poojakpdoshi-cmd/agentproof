import { canonicalPath } from './paths.ts';
import { endpoint, parsePolicy, permits } from './policy.ts';
import { keys, record } from './validation.ts';

export type ToolDecision = { allowed: boolean; reason: string; tool: string; params?: Record<string, unknown> };

// Fixed, reviewed adapters. Tool names or descriptions never grant authority.
export function toolGate(policy: unknown): (params: unknown) => ToolDecision {
  const grants = parsePolicy(policy);
  return params => {
    let tool = 'unknown';
    const deny = (reason: string): ToolDecision => ({ allowed: false, reason, tool });
    try {
      if (!record(params) || !keys(params, ['name', 'arguments', '_meta'], ['name', 'arguments'])
        || !record(params.arguments)) return deny('invalid-arguments');
      if (!['read_file', 'write_file', 'network_request'].includes(params.name as string)) return deny('unknown-tool');
      tool = params.name as string;
      // Permit only protocol progress tokens, never arbitrary outbound metadata.
      if (Object.hasOwn(params, '_meta')) {
        if (!record(params._meta) || !keys(params._meta, ['progressToken'])) return deny('invalid-metadata');
        const token = params._meta.progressToken;
        if (Object.hasOwn(params._meta, 'progressToken') && typeof token !== 'string'
          && !(typeof token === 'number' && Number.isSafeInteger(token))) return deny('invalid-metadata');
      }
      const args = params.arguments;
      if (tool === 'network_request') {
        if (!keys(args, ['url', 'method'], ['url']) || (Object.hasOwn(args, 'method')
          && args.method !== 'GET' && args.method !== 'HEAD')) return deny('outbound-data-forbidden');
        const target = endpoint(args.url);
        if (target === null) return deny('invalid-endpoint');
        if (!grants.network.includes(target)) return deny('not-granted');
        return { allowed: true, reason: 'authorized', tool, params };
      }
      const fields = tool === 'read_file' ? ['path'] : ['path', 'data'];
      if (!keys(args, fields, fields) || (tool === 'write_file' && typeof args.data !== 'string')) {
        return deny('invalid-arguments');
      }
      const target = canonicalPath(args.path);
      if (target === null) return deny('invalid-path');
      if (!permits(grants[tool === 'read_file' ? 'read' : 'write'], target)) return deny('not-granted');
      return { allowed: true, reason: 'authorized', tool,
        params: { ...params, arguments: { ...args, path: target } } };
    } catch { return deny('policy-error'); }
  };
}
