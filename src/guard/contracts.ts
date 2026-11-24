import { canonicalPath } from '../paths.ts';
import { keys, record } from '../validation.ts';

// Reviewed tool contracts. A tool's name or description never grants authority: only a
// registered contract tells the firewall which argument is the target resource, which
// arguments carry outbound data, and what effect the call has.
export type Effect = 'read' | 'write' | 'delete' | 'egress' | 'send' | 'execute' | 'admin';
export type ResourceKind = 'path' | 'url' | 'email' | 'command' | 'principal';
export type ArgType = 'string' | 'number' | 'boolean';
export type Contract = Readonly<{
  tool: string;
  effect: Effect;
  resource: { arg: string; kind: ResourceKind };
  args: Readonly<Record<string, { type: ArgType; required?: boolean; enum?: readonly string[]; max?: number }>>;
  data: readonly string[]; // arguments whose content leaves the agent (bodies, payloads, commands)
}>;
export type ParsedAction = Readonly<{
  tool: string; contract: Contract; arguments: Readonly<Record<string, unknown>>;
  resource: string; host?: string; effect: Effect; destructive: boolean; outbound: string[];
}>;

const s = (required = true, max = 65536) => ({ type: 'string' as const, required, max });
export const BUILTIN_CONTRACTS: Record<string, Contract> = Object.freeze({
  read_file: { tool: 'read_file', effect: 'read', resource: { arg: 'path', kind: 'path' }, args: { path: s(true, 1024) }, data: [] },
  list_directory: { tool: 'list_directory', effect: 'read', resource: { arg: 'path', kind: 'path' }, args: { path: s(true, 1024) }, data: [] },
  write_file: { tool: 'write_file', effect: 'write', resource: { arg: 'path', kind: 'path' }, args: { path: s(true, 1024), data: s(true, 1 << 20) }, data: ['data'] },
  delete_file: { tool: 'delete_file', effect: 'delete', resource: { arg: 'path', kind: 'path' }, args: { path: s(true, 1024) }, data: [] },
  network_request: { tool: 'network_request', effect: 'egress', resource: { arg: 'url', kind: 'url' },
    args: { url: s(true, 2048), method: { type: 'string', enum: ['GET', 'HEAD', 'POST', 'PUT'] }, body: s(false, 1 << 20) }, data: ['url', 'body'] },
  send_email: { tool: 'send_email', effect: 'send', resource: { arg: 'to', kind: 'email' },
    args: { to: s(true, 320), subject: s(true, 998), body: s(true, 1 << 20) }, data: ['subject', 'body'] },
  execute_command: { tool: 'execute_command', effect: 'execute', resource: { arg: 'command', kind: 'command' }, args: { command: s(true, 4096) }, data: ['command'] },
  grant_role: { tool: 'grant_role', effect: 'admin', resource: { arg: 'principal', kind: 'principal' },
    args: { principal: s(true, 256), role: s(true, 64) }, data: [] },
});

export function canonicalUrl(input: unknown): { url: string; host: string; query: string } | null {
  if (typeof input !== 'string' || input.length > 2048 || /[\s\\]/.test(input)) return null;
  let url: URL;
  try { url = new URL(input); } catch { return null; }
  if (url.protocol !== 'https:' || url.username || url.password || !url.hostname) return null;
  return { url: url.origin + url.pathname, host: url.hostname, query: url.search + url.hash };
}
export const canonicalEmail = (input: unknown): string | null =>
  typeof input === 'string' && /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$/.test(input) ? input.toLowerCase() : null;
export const canonicalCommand = (input: unknown): string | null =>
  typeof input === 'string' && input.trim() && !/[\x00-\x08\x0b-\x1f\x7f]/.test(input) ? input.trim().replace(/\s+/g, ' ') : null;

const DESTRUCTIVE_COMMAND = /(?:^|[;&|]\s*)(?:rm|rmdir|shred|mkfs|dd|truncate|del|format)\b|\bgit\s+(?:push\s+.*--force|reset\s+--hard|clean\s+-[a-z]*f)|\bdrop\s+(?:table|database)\b|>\s*\/dev\/sd/i;
const PRIVILEGED_COMMAND = /(?:^|[;&|]\s*)(?:sudo|su|doas|chmod|chown|setcap|usermod|passwd|visudo)\b|\/etc\/(?:passwd|shadow|sudoers)/i;
export const commandFlags = (command: string) => ({ destructive: DESTRUCTIVE_COMMAND.test(command), privileged: PRIVILEGED_COMMAND.test(command),
  chained: /[;&|`]|\$\(/.test(command) });

// Validates arguments against the contract and canonicalizes the target resource.
export function parseAction(input: unknown, contracts: Record<string, Contract>): ParsedAction | { error: 'INVALID_REQUEST' | 'UNKNOWN_TOOL' | 'INVALID_ARGUMENTS' | 'INVALID_RESOURCE' } {
  if (!record(input) || !keys(input, ['tool', 'arguments'], ['tool', 'arguments']) || typeof input.tool !== 'string' || !record(input.arguments)) {
    return { error: 'INVALID_REQUEST' };
  }
  if (!Object.hasOwn(contracts, input.tool)) return { error: 'UNKNOWN_TOOL' };
  const contract = contracts[input.tool];
  const args = input.arguments;
  const spec = contract.args;
  if (!keys(args, Object.keys(spec), Object.keys(spec).filter(k => spec[k].required))) return { error: 'INVALID_ARGUMENTS' };
  for (const [name, value] of Object.entries(args)) {
    const rule = spec[name];
    if (typeof value !== rule.type) return { error: 'INVALID_ARGUMENTS' };
    if (typeof value === 'string' && ((rule.max && value.length > rule.max) || (rule.enum && !rule.enum.includes(value)))) return { error: 'INVALID_ARGUMENTS' };
  }
  const raw = args[contract.resource.arg];
  let resource: string | null = null, host: string | undefined;
  const outbound = contract.data.filter(name => typeof args[name] === 'string').map(name => args[name] as string);
  switch (contract.resource.kind) {
    case 'path': resource = canonicalPath(raw); break;
    case 'url': {
      const parsed = canonicalUrl(raw);
      if (parsed) { resource = parsed.url; host = parsed.host; if (parsed.query) outbound.push(parsed.query); }
      break;
    }
    case 'email': resource = canonicalEmail(raw); if (resource) host = resource.split('@')[1]; break;
    case 'command': resource = canonicalCommand(raw); break;
    case 'principal': resource = typeof raw === 'string' && /^[A-Za-z0-9._@-]{1,256}$/.test(raw) ? raw.toLowerCase() : null; break;
  }
  if (resource === null) return { error: 'INVALID_RESOURCE' };
  let destructive = contract.effect === 'delete';
  if (contract.effect === 'execute') destructive = commandFlags(resource).destructive;
  return Object.freeze({ tool: contract.tool, contract, arguments: Object.freeze({ ...args }), resource, host, effect: contract.effect, destructive, outbound });
}
