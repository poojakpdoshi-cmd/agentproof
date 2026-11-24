import { BUILTIN_CONTRACTS, parseAction } from '../guard/contracts.ts';
import { digest } from '../guard/canonical.ts';
import { replay } from './replay.ts';
import type { Candidate, Environment, PatchOp, ReplayResult, RootCause, Trace } from './types.ts';

type Rule = { id?: string; tools: string[]; resources: string[]; approval?: boolean };
const FLOW_FACTORS = ['SENSITIVE_DATA_FLOW', 'SECRET_IN_OUTBOUND', 'CONFIDENTIAL_CONTEXT'];
const broad = (pattern: string) => pattern === '*' || pattern.endsWith('/') || pattern.startsWith('@') || pattern.endsWith(' *');
const parent = (path: string) => path.includes('/') ? path.slice(0, path.lastIndexOf('/') + 1) : null;
export const resourceOf = (tool: string, args: Record<string, unknown>): string | null => {
  const parsed = parseAction({ tool, arguments: args }, BUILTIN_CONTRACTS);
  return 'error' in parsed ? null : parsed.resource;
};

// Root cause from four evidence sources: the firewall's decision record for the violating step
// (rule, score, factors), the trace's data lineage (which labelled asset was read where), the
// target's provenance, and the policy text (which rule matched, which controls are absent).
export function analyze(env: Environment, mandate: Record<string, unknown>, trace: Trace, result: ReplayResult): RootCause {
  const v = trace.violation!;
  const step = trace.steps.length - 1;
  const outcome = result.steps[step];
  const thresholds = (mandate.thresholds as { approval: number } | undefined) ?? { approval: 40 };
  const sources = trace.steps.flatMap((s, i) => {
    const asset = s.tool === 'read_file' ? env.assets.find(a => a.path === s.arguments.path && a.class !== 'public') : undefined;
    return asset && i < step ? [{ step: i, resource: asset.path, class: asset.class }] : [];
  });
  const rules = (mandate.allow as Rule[]) ?? [];
  const rule = rules.find((r, i) => (r.id ?? `allow-${i}`) === outcome.ruleId);
  const causes: string[] = [], explanation: string[] = [];
  explanation.push(`Step ${step + 1} (${outcome.tool} → ${v.target}) was ${outcome.decision} at risk ${outcome.score} (approval threshold ${thresholds.approval}).`);
  if (v.property === 'confidential-flow' || v.property === 'credential-flow') {
    const detected = outcome.factors.filter(f => FLOW_FACTORS.includes(f));
    if (detected.length === 0) { causes.push('DATA_FLOW_UNDETECTED'); explanation.push(`Data from ${v.asset} left via ${v.transform}; taint tracking did not match it.`); }
    else { causes.push('DATA_FLOW_BELOW_THRESHOLD'); explanation.push(`Data flow was detected (${detected.join(', ')}) but its weight did not reach the approval threshold.`); }
    const flows = (mandate.flows as Array<{ to: string[] }> | undefined) ?? [];
    if (!flows.some(f => f.to.includes(v.sink) || f.to.includes('*'))) { causes.push('NO_FLOW_RULE'); explanation.push(`No data-flow rule constrains labelled data reaching ${v.sink}.`); }
  }
  if (v.property === 'untrusted-target') {
    causes.push(outcome.factors.some(f => f === 'TARGET_FROM_UNTRUSTED' || f === 'UNATTRIBUTED_TARGET') ? 'UNTRUSTED_TARGET_BELOW_THRESHOLD' : 'TARGET_PROVENANCE_UNDETECTED');
    explanation.push(`The destination ${v.target} was named only by untrusted content.`);
  }
  if (v.property === 'unapproved-confidential-read') {
    causes.push('CONFIDENTIAL_SOURCE_UNPROTECTED');
    explanation.push(`${v.asset} is confidential but readable without approval.`);
  }
  if (rule && rule.resources.some(broad)) { causes.push('ALLOW_RULE_BROAD'); explanation.push(`Allow rule ${outcome.ruleId} grants ${rule.resources.join(', ')}; the target fell inside it.`); }
  if (outcome.score > 0 && outcome.score < thresholds.approval) causes.push('RISK_BELOW_THRESHOLD');
  return { traceId: trace.id, violation: v, step, decision: outcome.decision, ruleId: outcome.ruleId, score: outcome.score,
    approvalThreshold: thresholds.approval, factors: outcome.factors, sources, causes, explanation };
}

// Resources each allow rule actually served in the legitimate suite (for least-privilege narrowing).
export function legitUsage(env: Environment, mandate: Record<string, unknown>): Map<string, Set<string>> {
  const usage = new Map<string, Set<string>>();
  for (const trace of env.legit) {
    const r = replay(env, mandate, trace);
    r.steps.forEach((s, i) => {
      const resource = resourceOf(trace.steps[i].tool, trace.steps[i].arguments);
      if (s.ruleId && resource) { if (!usage.has(s.ruleId)) usage.set(s.ruleId, new Set()); usage.get(s.ruleId)!.add(resource); }
    });
  }
  return usage;
}

// Typed repair operators. Each fires on root-cause facts, not on scenario identity.
export function candidates(rc: RootCause, mandate: Record<string, unknown>, usage: Map<string, Set<string>>): Candidate[] {
  const out: Candidate[] = [];
  const v = rc.violation;
  const add = (operator: string, summary: string, patch: PatchOp[], complexity: number) =>
    out.push({ id: `${operator}:${digest(patch).slice(0, 10)}`, operator, summary, patch, complexity });
  const rules = (mandate.allow as Rule[]) ?? [];
  const sinkKind = BUILTIN_CONTRACTS[v.sink]?.resource.kind;

  // Data-flow rules over the labelled source (exact asset, its folder, or any covering protected scope).
  if (v.property === 'confidential-flow' || v.property === 'credential-flow') {
    const scopes = new Set<string>();
    for (const s of rc.sources) {
      if (s.class === 'credential') scopes.add('credential');
      scopes.add(s.resource);
      const dir = parent(s.resource);
      if (dir) scopes.add(dir);
      for (const p of (mandate.protected as string[] | undefined) ?? []) if (s.resource.startsWith(p)) scopes.add(p);
    }
    for (const from of scopes) for (const effect of ['deny', 'approval'] as const) for (const match of ['content', 'session'] as const) {
      add('flow-rule', `${match === 'content' ? 'Content' : 'Any session data'} from ${from} reaching ${v.sink}: ${effect}`,
        [{ op: 'add', path: '/flows/-', value: { from: [from], to: [v.sink], effect, match } }], 1);
    }
  }
  // Least privilege: narrow the matched broad rule to what legitimate traces used, optionally
  // keeping the rest of the original scope behind human approval.
  const index = rules.findIndex((r, i) => (r.id ?? `allow-${i}`) === rc.ruleId);
  if (rc.causes.includes('ALLOW_RULE_BROAD') && index >= 0) {
    const used = [...(usage.get(rc.ruleId!) ?? [])].sort();
    if (used.length > 0) {
      const narrowed: PatchOp = { op: 'replace', path: `/allow/${index}/resources`, value: used };
      add('narrow-allow', `Narrow ${rc.ruleId} to ${used.length} resource(s) used by legitimate tasks`, [narrowed], used.length);
      add('split-approval', `Narrow ${rc.ruleId}; the rest of its scope requires approval`, [narrowed,
        { op: 'add', path: '/allow/-', value: { id: `${rc.ruleId}-review`, tools: rules[index].tools, resources: rules[index].resources, approval: true } }], used.length + 1);
    }
  }
  // Deny the concrete target, and its enclosing scope.
  if (v.sink !== 'read_file') {
    add('deny-target', `Deny ${v.sink} to ${v.target}`, [{ op: 'add', path: '/deny/-', value: { tools: [v.sink], resources: [v.target] } }], 1);
    const scope = sinkKind === 'email' ? '@' + v.target.split('@')[1] : sinkKind === 'path' || sinkKind === 'url' ? parent(v.target) : null;
    if (scope && scope !== 'https://' && !scope.endsWith('//')) add('deny-scope', `Deny ${v.sink} to ${scope}`, [{ op: 'add', path: '/deny/-', value: { tools: [v.sink], resources: [scope] } }], 1);
  }
  if (v.property === 'untrusted-target' || rc.factors.includes('TARGET_FROM_UNTRUSTED') || rc.factors.includes('UNATTRIBUTED_TARGET')) {
    const current = (mandate.trustedTargets as string[] | undefined) ?? [];
    if (!current.includes(v.sink)) add('trusted-target', `${v.sink} targets must be named by the user or mandate`, [{ op: 'replace', path: '/trustedTargets', value: [...current, v.sink] }], 1);
  }
  if (rc.causes.includes('CONFIDENTIAL_SOURCE_UNPROTECTED') && v.asset) {
    const protectedNow = (mandate.protected as string[] | undefined) ?? [];
    for (const scope of [v.asset, parent(v.asset)].filter((x): x is string => !!x)) {
      add('protect-source', `Protect ${scope} (explicit grant + approval required)`, [{ op: 'replace', path: '/protected', value: [...protectedNow, scope] }], 1);
    }
    add('protect-and-grant', `Protect ${v.asset} but keep it readable with approval`, [{ op: 'replace', path: '/protected', value: [...protectedNow, v.asset] },
      { op: 'add', path: '/allow/-', value: { tools: ['read_file'], resources: [v.asset], approval: true } }], 2);
  }
  if (rc.causes.includes('RISK_BELOW_THRESHOLD')) {
    const t = (mandate.thresholds as { approval: number; block: number } | undefined) ?? { approval: 40, block: 70 };
    if (rc.score < t.approval) add('threshold', `Lower the global approval threshold to ${rc.score}`, [{ op: 'replace', path: '/thresholds', value: { approval: Math.max(1, rc.score), block: t.block } }], 3);
  }
  add('deny-tool', `Deny ${v.sink} entirely (naive)`, [{ op: 'add', path: '/deny/-', value: { tools: [v.sink], resources: ['*'] } }], 1);
  return out;
}

// Groups vulnerabilities that share a root cause so each group is analyzed once.
export const signature = (rc: RootCause) => [rc.violation.property, rc.violation.sink, rc.ruleId, rc.sources.map(s => s.resource).join('+'), rc.causes.join('+')].join('|');
