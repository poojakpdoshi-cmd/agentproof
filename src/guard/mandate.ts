import { canonicalPath } from '../paths.ts';
import { keys, record, stringList } from '../validation.ts';
import { digest } from './canonical.ts';
import { canonicalCommand, canonicalEmail, canonicalUrl } from './contracts.ts';
import type { Contract, ParsedAction, ResourceKind } from './contracts.ts';

// An intent mandate is the operator-approved, machine-checkable form of the user's objective:
// which tools may touch which resources, until when, and which need a human. Deny by default.
export type Rule = Readonly<{ id: string; tools: readonly string[]; resources: readonly string[]; approval: boolean; maxCalls?: number }>;
// Data-flow rule: content from matching sources (path patterns, or 'credential') reaching the
// listed tools requires approval or is denied. 'content' matches the outbound data itself;
// 'session' triggers once such a source has entered the session at all (coarser, stricter).
export type FlowRule = Readonly<{ id: string; from: readonly string[]; to: readonly string[]; effect: 'approval' | 'deny'; match: 'content' | 'session' }>;
export type Classification = Readonly<{ resource: string; class: 'public' | 'confidential' | 'credential'; confidence: number; authority: 'operator' }>;
export type Declassification = Readonly<{ from: readonly string[]; tools: readonly string[]; resources: readonly string[]; effect: 'allow' | 'approval' | 'deny' }>;
export type IntentScope = Readonly<{ tools: readonly string[]; resources: readonly string[]; authority: 'operator' }>;
export type Mandate = Readonly<{
  id: string; version: string; agent: string; user: string; objective: string;
  notBefore?: number; expiresAt: number;
  allow: readonly Rule[]; deny: readonly Rule[]; protected: readonly string[];
  thresholds: Readonly<{ approval: number; block: number }>;
  flows: readonly FlowRule[]; trustedTargets: readonly string[];
  intentScopes: readonly IntentScope[];
  classifications: readonly Classification[]; enforceLineage: boolean; declassifications: readonly Declassification[];
}>;

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

// Normalizes a resource pattern for one resource kind; null means the pattern cannot apply.
export function normalizePattern(pattern: string, kind: ResourceKind): string | null {
  if (pattern === '*') return '*';
  switch (kind) {
    case 'path': {
      const directory = pattern.endsWith('/');
      const value = canonicalPath(directory ? pattern.slice(0, -1) : pattern);
      return value === null ? null : value + (directory ? '/' : '');
    }
    case 'url': {
      const parsed = canonicalUrl(pattern);
      return parsed && !parsed.query ? parsed.url : null;
    }
    case 'email': return pattern.startsWith('@') ? (canonicalEmail('x' + pattern) ? pattern.toLowerCase() : null) : canonicalEmail(pattern);
    case 'command': {
      const wildcard = pattern.endsWith(' *');
      const value = canonicalCommand(wildcard ? pattern.slice(0, -2) : pattern);
      return value === null ? null : value + (wildcard ? ' *' : '');
    }
    case 'principal': return /^[A-Za-z0-9._@-]{1,256}$/.test(pattern) ? pattern.toLowerCase() : null;
  }
}

export function patternMatches(pattern: string, resource: string, kind: ResourceKind): boolean {
  if (pattern === '*') return true;
  switch (kind) {
    case 'path': case 'url': return pattern.endsWith('/') ? resource.startsWith(pattern) : resource === pattern;
    case 'email': return pattern.startsWith('@') ? resource.endsWith(pattern) : resource === pattern;
    case 'command': {
      if (!pattern.endsWith(' *')) return resource === pattern;
      // Prefix grants never cover chained or substituted commands.
      const prefix = pattern.slice(0, -2);
      return !/[;&|`<>]|\$\(/.test(resource) && (resource === prefix || resource.startsWith(prefix + ' '));
    }
    case 'principal': return resource === pattern;
  }
}

function parseRule(value: unknown, index: number, contracts: Record<string, Contract>, kind: 'allow' | 'deny'): Rule {
  if (!record(value) || !keys(value, ['id', 'tools', 'resources', 'approval', 'maxCalls'], ['tools', 'resources'])
    || !stringList(value.tools) || value.tools.length === 0 || !stringList(value.resources) || value.resources.length === 0
    || (Object.hasOwn(value, 'id') && (typeof value.id !== 'string' || !ID.test(value.id)))
    || (Object.hasOwn(value, 'approval') && typeof value.approval !== 'boolean')
    || (Object.hasOwn(value, 'maxCalls') && (!Number.isSafeInteger(value.maxCalls) || (value.maxCalls as number) < 1))) {
    throw new Error(`Invalid mandate ${kind} rule ${index}`);
  }
  const tools = value.tools.includes('*') ? ['*'] : value.tools;
  for (const tool of tools) if (tool !== '*' && !Object.hasOwn(contracts, tool)) throw new Error(`Unknown tool in ${kind} rule ${index}`);
  // Every named tool must understand every pattern; '*' tools apply patterns per kind.
  if (!tools.includes('*')) {
    for (const tool of tools) for (const pattern of value.resources) {
      if (normalizePattern(pattern, contracts[tool].resource.kind) === null) throw new Error(`Invalid resource in ${kind} rule ${index}`);
    }
  }
  return Object.freeze({ id: (value.id as string | undefined) ?? `${kind}-${index}`, tools: Object.freeze([...tools]),
    resources: Object.freeze([...value.resources]), approval: value.approval === true,
    ...(Object.hasOwn(value, 'maxCalls') ? { maxCalls: value.maxCalls as number } : {}) });
}

export function parseMandate(input: unknown, contracts: Record<string, Contract>): Mandate {
  if (!record(input) || !keys(input, ['id', 'subject', 'objective', 'notBefore', 'expiresAt', 'allow', 'deny', 'protected', 'thresholds', 'flows', 'trustedTargets', 'intentScopes', 'classifications', 'enforceLineage', 'declassifications'],
    ['id', 'subject', 'objective', 'expiresAt', 'allow'])) throw new Error('Invalid mandate');
  const { id, subject, objective } = input;
  if (typeof id !== 'string' || !ID.test(id) || !record(subject) || !keys(subject, ['agent', 'user'], ['agent', 'user'])
    || typeof subject.agent !== 'string' || !ID.test(subject.agent) || typeof subject.user !== 'string' || !ID.test(subject.user)
    || typeof objective !== 'string' || objective.length === 0 || objective.length > 4000) throw new Error('Invalid mandate identity');
  const time = (value: unknown) => {
    const parsed = typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(value) ? Date.parse(value) : NaN;
    if (!Number.isFinite(parsed)) throw new Error('Invalid mandate time');
    return parsed;
  };
  const expiresAt = time(input.expiresAt);
  const notBefore = Object.hasOwn(input, 'notBefore') ? time(input.notBefore) : undefined;
  if (notBefore !== undefined && notBefore >= expiresAt) throw new Error('Invalid mandate window');
  const list = (value: unknown, kind: 'allow' | 'deny') => {
    if (!Array.isArray(value) || value.length > 256) throw new Error(`Invalid mandate ${kind} list`);
    return Object.freeze(value.map((rule, i) => parseRule(rule, i, contracts, kind)));
  };
  const allow = list(input.allow, 'allow');
  const deny = Object.hasOwn(input, 'deny') ? list(input.deny, 'deny') : Object.freeze([]);
  const ids = [...allow, ...deny].map(rule => rule.id);
  if (new Set(ids).size !== ids.length) throw new Error('Duplicate mandate rule id');
  let protectedResources: string[] = [];
  if (Object.hasOwn(input, 'protected')) {
    if (!stringList(input.protected) || input.protected.includes('*')) throw new Error('Invalid protected resources');
    protectedResources = input.protected;
  }
  let thresholds = { approval: 40, block: 70 };
  if (Object.hasOwn(input, 'thresholds')) {
    const t = input.thresholds;
    if (!record(t) || !keys(t, ['approval', 'block'], ['approval', 'block']) || !Number.isSafeInteger(t.approval) || !Number.isSafeInteger(t.block)
      || (t.approval as number) < 1 || (t.approval as number) >= (t.block as number) || (t.block as number) > 100) throw new Error('Invalid thresholds');
    thresholds = { approval: t.approval as number, block: t.block as number };
  }
  const flows: FlowRule[] = [];
  if (Object.hasOwn(input, 'flows')) {
    if (!Array.isArray(input.flows) || input.flows.length > 256) throw new Error('Invalid flow rules');
    input.flows.forEach((f: unknown, i) => {
      if (!record(f) || !keys(f, ['id', 'from', 'to', 'effect', 'match'], ['from', 'to', 'effect']) || !stringList(f.from) || f.from.length === 0
        || !stringList(f.to) || f.to.length === 0 || (f.effect !== 'approval' && f.effect !== 'deny')
        || (Object.hasOwn(f, 'match') && f.match !== 'content' && f.match !== 'session')
        || (Object.hasOwn(f, 'id') && (typeof f.id !== 'string' || !ID.test(f.id)))
        || f.from.some(p => p !== 'credential' && normalizePattern(p, 'path') === null)
        || f.to.some(t => t !== '*' && !Object.hasOwn(contracts, t))) throw new Error(`Invalid flow rule ${i}`);
      flows.push(Object.freeze({ id: (f.id as string | undefined) ?? `flow-${i}`, from: Object.freeze([...f.from]), to: Object.freeze([...f.to]),
        effect: f.effect, match: (f.match as 'content' | 'session' | undefined) ?? 'content' }));
    });
  }
  let trustedTargets: string[] = [];
  if (Object.hasOwn(input, 'trustedTargets')) {
    if (!stringList(input.trustedTargets) || input.trustedTargets.some(t => !Object.hasOwn(contracts, t))) throw new Error('Invalid trusted targets');
    trustedTargets = input.trustedTargets;
  }
  const intentScopes: IntentScope[] = [];
  if (Object.hasOwn(input, 'intentScopes')) {
    if (!Array.isArray(input.intentScopes) || input.intentScopes.length > 256) throw new Error('Invalid intent scopes');
    for (const scope of input.intentScopes) {
      if (!record(scope) || !keys(scope, ['tools', 'resources', 'authority'], ['tools', 'resources', 'authority'])
        || !stringList(scope.tools) || scope.tools.length === 0 || !stringList(scope.resources) || scope.resources.length === 0
        || scope.authority !== 'operator' || scope.tools.some(t => !Object.hasOwn(contracts, t)
          || contracts[t].effect !== 'write' || contracts[t].resource.kind !== 'path')
        || scope.resources.some(p => normalizePattern(p, 'path') === null || p === '*')) throw new Error('Invalid intent scope');
      intentScopes.push(Object.freeze({ tools: Object.freeze([...scope.tools]), resources: Object.freeze([...scope.resources]), authority: 'operator' }));
    }
  }
  if (Object.hasOwn(input, 'enforceLineage') && typeof input.enforceLineage !== 'boolean') throw new Error('Invalid lineage setting');
  const classifications: Classification[] = [];
  if (Object.hasOwn(input, 'classifications')) {
    if (!Array.isArray(input.classifications) || input.classifications.length > 256) throw new Error('Invalid classifications');
    for (const item of input.classifications) {
      if (!record(item) || !keys(item, ['resource', 'class', 'confidence', 'authority'], ['resource', 'class', 'confidence', 'authority'])
        || typeof item.resource !== 'string' || normalizePattern(item.resource, 'path') === null || item.resource === '*'
        || !['public', 'confidential', 'credential'].includes(String(item.class)) || typeof item.confidence !== 'number'
        || !Number.isFinite(item.confidence) || item.confidence < 0 || item.confidence > 1 || item.authority !== 'operator') throw new Error('Invalid classification');
      classifications.push({ resource: item.resource, class: item.class as Classification['class'], confidence: item.confidence, authority: 'operator' });
    }
  }
  const declassifications: Declassification[] = [];
  if (Object.hasOwn(input, 'declassifications')) {
    if (!Array.isArray(input.declassifications) || input.declassifications.length > 256) throw new Error('Invalid declassifications');
    for (const item of input.declassifications) {
      if (!record(item) || !keys(item, ['from', 'tools', 'resources', 'effect'], ['from', 'tools', 'resources', 'effect'])
        || !stringList(item.from) || item.from.length === 0 || item.from.some(p => p !== 'credential' && normalizePattern(p, 'path') === null)
        || !stringList(item.tools) || item.tools.length === 0 || item.tools.some(t => !Object.hasOwn(contracts, t))
        || !stringList(item.resources) || item.resources.length === 0 || item.tools.some(t => (item.resources as string[]).some((p: string) => normalizePattern(p, contracts[t].resource.kind) === null))
        || !['allow', 'approval', 'deny'].includes(String(item.effect))
        || item.effect === 'allow' && item.resources.some((p: string) => p === '*' || p.endsWith('/') || p.startsWith('@'))) throw new Error('Invalid declassification');
      declassifications.push({ from: [...item.from], tools: [...item.tools], resources: [...item.resources], effect: item.effect as Declassification['effect'] });
    }
  }
  const allIds = [...ids, ...flows.map(f => f.id)];
  if (new Set(allIds).size !== allIds.length) throw new Error('Duplicate mandate rule id');
  return Object.freeze({ id, version: digest(input).slice(0, 16), agent: subject.agent, user: subject.user, objective,
    ...(notBefore === undefined ? {} : { notBefore }), expiresAt, allow, deny, protected: Object.freeze([...protectedResources]),
    thresholds: Object.freeze(thresholds), flows: Object.freeze(flows), trustedTargets: Object.freeze([...trustedTargets]),
    intentScopes: Object.freeze(intentScopes),
    classifications: Object.freeze(classifications), enforceLineage: input.enforceLineage === true, declassifications: Object.freeze(declassifications) });
}

// Does a taint label (canonical source path, or 'credential') fall under a flow rule's sources?
export function flowSourceMatches(rule: FlowRule, label: string): boolean {
  return rule.from.some(raw => sourcePatternMatches(raw, label));
}
export function sourcePatternMatches(raw: string, label: string): boolean {
  if (raw === 'credential' || label === 'credential') return raw === label;
  const pattern = normalizePattern(raw, 'path');
  return pattern !== null && patternMatches(pattern, label, 'path');
}

export function ruleMatches(rule: Rule, action: ParsedAction): boolean {
  if (!rule.tools.includes('*') && !rule.tools.includes(action.tool)) return false;
  const kind = action.contract.resource.kind;
  return rule.resources.some(raw => {
    const pattern = normalizePattern(raw, kind);
    return pattern !== null && patternMatches(pattern, action.resource, kind);
  });
}

// Protected scopes need an allow pattern at least as specific as the protected scope itself.
export function protectedScope(mandate: Mandate, action: ParsedAction): { hit: boolean; explicit: boolean } {
  const kind = action.contract.resource.kind;
  const scopes = mandate.protected.map(raw => normalizePattern(raw, kind)).filter((p): p is string => p !== null && p !== '*');
  const hits = scopes.filter(scope => patternMatches(scope, action.resource, kind));
  if (hits.length === 0) return { hit: false, explicit: false };
  const explicit = mandate.allow.some(rule => (rule.tools.includes(action.tool)) && rule.resources.some(raw => {
    const pattern = normalizePattern(raw, kind);
    return pattern !== null && pattern !== '*' && patternMatches(pattern, action.resource, kind)
      && hits.every(scope => pattern === scope || pattern.startsWith(scope) || (scope.startsWith('@') && pattern.endsWith(scope)));
  }));
  return { hit: true, explicit };
}
