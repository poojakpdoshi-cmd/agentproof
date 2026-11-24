import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { record, keys } from '../validation.ts';
import { canonical, digest, hmac, safeEqual, sha256 } from './canonical.ts';
import { BUILTIN_CONTRACTS, commandFlags, parseAction } from './contracts.ts';
import type { Contract, ParsedAction } from './contracts.ts';
import { JAILBREAK_SIGNALS, detectInjection } from './injection.ts';
import { EvidenceLedger } from './ledger.ts';
import type { Anchor } from './ledger.ts';
import { parseMandate, protectedScope, ruleMatches } from './mandate.ts';
import type { Mandate } from './mandate.ts';
import { SOURCES, TaintTracker, targetOrigin, trusted } from './provenance.ts';
import type { Segment } from './provenance.ts';
import { findSecrets, redactText, redactValue, secretTypes } from './redact.ts';
import { HARD_BLOCK, WEIGHTS, classify, level, total } from './risk.ts';
import type { Factor, RiskLevel } from './risk.ts';

export type DecisionKind = 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL';
export type ToolAction = { tool: string; arguments: Record<string, unknown> };
export type EvaluateRequest = { agent: string; mandate: string; session?: string; action: unknown; context?: unknown };
export type Verdict = Readonly<{
  actionId: string; decision: DecisionKind; risk: Readonly<{ score: number; level: RiskLevel; factors: readonly Factor[] }>;
  reasons: readonly string[]; threats: readonly string[]; policyId: string; ruleId?: string; tool: string; effect?: string;
  resource?: string; actionDigest: string; timestamp: string; latencyMs: number; evidence?: Anchor; token?: string; session: string;
}>;
export type ExternalVerdict = { outcome: 'allow' | 'deny' | 'review_required' | 'unknown'; reason?: string; code?: string; reference?: string };
// Provider-neutral second opinion (AgntID adapter, an internal PDP, ...). Most restrictive wins.
export interface Authorizer { readonly name: string; authorize(input: { verdict: Verdict; action: ToolAction; mandate: Mandate; agent: string }): Promise<ExternalVerdict> }
export interface Executor { readonly name: string; execute(action: ToolAction, context: { actionId: string; mandate: Mandate; agent: string; session: string }): Promise<unknown> }
export type ExecutionResult = { ok: true; actionId: string; output: unknown; secretsRedacted: number; injectionSignals: string[] }
  | { ok: false; actionId?: string; code: string };

type Pending = { verdict: Verdict; action: ToolAction; mandate: Mandate; agent: string; approved: boolean };
type Session = { calls: Map<string, number>; taint: TaintTracker; observed: Segment[] };
export type FirewallOptions = {
  mandates: unknown[]; contracts?: Record<string, Contract>; ledger?: EvidenceLedger; key?: Buffer; clock?: () => Date;
  ids?: () => string; executor?: Executor; authorizer?: Authorizer; authorizerTimeoutMs?: number; tokenTtlMs?: number; redactOutputs?: boolean;
};

const clip = (value: unknown): unknown => {
  if (typeof value === 'string') return value.length > 512 ? value.slice(0, 256) + `…[${value.length} chars sha256:${sha256(value).slice(0, 16)}]` : value;
  if (Array.isArray(value)) return value.slice(0, 32).map(clip);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).slice(0, 32).map(([k, v]) => [k, clip(v)]));
  return value;
};
const textOf = (output: unknown): string => {
  if (typeof output === 'string') return output;
  if (record(output) && Array.isArray(output.content)) {
    const blocks = output.content.map(block => record(block) && typeof block.text === 'string' ? block.text : '');
    if (Object.hasOwn(output, 'structuredContent')) { try { blocks.push(JSON.stringify(output.structuredContent) ?? ''); } catch { /* ignore */ } }
    return blocks.join('\n');
  }
  try { return JSON.stringify(output) ?? ''; } catch { return ''; }
};
function redactOutput(output: unknown): unknown {
  if (typeof output === 'string') return redactText(output);
  if (record(output) && Array.isArray(output.content)) {
    return { ...output, content: output.content.map(block => record(block) && typeof block.text === 'string' ? { ...block, text: redactText(block.text) } : block),
      ...(Object.hasOwn(output, 'structuredContent') ? { structuredContent: redactValue(output.structuredContent) } : {}) };
  }
  return redactValue(output);
}

export class Firewall {
  #mandates = new Map<string, Mandate>();
  #contracts: Record<string, Contract>;
  #sessions = new Map<string, Session>();
  #pending = new Map<string, Pending>();
  #nonces = new Set<string>();
  #key: Buffer;
  #clock: () => Date;
  #ids: () => string;
  #options: FirewallOptions;
  readonly ledger: EvidenceLedger;

  constructor(options: FirewallOptions) {
    this.#options = options;
    this.#contracts = options.contracts ?? BUILTIN_CONTRACTS;
    this.#key = options.key ?? randomBytes(32);
    this.#clock = options.clock ?? (() => new Date());
    this.#ids = options.ids ?? (() => 'act_' + randomBytes(8).toString('hex'));
    this.ledger = options.ledger ?? new EvidenceLedger({ clock: this.#clock });
    for (const input of options.mandates) {
      const mandate = parseMandate(input, this.#contracts);
      if (this.#mandates.has(mandate.id)) throw new Error('Duplicate mandate id');
      this.#mandates.set(mandate.id, mandate);
      this.ledger.append('mandate', { mandate: mandate.id, version: mandate.version, agent: mandate.agent, user: mandate.user,
        objective: mandate.objective, expiresAt: new Date(mandate.expiresAt).toISOString(),
        allow: mandate.allow.map(r => ({ id: r.id, tools: r.tools, resources: r.resources, approval: r.approval, maxCalls: r.maxCalls })),
        deny: mandate.deny.map(r => ({ id: r.id, tools: r.tools, resources: r.resources })), protected: mandate.protected, thresholds: mandate.thresholds });
    }
  }

  #session(id: string): Session {
    let session = this.#sessions.get(id);
    if (!session) { session = { calls: new Map(), taint: new TaintTracker(), observed: [] }; this.#sessions.set(id, session); }
    return session;
  }

  // Record content entering the agent's context outside execute() (e.g. relayed by a proxy).
  observe(sessionId: string, source: Segment['source'], text: string, sensitive = false): { secrets: number; injection: string[] } {
    const session = this.#session(sessionId);
    if (!trusted(source)) session.observed.push(Object.freeze({ source, text: text.slice(0, 64 * 1024) }));
    if (session.observed.length > 64) session.observed.shift();
    if (sensitive) session.taint.addSensitive(text);
    const secrets = session.taint.addSecrets(text);
    return { secrets, injection: trusted(source) ? [] : detectInjection(text).signals };
  }

  // Synchronous, local-only decision. No await between policy checks and counter updates.
  evaluate(request: EvaluateRequest): Verdict {
    const started = performance.now();
    const actionId = this.#ids();
    const timestamp = this.#clock().toISOString();
    const factors: Factor[] = [];
    const reasons: string[] = [];
    const req = request as unknown;
    const sessionId = record(req) && typeof req.session === 'string' && req.session.length <= 128 ? req.session : 'default';
    const mandate = record(req) && typeof req.mandate === 'string' ? this.#mandates.get(req.mandate) : undefined;
    const rawAction = record(req) ? req.action : undefined;
    let actionDigest = '';
    try { actionDigest = digest(rawAction ?? null); } catch { actionDigest = sha256('non-canonical'); }
    const finish = (decision: DecisionKind, parsed?: ParsedAction, ruleId?: string): Verdict => {
      const score = total(factors);
      const reasonList = [...new Set([...reasons, ...factors.map(f => f.code)])];
      const verdict: Verdict = {
        actionId, decision, risk: Object.freeze({ score, level: decision === 'BLOCK' && reasons.some(r => (HARD_BLOCK as readonly string[]).includes(r)) && score < 50 ? 'HIGH' : level(score), factors: Object.freeze(factors) }),
        reasons: Object.freeze(reasonList), threats: Object.freeze(classify(reasonList, parsed?.effect)),
        policyId: mandate ? `${mandate.id}@${mandate.version}` : 'none', ...(ruleId ? { ruleId } : {}),
        tool: parsed?.tool ?? (record(rawAction) && typeof rawAction.tool === 'string' ? rawAction.tool.slice(0, 64) : 'unknown'),
        ...(parsed ? { effect: parsed.effect, resource: redactText(parsed.resource) } : {}),
        actionDigest, timestamp, latencyMs: Math.round((performance.now() - started) * 1000) / 1000, session: sessionId,
      };
      return this.#record(verdict, request, parsed, mandate);
    };

    if (!record(req) || !keys(req, ['agent', 'mandate', 'session', 'action', 'context'], ['agent', 'mandate', 'action'])
      || typeof req.agent !== 'string') { reasons.push('INVALID_REQUEST'); return finish('BLOCK'); }
    if (!mandate) { reasons.push('UNKNOWN_MANDATE'); return finish('BLOCK'); }
    if (req.agent !== mandate.agent) { reasons.push('IDENTITY_MISMATCH'); return finish('BLOCK'); }
    const now = this.#clock().getTime();
    if (now >= mandate.expiresAt) { reasons.push('MANDATE_EXPIRED'); return finish('BLOCK'); }
    if (mandate.notBefore !== undefined && now < mandate.notBefore) { reasons.push('MANDATE_NOT_YET_VALID'); return finish('BLOCK'); }
    const segments: Segment[] = [];
    if (Object.hasOwn(req, 'context')) {
      if (!Array.isArray(req.context) || req.context.length > 256 || !req.context.every(s => record(s) && keys(s, ['source', 'text', 'id'], ['source', 'text'])
        && SOURCES.includes(s.source as Segment['source']) && typeof s.text === 'string' && s.text.length <= 256 * 1024)) {
        reasons.push('INVALID_REQUEST'); return finish('BLOCK');
      }
      segments.push(...(req.context as Segment[]));
    }
    const parsed = parseAction(rawAction, this.#contracts);
    if ('error' in parsed) { reasons.push(parsed.error); return finish('BLOCK'); }
    const session = this.#session(sessionId);
    const context = [...segments, ...session.observed];

    // 1. Deterministic authorization: explicit deny > protected scope > allow rules. Deny by default.
    const denied = mandate.deny.find(rule => ruleMatches(rule, parsed));
    const allowed = mandate.allow.filter(rule => ruleMatches(rule, parsed));
    if (denied && allowed.length > 0) factors.push({ code: 'POLICY_CONFLICT', points: WEIGHTS.policyConflict, detail: `deny rule ${denied.id} overrides allow rule ${allowed[0].id}` });
    const scope = protectedScope(mandate, parsed);
    let forceApproval = false;
    if (scope.hit) {
      factors.push({ code: 'PROTECTED_RESOURCE_ACCESS', points: WEIGHTS.protectedResource, detail: 'target is inside a protected scope' });
      if (!scope.explicit) reasons.push('PROTECTED_RESOURCE');
      forceApproval = true;
    }
    if (denied) reasons.push('EXPLICIT_DENY');
    else if (allowed.length === 0) reasons.push('NOT_IN_MANDATE');
    const rule = allowed.find(r => !r.approval) ?? allowed[0];
    if (rule?.approval) forceApproval = true;
    if (rule?.maxCalls !== undefined && (session.calls.get(rule.id) ?? 0) >= rule.maxCalls) reasons.push('RATE_LIMIT');

    // 2. Context and instruction-origin analysis.
    let untrustedScore = 0, directScore = 0;
    const signals = new Set<string>();
    for (const segment of context) {
      const result = detectInjection(segment.text, 0, trusted(segment.source) ? JAILBREAK_SIGNALS : undefined);
      result.signals.forEach(s => signals.add(s));
      if (trusted(segment.source)) directScore = Math.max(directScore, result.score);
      else untrustedScore = Math.max(untrustedScore, result.score);
    }
    if (untrustedScore > 0) factors.push({ code: 'INJECTION_IN_UNTRUSTED_CONTEXT', points: Math.round(WEIGHTS.injectionInUntrustedContext * untrustedScore), detail: `detector score ${untrustedScore}: ${[...signals].join(', ')}` });
    if (directScore > 0) factors.push({ code: 'DIRECT_INJECTION', points: Math.round(WEIGHTS.directInjection * directScore), detail: `detector score ${directScore} in trusted input` });
    const origin = targetOrigin(parsed, mandate, context);
    if (origin === 'untrusted') factors.push({ code: 'TARGET_FROM_UNTRUSTED', points: WEIGHTS.targetFromUntrusted(parsed.effect), detail: 'target appears only in untrusted content' });
    else if (origin === 'unattributed' && WEIGHTS.unattributedTarget(parsed.effect) > 0) factors.push({ code: 'UNATTRIBUTED_TARGET', points: WEIGHTS.unattributedTarget(parsed.effect), detail: 'target not named by the user or mandate' });

    // 3. Data flow: credentials and protected content leaving through arguments.
    const outbound = parsed.outbound.join('\n');
    if (outbound) {
      const secretFound = parsed.outbound.some(text => findSecrets(text).length > 0);
      if (secretFound && WEIGHTS.secretInOutbound(parsed.effect) > 0) factors.push({ code: 'SECRET_IN_OUTBOUND', points: WEIGHTS.secretInOutbound(parsed.effect), detail: `credential pattern in outbound data: ${secretTypes(outbound).join(', ')}` });
      if (session.taint.matches(outbound) && WEIGHTS.sensitiveDataFlow(parsed.effect) > 0) factors.push({ code: 'SENSITIVE_DATA_FLOW', points: WEIGHTS.sensitiveDataFlow(parsed.effect), detail: 'outbound data contains content read from a sensitive source' });
      if (session.taint.confidential && ['egress', 'send', 'execute'].includes(parsed.effect)) {
        factors.push({ code: 'CONFIDENTIAL_CONTEXT', points: WEIGHTS.confidentialContext, detail: 'session context holds protected content or credentials' });
      }
      const propagated = detectInjection(outbound);
      if (propagated.score >= 0.5) factors.push({ code: 'INJECTION_IN_OUTBOUND', points: WEIGHTS.injectionInOutbound, detail: `outbound content carries instructions: ${propagated.signals.join(', ')}` });
    }

    // 4. Operation semantics.
    if (parsed.effect === 'egress' || parsed.effect === 'send') factors.push({ code: 'EXTERNAL_EGRESS', points: WEIGHTS.externalEgress, detail: `data leaves via ${parsed.tool}${parsed.host ? ' to ' + parsed.host : ''}` });
    if (parsed.effect === 'egress' && (typeof parsed.arguments.body === 'string' || !['GET', 'HEAD', undefined].includes(parsed.arguments.method as string | undefined))) {
      factors.push({ code: 'OUTBOUND_PAYLOAD', points: WEIGHTS.outboundPayload, detail: `uploads data with ${String(parsed.arguments.method ?? 'GET')}` });
    }
    if (parsed.destructive) factors.push({ code: 'DESTRUCTIVE_OPERATION', points: WEIGHTS.destructive, detail: `${parsed.tool} is destructive` });
    if (parsed.effect === 'admin' || (parsed.effect === 'execute' && commandFlags(parsed.resource).privileged)) factors.push({ code: 'PRIVILEGE_ESCALATION', points: WEIGHTS.privilegeEscalation, detail: 'action changes privileges or runs privileged commands' });
    if (parsed.effect === 'execute' && commandFlags(parsed.resource).chained) factors.push({ code: 'COMMAND_CHAINING', points: WEIGHTS.commandChaining, detail: 'command contains chaining, piping or substitution' });

    // 5. Decision: hard reasons block; otherwise thresholds and forced approvals escalate.
    const score = total(factors);
    if (reasons.length > 0 || score >= mandate.thresholds.block) return finish('BLOCK', parsed, rule?.id);
    if (rule) session.calls.set(rule.id, (session.calls.get(rule.id) ?? 0) + 1);
    if (forceApproval || score >= mandate.thresholds.approval) return finish('REQUIRE_APPROVAL', parsed, rule?.id);
    return finish('ALLOW', parsed, rule?.id);
  }

  #record(verdict: Verdict, request: EvaluateRequest, parsed: ParsedAction | undefined, mandate: Mandate | undefined): Verdict {
    const req = request as unknown;
    const context = record(req) && Array.isArray(req.context) ? req.context : [];
    const entry = this.ledger.append('decision', {
      actionId: verdict.actionId, session: verdict.session, agent: record(req) && typeof req.agent === 'string' ? req.agent.slice(0, 128) : null,
      policyId: verdict.policyId, ruleId: verdict.ruleId ?? null, objective: mandate?.objective ?? null,
      action: parsed ? { tool: parsed.tool, effect: parsed.effect, resource: parsed.resource, arguments: clip(parsed.arguments) } : { tool: verdict.tool },
      actionDigest: verdict.actionDigest,
      context: { segments: context.length, untrusted: context.filter(s => record(s) && typeof s.source === 'string' && !trusted(s.source as Segment['source'])).length },
      decision: verdict.decision, risk: verdict.risk, reasons: verdict.reasons, threats: verdict.threats, latencyMs: verdict.latencyMs,
    });
    let token: string | undefined;
    if (parsed && mandate && verdict.decision !== 'BLOCK') {
      this.#pending.set(verdict.actionId, { verdict, action: { tool: parsed.tool, arguments: { ...parsed.arguments } }, mandate,
        agent: (req as { agent: string }).agent, approved: verdict.decision === 'ALLOW' });
      if (this.#pending.size > 10_000) this.#pending.delete(this.#pending.keys().next().value!);
      if (verdict.decision === 'ALLOW') token = this.#issue(verdict, mandate);
    }
    return Object.freeze({ ...verdict, evidence: { seq: entry.seq, hash: entry.hash }, ...(token ? { token } : {}) });
  }

  #issue(verdict: Verdict, mandate: Mandate): string {
    const expires = Math.min(this.#clock().getTime() + (this.#options.tokenTtlMs ?? 60_000), mandate.expiresAt);
    const payload = Buffer.from(canonical({ a: verdict.actionId, d: verdict.actionDigest, m: verdict.policyId, s: verdict.session,
      e: expires, n: randomBytes(12).toString('hex') })).toString('base64url');
    return payload + '.' + hmac(this.#key, payload);
  }

  // Local decision plus an optional external authorizer. Unavailable, slow, malformed or
  // unknown external answers fail closed: the action is blocked, never silently allowed.
  async decide(request: EvaluateRequest): Promise<Verdict> {
    const local = this.evaluate(request);
    const authorizer = this.#options.authorizer;
    if (!authorizer || local.decision === 'BLOCK') return local;
    const pending = this.#pending.get(local.actionId)!;
    let external: ExternalVerdict;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      external = await Promise.race([
        authorizer.authorize({ verdict: local, action: pending.action, mandate: pending.mandate, agent: pending.agent }),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), this.#options.authorizerTimeoutMs ?? 2000); }),
      ]);
      if (!record(external) || !['allow', 'deny', 'review_required', 'unknown'].includes(external.outcome)) throw new Error('malformed');
    } catch {
      external = { outcome: 'unknown', code: 'AUTHZ_UNAVAILABLE' };
    } finally { clearTimeout(timer); }
    const entry = this.ledger.append('external-authorization', { actionId: local.actionId, authorizer: authorizer.name,
      outcome: external.outcome, code: external.code ?? null, reason: external.reason?.slice(0, 300) ?? null, reference: external.reference ?? null });
    const evidence = { seq: entry.seq, hash: entry.hash };
    if (external.outcome === 'allow') return Object.freeze({ ...local, evidence });
    const { token: _drop, ...rest } = local;
    if (external.outcome === 'review_required') {
      pending.approved = false;
      return Object.freeze({ ...rest, decision: 'REQUIRE_APPROVAL' as const, reasons: [...local.reasons, 'EXTERNAL_REVIEW'], evidence });
    }
    this.#pending.delete(local.actionId);
    const code = external.outcome === 'deny' ? 'EXTERNAL_DENY' : 'AUTHZ_UNAVAILABLE';
    return Object.freeze({ ...rest, decision: 'BLOCK' as const, reasons: [...local.reasons, code],
      threats: classify([...local.reasons, code], local.effect as never), evidence });
  }

  // Human-in-the-loop resolution of a REQUIRE_APPROVAL verdict. Approval issues a one-time token.
  approve(actionId: string, approver: string, approved: boolean): { ok: boolean; token?: string; code?: string } {
    const pending = this.#pending.get(actionId);
    if (!pending || pending.verdict.decision !== 'REQUIRE_APPROVAL' || pending.approved) return { ok: false, code: 'NO_PENDING_APPROVAL' };
    if (typeof approver !== 'string' || !/^[A-Za-z0-9._@:-]{1,128}$/.test(approver) || approver === pending.agent) return { ok: false, code: 'INVALID_APPROVER' };
    this.ledger.append('approval', { actionId, approver, approved, actionDigest: pending.verdict.actionDigest });
    if (!approved) { this.#pending.delete(actionId); return { ok: true }; }
    if (this.#clock().getTime() >= pending.mandate.expiresAt) { this.#pending.delete(actionId); return { ok: false, code: 'MANDATE_EXPIRED' }; }
    pending.approved = true;
    return { ok: true, token: this.#issue(pending.verdict, pending.mandate) };
  }

  // Verifies that the action about to run is exactly the one that was authorized. One-time use.
  consume(token: unknown, action: unknown): { ok: true; actionId: string; pending: Pending } | { ok: false; actionId?: string; code: string } {
    const fail = (code: string, actionId?: string) => {
      this.ledger.append('binding-violation', { code, actionId: actionId ?? null });
      return { ok: false as const, code, ...(actionId ? { actionId } : {}) };
    };
    if (typeof token !== 'string' || token.length > 2048) return fail('INVALID_TOKEN');
    const [payload, mac] = token.split('.');
    if (!payload || !mac || !safeEqual(hmac(this.#key, payload), mac)) return fail('INVALID_TOKEN');
    let claims: { a: string; d: string; m: string; s: string; e: number; n: string };
    try { claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); } catch { return fail('INVALID_TOKEN'); }
    if (this.#nonces.has(claims.n)) return fail('TOKEN_REPLAY', claims.a);
    this.#nonces.add(claims.n);
    if (this.#clock().getTime() > claims.e) return fail('TOKEN_EXPIRED', claims.a);
    const pending = this.#pending.get(claims.a);
    if (!pending || !pending.approved) return fail('NOT_AUTHORIZED', claims.a);
    let presented = '';
    try { presented = digest(action); } catch { /* non-canonical */ }
    if (!safeEqual(presented, claims.d) || !safeEqual(presented, pending.verdict.actionDigest)) {
      this.#pending.delete(claims.a);
      return fail('DECISION_EXECUTION_MISMATCH', claims.a);
    }
    if (this.#clock().getTime() >= pending.mandate.expiresAt) return fail('MANDATE_EXPIRED', claims.a);
    this.#pending.delete(claims.a);
    return { ok: true, actionId: claims.a, pending };
  }

  // Controlled execution: binding check -> executor -> output verification -> evidence.
  async execute(token: unknown, action: unknown): Promise<ExecutionResult> {
    const executor = this.#options.executor;
    if (!executor) return { ok: false, code: 'NO_EXECUTOR' };
    const bound = this.consume(token, action);
    if (!bound.ok) return bound;
    const { pending, actionId } = bound;
    let output: unknown;
    try {
      output = await executor.execute(pending.action, { actionId, mandate: pending.mandate, agent: pending.agent, session: pending.verdict.session });
    } catch (error) {
      const raw = error instanceof Error ? (error as Error & { code?: unknown; details?: unknown }) : undefined;
      const code = typeof raw?.code === 'string' && /^[A-Z][A-Z0-9_]{0,39}$/.test(raw.code) ? raw.code : 'EXECUTION_FAILED';
      this.ledger.append('execution', { actionId, executor: executor.name, status: 'error', code, details: clip(raw?.details ?? null) });
      return { ok: false, actionId, code };
    }
    return this.verifyOutput(actionId, pending.verdict.session, output, executor.name, pending.mandate, pending.action);
  }

  // Output verification: secrets are redacted before the agent sees them; injected
  // instructions are flagged and remembered as untrusted context for later decisions.
  verifyOutput(actionId: string, sessionId: string, output: unknown, executor: string, mandate?: Mandate, action?: ToolAction): ExecutionResult & { ok: true } {
    const text = textOf(output);
    let sensitive = false;
    if (mandate && action) {
      const parsed = parseAction(action, this.#contracts);
      sensitive = !('error' in parsed) && protectedScope(mandate, parsed).hit;
    }
    const observed = this.observe(sessionId, 'tool', text, sensitive);
    const redact = this.#options.redactOutputs !== false && observed.secrets > 0;
    const delivered = redact ? redactOutput(output) : output;
    this.ledger.append('execution', { actionId, executor, status: 'ok', outputDigest: sha256(text), outputBytes: Buffer.byteLength(text),
      secretsRedacted: redact ? observed.secrets : 0, injectionSignals: observed.injection, sensitiveSource: sensitive, preview: clip(redactText(text.slice(0, 300))) });
    return { ok: true, actionId, output: delivered, secretsRedacted: redact ? observed.secrets : 0, injectionSignals: observed.injection };
  }

  mandate(id: string): Mandate | undefined { return this.#mandates.get(id); }
}
