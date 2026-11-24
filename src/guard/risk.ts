import type { Effect } from './contracts.ts';

// Explainable additive risk model. Every point in a score comes from a named factor with a
// fixed, documented weight (THREAT_MODEL.md / ARCHITECTURE.md). Scores never authorize an
// action on their own: hard policy reasons block first, scores only escalate allowed actions.
export type Factor = Readonly<{ code: string; points: number; detail: string }>;
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

const outboundEffect = (e: Effect) => e === 'egress' || e === 'send' || e === 'execute';
export const WEIGHTS = Object.freeze({
  injectionInUntrustedContext: 30, // multiplied by detector score (0..1)
  directInjection: 20, // multiplied by detector score for trusted user text
  targetFromUntrusted: (e: Effect) => e === 'read' ? 20 : e === 'write' ? 30 : 45,
  unattributedTarget: (e: Effect) => e === 'read' || e === 'write' ? 0 : 15,
  secretInOutbound: (e: Effect) => outboundEffect(e) ? 60 : e === 'write' ? 40 : 0,
  sensitiveDataFlow: (e: Effect) => outboundEffect(e) ? 70 : e === 'write' ? 30 : 0,
  externalEgress: 15,
  outboundPayload: 20, // egress that uploads a body or uses a non-GET/HEAD method
  destructive: 35,
  privilegeEscalation: 50,
  commandChaining: 20,
  protectedResource: 30,
  policyConflict: 20,
  injectionInOutbound: 25, // persisting or sending text that carries instructions (memory poisoning)
  confidentialContext: 30, // outbound action after protected content or credentials entered the session
});

export const HARD_BLOCK = Object.freeze(['INVALID_REQUEST', 'UNKNOWN_TOOL', 'INVALID_ARGUMENTS', 'INVALID_RESOURCE', 'UNKNOWN_MANDATE',
  'IDENTITY_MISMATCH', 'MANDATE_EXPIRED', 'MANDATE_NOT_YET_VALID', 'EXPLICIT_DENY', 'NOT_IN_MANDATE', 'PROTECTED_RESOURCE',
  'RATE_LIMIT', 'AUTHZ_UNAVAILABLE', 'EXTERNAL_DENY', 'FLOW_VIOLATION', 'UNTRUSTED_TARGET'] as const);

export const level = (score: number): RiskLevel => score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW';
export const total = (factors: readonly Factor[]) => Math.min(100, factors.reduce((sum, f) => sum + f.points, 0));

const THREATS: Record<string, string> = {
  INJECTION_IN_UNTRUSTED_CONTEXT: 'PROMPT_INJECTION', DIRECT_INJECTION: 'PROMPT_INJECTION', TARGET_FROM_UNTRUSTED: 'PROMPT_INJECTION',
  INJECTION_IN_OUTBOUND: 'PROMPT_INJECTION', OUTBOUND_PAYLOAD: 'DATA_EXFILTRATION', SECRET_IN_OUTBOUND: 'CREDENTIAL_EXPOSURE', SENSITIVE_DATA_FLOW: 'DATA_EXFILTRATION', CONFIDENTIAL_CONTEXT: 'DATA_EXFILTRATION',
  PRIVILEGE_ESCALATION: 'PRIVILEGE_ESCALATION', DESTRUCTIVE_OPERATION: 'DESTRUCTIVE_ACTION', COMMAND_CHAINING: 'COMMAND_INJECTION',
  NOT_IN_MANDATE: 'UNAUTHORIZED_ACCESS', EXPLICIT_DENY: 'UNAUTHORIZED_ACCESS', PROTECTED_RESOURCE: 'UNAUTHORIZED_ACCESS',
  IDENTITY_MISMATCH: 'IDENTITY_MISMATCH', MANDATE_EXPIRED: 'EXPIRED_AUTHORITY', MANDATE_NOT_YET_VALID: 'EXPIRED_AUTHORITY',
  UNKNOWN_MANDATE: 'UNAUTHORIZED_ACCESS', POLICY_CONFLICT: 'POLICY_CONFLICT', RATE_LIMIT: 'RATE_ABUSE',
  INVALID_REQUEST: 'MALFORMED_INPUT', INVALID_ARGUMENTS: 'MALFORMED_INPUT', INVALID_RESOURCE: 'MALFORMED_INPUT', UNKNOWN_TOOL: 'UNAUTHORIZED_TOOL',
  AUTHZ_UNAVAILABLE: 'INTEGRATION_FAILURE', EXTERNAL_DENY: 'EXTERNAL_POLICY_DENIAL',
  FLOW_VIOLATION: 'DATA_EXFILTRATION', FLOW_RULE: 'DATA_EXFILTRATION', UNTRUSTED_TARGET: 'PROMPT_INJECTION',
};

export function classify(codes: readonly string[], effect?: Effect): string[] {
  const out = new Set<string>();
  for (const code of codes) if (THREATS[code]) out.add(THREATS[code]);
  if (codes.includes('TARGET_FROM_UNTRUSTED') && effect && outboundEffect(effect)) out.add('DATA_EXFILTRATION');
  return [...out].sort();
}
