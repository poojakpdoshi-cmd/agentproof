import { canonicalPath } from '../paths.ts';
import { keys, record } from '../validation.ts';
import { BUILTIN_CONTRACTS } from './contracts.ts';
import { Firewall } from './firewall.ts';
import type { ToolAction } from './firewall.ts';
import { EvidenceLedger } from './ledger.ts';

// Adapts the guard firewall to the MCP proxy's tool-call interception point.
// Same decision shape as the original toolGate, plus the action id used to verify output.
export type GuardDecision = { allowed: boolean; reason: string; tool: string; params?: Record<string, unknown>; actionId?: string; action?: ToolAction };

export function mcpGuard(mandateInput: unknown, options: { evidence?: string; key?: Buffer } = {}) {
  const ledger = new EvidenceLedger({ file: options.evidence, key: options.key });
  const firewall = new Firewall({ mandates: [mandateInput], ledger });
  const mandate = firewall.mandate((mandateInput as { id: string }).id)!;
  const visible = new Set(mandate.allow.flatMap(rule => rule.tools.includes('*') ? Object.keys(BUILTIN_CONTRACTS) : rule.tools));

  const gate = (params: unknown): GuardDecision => {
    const tool = record(params) && typeof params.name === 'string' && Object.hasOwn(BUILTIN_CONTRACTS, params.name) ? params.name : 'unknown';
    const deny = (reason: string, actionId?: string): GuardDecision => ({ allowed: false, reason, tool, ...(actionId ? { actionId } : {}) });
    if (!record(params) || !keys(params, ['name', 'arguments', '_meta'], ['name', 'arguments']) || !record(params.arguments)) return deny('invalid-arguments');
    if (Object.hasOwn(params, '_meta')) {
      const meta = params._meta;
      if (!record(meta) || !keys(meta, ['progressToken'])) return deny('invalid-metadata');
      const token = meta.progressToken;
      if (Object.hasOwn(meta, 'progressToken') && typeof token !== 'string' && !(typeof token === 'number' && Number.isSafeInteger(token))) return deny('invalid-metadata');
    }
    // Forward the canonical path the decision was made on, never an alias of it.
    const args = { ...params.arguments };
    const contract = Object.hasOwn(BUILTIN_CONTRACTS, String(params.name)) ? BUILTIN_CONTRACTS[String(params.name)] : undefined;
    if (contract?.resource.kind === 'path') {
      const canonical = canonicalPath(args[contract.resource.arg]);
      if (canonical !== null) args[contract.resource.arg] = canonical;
    }
    const action: ToolAction = { tool: String(params.name), arguments: args };
    const verdict = firewall.evaluate({ agent: mandate.agent, mandate: mandate.id, session: 'mcp', action });
    if (verdict.decision === 'REQUIRE_APPROVAL') return deny('approval-required ' + verdict.actionId, verdict.actionId);
    if (verdict.decision === 'BLOCK') return deny('blocked ' + verdict.reasons.join(','), verdict.actionId);
    const bound = firewall.consume(verdict.token, action);
    if (!bound.ok) return deny('binding ' + bound.code, verdict.actionId);
    return { allowed: true, reason: 'authorized', tool, actionId: verdict.actionId, action, params: { ...params, arguments: args } };
  };

  // Output verification for relayed tool results; returns the (possibly redacted) result.
  const output = (actionId: string, action: ToolAction, result: unknown): unknown =>
    firewall.verifyOutput(actionId, 'mcp', result, 'mcp-upstream', mandate, action).output;

  const listTools = (result: unknown): unknown => {
    if (!record(result) || !Array.isArray(result.tools)) return result;
    return { ...result, tools: result.tools.filter(t => record(t) && typeof t.name === 'string' && visible.has(t.name)) };
  };
  return { gate, output, listTools, firewall };
}
