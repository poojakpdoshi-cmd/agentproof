import { canonicalPath } from '../paths.ts';
import { keys, record } from '../validation.ts';
import { BUILTIN_CONTRACTS } from './contracts.ts';
import { Firewall } from './firewall.ts';
import type { ToolAction } from './firewall.ts';
import { EvidenceLedger } from './ledger.ts';
import { createServer } from 'node:http';
import { redactValue } from './redact.ts';
import { randomBytes } from 'node:crypto';

// Adapts the guard firewall to the MCP proxy's tool-call interception point.
// Same decision shape as the original toolGate, plus the action id used to verify output.
export type GuardDecision = { allowed: boolean; reason: string; tool: string; params?: Record<string, unknown>; actionId?: string; action?: ToolAction };

export function mcpGuard(mandateInput: unknown, options: { evidence?: string; key?: Buffer } = {}) {
  const ledger = new EvidenceLedger({ file: options.evidence, key: options.key });
  const firewall = new Firewall({ mandates: [mandateInput], ledger });
  const mandate = firewall.mandate((mandateInput as { id: string }).id)!;
  const visible = new Set(mandate.allow.flatMap(rule => rule.tools.includes('*') ? Object.keys(BUILTIN_CONTRACTS) : rule.tools));

  const held = new Map<string, { action: ToolAction; params: Record<string, unknown>; tool: string; reasons: string; resolve: (d: GuardDecision) => void }>();
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
    if (verdict.decision === 'REQUIRE_APPROVAL') return { ...deny('approval-required ' + verdict.reasons.join(','), verdict.actionId), action, params: { ...params, arguments: args } };
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
  // Human approval for held calls. The proxy waits on hold(); an operator decides via the
  // loopback approval API (bearer token printed once to stderr). The agent cannot approve itself.
  const hold = (d: GuardDecision, timeoutMs: number): Promise<GuardDecision> => new Promise(resolve => {
    if (held.size >= 32 || !d.actionId || !d.action || !d.params) { resolve({ ...d, reason: 'approval-queue-full' }); return; }
    const id = d.actionId;
    const timer = setTimeout(() => { held.delete(id); resolve({ ...d, reason: 'approval-timeout' }); }, timeoutMs);
    held.set(id, { action: d.action, params: d.params, tool: d.tool, reasons: d.reason, resolve: r => { clearTimeout(timer); held.delete(id); resolve(r); } });
  });
  const decide = (actionId: string, approver: string, approved: boolean): { ok: boolean; code?: string } => {
    const h = held.get(actionId);
    if (!h) return { ok: false, code: 'NO_PENDING_APPROVAL' };
    const r = firewall.approve(actionId, approver, approved);
    if (!r.ok) return { ok: false, code: r.code };
    if (!approved) { h.resolve({ allowed: false, reason: 'approval-rejected', tool: h.tool, actionId }); return { ok: true }; }
    const bound = firewall.consume(r.token, h.action);
    h.resolve(bound.ok ? { allowed: true, reason: 'approved', tool: h.tool, actionId, action: h.action, params: h.params }
      : { allowed: false, reason: 'binding ' + bound.code, tool: h.tool, actionId });
    return { ok: true };
  };
  const approvalServer = (port: number) => {
    const token = randomBytes(24).toString('hex');
    const hosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
    const server = createServer(async (req, res) => {
      const send = (code: number, body: unknown) => res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }).end(JSON.stringify(body));
      if (!hosts.has(req.headers.host ?? '') || req.headers.authorization !== `Bearer ${token}`) return send(403, { error: 'forbidden' });
      if (req.method === 'GET' && req.url === '/pending') return send(200, [...held.entries()].map(([id, h]) => ({ actionId: id, tool: h.tool, arguments: redactValue(h.action.arguments), reasons: h.reasons })));
      if (req.method !== 'POST' || req.url !== '/decide') return send(404, { error: 'not found' });
      let raw = '';
      for await (const c of req) { raw += c; if (raw.length > 4096) return send(413, { error: 'too large' }); }
      try { const b = JSON.parse(raw); const r = decide(String(b.actionId), String(b.approver ?? ''), b.approved === true); return send(r.ok ? 200 : 409, r); }
      catch { return send(400, { error: 'json' }); }
    });
    server.listen(port, '127.0.0.1');
    server.unref();
    return { token, close: () => server.close() };
  };
  return { gate, output, listTools, firewall, hold, decide, approvalServer };
}
