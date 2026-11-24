// AgntID Runtime adapter for AgentProof.
//
// Wire contract source: the official AgntID Python SDK, agntid-python 0.2.0 (MIT,
// github.com/AGNTID-AI/agntid-python): task glue tools `agntid_task_open` / `agntid_task_close`,
// the `agntid_task_id` correlation argument, `__agntid_*` platform fields, and the policy
// decision envelope parsed by `agntid.decision.parse_decision`. The AgntID Runtime is an
// enforcing MCP proxy: it decides and forwards in the same tools/call. There is no
// decide-only API, so AgentProof uses it in two documented ways:
//   1. authorizer(): the task-open intent snapshot (prompt-relevant tool shortlist) as an
//      external, fail-closed second opinion before AgentProof issues an execution token;
//   2. executor(): allowed calls are executed THROUGH the Runtime, which applies its own
//      identity, policy and credential controls; its verdict is recorded as evidence.
// NOT VERIFIED against a live Runtime from this repository (see AGNTID_INTEGRATION.md).
import { randomUUID } from 'node:crypto';
import { record } from '../validation.ts';
import type { Authorizer, Executor, ExternalVerdict, ToolAction } from '../guard/firewall.ts';

export type AgntidOutcome = 'allow' | 'deny' | 'review_required' | 'unknown';
export type AgntidDecision = { outcome: AgntidOutcome; allowed: boolean; reason: string; code: string; policyName: string; correlationId: string; intentStatus: string };
export type TaskOpen = { ok: boolean; reason: string; intentPrepared: boolean; intentReason: string; relevantTools: string[] | null; snapshotId: string };
export type ToolResult = { content?: unknown[]; structuredContent?: unknown; isError?: boolean };
export interface McpCaller { callTool(name: string, args: Record<string, unknown>): Promise<ToolResult>; listTools(): Promise<string[]>; close(): Promise<void> }

const PLATFORM_PREFIX = '__agntid_';
const outcomeOf = (value: unknown): AgntidOutcome => {
  const v = String(value ?? '').toLowerCase();
  return ['hitl', 'review', 'review_required'].includes(v) ? 'review_required' : v === 'allow' || v === 'deny' ? v : 'unknown';
};

function extractJson(text: string): Record<string, unknown> | null {
  for (const candidate of [text.trim(), text.includes('{') ? text.slice(text.indexOf('{')) : '']) {
    if (!candidate) continue;
    try { const value = JSON.parse(candidate); if (record(value) || (value && typeof value === 'object' && !Array.isArray(value))) return value; } catch { /* next */ }
  }
  return null;
}
function payloadOf(result: unknown): Record<string, unknown> | null {
  if (!result || typeof result !== 'object') return null;
  const r = result as ToolResult;
  if (r.structuredContent && typeof r.structuredContent === 'object' && !Array.isArray(r.structuredContent)) return r.structuredContent as Record<string, unknown>;
  for (const block of r.content ?? []) {
    const text = block && typeof block === 'object' ? (block as { text?: unknown }).text : undefined;
    if (typeof text === 'string') { const json = extractJson(text); if (json) return json; }
  }
  return null;
}

// Port of agntid.decision.parse_decision (policy decision or wrapped error envelope).
export function parseAgntidDecision(payload: unknown): AgntidDecision | null {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const data = payload as Record<string, unknown>;
  const policy = (data.__agntid_policy_decision ?? data) as Record<string, unknown>;
  if (!policy || typeof policy !== 'object') return null;
  if (!Object.hasOwn(policy, 'allowed') && !Object.hasOwn(data, '__agntid_error')) return null;
  const intent = policy.intent_validation && typeof policy.intent_validation === 'object' ? policy.intent_validation as Record<string, unknown> : {};
  const flow = data.__agntid_execution_flow && typeof data.__agntid_execution_flow === 'object' ? data.__agntid_execution_flow as Record<string, unknown> : {};
  const review = (intent.review ?? flow.review) as Record<string, unknown> | undefined;
  const allowed = policy.allowed === true;
  let outcome = outcomeOf(intent.verdict);
  if (review && typeof review === 'object') outcome = outcomeOf(review.outcome);
  else if (outcome === 'unknown') outcome = allowed ? 'allow' : 'deny';
  const str = (v: unknown) => typeof v === 'string' ? v.slice(0, 500) : '';
  return { outcome, allowed, reason: str(intent.verdict_reason) || str(policy.reason) || str(data.__agntid_error), code: str(intent.verdict_code),
    policyName: str(policy.policy_name), correlationId: str(policy.correlation_id), intentStatus: str(intent.status) };
}

// Port of agntid.intent.parse_task_open_details (subset used for tool shortlisting).
export function parseTaskOpen(result: unknown): TaskOpen {
  const payload = payloadOf(result) ?? (record(result) ? result : null);
  if (!payload) return { ok: false, reason: 'invalid_task_open_result', intentPrepared: false, intentReason: '', relevantTools: null, snapshotId: '' };
  const unwrapped = (record(payload.__agntid_result) ? payload.__agntid_result : payload) as Record<string, unknown>;
  const intent = unwrapped.intent && typeof unwrapped.intent === 'object' ? unwrapped.intent as Record<string, unknown> : {};
  const snapshot = intent.snapshot && typeof intent.snapshot === 'object' ? intent.snapshot as Record<string, unknown> : null;
  const names = snapshot && Array.isArray(snapshot.relevant_tool_names) && snapshot.relevant_tool_names.length > 0 ? snapshot.relevant_tool_names
    : snapshot && Array.isArray(snapshot.relevant_tool_ids) ? snapshot.relevant_tool_ids : null;
  return { ok: unwrapped.ok === true, reason: String(unwrapped.reason ?? ''), intentPrepared: intent.prepared === true,
    intentReason: String(intent.reason ?? ''), relevantTools: names ? names.filter((n): n is string => typeof n === 'string') : null,
    snapshotId: snapshot ? String(snapshot.id ?? '') : '' };
}

// Mirrors agntid.mcp_wrapper.strip_platform_fields: platform fields never reach the agent.
export function stripPlatformFields(value: unknown, depth = 0): unknown {
  if (depth > 32) return null;
  if (Array.isArray(value)) return value.map(v => stripPlatformFields(v, depth + 1));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).filter(([k]) => !k.startsWith(PLATFORM_PREFIX)).map(([k, v]) => [k, stripPlatformFields(v, depth + 1)]));
  }
  return value;
}

// Loopback HTTP for the customer-hosted Runtime, HTTPS otherwise; never credentials in URLs.
export function validateRuntimeUrl(input: string): string {
  const url = new URL(input);
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) || url.username || url.password || url.search || url.hash) {
    throw new Error('AgntID Runtime URL must be loopback http or https without credentials, query or fragment');
  }
  return url.href;
}

// Streamable HTTP MCP client via the official MCP TypeScript SDK (loaded only when used).
export async function connectRuntime(url: string, options: { accessToken?: string; timeoutMs?: number } = {}): Promise<McpCaller> {
  const target = new URL(validateRuntimeUrl(url));
  const [{ Client }, { StreamableHTTPClientTransport }] = await Promise.all([
    import('@modelcontextprotocol/sdk/client/index.js'), import('@modelcontextprotocol/sdk/client/streamableHttp.js')]);
  const headers: Record<string, string> = options.accessToken ? { Authorization: `Bearer ${options.accessToken}` } : {};
  const transport = new StreamableHTTPClientTransport(target, { requestInit: { headers, redirect: 'error' } });
  const client = new Client({ name: 'agentproof-agntid-adapter', version: '1.0.0' });
  const timeout = options.timeoutMs ?? 10_000;
  await client.connect(transport, { timeout });
  return {
    async callTool(name, args) { return await client.callTool({ name, arguments: args }, undefined, { timeout }) as ToolResult; },
    async listTools() { return (await client.listTools(undefined, { timeout })).tools.map(t => t.name); },
    async close() { await client.close(); },
  };
}

export class AgntidError extends Error {
  readonly code: 'EXTERNAL_DENY' | 'EXTERNAL_REVIEW' | 'AUTHZ_UNAVAILABLE' | 'EXECUTION_FAILED';
  readonly details: Record<string, unknown>;
  constructor(code: AgntidError['code'], details: Record<string, unknown>) {
    super(code);
    this.code = code;
    this.details = details;
  }
}

export class AgntidRuntime {
  #caller: McpCaller;
  #agent: string;
  #user: string;
  #taskId: string | null = null;
  #task: TaskOpen | null = null;

  constructor(caller: McpCaller, identity: { agentId: string; userId: string }) {
    this.#caller = caller;
    this.#agent = identity.agentId;
    this.#user = identity.userId;
  }

  get taskId(): string | null { return this.#taskId; }
  get task(): TaskOpen | null { return this.#task; }

  async openTask(prompt: string, executionContext?: Record<string, unknown>): Promise<TaskOpen> {
    if (this.#taskId) throw new Error('Task already open');
    const taskId = randomUUID();
    const result = await this.#caller.callTool('agntid_task_open', { task_id: taskId, agent_id: this.#agent, user_id: this.#user, prompt,
      ...(executionContext ? { execution_context: executionContext } : {}) });
    this.#task = parseTaskOpen(result);
    if (this.#task.ok) this.#taskId = taskId;
    return this.#task;
  }

  async closeTask(): Promise<void> {
    if (!this.#taskId) return;
    const taskId = this.#taskId;
    this.#taskId = null;
    await this.#caller.callTool('agntid_task_close', { task_id: taskId });
  }

  // Executes through the Runtime. Allowed results are returned without platform fields.
  async callTool(action: ToolAction): Promise<{ decision: AgntidDecision | null; result: unknown }> {
    if (!this.#taskId) throw new AgntidError('AUTHZ_UNAVAILABLE', { reason: 'no open AgntID task' });
    if (Object.keys(action.arguments).some(k => k === 'agntid_task_id' || k.startsWith(PLATFORM_PREFIX))) {
      throw new AgntidError('EXTERNAL_DENY', { reason: 'agent-supplied AgntID control argument' });
    }
    let result: ToolResult;
    try { result = await this.#caller.callTool(action.tool, { ...action.arguments, agntid_task_id: this.#taskId }); }
    catch (error) {
      const decision = parseAgntidDecision(extractJson(error instanceof Error ? error.message : ''));
      if (decision) throw new AgntidError(decision.outcome === 'review_required' ? 'EXTERNAL_REVIEW' : 'EXTERNAL_DENY', { ...decision });
      throw new AgntidError('AUTHZ_UNAVAILABLE', { reason: 'runtime transport failure' });
    }
    const decision = parseAgntidDecision(payloadOf(result));
    if (decision && (decision.outcome === 'deny' || decision.outcome === 'review_required' || !decision.allowed)) {
      throw new AgntidError(decision.outcome === 'review_required' ? 'EXTERNAL_REVIEW' : 'EXTERNAL_DENY', { ...decision });
    }
    if (result.isError) throw new AgntidError('EXECUTION_FAILED', { reason: 'tool returned an error without an AgntID decision' });
    return { decision, result: stripPlatformFields(result) };
  }

  // Intent shortlist from task open. Fail closed if the Runtime prepared no snapshot.
  authorizer(): Authorizer {
    return { name: 'agntid-task-intent', authorize: async ({ action }): Promise<ExternalVerdict> => {
      const task = this.#task;
      if (!task || !this.#taskId) return { outcome: 'unknown', code: 'AUTHZ_UNAVAILABLE', reason: 'no open AgntID task' };
      if (!task.intentPrepared || task.relevantTools === null) return { outcome: 'unknown', code: 'AUTHZ_UNAVAILABLE', reason: task.intentReason || 'intent not prepared' };
      return task.relevantTools.includes(action.tool)
        ? { outcome: 'allow', code: 'AGNTID_INTENT_RELEVANT', reference: task.snapshotId }
        : { outcome: 'deny', code: 'AGNTID_INTENT_NOT_RELEVANT', reason: 'tool not shortlisted for this task', reference: task.snapshotId };
    } };
  }

  executor(): Executor {
    return { name: 'agntid-runtime', execute: async action => (await this.callTool(action)).result };
  }
}
