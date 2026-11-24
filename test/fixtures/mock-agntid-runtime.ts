// MOCK AgntID Runtime — NOT AgntID software and NOT evidence of a live integration.
// A real MCP server (official SDK, Streamable HTTP, 127.0.0.1 only) that emits the payload
// shapes the official agntid-python 0.2.0 SDK parses (task open result, __agntid_policy_decision,
// review verdicts). Its toy policy is ours, chosen to exercise allow / deny / review paths.
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomUUID } from 'node:crypto';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

export type MockOptions = { prepareIntent?: boolean; files?: Record<string, string>; requireToken?: string };
const text = (payload: unknown, isError = false) => ({ content: [{ type: 'text', text: JSON.stringify(payload) }], ...(isError ? { isError: true } : { structuredContent: payload }) });
const deny = (reason: string, policy: string, verdict = 'deny') => text({ __agntid_error: reason,
  __agntid_policy_decision: { allowed: false, reason, policy_name: policy, correlation_id: 'mock-' + randomUUID().slice(0, 8),
    intent_validation: { verdict, verdict_reason: reason, verdict_code: verdict === 'deny' ? 'MOCK_DENY' : 'MOCK_REVIEW', status: 'evaluated' } } }, true);

export async function startMockAgntid(options: MockOptions = {}) {
  const files = new Map(Object.entries(options.files ?? {}));
  const tasks = new Map<string, string[]>();
  const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
  const server = new Server({ name: 'MOCK-agntid-runtime', version: '0.0.0-mock' }, { capabilities: { tools: {} } });
  const tool = (name: string) => ({ name, inputSchema: { type: 'object' as const } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: ['agntid_task_open', 'agntid_task_close', 'read_file', 'write_file', 'send_email'].map(tool) }));
  server.setRequestHandler(CallToolRequestSchema, async request => {
    const name = request.params.name;
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    calls.push({ name, args });
    if (name === 'agntid_task_open') {
      const prompt = String(args.prompt ?? '').toLowerCase();
      const relevant = [...(/summar|report|read/.test(prompt) ? ['read_file', 'write_file'] : []), ...(/email|send/.test(prompt) ? ['send_email'] : [])];
      tasks.set(String(args.task_id), relevant);
      return text({ ok: true, reason: '', intent: options.prepareIntent === false ? { prepared: false, reason: 'MOCK intent preparation disabled' }
        : { prepared: true, eligible_tool_count: 3, relevant_tool_count: relevant.length, snapshot: { id: 'mock-snapshot-1', relevant_tool_names: relevant } } });
    }
    if (name === 'agntid_task_close') { tasks.delete(String(args.task_id)); return text({ ok: true }); }
    const taskId = String(args.agntid_task_id ?? '');
    if (!tasks.has(taskId)) return deny('Request cannot be attributed to an open task', 'mock-task-attribution');
    if (!tasks.get(taskId)!.includes(name)) return deny('Tool is not relevant to the task intent', 'mock-intent');
    const { agntid_task_id: _t, ...toolArgs } = args;
    if (name === 'read_file' && String(toolArgs.path).startsWith('secrets/')) return deny('Policy denies secrets/', 'mock-no-secrets');
    if (name === 'send_email') return deny('Human review required for outbound email', 'mock-email-review', 'review_required');
    const decision = { allowed: true, policy_name: 'mock-allow', correlation_id: 'mock-' + randomUUID().slice(0, 8) };
    if (name === 'read_file') {
      const data = files.get(String(toolArgs.path));
      if (data === undefined) return { content: [{ type: 'text', text: 'not found' }], isError: true };
      return { content: [{ type: 'text', text: data }], structuredContent: { text: data, __agntid_policy_decision: decision } };
    }
    files.set(String(toolArgs.path), String(toolArgs.data));
    return { content: [{ type: 'text', text: 'written' }], structuredContent: { ok: true, __agntid_policy_decision: decision } };
  });
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID(), enableJsonResponse: true });
  await server.connect(transport);
  const http = createServer(async (req, res) => {
    if (options.requireToken && req.headers.authorization !== `Bearer ${options.requireToken}`) { res.writeHead(401).end(); return; }
    let body = '';
    for await (const chunk of req) body += chunk;
    await transport.handleRequest(req, res, body ? JSON.parse(body) : undefined);
  });
  await new Promise<void>(resolve => http.listen(0, '127.0.0.1', resolve));
  const { port } = http.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}/mcp`, calls, files,
    async close() { await transport.close(); http.closeAllConnections(); await new Promise(resolve => http.close(resolve)); } };
}
