#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { toolGate } from './mcp-policy.ts';
import { mcpGuard } from './guard/mcp-guard.ts';
import type { ToolAction } from './guard/firewall.ts';
import { lines, message, rpcError, send, MAX_FRAME } from './mcp-protocol.ts';
import type { Id, Message } from './mcp-protocol.ts';
import { record } from './validation.ts';

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    process.stdout.write('Usage: node src/mcp-proxy.ts --policy policy.json -- COMMAND [ARGS...]\n'
      + '       node src/mcp-proxy.ts --mandate mandate.json [--evidence evidence.jsonl] -- COMMAND [ARGS...]\n');
    return;
  }
  const guardMode = args[0] === '--mandate';
  const evidence = guardMode && args[2] === '--evidence' ? args[3] : undefined;
  const separator = evidence === undefined ? 2 : 4;
  if ((args[0] !== '--policy' && !guardMode) || !args[1] || args[separator] !== '--' || !args[separator + 1]
    || (guardMode && args[2] === '--evidence' && !evidence)) throw new Error('Invalid arguments');
  const policyBytes = readFileSync(args[1]);
  if (policyBytes.length > MAX_FRAME) throw new Error('Policy too large');
  // Invalid policy or mandate aborts before the upstream process is even created.
  const config: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(policyBytes));
  const guard = guardMode ? mcpGuard(config, { evidence }) : undefined;
  const gate = guard ? guard.gate : toolGate(config);
  const command = args[separator + 1];
  const child = spawn(command, args.slice(separator + 2), { stdio: ['pipe', 'pipe', 'pipe'], shell: false });
  const clientPending = new Map<Id, { method: string; actionId?: string; action?: ToolAction }>();
  const serverPending = new Set<Id>();
  const clientSeen = new Set<Id>();
  const serverSeen = new Set<Id>();
  let state: 'new' | 'initializing' | 'initialized' | 'ready' = 'new';
  let failed = false;
  let sequence = 0;
  let shutdown: ReturnType<typeof setTimeout> | undefined;
  const audit = (tool: string, decision: string, reason: string) => {
    process.stderr.write(JSON.stringify({ sequence: ++sequence, tool, decision, reason }) + '\n');
  };
  const stop = () => { child.kill(); process.stdin.destroy(); };
  const closed = new Promise<void>(resolve => {
    child.on('error', () => { failed = true; stop(); });
    child.on('close', code => { if (code !== 0) failed = true; process.stdin.destroy(); resolve(); });
  });
  // Upstream diagnostics are not trusted audit records and may contain payloads.
  child.stderr.resume();
  child.stdin.on('error', () => { failed = true; stop(); });
  process.stdout.on('error', () => { failed = true; stop(); });
  const claim = (seen: Set<Id>, id: Id) => {
    if (seen.has(id) || seen.size >= 10000) throw new Error('Duplicate ID or session limit');
    seen.add(id);
  };

  const client = async () => {
    for await (const line of lines(process.stdin)) {
      if (failed) break;
      let input: unknown;
      try { input = JSON.parse(line); }
      catch { await send(process.stdout, rpcError(null, -32700, 'Parse error')); continue; }
      if (!message(input)) { await send(process.stdout, rpcError(null, -32600, 'Invalid Request')); continue; }
      const value: Message = input;
      const hasId = Object.hasOwn(value, 'id');
      if (!value.method) {
        if (!serverPending.delete(value.id!)) throw new Error('Unsolicited client response');
        await send(child.stdin, value);
        continue;
      }
      if (hasId) claim(clientSeen, value.id!);
      const error = async (code: number, text: string) => {
        if (hasId) await send(process.stdout, rpcError(value.id!, code, text));
      };
      if (!hasId) {
        if (value.method === 'notifications/initialized' && state === 'initialized') {
          state = 'ready';
          await send(child.stdin, value);
        } else if (value.method === 'notifications/cancelled' && state === 'ready') {
          await send(child.stdin, value);
        } else if (value.method === 'tools/call') audit('unknown', 'deny', 'request-id-required');
        continue;
      }
      if (value.method === 'initialize') {
        if (state !== 'new') { await error(-32600, 'Already initialized'); continue; }
        if (!record(value.params) || !record(value.params.capabilities)) {
          await error(-32602, 'Invalid initialization'); continue;
        }
        // Upstream may use only capabilities this intermediary actually relays.
        value.params = { ...value.params, capabilities: {} };
        state = 'initializing';
      } else if (value.method !== 'ping' && state !== 'ready') {
        await error(-32000, 'Initialization required'); continue;
      }
      if (value.method === 'tools/call') {
        const decision: ReturnType<typeof gate> & { actionId?: string; action?: ToolAction } = gate(value.params);
        audit(decision.tool, decision.allowed ? 'allow' : 'deny', decision.reason);
        if (!decision.allowed) {
          await send(process.stdout, { jsonrpc: '2.0', id: value.id,
            result: { isError: true, content: [{ type: 'text', text: 'AgentProof denied: ' + decision.reason }] } });
          continue;
        }
        value.params = decision.params;
        if (clientPending.size >= 128) throw new Error('Too many pending requests');
        clientPending.set(value.id!, { method: value.method, actionId: decision.actionId, action: decision.action });
        await send(child.stdin, value);
        continue;
      } else if (!['initialize', 'ping', 'tools/list'].includes(value.method)) {
        await error(-32601, 'Method not supported by AgentProof'); continue;
      }
      if (clientPending.size >= 128) throw new Error('Too many pending requests');
      clientPending.set(value.id!, { method: value.method });
      await send(child.stdin, value);
    }
    child.stdin.end();
    shutdown = setTimeout(() => { failed = true; stop(); }, 2000);
    shutdown.unref();
  };

  const server = async () => {
    for await (const line of lines(child.stdout)) {
      if (failed) break;
      const value: unknown = JSON.parse(line);
      if (!message(value)) throw new Error('Invalid server message');
      if (!value.method) {
        const pending = clientPending.get(value.id!);
        if (!pending) throw new Error('Unsolicited server response');
        const method = pending.method;
        // Guard mode: verify tool output (secret redaction, injection flags, data-flow taint)
        // and show the agent only the tools its mandate can ever authorize.
        if (guard && Object.hasOwn(value, 'result')) {
          if (method === 'tools/call' && pending.actionId && pending.action) {
            const verified = guard.output(pending.actionId, pending.action, value.result);
            if (!record(verified)) throw new Error('Invalid tool result');
            value.result = verified;
          } else if (method === 'tools/list') value.result = guard.listTools(value.result);
        }
        if (method === 'initialize') {
          if (Object.hasOwn(value, 'error')) state = 'new';
          else {
            if (!record(value.result) || !record(value.result.capabilities)) throw new Error('Invalid initialization result');
            const capabilities = value.result.capabilities;
            value.result = { ...value.result, capabilities: Object.hasOwn(capabilities, 'tools')
              ? { tools: capabilities.tools } : {} };
            state = 'initialized';
          }
        }
        clientPending.delete(value.id!);
        await send(process.stdout, value);
      } else if (Object.hasOwn(value, 'id')) {
        claim(serverSeen, value.id!);
        // Do not allow upstream sampling/elicitation to become an unguarded tool channel.
        if (value.method !== 'ping') {
          await send(child.stdin, rpcError(value.id!, -32601, 'Server method not supported by AgentProof'));
          continue;
        }
        if (serverPending.size >= 128) throw new Error('Too many pending server requests');
        serverPending.add(value.id!);
        await send(process.stdout, value);
      } else if (['notifications/progress', 'notifications/message', 'notifications/tools/list_changed',
        'notifications/cancelled'].includes(value.method)) await send(process.stdout, value);
    }
    for (const id of clientPending.keys()) {
      clientPending.delete(id);
      failed = true;
      await send(process.stdout, rpcError(id, -32002, 'Upstream unavailable'));
    }
    process.stdin.destroy();
  };

  try {
    await Promise.all([client(), server()]);
  } catch {
    failed = true;
    stop();
    for (const id of clientPending.keys()) {
      clientPending.delete(id);
      await send(process.stdout, rpcError(id, -32002, 'Proxy session failed')).catch(() => {});
    }
    clientPending.clear();
  } finally {
    await closed;
    if (shutdown) clearTimeout(shutdown);
  }
  if (failed) throw new Error('Proxy session failed');
}

main().catch(() => {
  process.stderr.write('AgentProof proxy stopped: invalid configuration or protocol/session failure.\n');
  process.exitCode = 2;
});
