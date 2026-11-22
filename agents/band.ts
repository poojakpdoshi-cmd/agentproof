import { Agent, GenericAdapter } from '@band-ai/sdk';
import { createHash, randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { red, blue } from './workflow.ts';
import { localModel } from './model.ts';
import { geminiModel } from './gemini.ts';
import type { Reasoner } from './model.ts';
import { fileURLToPath } from 'node:url';

// Live evidence: platform IDs become role labels + truncated SHA-256 fingerprints; no keys or env values are written.
export function liveRecorder(file: string, env: Record<string, string>) {
  const labels: Record<string, string> = { [env.BAND_RED_ID]: 'red-agent', [env.BAND_BLUE_ID]: 'blue-agent',
    [env.BAND_OWNER_ID]: 'owner', [env.BAND_ROOM_ID]: 'private-room' };
  const id = (v: unknown) => typeof v === 'string' && v
    ? `${labels[v] ?? 'id'} sha256:${createHash('sha256').update(v).digest('hex').slice(0, 12)}` : null;
  const evidence = { phase: '6', mode: 'LIVE_BAND_LIVE_MODEL', provider: env.AI_PROVIDER, sdk: '@band-ai/sdk@1.0.0',
    note: 'Recorded by agents/band.ts during a live run. IDs redacted; payloads are dummy-lab data.', events: [] as unknown[] };
  const secrets = Object.entries(env).filter(([k, v]) => /KEY|_ID$/.test(k) && v).map(([, v]) => v);
  return (event: Record<string, any>) => {
    evidence.events.push({ at: new Date().toISOString(), ...event,
      ...(event.messageId !== undefined ? { messageId: id(event.messageId) } : {}),
      ...(event.sentMessageId !== undefined ? { sentMessageId: id(event.sentMessageId) } : {}),
      ...(event.from !== undefined ? { from: id(event.from) } : {}) });
    const json = JSON.stringify(evidence, null, 2) + '\n';
    if (secrets.some(v => json.includes(v))) throw new Error('Evidence redaction failed');
    writeFileSync(file, json);
  };
}
// Only this project's fixed messages are logged; anything else (paths, provider/model text) becomes name/code only.
const knownErrors = new Set(['Gemini inference failed; session stopped (no automatic retry)', 'Gemini session stopped or request budget exhausted',
  'Gemini request already in progress', 'Invalid Red decision', 'Unsupported Red action', 'Invalid probe', 'Probe limit', 'Invalid findings',
  'Invalid Blue decision', 'Invalid policy', 'BAND delivery failed', 'Message limit', 'Local model request failed', 'Model response too large', 'No model output']);
const safeError = (e: any) => typeof e?.message === 'string' && knownErrors.has(e.message) ? e.message
  : (/^[A-Za-z]{1,40}$/.test(e?.name) ? e.name : 'Error') + (/^[A-Z0-9_]{1,40}$/.test(e?.code) ? ' ' + e.code : '');

export function handler(role: 'red' | 'blue', model: Reasoner, roomId: string, peerId: string, ownerId: string,
  record: (event: Record<string, unknown>) => void = () => {}) {
  const log = (event: Record<string, unknown>) => { try { record({ role, ...event }); } catch { /* evidence must not alter the run */ } };
  const seen = new Set<string>();
  let busy = false;
  return async ({ message, tools, roomId: incomingRoom }: any) => {
    if (incomingRoom !== roomId || (role === 'red' ? message.senderId !== ownerId : message.senderId !== peerId)) {
      tools.turn?.settle(); return;
    }
    if (busy || seen.has(message.id) || seen.size >= 20) { tools.turn?.settle(); return; }
    if (typeof message.content !== 'string' || message.content.length > 65536) throw new Error('Message limit');
    if (role === 'red' && !/(?:^|\s)start\s*$/i.test(message.content)) { tools.turn?.settle(); return; }
    seen.add(message.id); busy = true;
    log({ event: 'received', messageId: message.id, from: message.senderId, bytes: message.content.length });
    try {
      const result = role === 'red' ? await red(model, randomUUID()) : await blue(model, JSON.parse(message.content));
      const sent = await tools.sendMessage(JSON.stringify(result), [{ id: role === 'red' ? peerId : ownerId }]);
      if (sent?.ok === false) throw new Error('BAND delivery failed');
      log({ event: role === 'red' ? 'findings-sent' : 'retest-report-sent', sentMessageId: sent?.id ?? null, payload: result });
    } catch (error) {
      log({ event: 'failed', error: safeError(error) });
      throw error;
    } finally { busy = false; }
  };
}
export function config(env: NodeJS.ProcessEnv) {
  const provider = env.AI_PROVIDER ?? 'ollama';
  if (!['ollama', 'gemini'].includes(provider)) throw new Error('Unsupported AI_PROVIDER');
  const names = ['BAND_RED_ID', 'BAND_RED_API_KEY', 'BAND_BLUE_ID', 'BAND_BLUE_API_KEY', 'BAND_ROOM_ID', 'BAND_OWNER_ID',
    ...(provider === 'gemini' ? ['GEMINI_API_KEY', 'GEMINI_MODEL'] : ['OLLAMA_MODEL'])];
  const missing = names.filter(name => !env[name]);
  if (missing.length) throw new Error('Missing: ' + missing.join(', '));
  if (env.BAND_RED_ID === env.BAND_BLUE_ID) throw new Error('Distinct agent identities required');
  return { ...env, AI_PROVIDER: provider } as Record<string, string>;
}
export async function main() {
  const env = config(process.env);
  const model = env.AI_PROVIDER === 'gemini' ? geminiModel(env) : localModel(env.OLLAMA_MODEL);
  if (env.AI_PROVIDER === 'ollama') {
    // Gemini has no startup request; its explicit opt-in is checked before BAND connects.
    const response = await fetch('http://127.0.0.1:11434/api/tags', { signal: AbortSignal.timeout(3000), redirect: 'error' });
    const tags = await response.json();
    if (!response.ok || !tags.models?.some((v: any) => v.name === env.OLLAMA_MODEL && !v.remote_host && !v.remote_model)) throw new Error('Local model not installed');
  }
  const record = liveRecorder(fileURLToPath(new URL('../docs/phase6-live.json', import.meta.url)), env);
  const agents = (['red', 'blue'] as const).map(role => Agent.create({
    config: { agentId: env[`BAND_${role.toUpperCase()}_ID`], apiKey: env[`BAND_${role.toUpperCase()}_API_KEY`] },
    linkOptions: { conflictPolicy: 'reject' },
    adapter: new GenericAdapter(handler(role, model, env.BAND_ROOM_ID,
      env[role === 'red' ? 'BAND_BLUE_ID' : 'BAND_RED_ID'], env.BAND_OWNER_ID, record)),
  }));
  const stop = async () => { await Promise.allSettled(agents.map(agent => agent.stop(5000))); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  try { for (const agent of agents) await agent.start(); }
  catch (error) { await stop(); throw error; }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch(() => {
  console.error('Live run blocked: check BAND configuration and selected AI provider settings/authorization. No offline substitution.');
  process.exitCode = 2;
});
