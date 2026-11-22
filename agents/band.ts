import { Agent, GenericAdapter } from '@band-ai/sdk';
import { randomUUID } from 'node:crypto';
import { red, blue } from './workflow.ts';
import { localModel } from './model.ts';
import { geminiModel } from './gemini.ts';
import type { Reasoner } from './model.ts';
import { fileURLToPath } from 'node:url';

export function handler(role: 'red' | 'blue', model: Reasoner, roomId: string, peerId: string, ownerId: string) {
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
    try {
      const result = role === 'red' ? await red(model, randomUUID()) : await blue(model, JSON.parse(message.content));
      const sent = await tools.sendMessage(JSON.stringify(result), [{ id: role === 'red' ? peerId : ownerId }]);
      if (sent?.ok === false) throw new Error('BAND delivery failed');
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
  const agents = (['red', 'blue'] as const).map(role => Agent.create({
    config: { agentId: env[`BAND_${role.toUpperCase()}_ID`], apiKey: env[`BAND_${role.toUpperCase()}_API_KEY`] },
    linkOptions: { conflictPolicy: 'reject' },
    adapter: new GenericAdapter(handler(role, model, env.BAND_ROOM_ID,
      env[role === 'red' ? 'BAND_BLUE_ID' : 'BAND_RED_ID'], env.BAND_OWNER_ID)),
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
