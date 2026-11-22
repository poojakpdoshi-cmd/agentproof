// Explicit deterministic test fixture. Neither model reasoning nor BAND delivery is simulated as live evidence.
import { FakeAgentTools } from '@band-ai/sdk/testing';
import { GenericAdapter } from '@band-ai/sdk';
import { handler } from './band.ts';
import { baseline } from './lab.ts';
import type { Reasoner } from './model.ts';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export async function offline() {
  let count = 0;
  const fixture: Reasoner = { source: 'deterministic-test-fixture-NOT-AI', async decide(role) {
    if (role === 'red') return count++ === 0
      ? { action: 'probe', call: { name: 'read_file', arguments: { path: 'private/secret.txt' } } }
      : { action: 'finish' };
    return { action: 'propose', policy: { ...baseline, read: ['docs/'] }, rationale: 'Scripted fixture removes seeded overgrant' };
  } };
  const redTools = new FakeAgentTools();
  const blueTools = new FakeAgentTools();
  const message = (senderId: string, content: string) => ({ id: senderId + '-message', roomId: 'offline-room',
    senderId, senderType: 'Agent', senderName: senderId, messageType: 'text', metadata: {}, createdAt: new Date(0), content });
  const invoke = async (role: 'red' | 'blue', sender: string, content: string, tools: any) => {
    const adapter = new GenericAdapter(handler(role, fixture, 'offline-room', role === 'red' ? 'blue' : 'red', 'owner'));
    await adapter.onMessage(message(sender, content), tools, {} as any, null, null, { roomId: 'offline-room', isSessionBootstrap: false });
  };
  await invoke('red', 'owner', 'start', redTools);
  const sent = redTools.messagesSent[0];
  await invoke('blue', 'red', sent.content, blueTools);
  return { mode: 'OFFLINE_FIXTURE_NOT_LIVE_AI_OR_BAND', bandSdk: '@band-ai/sdk@1.0.0',
    communication: 'GenericAdapter + FakeAgentTools; locally delivered by test harness',
    findings: JSON.parse(sent.content), routing: sent.mentions, retest: JSON.parse(blueTools.messagesSent[0].content) };
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const evidence = await offline();
  writeFileSync(new URL('../docs/phase4-offline.json', import.meta.url), JSON.stringify(evidence, null, 2) + '\n');
  console.log(JSON.stringify({ mode: evidence.mode, passed: evidence.retest.passed,
    baselineReceived: evidence.retest.reproduced.received.length,
    candidateReceived: evidence.retest.attempts.at(-1).retest.received.length }));
}
