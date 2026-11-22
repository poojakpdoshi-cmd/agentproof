// Live BAND transport check only. Fixed nonce exchange is NOT an AI workflow.
import { Agent, BandLink, GenericAdapter } from '@band-ai/sdk';
import { NoopLogger } from '@band-ai/sdk/core';
import { randomUUID } from 'node:crypto';
import { appendFileSync, writeFileSync } from 'node:fs';
const env = process.env;
const logger = new NoopLogger();
const nonce = randomUUID();
const events: unknown[] = [];
const agents: Agent[] = [];
let timer: ReturnType<typeof setTimeout>;
try {
  const link = new BandLink({ agentId: env.BAND_RED_ID!, apiKey: env.BAND_RED_API_KEY!, logger });
  let room = env.BAND_ROOM_ID;
  if (!room) {
    room = (await link.rest.createChat({ title: 'AgentProof private dummy security lab' })).id;
    appendFileSync('.env', `BAND_ROOM_ID=${room}\n`);
  }
  const participants = await link.rest.listChatParticipants(room);
  for (const id of [env.BAND_BLUE_ID, env.BAND_OWNER_ID]) {
    if (id && !participants.some(p => p.id === id)) await link.rest.addChatParticipant(room, { participantId: id, role: 'member' });
  }
  let done!: () => void;
  const received = new Promise<void>(resolve => { done = resolve; });
  for (const role of ['RED', 'BLUE']) {
    agents.push(Agent.create({ config: { agentId: env[`BAND_${role}_ID`]!, apiKey: env[`BAND_${role}_API_KEY`]! },
      logger, roomFilter: r => r.id === room, linkOptions: { conflictPolicy: 'reject' },
      adapter: new GenericAdapter(async ({ message, tools, roomId }) => {
        if (roomId !== room || !message.content.includes(nonce)
          || message.senderId !== env[role === 'BLUE' ? 'BAND_RED_ID' : 'BAND_BLUE_ID']) { tools.turn.settle(); return; }
        events.push({ role, receivedMessageId: message.id, senderId: message.senderId, roomId, at: new Date().toISOString() });
        if (role === 'BLUE') await tools.sendMessage('Connectivity ACK only (not AI): ' + nonce, [{ id: env.BAND_RED_ID! }]);
        else { tools.turn.settle(); done(); }
      }),
    }));
  }
  for (const agent of agents) await agent.start();
  await link.rest.createChatMessage(room, { content: 'Connectivity probe only (not AI): ' + nonce, mentions: [{ id: env.BAND_BLUE_ID! }] });
  await Promise.race([received, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Timeout')), 40000); })]);
  const evidence = { liveBandVerified: true, autonomousAI: false, sdk: '@band-ai/sdk@1.0.0', roomId: room, events };
  writeFileSync(new URL('../docs/phase4.1-band.json', import.meta.url), JSON.stringify(evidence, null, 2) + '\n');
  console.log(JSON.stringify({ liveBandRoundTrip: true, receivedEvents: events.length, aiRun: false }));
} catch (error: any) {
  console.log(JSON.stringify({ liveBandRoundTrip: false, errorType: error?.name, status: error?.statusCode ?? null }));
  process.exitCode = 2;
} finally {
  clearTimeout(timer!);
  await Promise.allSettled(agents.map(agent => agent.stop(5000)));
}
