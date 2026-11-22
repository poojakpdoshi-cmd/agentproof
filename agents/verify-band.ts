import { BandLink } from '@band-ai/sdk';
import { NoopLogger } from '@band-ai/sdk/core';
import { appendFileSync } from 'node:fs';
const env = process.env;
const links = ['RED', 'BLUE'].map(role => new BandLink({ agentId: env[`BAND_${role}_ID`]!, apiKey: env[`BAND_${role}_API_KEY`]!, logger: new NoopLogger() }));
for (let i = 0; i < links.length; i++) {
  try {
    const identity = await links[i].rest.getAgentMe({ maxRetries: 0, timeoutInSeconds: 12 });
    if (identity.id !== env[`BAND_${i ? 'BLUE' : 'RED'}_ID`]) throw new Error('identity mismatch');
    console.log(JSON.stringify({ role: i ? 'Blue' : 'Red', authenticated: true }));
    if (i === 0 && identity.ownerUuid && !env.BAND_OWNER_ID) appendFileSync('.env', `BAND_OWNER_ID=${identity.ownerUuid}\n`);
    const chats = await links[i].rest.listChats({ page: 1, pageSize: 20 });
    console.log(JSON.stringify({ role: i ? 'Blue' : 'Red', rooms: chats.data.map((v: any) => ({ id: v.id, title: v.title })) }));
  } catch (e: any) { console.log(JSON.stringify({ role: i ? 'Blue' : 'Red', authenticated: false, errorType: e?.name, status: e?.statusCode ?? e?.status ?? null })); }
}
