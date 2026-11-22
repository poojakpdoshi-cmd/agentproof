import timers from 'node:timers/promises';
import { systemInstruction } from './model.ts';
import type { Reasoner } from './model.ts';

// One instance is shared by Red/Blue: at most six Red and three Blue requests.
// No retries or fallback; the operator must investigate before restarting.
export function geminiModel(env: NodeJS.ProcessEnv): Reasoner {
  if (env.GEMINI_LIVE_ENABLED !== 'true' || env.GEMINI_FREE_TIER_CONFIRMED !== 'true') {
    throw new Error('Gemini disabled: eligible operator authorization and free-tier confirmation required');
  }
  const key = env.GEMINI_API_KEY;
  const model = env.GEMINI_MODEL;
  if (!key || !/^[\x21-\x7e]{1,512}$/.test(key)) throw new Error('Invalid GEMINI_API_KEY');
  if (!model || !/^gemini-[a-z0-9][a-z0-9.-]{0,99}$/.test(model)) throw new Error('Invalid GEMINI_MODEL');
  let busy = false, stopped = false, requests = 0, nextRequest = 0;
  return { source: 'gemini:' + model, async decide(role, context) {
    if (stopped || requests >= 9) throw new Error('Gemini session stopped or request budget exhausted');
    if (busy) throw new Error('Gemini request already in progress');
    busy = true;
    try {
      const input = JSON.stringify(context);
      if (typeof input !== 'string' || Buffer.byteLength(input) > 65536) throw new Error();
      const delay = Math.max(0, nextRequest - Date.now());
      if (delay) await timers.setTimeout(delay);
      requests++;
      nextRequest = Date.now() + 15000;
      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(120000),
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: systemInstruction(role) }] },
          contents: [{ role: 'user', parts: [{ text: input }] }],
          generationConfig: { temperature: 0, candidateCount: 1, maxOutputTokens: 1500, responseMimeType: 'application/json' },
        }),
      });
      if (!response.ok) {
        await response.body?.cancel();
        // In particular 429 latches closed; never retry against exhausted quotas.
        throw new Error();
      }
      if (!response.body) throw new Error();
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 65536) { await reader.cancel(); throw new Error(); }
          chunks.push(value);
        }
      } finally { reader.releaseLock(); }
      const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
      const candidate = data.candidates?.[0];
      if (data.error || data.promptFeedback?.blockReason || data.candidates?.length !== 1
        || candidate?.finishReason !== 'STOP' || candidate.content?.role !== 'model'
        || candidate.safetyRatings?.some((v: any) => v.blocked)) throw new Error();
      const parts = candidate.content.parts;
      if (!Array.isArray(parts) || !parts.length || parts.some((p: any) =>
        !p || typeof p.text !== 'string' || Object.keys(p).some(k => !['text', 'thought', 'thoughtSignature'].includes(k))
        || (p.thought !== undefined && typeof p.thought !== 'boolean'))) throw new Error();
      const output = JSON.parse(parts.filter((p: any) => !p.thought).map((p: any) => p.text).join(''));
      if (!output || typeof output !== 'object' || Array.isArray(output)) throw new Error();
      // Action and policy validation remains in the existing workflow.
      return output;
    } catch {
      stopped = true;
      // Never expose provider bodies, prompts, keys or fetch exception details.
      throw new Error('Gemini inference failed; session stopped (no automatic retry)');
    } finally { busy = false; }
  } };
}
