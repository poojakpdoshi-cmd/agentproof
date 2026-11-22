import type { Readable, Writable } from 'node:stream';
import { keys, record } from './validation.ts';

export type Id = string | number;
export type Message = Record<string, unknown> & { jsonrpc: '2.0'; id?: Id; method?: string };
export const MAX_FRAME = 1024 * 1024;
export const validId = (id: unknown): id is Id => typeof id === 'string'
  || (typeof id === 'number' && Number.isSafeInteger(id));

export function message(value: unknown): value is Message {
  if (!record(value) || value.jsonrpc !== '2.0') return false;
  if (Object.hasOwn(value, 'id') && !validId(value.id)) return false;
  if (Object.hasOwn(value, 'method')) {
    return typeof value.method === 'string' && value.method.length > 0
      && keys(value, ['jsonrpc', 'id', 'method', 'params'])
      && (!Object.hasOwn(value, 'params') || record(value.params));
  }
  if (!Object.hasOwn(value, 'id') || !keys(value, ['jsonrpc', 'id', 'result', 'error'])) return false;
  if (Object.hasOwn(value, 'result') === Object.hasOwn(value, 'error')) return false;
  if (Object.hasOwn(value, 'result')) return record(value.result);
  return !Object.hasOwn(value, 'error') || (record(value.error)
    && Number.isSafeInteger(value.error.code) && typeof value.error.message === 'string');
}

export async function* lines(stream: Readable): AsyncGenerator<string> {
  let pending = Buffer.alloc(0);
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  for await (const chunk of stream) {
    const bytes = Buffer.from(chunk);
    let start = 0;
    for (let end = bytes.indexOf(10); end !== -1; end = bytes.indexOf(10, start)) {
      if (pending.length + end - start > MAX_FRAME) throw new Error('Frame too large');
      const frame = Buffer.concat([pending, bytes.subarray(start, end)]);
      pending = Buffer.alloc(0);
      start = end + 1;
      const line = decoder.decode(frame);
      if (line.trim() !== '') yield line;
    }
    if (pending.length + bytes.length - start > MAX_FRAME) throw new Error('Frame too large');
    pending = Buffer.concat([pending, bytes.subarray(start)]);
  }
  if (pending.length > 0) throw new Error('Truncated frame');
}

export function send(stream: Writable, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    stream.write(JSON.stringify(value) + '\n', error => error ? reject(error) : resolve());
  });
}

export const rpcError = (id: Id | null, code: number, text: string) =>
  ({ jsonrpc: '2.0', ...(id === null ? {} : { id }), error: { code, message: text } });
