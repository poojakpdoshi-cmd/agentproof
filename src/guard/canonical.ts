import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

// Canonical JSON for hashing: sorted keys (UTF-16 order, as in RFC 8785), no whitespace.
// Only plain JSON data is accepted; anything ambiguous throws so callers fail closed.
export function canonical(value: unknown, depth = 0): string {
  if (depth > 64) throw new Error('Canonical depth exceeded');
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Non-finite number');
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) return '[' + value.map(item => canonical(item, depth + 1)).join(',') + ']';
  if (typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    const object = value as Record<string, unknown>;
    return '{' + Object.keys(object).filter(key => object[key] !== undefined).sort()
      .map(key => JSON.stringify(key) + ':' + canonical(object[key], depth + 1)).join(',') + '}';
  }
  throw new Error('Unsupported value in canonical JSON');
}

export const sha256 = (data: string | Buffer): string => createHash('sha256').update(data).digest('hex');
export const digest = (value: unknown): string => sha256(canonical(value));
export const hmac = (key: Buffer, data: string): string => createHmac('sha256', key).update(data).digest('hex');

export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a), right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

// Byte-compatible with agntid-python 0.2.0 `arguments_digest`:
// json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False) -> SHA-256.
// Python sorts keys by code point and prints floats differently from JS (1.0 vs 1), so
// non-integer numbers are refused instead of risking a silent approval-binding mismatch.
export function agntidArgumentsDigest(args: Record<string, unknown>): string {
  const encode = (value: unknown, depth: number): string => {
    if (depth > 64) throw new Error('Digest depth exceeded');
    if (value === null || typeof value === 'boolean') return JSON.stringify(value);
    if (typeof value === 'string') {
      if (/[\uD800-\uDFFF]/.test(value.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, ''))) throw new Error('Lone surrogate');
      return JSON.stringify(value);
    }
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value)) throw new Error('Only safe integers are digest-compatible');
      return String(value);
    }
    if (Array.isArray(value)) return '[' + value.map(item => encode(item, depth + 1)).join(',') + ']';
    if (typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
      const object = value as Record<string, unknown>;
      const byCodePoint = (a: string, b: string) => {
        const x = Array.from(a, c => c.codePointAt(0)!), y = Array.from(b, c => c.codePointAt(0)!);
        for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
        return x.length - y.length;
      };
      return '{' + Object.keys(object).sort(byCodePoint)
        .map(key => JSON.stringify(key) + ':' + encode(object[key], depth + 1)).join(',') + '}';
    }
    throw new Error('Unsupported value in AgntID digest');
  };
  return sha256(Buffer.from(encode(args, 0), 'utf8'));
}
