// Deterministic secret and PII detection used for evidence, dashboards and output filtering.
// Pattern-based: it finds common credential formats, not every possible secret.
export type SecretFinding = { type: string; start: number; end: number };

const luhn = (digits: string): boolean => {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
};

const DETECTORS: Array<{ type: string; pattern: RegExp; accept?: (match: string) => boolean }> = [
  { type: 'private-key', pattern: /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\s\S]{0,8192}?-----END [A-Z ]{0,40}PRIVATE KEY-----/g },
  { type: 'aws-access-key', pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { type: 'github-token', pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g },
  { type: 'slack-token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,200}/g },
  { type: 'stripe-key', pattern: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,200}\b/g },
  { type: 'api-key', pattern: /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,200}/g },
  { type: 'google-api-key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { type: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { type: 'bearer-token', pattern: /\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*/gi },
  { type: 'connection-string', pattern: /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:@/]{1,100}:[^\s@/]{3,200}@[^\s'"]{1,300}/gi },
  { type: 'credential-assignment',
    pattern: /\b[A-Za-z0-9_.-]{0,40}(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]{0,40}["']?\s*[:=]\s*["']?[^\s"',;]{6,}/gi },
  { type: 'us-ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  { type: 'payment-card', pattern: /\b\d(?:[ -]?\d){12,18}\b/g, accept: match => luhn(match.replace(/\D/g, '')) },
];
const EMAIL = /\b([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24})\b/g;
const SENSITIVE_KEY = /(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|credential)/i;
const MAX_SCAN = 256 * 1024;

export function findSecrets(text: string): SecretFinding[] {
  const sample = text.length > MAX_SCAN ? text.slice(0, MAX_SCAN) : text;
  const found: SecretFinding[] = [];
  for (const { type, pattern, accept } of DETECTORS) {
    for (const match of sample.matchAll(pattern)) {
      if (accept && !accept(match[0])) continue;
      const start = match.index!, end = start + match[0].length;
      if (!found.some(f => start < f.end && end > f.start)) found.push({ type, start, end });
    }
  }
  return found.sort((a, b) => a.start - b.start);
}

export const secretTypes = (text: string): string[] => [...new Set(findSecrets(text).map(f => f.type))];

// Emails keep their domain (needed to explain destination decisions); the local part is masked.
export function redactText(text: string): string {
  if (text.length > MAX_SCAN) text = text.slice(0, MAX_SCAN) + '[TRUNCATED]';
  let out = '', cursor = 0;
  for (const finding of findSecrets(text)) {
    out += text.slice(cursor, finding.start) + `[REDACTED:${finding.type}]`;
    cursor = finding.end;
  }
  out += text.slice(cursor);
  return out.replace(EMAIL, (_, local: string, domain: string) => `${local[0]}***@${domain}`);
}

// Deep redaction for evidence. Values under credential-like keys are removed outright.
export function redactValue(value: unknown, depth = 0): unknown {
  if (depth > 32) return '[REDACTED:depth]';
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.slice(0, 256).map(item => redactValue(item, depth + 1));
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = SENSITIVE_KEY.test(key) && typeof item === 'string' ? '[REDACTED:sensitive-field]' : redactValue(item, depth + 1);
    }
    return out;
  }
  return value;
}
