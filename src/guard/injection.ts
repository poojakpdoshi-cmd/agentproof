// Heuristic prompt-injection detector for text entering an agent's context.
// It is probabilistic by nature: it raises risk, it never proves safety. Authorization
// decisions rest on the mandate; this signal only adds explainable, bounded risk.
export type InjectionResult = { score: number; signals: string[] };

const INVISIBLE = /[­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮⁠-⁤⁪-⁯︀-️﻿]/g;
const CONFUSABLES: Record<string, string> = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ӏ': 'l', 'ѕ': 's', 'ј': 'j', 'ԁ': 'd', 'ɡ': 'g', 'ո': 'n', 'ı': 'i' };
const LEET: Record<string, string> = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's' };

export function normalize(text: string): string {
  return text.normalize('NFKC').replace(INVISIBLE, '')
    .replace(/[Ѐ-ӿɐ-ʯ԰-֏ı]/g, c => CONFUSABLES[c] ?? c)
    .replace(/&(lt|gt|amp|quot|#39|#x27);/g, (_, e: string) => ({ lt: '<', gt: '>', amp: '&', quot: '"', '#39': "'", '#x27': "'" })[e]!)
    .toLowerCase().replace(/\r\n?/g, '\n').replace(/[^\S\n]+/g, ' ');
}
// Second view that undoes common letter/number substitutions inside words ("1gn0re").
const deleet = (text: string) => text.replace(/\b[\w@$]+\b/g, word => /[a-z]/.test(word) ? word.replace(/[013457@$]/g, c => LEET[c]) : word);

type Rule = { code: string; weight: number; pattern: RegExp; lines?: boolean };
const V_OVERRIDE = '(?:ignore|disregard|forget|override|skip|abandon|discard|drop)';
const RULES: Rule[] = [
  { code: 'INSTRUCTION_OVERRIDE', weight: 0.6, pattern: new RegExp(`\\b${V_OVERRIDE}\\b.{0,40}\\b(?:previous|prior|above|earlier|all|any|your|the|system|original|initial|preceding)\\b.{0,30}\\b(?:instructions?|prompts?|rules?|directives?|guidelines?|context|tasks?|orders?|constraints?)\\b`) },
  { code: 'NEW_INSTRUCTIONS', weight: 0.45, pattern: /\b(?:new|updated|real|actual|revised|true|hidden|secret|additional|important)\s+(?:instructions?|tasks?|objectives?|directives?|orders?|goals?)\b\s*(?:[:\-]|for (?:the |you|ai|assistant|agent))|\byour (?:new|real|true|actual|only) (?:task|goal|objective|job|purpose|instructions?) (?:is|are)\b/ },
  { code: 'ROLE_SPOOFING', weight: 0.5, lines: true, pattern: /(?:^|\n|[>"'\]])\s*(?:system|developer|admin|assistant)\s*(?:prompt|message|note|override|instruction)?\s*:(?!\/)|<\|?\s*(?:im_start|im_end|system|endoftext|assistant)\s*\|?>|\[\/?(?:system|inst|admin|developer)(?: message| note| override)?\]|#{2,}\s*(?:system|instructions?|admin)\b|\bbegin (?:system|admin) (?:prompt|message|override)\b/ },
  { code: 'PERSONA_SWITCH', weight: 0.35, pattern: /\byou are now\b|\bfrom now on,? you\b|\bpretend (?:to be|you are)\b|\bdeveloper mode\b|\bjailbr[eo]a?k\b|\bdo anything now\b|\bno (?:longer )?(?:bound|restricted) by\b|\bunrestricted (?:mode|ai|assistant)\b/ },
  { code: 'TOOL_DIRECTIVE', weight: 0.35, pattern: /\b(?:call|invoke|use|run|execute|trigger|launch)\b.{0,25}\b(?:the |a )?(?:tool|function|command|shell|terminal|script|plugin|send_email|execute_command|delete_file|network_request|write_file|grant_role|http request|curl|wget)\b/ },
  { code: 'EXFILTRATION_DIRECTIVE', weight: 0.45, pattern: /\b(?:send|forward|upload|post|transmit|exfiltrate|leak|email|e-mail|copy|share|submit|report|deliver|bcc|cc)\b.{0,80}?\b(?:to|at|into|with)\b.{0,12}?(?:https?:\/\/|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|\b[a-z0-9-]+\.(?:com|net|org|io|xyz|ru|cn|tk|test|example|site|top|info)\b)/ },
  { code: 'CREDENTIAL_SOLICITATION', weight: 0.4, pattern: /\b(?:read|send|print|reveal|show|include|output|dump|cat|list|retrieve|extract|share|give|attach|paste|leak|exfiltrate|collect|copy)\b.{0,50}\b(?:api[ _-]?keys?|passwords?|passwd|credentials?|secrets?|access tokens?|auth tokens?|tokens|\.env|env(?:ironment)? (?:vars?|variables)|private keys?|ssh keys?|id_rsa|session cookies?)\b/ },
  { code: 'CONCEALMENT', weight: 0.3, pattern: /\b(?:do not|don'?t|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|notify(?:ing)?|alert(?:ing)?|ask(?:ing)?|let(?:ting)?|show(?:ing)?|reveal(?:ing)?)\b.{0,25}\b(?:the )?(?:user|human|anyone|operator|admin|owner|customer|them)\b|\b(?:silently|secretly|covertly|quietly)\b.{0,40}\b(?:send|run|execute|delete|forward|copy|upload|grant|read)\b/ },
  { code: 'POLICY_BYPASS', weight: 0.45, pattern: /\b(?:bypass|disable|turn off|switch off|circumvent|evade|ignore|skip|deactivate|suppress)\b.{0,30}\b(?:security|safety|polic(?:y|ies)|guard(?:rails?)?|filters?|restrictions?|firewall|approvals?|monitoring|logging|audit|checks?|agentproof|authorization|permissions?)\b|\b(?:admin|god|sudo|root|maintenance|debug|override) (?:mode|override|access|privileges)\b/ },
  { code: 'PRIVILEGE_ESCALATION', weight: 0.4, pattern: /\bsudo\b|\bchmod\s+(?:-r\s+)?[0-7]*7[0-7]*\b|\bchown\b|\bsetuid\b|\b(?:grant|give|assign|add)\b.{0,25}\b(?:admin|administrator|root|owner|superuser|all)\b.{0,15}\b(?:access|permissions?|privileges?|role|rights)\b|\b(?:escalate|elevate)\b.{0,15}\bprivileges?\b|\bsudoers\b/ },
  { code: 'DESTRUCTIVE_DIRECTIVE', weight: 0.3, pattern: /\brm\s+-[a-z]*[rf][a-z]*\b|\bdrop\s+(?:table|database|schema)\b|\btruncate\s+table\b|\b(?:delete|wipe|erase|destroy|purge|remove)\b.{0,30}\b(?:all|every|entire|whole|database|repo(?:sitory)?|backups?|files|records|logs|history)\b/ },
  { code: 'URGENCY_AUTHORITY', weight: 0.15, pattern: /\b(?:urgent|immediately|right now|mandatory|compulsory|this is required|failure to comply)\b|\b(?:ceo|cto|security team|it department|administrator|system administrator) (?:requires|requests|demands|has authorized|authorized)\b/ },
  { code: 'MARKDOWN_EXFIL', weight: 0.45, pattern: /!\[[^\]]{0,100}\]\(\s*https?:\/\/[^)\s]{1,300}[?&][^)\s=]{1,50}=/ },
  { code: 'HIDDEN_MARKUP', weight: 0.25, pattern: /<!--[\s\S]{0,400}?\b(?:instruction|assistant|ai|agent|ignore|system|execute|send)\b[\s\S]{0,400}?-->|display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*(?:white|#fff(?:fff)?)\b/ },
];

const SQUASHED_OVERRIDE = /(?:ignore|disregard|forget|override)(?:all|any|the|your)?(?:previous|prior|above|earlier|system|original)(?:instructions?|prompts?|rules?|directives?)/;
const noisyOr = (weights: number[]) => 1 - weights.reduce((p, w) => p * (1 - w), 1);

function scan(view: string, signals: Map<string, number>): void {
  const flat = view.replace(/\n/g, ' ');
  for (const rule of RULES) {
    if (rule.pattern.test(rule.lines ? view : flat)) signals.set(rule.code, Math.max(signals.get(rule.code) ?? 0, rule.weight));
  }
}

// Signals that indicate an attempt to subvert the instruction hierarchy itself. Used for
// trusted (user) text, where requests to send, run or delete things are ordinary work.
export const JAILBREAK_SIGNALS: ReadonlySet<string> = new Set(['INSTRUCTION_OVERRIDE', 'NEW_INSTRUCTIONS', 'ROLE_SPOOFING', 'PERSONA_SWITCH',
  'POLICY_BYPASS', 'CONCEALMENT', 'HIDDEN_MARKUP', 'OBFUSCATION', 'INVISIBLE_CHARACTERS', 'ENCODED_PAYLOAD']);

export function detectInjection(text: string, depth = 0, only?: ReadonlySet<string>): InjectionResult {
  const signals = new Map<string, number>();
  if (typeof text !== 'string' || text.length === 0) return { score: 0, signals: [] };
  const sample = text.length > 200_000 ? text.slice(0, 200_000) : text;
  const invisible = sample.match(INVISIBLE)?.length ?? 0;
  const view = normalize(sample);
  scan(view, signals);
  const unleeted = deleet(view);
  if (unleeted !== view) {
    const before = signals.size;
    scan(unleeted, signals);
    if (signals.size > before) signals.set('OBFUSCATION', 0.2);
  }
  // Separator obfuscation ("i g n o r e", "i.g.n.o.r.e"): match the core override phrase
  // with every non-letter removed. Narrow by design to limit cross-word false positives.
  const squashed = unleeted.replace(/[^a-z]/g, '');
  if (!signals.has('INSTRUCTION_OVERRIDE') && SQUASHED_OVERRIDE.test(squashed)) {
    signals.set('INSTRUCTION_OVERRIDE', 0.6);
    signals.set('OBFUSCATION', 0.2);
  }
  if (invisible >= 3) signals.set('INVISIBLE_CHARACTERS', 0.25);
  if (/[Ѐ-ӿ]/.test(sample) && /[a-z]/i.test(sample) && /\b\w*[a-z]\w*[Ѐ-ӿ]\w*\b|\b\w*[Ѐ-ӿ]\w*[a-z]\w*\b/i.test(sample)) {
    signals.set('MIXED_SCRIPT', 0.2);
  }
  // One level of encoded payload inspection (base64 / hex / percent-encoding).
  if (depth === 0) {
    const decoded: string[] = [];
    for (const blob of sample.match(/[A-Za-z0-9+/_-]{24,}={0,2}/g) ?? []) {
      const text = Buffer.from(blob.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
      if (/^[\x09\x0a\x0d\x20-\x7e]{12,}$/.test(text)) decoded.push(text);
    }
    for (const blob of sample.match(/\b(?:[0-9a-f]{2}){12,}\b/gi) ?? []) {
      const text = Buffer.from(blob, 'hex').toString('utf8');
      if (/^[\x09\x0a\x0d\x20-\x7e]{12,}$/.test(text)) decoded.push(text);
    }
    if (/(?:%[0-9a-f]{2}){6,}/i.test(sample)) { try { decoded.push(decodeURIComponent(sample)); } catch { /* malformed */ } }
    for (const inner of decoded) {
      const result = detectInjection(inner, 1);
      if (result.signals.length > 0) {
        for (const code of result.signals) signals.set(code, Math.max(signals.get(code) ?? 0, RULES.find(r => r.code === code)?.weight ?? 0.2));
        signals.set('ENCODED_PAYLOAD', 0.3);
      }
    }
  }
  if (only) for (const code of [...signals.keys()]) if (!only.has(code)) signals.delete(code);
  return { score: Math.round(noisyOr([...signals.values()]) * 1000) / 1000, signals: [...signals.keys()].sort() };
}
