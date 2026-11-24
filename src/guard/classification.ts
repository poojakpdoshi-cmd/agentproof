// Deterministic inspection is a backstop for inaccurate metadata, not a semantic classifier.
// Keep checks bounded and explainable; never treat text supplied by a tool as trusted metadata.
export function inspectSensitive(text: string): { sensitive: boolean; signals: string[] } {
  const sample = text.slice(0, 1 << 20);
  const signals: string[] = [];
  if (/\b(?:medical (?:diagnosis|leave|condition|appointment)|diagnos(?:is|ed)|insulin|patient\s+record)\b/i.test(sample)) signals.push('health');
  if (/\b(?:salary|payroll|compensation)\b.{0,80}\b\d{4,}\b/i.test(sample)) signals.push('payroll');
  if (/\b\d{3}-\d{2}-\d{4}\b/.test(sample)) signals.push('identity-number');
  return { sensitive: signals.length > 0, signals };
}
