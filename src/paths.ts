import path from 'node:path';

// Deliberately portable virtual namespace; never resolve against the host disk.
export function canonicalPath(input: unknown): string | null {
  if (typeof input !== 'string' || input.length === 0 || input.length > 1024
    || path.posix.isAbsolute(input) || path.win32.isAbsolute(input)) return null;
  const parts = input.replaceAll('\\', '/').split('/');
  for (const part of parts) {
    if (!/^[a-zA-Z0-9_][a-zA-Z0-9_. -]*$/.test(part)
      || /[. ]$/.test(part) || part.length > 255
      || /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:[ .]|$)/i.test(part)) return null;
  }
  return parts.join('/').toLowerCase();
}
