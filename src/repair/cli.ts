#!/usr/bin/env node
// node src/repair/cli.ts ENV_MODULE [--out FILE]   run discovery + repair, write a report
// node src/repair/cli.ts verify REPORT.json ENV_MODULE   re-verify every certificate from scratch
// ENV_MODULE must export `env` (an Environment). Reports contain synthetic data only.
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { repair, verifyCertificate } from './engine.ts';
import type { Environment } from './types.ts';

const args = process.argv.slice(2);
const load = async (file: string): Promise<Environment> => (await import(pathToFileURL(path.resolve(file)).href)).env;
if (args[0] === 'verify' && args[1] && args[2]) {
  const report = JSON.parse(readFileSync(args[1], 'utf8'));
  const env = await load(args[2]);
  let ok = true;
  for (const p of report.proposals) {
    const attacks = report.attacks.filter((a: { id: string }) => Object.hasOwn(p.certificate.security.before, a.id));
    const r = verifyCertificate(p.certificate, env, p.before, attacks);
    ok &&= r.ok;
    console.log(`${p.id}: ${r.ok ? 'VERIFIED' : 'MISMATCH ' + r.mismatches.join(', ')}`);
  }
  process.exitCode = ok ? 0 : 1;
} else if (args[0]) {
  const env = await load(args[0]);
  const report = repair(env);
  const out = args.includes('--out') ? args[args.indexOf('--out') + 1] : `repair-${env.id}.json`;
  writeFileSync(out, JSON.stringify(report, null, 2) + '\n');
  console.log(`${env.id}: ${report.discovered} attacks generated, ${report.initialVulnerabilities} vulnerabilities, ${report.proposals.length} repair(s), ${report.residual.length} residual, ${report.latencyMs} ms`);
  for (const p of report.proposals) console.log(`  ${p.id}  ${p.chosen.candidate.summary}  (fixes ${p.chosen.vulnerabilitiesFixed}, legit blocked ${p.chosen.legitBlocked}, held ${p.chosen.legitHeld})`);
  console.log(`Report: ${out}. Verify: node src/repair/cli.ts verify ${out} ${args[0]}`);
} else {
  process.stderr.write('Usage: node src/repair/cli.ts ENV_MODULE [--out FILE] | verify REPORT.json ENV_MODULE\n');
  process.exitCode = 2;
}
