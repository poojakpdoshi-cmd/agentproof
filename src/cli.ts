#!/usr/bin/env node
import { Simulator } from './simulator.ts';
import { record, keys } from './validation.ts';

const usage = 'AgentProof Phase 1\nUsage: node src/cli.ts < scenario.json\nInput: {"policy":{},"files":{},"actions":[]}\nOutput: one JSON audit record per action. Exit: 0 allowed, 1 denied, 2 invalid input.\n';

async function main(): Promise<void> {
  if (process.argv.length === 3 && process.argv[2] === '--help') {
    process.stdout.write(usage);
    return;
  }
  if (process.argv.length !== 2) throw new Error('Invalid arguments');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > 1024 * 1024) throw new Error('Input too large');
    chunks.push(buffer);
  }
  const scenario: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks)));
  if (!record(scenario) || !keys(scenario, ['policy', 'files', 'actions'], ['actions'])
    || !Array.isArray(scenario.actions)) throw new Error('Invalid scenario');
  const simulator = new Simulator(
    Object.hasOwn(scenario, 'policy') ? scenario.policy : undefined,
    Object.hasOwn(scenario, 'files') ? scenario.files : undefined,
  );
  for (const action of scenario.actions) {
    const { audit } = simulator.execute(action);
    process.stdout.write(JSON.stringify(audit) + '\n');
    if (audit.decision === 'deny') process.exitCode = 1;
  }
}

main().catch(() => {
  // Never echo untrusted input or dummy file contents into diagnostics.
  process.stderr.write('Invalid scenario or arguments. Use --help.\n');
  process.exitCode = 2;
});
