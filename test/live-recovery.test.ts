import assert from 'node:assert/strict';
import test from 'node:test';
import { LocalAgent } from '../demo/local-agent.ts';
import { run } from '../demo/live-validation.ts';
import { CASES } from '../demo/live-validation-cases.ts';
import { RECOVERY_CASES } from '../demo/live-recovery-cases.ts';
import { requestedOutputs } from '../demo/recovery.ts';
import type { RecoveryFeedback } from '../demo/recovery.ts';
import { repair } from '../src/repair/engine.ts';

function scripted(responses: unknown[]) {
  const feedback: Array<RecoveryFeedback | undefined> = [];
  let index = 0;
  const agent = new LocalAgent('mock', async (_url, init) => {
    const request = JSON.parse(String(init?.body));
    feedback.push(JSON.parse(request.messages[1].content).feedback);
    const response = responses[index++];
    assert.notEqual(response, undefined, 'unexpected model call');
    return new Response(JSON.stringify({ message: { content: JSON.stringify(response) } }), { status: 200 });
  });
  return { agent, feedback };
}

test('blocked destination receives trusted feedback; only a new authorized model action completes', async () => {
  const selected = CASES[2], policy = repair(selected.environment).finalPolicy;
  const { agent, feedback } = scripted([
    { tool: 'read_file', arguments: { path: 'docs/weekly.md' } },
    { tool: 'write_file', arguments: { path: 'out/strategy-copy.md', data: 'The product shipped on time; tickets fell 12%.' } },
    { tool: 'write_file', arguments: { path: 'out/summary.md', data: 'The product shipped on time; tickets fell 12%.' } },
    { done: true },
  ]);
  const result = await run(agent, selected.environment, selected.unauthorizedRead, selected.unauthorizedWrite, policy);
  assert.equal(result.unauthorizedWriteAttempts, 1);
  assert.equal(result.unauthorizedWriteExecutions, 0);
  assert.equal(result.legitimateCompleted, true);
  assert.equal(result.completionVerified, true);
  assert.equal(result.recoveryTurns, 1);
  assert.ok(feedback[2]?.denialReasons.includes('UNTRUSTED_TARGET'));
  assert.equal(feedback[2]?.originalTask, selected.environment.mandate.objective);
});

test('missing output prevents a false done and retries stop at the bound', async () => {
  const selected = RECOVERY_CASES[1];
  const { agent, feedback } = scripted([{ done: true }, { done: true }, { done: true }]);
  const result = await run(agent, selected.environment, selected.unauthorizedRead, selected.unauthorizedWrite);
  assert.equal(result.stopped, 'incomplete output');
  assert.equal(result.completionVerified, false);
  assert.equal(result.falseSuccessPrevented, true);
  assert.equal(result.prematureDone, 3);
  assert.equal(result.recoveryTurns, 2);
  assert.equal(result.actionAttempts, 0);
  assert.equal(feedback[1]?.kind, 'missing-output');
  assert.deepEqual(feedback[1]?.missingOutputs, ['reports/weekly.md']);
  assert.deepEqual(requestedOutputs(selected.environment), ['reports/weekly.md']);
});
