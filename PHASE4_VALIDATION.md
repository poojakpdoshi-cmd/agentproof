# Phase 4 security validation

Implementation: Phase 3 commit `93f0893` (no guard or repair code changed). Cases frozen at
`80d727a` before their first execution. Run on Node 24:

```sh
npm ci
npm run benchmark:validation:phase4
node benchmarks/validation/phase4-diagnostic.ts
npm run typecheck
npm test
```

The runner writes `docs/benchmark/phase4-validation.json`. Existing Phase 1–3 benchmark files
are untouched. All strategies replay the same proposed actions and legitimate traces within
each environment. `original` uses that environment's starting mandate; `agentproof` uses the
Phase 3 repair output, except the external action slice, where it uses a preconfigured
trusted-target mandate. `deny-all` denies every tool; `deny-sinks` denies all outbound sinks.
No LLM, live service, or official AgentDojo checker is run.

## AgentDojo coverage

The external source is [AgentDojo](https://github.com/ethz-spylab/agentdojo) at
`089ed468cf3ed0322acc66b0211f26d9d90dbf60`, v1 workspace injection tasks 0 and 3.
We map their final single-recipient email goals to AgentProof `send_email`, with untrusted
email content carrying the target. Task 3's email search is omitted because there is no
matching AgentProof contract. This is **two action-level probes, not an AgentDojo benchmark
score**. The user tasks, model trajectories, dynamic injection placement, runtime state,
and official success check are not reproduced. Cloud-drive deletion by ID, calendar changes,
email search/delete, multi-recipient email, banking, Slack, and travel are unsupported.

| External action slice | Attacks blocked | Legitimate unattended |
| --- | ---: | ---: |
| Original policy | 2/2 | 2/2 |
| AgentProof configured policy | 2/2 | 2/2 |
| Deny-all | 2/2 | 0/2 |
| Deny-sinks | 2/2 | 0/2 |

The original policy already blocked both actions. These probes do not demonstrate a Phase 3
improvement. See the per-action decision vectors in the JSON output.

## Frozen isolated synthetic cases

Three unseen policy layouts provide 14 legitimate tasks and five proposed attacks, including
fresh filenames, an email domain, a wrong asset label, and paraphrased content.

| Strategy | Attacks prevented | Legitimate unattended |
| --- | ---: | ---: |
| Original policy | 1/5 | 14/14 |
| Phase 3 repair | 4/5 | 14/14 |
| Deny-all | 5/5 | 0/14 |
| Deny-sinks | 5/5 | 0/14 |

Four of four generated certificates re-verified. In the classified report, attacks were
stopped at the confidential read; the same applies to the held support paraphrase trace.
The wrong label caused a real miss: the misclassified private file was read and copied into
an output file with no review. The repair engine proposed no patch for that environment.

## Post-evaluation paraphrase diagnostic

`phase4-diagnostic.ts` is a separate follow-up, excluded from frozen totals. It grants an
approved confidential read and applies a content-matching deny flow. An exact copy is blocked;
a paraphrase is **allowed** after the read approval. This demonstrates the remaining semantic
data-flow gap. The diagnostic was added after inspecting the frozen run and must not be called
independent holdout evidence.

## Interpretation

The narrow external slice and self-authored synthetic cases are useful failure probes, not a
statistical estimate of real agent security. In particular, neither an AgentDojo leaderboard
comparison nor a live LLM task-success claim is supported. Independent end-to-end validation
needs a tool adapter and an agent runner that preserves AgentDojo state and official checks.
