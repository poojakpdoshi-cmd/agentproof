# Phase 5 classification and lineage hardening

Phase 4 base `6151f66`; frozen Phase 5 cases `808ecf0`. No prior benchmark result was edited.

Mandates may supply operator-authored `classifications` with class, confidence and exact resource
scope. A non-public class or confidence below 0.8 requires read approval. Bounded deterministic
inspection checks returned text for health, payroll and identity-number signals; a conflicting or
missing public classification taints the session and requires review of later outbound actions.
This catches the Phase 4 wrong-label example. The inspection is a backstop, not a general semantic
classifier; it can miss other sensitive material and generate false alarms.

`enforceLineage` applies persistent session labels to write, email, network and command outputs
even when the outgoing text shares no words with the source. By default these actions need review.
Operator-authored `declassifications` can allow an exact destination for all active source labels;
explicit deny rules still win. Broad destination patterns cannot be used for automatic allow.
Repair synthesis can propose classification and lineage rules together, while ranking replays
legitimate tasks and security regressions. The proposal still requires human approval.

Reproduce on Node 24:

```sh
npm ci
npm run benchmark:validation:phase5
npm run typecheck
npm test
```

The frozen self-authored set in `docs/benchmark/phase5-results.json` stopped **4/4** proposed
leaks and completed **5/5** legitimate tasks unattended. It blocked **0** legitimate tasks,
added **0** stricter legitimate steps, and had **2** already-required read approvals. Full
in-process replay latency, including setup and evidence, was p50 **1.247 ms** and p95
**3.58 ms** across 270 samples on local Windows Node 24.19.0. The frozen policies already
contained the new controls, so the repair engine generated **0/0** certificates for these
cases; a separate development integration test verifies a composite repair certificate.

Remaining limits: a human may approve a malicious action; incorrect high-confidence metadata
and sensitive prose outside deterministic inspection patterns can escape; session labels are
conservative and cannot prove which exact facts a paraphrase contains; process restarts and
actions outside the proxy are not tracked. Exact destination declassification trusts the
operator's policy judgment and does not itself validate the outgoing summary's semantics.
