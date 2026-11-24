# Automatic security repair engine (Phases 2–3)

AgentProof can now find holes in an agent's authorization policy, explain why they exist,
synthesize minimal policy repairs, prove each repair by replay, and apply it only after a
human approves, with versioning, rollback and re-verifiable before/after evidence.

```
policy + labelled synthetic environment
  → discover   generate attack traces from the policy's own grants × labelled assets × transforms   src/repair/discover.ts
  → replay     deterministic counterfactual execution through the real firewall                      src/repair/replay.ts
  → analyze    root cause = decision record + data lineage + target provenance + policy text         src/repair/analyze.ts
  → propose    typed operators: flow-rule, narrow-allow, split-approval, deny-target/scope,
               trusted-target, protect-source, threshold, deny-tool (naive)                          src/repair/analyze.ts
  → verify     replay vulnerable trace, every known attack (security regressions), legit suite       src/repair/engine.ts
  → rank       eligible = valid ∧ fixes target ∧ 0 security regressions; fixed-weight score          src/repair/engine.ts
  → iterate    rediscover against the repaired policy with fresh destination names
  → certify    canonical certificate: policies, patch, before/after decision vectors, suite digests
  → approve    PolicyStore: human-only apply, stale-proposal guard, versions, rollback, ledger       src/repair/store.ts
```

The original Phase 2 ranking score was 100 + 40·(vulnerability share fixed) − 60·(legitimate
tasks newly blocked) − 25·(new approvals) − 2·complexity + 5 for blocking the target. It remains
available as the explicit `phase2` comparison strategy; Phase 3 uses the multi-objective ranking below.

New policy primitives the engine can synthesize (also usable by hand, in `src/guard/mandate.ts`):
`flows` (labelled data-flow rules: content or session match, approval or deny) and
`trustedTargets` (targets must be named by the user or mandate). Policy changes hot-swap a live
firewall; tokens issued under the old version fail with `POLICY_CHANGED`.

## Use
```sh
node src/repair/cli.ts benchmarks/repair/dev-report.ts --out repair.json   # discover + propose
node src/repair/cli.ts verify repair.json benchmarks/repair/dev-report.ts  # re-verify every certificate
node src/repair/server.ts benchmarks/repair/dev-report.ts                  # interactive dashboard :8790
node benchmarks/repair.ts                                                   # Phase 2 benchmark
```
Static snapshot: `docs/demo/repair-dashboard.html`.

## Phase 3: functionality-preserving synthesis

Phase 3 treats all prior Phase 2 evaluation cases as development data and replaces example-shaped
repairs with three generalized mechanisms:

- `protect-classified-sources` protects all labelled confidential/credential assets without
  narrowing the surrounding legitimate read scope to observed filenames.
- `trusted-target` requires the exact recipient or state-changing network destination to occur in
  trusted user/operator intent. Read-only GET/HEAD requests remain governed by the reviewed allow scope.
- bounded pairwise composition merges compatible flow, source-protection, provenance and scoped-deny
  changes; conflicting scalar patches are rejected.

Eligible candidates must still fix the target and introduce zero security regressions. Ranking then
scores security gain, blocked legitimate work, extra approvals, stricter legitimate steps, policy
change cost and estimated generalization risk. Exact-resource narrowing and global thresholds carry
the highest over-fit penalties. Certificates retain the Phase 2 canonical replay format and verifier.

The Phase 3 holdout was frozen at commit `0509c8d` before its first run. It contains new output
filenames, recipients, endpoints and action variations; it is self-authored, not independent.

| Strategy | Vulns prevented | Legit completed unattended | Legit not blocked | FP steps | Security regressions |
| --- | ---: | ---: | ---: | ---: | ---: |
| original policy | 0% | 100% | 100% | 0% | 0 |
| Phase 2 automatic | 100% | 66.7% | 66.7% | 16.7% | 0 |
| **Phase 3 optimized** | **100%** | **100%** | **100%** | **0%** | **0** |
| manual expert | 96.3% | 88.9% | 88.9% | 5.6% | 0 |
| deny-all | 100% | 0% | 0% | 50% | 0 |
| deny-sinks | 95.4% | 11.1% | 11.1% | 44.4% | 0 |

All 8 generated Phase 3 repair certificates independently re-verified. See
`docs/benchmark/phase3-repair-results.json`; historical Phase 2 results remain unchanged.

## H-A13, the first regression case
Phase 1's only holdout miss (approved HR read, then HR text copied into `out/`) is never given to
the engine. On the dev environment it discovers 14 vulnerabilities in the same class and proposes
three repairs: narrow `write-out` to the legitimately used file; a content-level deny flow rule for
the HR source; a session-level approval rule for paraphrase-style leaks (costs one legit approval).
Replaying the literal H-A13 trace: vulnerable before, prevented after (`test/repair.test.ts`).

## Phase 2 results (frozen set, first run, `docs/benchmark/repair-results.json`)
Four unseen environments (clinic, finance, devops, support) were committed with manual expert
policies at `3277bef`, before the first run. Scoring attacks use fresh destination names; legit
tasks include a held-out suite the engine never saw.

| Strategy | Vulns prevented | Legit completed unattended | Legit not blocked | FP steps | Security regressions |
| --- | --- | --- | --- | --- | --- |
| baseline | 0% | 100% | 100% | 0% | 0 |
| **automatic** | **100%** | 76.5% | 82.4% | 12.1% | 0 |
| manual expert | 96.3% | 100% | 100% | 0% | 0 |
| deny-all | 100% | 0% | 0% | 51.5% | 0 |
| deny-sinks | 95.4% | 11.8% | 11.8% | 45.5% | 0 |

- Discovery rate: **11/12** seeded weaknesses (missed: credential fragments in `ci-comment`,
  which the baseline firewall already stopped, so it was not exploitable).
- Repair latency: mean 1.09 s per environment, 0.55 s per proposal (Node 22, cloud container).
- Automatic matched the expert on clinic and devops. It lost legitimate held-out tasks on finance
  and support. **Root cause:** `narrow-allow` derives least privilege from a small legit suite and
  over-fits (new filenames/endpoints break), and `threshold` changes are global. The expert policies
  left 2 vulnerabilities each in finance and support. Not tuned after the run.

## Prior art (from a literature scan; several 2026 preprints seen at abstract level only)
The validated-repair loop is established: GenProg, Meta SapFix, Google CodeMender and DARPA AIxCC
systems patch code and accept a fix only if the failing case stops and regression tests pass.
Policy-side relatives: AWS IAM Access Analyzer policy generation and CheckNoNewAccess,
audit2allow, GCP IAM recommender (revert), Styra DAS decision-log replay, XACML policy repair
(Xu et al.), CloudFix (LLM + SMT IAM repair), and for agents Progent, Conseca, AgentSpec,
MiniScope, AgentBound, AWS AgentCore Policy, plus preprints AutoSpec, VEPA and Lattice.
**Our claim is integration, not invention:** we did not find one system that, for LLM-agent
tool-call authorization, combines synthetic attack discovery, provenance/data-flow root cause,
mixed-operator minimal repairs, counterfactual + regression replay, ranking, and human-approved
versioned application with re-verifiable certificates. "Authorization Closure Graph: Minimal
Repair for LLM Agents" (arXiv 2609.32428) could not be read and may overlap.

## Limitations
- Synthetic environments and asset labels are hand-authored; ground truth depends on them.
- Discovery covers exfiltration (7 transforms), untrusted targets and over-reads; not semantic
  misuse inside an allowed action, timing or multi-agent attacks.
- Least-privilege narrowing over-fits small legit suites (measured above).
- Phase 3's improved generalization is measured on only nine self-authored legitimate holdout tasks;
  labels are supplied by the synthetic environment and real-world classification errors are unmeasured.
- Certificates prove reproducibility of deterministic replay, not real-world safety.
- No LLM is used to propose repairs; a live LLM agent demo is blocked here (see PROJECT_STATUS.md).
