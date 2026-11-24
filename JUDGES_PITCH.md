# Judges' pitch

## 60 seconds
AI agents now read untrusted content and act on it: they send email, call APIs, run commands.
One poisoned document can turn a summarizer into an exfiltration tool. AgentProof is a runtime
action firewall that sits between the agent and its tools. It checks every proposed call
against an intent mandate (what this user actually authorized, for which resources, until
when), and it asks a question most filters don't: *who chose this target?* If the recipient or
URL came only from untrusted content, or the payload carries data read from a protected file
(even base64-encoded), the action is blocked or sent to a human. Allowed actions get a one-time
token bound to their exact digest, so what was approved is what runs. Every decision lands in a
hash-chained, HMAC-signed evidence log anyone can verify. On a blind holdout set: 95.8%
detection, 0% false positives, zero deterministic bypasses, 0.25 ms p95. It runs as a drop-in
MCP proxy, needs no LLM to decide, and layers under AgntID's runtime with fail-closed semantics.

## 3-minute presentation
1. **Problem (20 s).** Indirect prompt injection turns permitted tools into attack paths
   (OWASP agentic risks: goal hijack, tool misuse). Classifiers alone are probabilistic;
   static allowlists miss *which* target an allowed tool is pointed at.
2. **Live A/B (80 s).** Run `npm run demo` (HACKATHON_DEMO.md): unprotected leak vs. blocked
   exfiltration, legitimate work continuing, human approval, token swap refused.
3. **How (40 s).** Deterministic mandate → target provenance → session taint → explainable risk
   → decision → bound execution → output verification → evidence. Show one dashboard row's
   factors summing to the score.
4. **Proof (25 s).** BENCHMARK_RESULTS.md: dev vs holdout, the documented miss, tamper and
   concurrency suites. 157 automated tests on Linux and Windows CI.
5. **AgntID (15 s).** Adapter built from the official SDK's wire contract: task-intent shortlist
   as an external authorizer, execution through the Runtime. Tested against a labelled mock; live
   run pending organizer access.

## Hard questions, honest answers
- **"Isn't injection detection just regex?"** Yes, and we say so. It only adds bounded risk. The
  blocks in the demo come from the mandate and provenance, which are deterministic.
- **"Can a paraphrased exfiltration get through?"** Yes, if the target is allowed and the content
  is reworded. Taint catches verbatim (≥ 24 chars) and encoded copies; `CONFIDENTIAL_CONTEXT`
  raises risk on any egress after protected data was read, which catches some rearrangements.
- **"What if the attacker names a recipient the user also named?"** Provenance treats it as
  trusted; the mandate, secret and taint checks still apply.
- **"Who protects the evidence?"** Hash chain + HMAC + an anchor stored elsewhere detect edits,
  rewrites and truncation; a key holder or someone deleting the whole file is out of scope.
  Use WORM storage for that.
- **"Is the AgntID integration real?"** The adapter follows the official SDK contract and is
  tested against our mock. We have not run it against a live Runtime and do not claim to.
- **"Benchmarks written by the same team?"** Yes. The holdout was authored before the first dev
  run and frozen; it is still not independent. We would like to run garak/PyRIT corpora next.
- **"Is this a sandbox?"** No. It intercepts requests; tools reachable directly bypass it.
- **"Human approval in the MCP proxy?"** Not yet interactive: the proxy holds the action and
  returns an error; the library API supports approvals.

## Positioning by event (same platform, no new features)
| Event type | Angle | Evidence to show |
| --- | --- | --- |
| Cybersecurity | runtime prevention of unauthorized agent actions | demo blocks, deterministic bypass 0/67, tamper suite |
| Generative AI | agents that stay on task under injected content | legit completion 100%, provenance explanation |
| Developer tools | drop-in MCP proxy + library, zero runtime deps | one-line proxy command, mandate JSON, tests |
| Responsible AI | explainable, accountable decisions | factor-by-factor scores, human approval, verifiable evidence |
| General innovation | safer adoption of autonomous agents | A/B demo, latency 0.25 ms p95 |

Check each event's rules on pre-existing projects before submitting: the repository's first
commits are dated 2026-11-22, and the guard pipeline was added on 2026-11-24 (see git history).
Issue #1 records the owner's reading that the AgntID challenge permits existing projects; that
was not verified against the official page from this environment.
