# Security

## What AgentProof guarantees (within THREAT_MODEL.md)
- **Deny by default.** A tool call executes only if a registered contract validates it and an
  unexpired mandate for that agent explicitly allows the tool on that resource. Explicit deny
  rules win. Protected scopes need a specific grant and a human. 0 bypasses across 67
  deterministic-policy benchmark cases (BENCHMARK_RESULTS.md).
- **Decision = execution.** Only an action whose canonical digest matches a one-time,
  HMAC-signed authorization executes; replays and swaps are refused and recorded.
- **Fail closed.** Errors, timeouts, malformed or unknown answers from an external authorizer
  block. A corrupted evidence file stops the proxy from starting rather than being extended.
- **No secrets in evidence or dashboards.** Credential patterns are redacted before writing;
  credential-like fields are dropped; emails are masked.

## What it does not guarantee
- Prompt-injection detection is heuristic. It raises risk; it is not complete protection.
- Data-flow tracking catches verbatim (≥ 24 chars) and base64/hex/percent-encoded copies of
  protected content and seen credentials, not paraphrases. Content read before AgentProof saw
  it is not tracked.
- The upstream tool is trusted to honor its contract. AgentProof is not an OS sandbox.
- Agent and approver identities are asserted by the integration; authenticate them upstream
  (for example with AgntID).
- In proxy mode, `REQUIRE_APPROVAL` is refused unless `--approvals` is set; then the call is held
  until an operator decides through a loopback, bearer-token API (timeout → refused).
- Repairs are applied only by a named human approver (never the engine or the agent), only to the
  exact policy they were verified against, and can be rolled back; all changes are ledgered.

## Operating guidance
- Keep mandates narrow and short-lived; prefer exact resources over prefixes.
- Set an evidence HMAC key (32 random bytes, stored outside the agent's reach) and record the
  head anchor elsewhere (`node src/verify-evidence.ts FILE --anchor SEQ:HASH`).
- Run the proxy as the only path to the upstream (stdio child process).
- Use synthetic data in tests; test fixtures assemble credential-shaped strings at runtime.
- Never pass keys on the command line: the verifier and dashboard read
  `AGENTPROOF_EVIDENCE_KEY` from the environment.

## Reporting
Please report suspected vulnerabilities privately through GitHub security advisories on this
repository rather than public issues. Include a minimal reproduction using dummy data.
