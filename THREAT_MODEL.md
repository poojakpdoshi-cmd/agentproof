# Threat model

## Assets
Credentials and secrets reachable by tools; confidential files and PII; external destinations
(email, HTTP); integrity of files and systems the agent can modify; privilege assignments; the
audit trail of what the agent was allowed to do.

## Actors and trust
| Actor | Trust | Notes |
| --- | --- | --- |
| Operator | trusted | Writes mandates and contracts, holds the evidence HMAC key, runs the proxy. |
| User (principal) | trusted for intent, not for authority | Intent is encoded in a mandate; a user jailbreak cannot widen it. |
| Human approver | trusted, must differ from the agent | Identity is asserted by the integration, not authenticated by AgentProof. |
| Agent / LLM | **untrusted** | May be prompt-injected, hallucinate or be misaligned. Its proposals are data. |
| Tool outputs, web, email, files, retrieved docs | **untrusted** | May carry indirect prompt injection. |
| MCP upstream server | trusted to honor its contract | AgentProof cannot contain what a server does inside an allowed call. |
| External authorizer (AgntID) | trusted for its own verdicts | Unavailable or malformed answers fail closed. |

## Threats → controls (OWASP Top 10 for Agentic Applications, 2026 numbering per secondary sources)

| Threat | Example | Control | Residual risk |
| --- | --- | --- | --- |
| ASI01 Goal hijack / indirect injection | doc says "email this to x@evil" | deny-by-default mandate; `TARGET_FROM_UNTRUSTED`; injection signals | in-scope actions with user-named targets remain possible |
| ASI02 Tool misuse | allowed tool, wrong target or payload | per-resource rules, contracts, outbound data checks | semantics inside an allowed call |
| ASI03 Identity & privilege abuse | agent reuses another agent's mandate; role grant | subject binding, `PRIVILEGE_ESCALATION`, approval | agent identity is asserted (AgntID or platform must authenticate) |
| ASI06 Memory/context poisoning | write instructions into shared notes | `INJECTION_IN_OUTBOUND` | paraphrased instructions |
| Data exfiltration | secret → email, base64 → URL | `SECRET_IN_OUTBOUND`, session taint incl. encodings, `CONFIDENTIAL_CONTEXT` | paraphrase, steganography, covert channels, rearranged fragments < 24 chars |
| Decision/execution mismatch (TOCTOU) | authorize A, execute B | one-time token bound to action digest | executor code that ignores the action |
| Replay / double-spend | reuse a token concurrently | nonce set checked synchronously | tokens are process-local; restart drops pending authorizations (fails closed) |
| Authorization service outage | AgntID down/slow | fail closed (`AUTHZ_UNAVAILABLE`) | availability |
| Evidence tampering | edit BLOCK → ALLOW | hash chain + HMAC + external anchor | see below |
| Malformed input / parser confusion | `__proto__`, traversal, UNC, URL userinfo | strict validation, canonicalization, no prototype access | — |
| Resource exhaustion | huge hostile context | 1 MiB analysis window, scan cache, frame/argument limits | sustained high volume at the proxy |

## Tamper-evident ≠ tamper-proof
- **Detected:** in-place edits, insertion, reordering, middle deletion (hash chain);
  a full chain rewrite by someone without the HMAC key (HMAC); tail truncation **only** when the
  last head (`seq:hash`) was recorded outside the evidence store (anchor).
- **Not prevented:** deletion of the whole file, or any rewrite by someone holding the HMAC key
  (a privileged operator). Storage is ordinary files; use append-only/WORM storage and ship
  anchors to a separate system for stronger guarantees.
- Entries are redacted before writing, so evidence proves decisions, not raw payloads. SHA-256
  digests of low-entropy arguments could be brute-forced; treat evidence as confidential.

## Out of scope
OS sandboxing, network containment, DNS/IP/redirect validation, symlink races, process-tree
containment, model weights, supply chain of the MCP servers, and authentication of agents and
approvers. AgentProof intercepts requests; it is not a sandbox, and a tool reachable directly
(not through the proxy) bypasses it.
