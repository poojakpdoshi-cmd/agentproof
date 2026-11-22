# AgentProof Phase 3 evidence — 2026-11-22

**Recommendation: PIVOT to a strict tool-adapter and MCP regression harness.**
The tested legacy interception works. Current-spec compatibility and a unique
governance-engine advantage are not established. Do not position this as a
production sandbox or broadly compatible MCP security gateway.

## Verified execution

- **105 tests passed, 0 failed, 0 skipped** on Windows / Node 24.19.0. All prior
  security and subprocess cases remain covered; seven SDK/audit tests were added.
- Official `@modelcontextprotocol/sdk@1.32.2` client **and server**, using SDK stdio
  transports: three approved calls executed (write/read/network); four denied
  calls never appeared in the server's receive journal or execution handler.
  Read-back returned the written dummy value. IDs, structured results and progress
  survived; the earlier tests retain out-of-order/bidirectional-ID coverage.
- Official v2 client/server packages **2.4.0**: direct `2026-07-28` connection and
  tool execution succeed. Through AgentProof, pinned-version discovery fails with
  `Version negotiation failed ... did not offer pinned protocol version ... via
  server/discover`; zero tools execute. This expected-incompatibility assertion
  passes as a test; it is **not** evidence of 2026 compatibility.
- Three benign calls succeed directly but are denied through AgentProof: tracing
  metadata, a Unicode filename and a dotfile. These are deliberate restrictions,
  but real false denials for general-purpose use.

Reproduce: `npm ci --ignore-scripts --no-audit --no-fund`, then `npm test`.
The existing Windows junction test needs permission to create temporary junctions.
SDKs and Microsoft packages are pinned **dev dependencies**; runtime remains
built-in Node only. Linux CI is configured but was not executed locally.

## Compatibility audit

| Surface | Official 2025-11-25 | Official 2026-07-28 | AgentProof evidence/status |
| --- | --- | --- | --- |
| Startup | Stateful initialize + initialized | Stateless discovery and per-request version/capabilities | Legacy SDK works; modern SDK fails |
| Requests/results | Correlated IDs; object results | Required resultType; multi-round-trip input_required results | Legacy subset only; no modern result semantics |
| Tools | Arguments, results, optional metadata/tasks | Modern metadata and optional extensions | Three fixed adapters; other tools/options/metadata denied |
| Notifications | Progress, cancellation; server requests permitted | Request-scoped/subscription notifications; no server JSON-RPC requests | Legacy progress/cancellation/ping relay tested; no subscriptions/MRTR |
| Capabilities/transports | Optional resources/prompts/roots/etc.; stdio/HTTP | Extensions, discovery and HTTP changes | Tools-only stdio; no HTTP/auth, resources, prompts, tasks, roots, sampling or elicitation |

Sources: [2025 base](https://modelcontextprotocol.io/specification/2025-11-25/basic),
[2025 tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools),
[2026 changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog),
[2026 versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning),
[2026 stdio](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio),
[official SDK release lines](https://github.com/modelcontextprotocol/typescript-sdk).
This is a focused audit, not exhaustive protocol conformance certification.

## Confirmed fixes only

1. Proxy advertised capabilities for blocked methods. Initialization now strips
   unsupported client capabilities and exposes only upstream tools capability.
2. Unknown-ID errors emitted `id: null`, rejected by the official SDK schema.
   Such errors now omit the ID; existing regression expectations were corrected.
3. Scalar/array/null result envelopes were accepted despite the object requirement.
   They now fail closed. SDK schema checks independently verify the requirement.

Fractional progress-token rejection was checked against the SDK and left unchanged.
No stateless-protocol implementation or general tool registry was added.

## Microsoft comparison

Executed the real `@microsoft/agent-governance-sdk@5.0.0` **PolicyEngine.evaluate**
against the same 27 dummy cases and exact file/endpoint grants. This is the
toolkit's documented flat-rule API, not its full governance pipeline. The test
does not compare Docker isolation, CLI hooks, Python integrations, identity,
audits, scanners, or a Microsoft end-to-end MCP deployment.

| Configuration | Correct | False allows | False denials | Median microseconds/decision |
| --- | ---: | ---: | ---: | ---: |
| AgentProof gate | 27/27 | 0 | 0 | 1.241 |
| Microsoft raw exact-resource rules | 21/27 | 4 | 2 | 0.212 |
| Microsoft + explicit shared contract adapter | 27/27 | 0 | 0 | 1.340 |

The raw policy matches specified fields; it is not a schema validator. Its four
extra allowances were body/header payloads, an extra file argument and a non-string
write; its two denials were Windows separator/case aliases. **These are differences
in the supplied policy/adapter configurations, not demonstrated Microsoft product
vulnerabilities.** Adding AgentProof's schema/path/URL primitives as an explicit
preprocessor removes every difference. Microsoft still decides the resource grants.
This shared-code comparison is not independent validation of those primitives.

Timing: seven rotated batches of 10,000 decisions after 5,000 warmups per engine;
no transport/audit cost. AgentProof batch range 0.978–1.606 µs; adapted Microsoft
1.122–1.838 µs. Overlap and one-host measurements preclude a speed-superiority claim.
Separate official-SDK transport benchmark: 100 paired reads, startup excluded;
direct median **0.997 ms**, proxied **1.452 ms**, delta **0.455 ms**;
p95 **1.560 / 1.912 ms**. Both routes include identical dummy journal I/O.
This transport measurement has no Microsoft counterpart.

Reproduce: `npm run benchmark` and `npm run benchmark:stdio`. See
[all scenarios/raw measurements](phase3-benchmark.json), [transport samples](phase3-stdio.json),
and [benchmark code](../benchmarks/security.ts). Reruns overwrite the measurements.
Microsoft references: [repository](https://github.com/microsoft/agent-governance-toolkit),
[SDK API](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-typescript).

## Remaining bypasses and potential value

- Direct upstream access bypasses interception. The upstream is trusted and can
  perform arbitrary host actions inside an allowed call; no syscall, symlink-race,
  DNS/rebinding, redirect, process-tree or data-flow containment exists.
- IDs, progress tokens, permitted write data, responses and unguarded control-plane
  payloads can carry information. No prompt-injection or content-exfiltration proof.
- Canonical lowercase paths assume the declared portable namespace; applying them
  to case-sensitive host filesystems can change meaning. Tool-list entries are not
  filtered to the three callable names. Frame/session limits and restricted metadata
  can reject valid workloads. JSON Schema/tool semantics are not fully validated.
- Potential value: an inspectable, dependency-free runtime gate with strict argument
  adapters, Windows adversarial cases, and transport-level proof of non-dispatch.
  Uniqueness is unproven; the Microsoft adapter reaches the same tested decisions.

**PIVOT:** retain the regression corpus and small adapters as an integration layer
for established governance systems. A production-gateway GO would require current
MCP compatibility, trusted real-tool bindings/containment and evidence from additional
real servers. The present evidence does not justify that claim.
