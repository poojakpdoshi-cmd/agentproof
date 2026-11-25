# AgntID integration

Phase 7 rechecked the official event and current SDK setup; see [live readiness](PHASE7_AGNTID_READINESS.md). The access observations below are historical.

**Status: adapter implemented and tested against a local MOCK runtime only. Not verified against
a live AgntID Runtime.** No AgntID decision in this repository is real AgntID output.

## What was verified, and how
| Source | Access | What it established |
| --- | --- | --- |
| Official SDK `github.com/AGNTID-AI/agntid-python` (MIT, v0.2.0, read at `6955671`) | cloned and read | wire contract below |
| SDK `docker-compose.yml` (Runtime 2.0.0) | read | Runtime image `ghcr.io/agntid-ai/achr-runtime`, MCP on port 8082, registration with a portal bootstrap token, optional intent protection "uses a customer-owned OpenAI credential selected in the portal" |
| agntid.ai pages | **blocked** by this environment's network policy; only search-engine snippets were seen | vendor positioning: embedded proxy between agent and MCP servers; per-call decisions from agent, user, task, tool and parameters; allow / narrow / block; short-lived scoped credentials; customer-hosted; response filtering "on the roadmap" |
| Event page `luma.com/voramom4` | **blocked** | official rules and judging criteria are **unverified**; the event details in issue #1 (28 Nov 2026, 11:00–15:00 IST, online, individual) are the owner's notes |

## Wire contract used by the adapter (from SDK source)
- Transport: MCP Streamable HTTP, default `http://localhost:8082/mcp`, optional OAuth bearer
  access token. The adapter uses the official MCP TypeScript SDK client.
- Task glue: `tools/call agntid_task_open {task_id, agent_id, user_id, prompt, execution_context?}`
  → `{ok, reason, intent: {prepared, reason, snapshot: {id, relevant_tool_names, …}}}`;
  `agntid_task_close {task_id}`.
- Protected calls carry `agntid_task_id` (the SDK's `wrap_client` injects it); `__agntid_*`
  fields are stripped from results.
- Decisions: `__agntid_policy_decision {allowed, reason, policy_name, correlation_id,
  intent_validation: {verdict, verdict_reason, verdict_code, status, review}}`; verdicts
  `allow` / `deny` / `review_required` (`hitl`, `review`).
- `arguments_digest = sha256(json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False))`.

## How AgentProof uses it (`src/integrations/agntid.ts`)
The Runtime enforces in-line; the SDK exposes no decide-only API. So:
1. **External authorizer** (`runtime.authorizer()`): after `openTask(objective)`, the Runtime's
   prompt-specific tool shortlist is consulted before AgentProof issues an execution token.
   Not shortlisted → `EXTERNAL_DENY`; no task, intent not prepared, error or timeout →
   `AUTHZ_UNAVAILABLE` (block). This mirrors the SDK's own fail-closed `filter_tools_for_task`.
2. **Executor** (`runtime.executor()`): allowed calls run *through* the Runtime, which applies
   its identity, policy and credential controls. Deny → `EXTERNAL_DENY`, review →
   `EXTERNAL_REVIEW`, transport failure → `AUTHZ_UNAVAILABLE`; all recorded in evidence.
3. Agent-supplied `agntid_task_id` / `__agntid_*` arguments are refused. Runtime URLs must be
   loopback HTTP or HTTPS without credentials, query or fragment.

Net effect: an action runs only if **both** AgentProof (mandate, provenance, taint, binding) and
AgntID allow it. AgentProof stays usable without AgntID.

## Mock (`test/fixtures/mock-agntid-runtime.ts`)
A real MCP server over Streamable HTTP on 127.0.0.1 that emits the payload shapes the SDK parses.
Its toy policy (deny `secrets/`, review for email, keyword intent shortlist) is ours. Tests in
`test/agntid.test.ts` cover allow, runtime deny of a local over-grant, intent-shortlist deny,
review mapping, control-argument injection, intent-not-prepared, no task, and runtime down.

## Observations from reading the SDK (not runtime findings)
1. **Cross-language digest divergence.** Python prints `1.0` where JavaScript prints `1`
   (verified locally), so a non-Python client computing `arguments_digest` for float arguments
   disagrees with Python. If the Runtime recomputes digests Python-style, approvals bound by
   such a client would fail (closed). AgentProof's port is byte-identical for strings,
   integers, booleans, null and nesting (CPython test vectors) and refuses floats.
2. **Shortlisting is advisory client-side.** The SDK notes the runtime protection profile is
   the upper bound and `filter_tools_for_task` only narrows the visible list; enforcement must
   stay in the Runtime. AgentProof treats the shortlist as one more fail-closed signal.
3. **Denial detection by substring.** `is_denial_error` matches phrases such as "policy" or
   "denied" in exception text; AgentProof parses the structured decision envelope instead.

## Remaining blockers for a live integration
1. AgntID portal account and bootstrap token to register a Runtime (organizer-provided access).
2. Network access from the test host to `runtime.agntid.ai:8443` and `ghcr.io` (blocked here for
   `agntid.ai`), plus Docker to run the Runtime.
3. A dummy MCP tool server registered behind the Runtime, with a protection profile.
4. Then: `AGNTID_MCP_URL=http://localhost:8082/mcp`, run `test/agntid.test.ts`-style flows against
   it, and record **actual** decisions (including failures) as redacted evidence, kept separate
   from mock results.
