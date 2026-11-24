# AgentProof

**Intent-aware runtime firewall for AI agent tool calls.** AgentProof sits between an agent and
its tools (MCP stdio proxy or library). It decides on every proposed call **before execution**:
allow, block, or require human approval. It then binds the decision to the exact action that runs,
verifies the output, and writes tamper-evident evidence. No LLM is needed to decide.

```
user intent → mandate ─┐
agent proposes call ───┼─► contract ─► deny-by-default policy ─► provenance + taint + risk ─► ALLOW / BLOCK / REQUIRE_APPROVAL
untrusted context ─────┘                                              (+ AgntID, most restrictive wins)
            ALLOW ─► one-time token bound to action digest ─► execution ─► output verification ─► hash-chained evidence ─► dashboard
```

What makes it different: it asks **who chose the target**. A recipient, URL, path or command that
appears only in untrusted content (tool output, web page, email, file, even base64-encoded) raises
risk sharply. Session data-flow tracking stops protected content and seen credentials from leaving
in outbound arguments, including encoded copies. See [COMPETITOR_ANALYSIS.md](COMPETITOR_ANALYSIS.md).

## Quick start (offline, synthetic data, no keys)

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm test               # 163 tests (+ npm run typecheck)
npm run demo           # A/B: unprotected agent leaks a synthetic key; protected agent does not
npm run dashboard      # http://127.0.0.1:8787/  (static copy: docs/demo/dashboard.html)
npm run verify -- docs/demo/evidence.jsonl
npm run benchmark:guard
```

Protect an MCP server with an intent mandate ([example](examples/demo-mandate.json)):

```sh
node src/mcp-proxy.ts --mandate examples/demo-mandate.json --evidence evidence.jsonl -- node examples/dummy-mcp-server.ts
```

Add `--approvals 8788` to hold `REQUIRE_APPROVAL` calls until an operator decides via the loopback API
(`GET /pending`, `POST /decide {actionId, approver, approved}`, bearer token printed once to stderr).

Library use:

```ts
import { Firewall } from './src/guard/firewall.ts';
const fw = new Firewall({ mandates: [mandate], executor });
const v = fw.evaluate({ agent: 'report-agent', mandate: 'q3-summary', action: { tool: 'send_email', arguments },
  context: [{ source: 'user', text: objective }, { source: 'file', text: documentTheAgentRead }] });
if (v.decision === 'ALLOW') await fw.execute(v.token, { tool: 'send_email', arguments });
```

## Results (synthetic, self-authored; details in [BENCHMARK_RESULTS.md](BENCHMARK_RESULTS.md))

| Blind holdout (38 scenarios) | Value |
| --- | --- |
| Attack detection | 95.8% (23/24); one miss documented |
| False positives on legitimate actions | 0% (0/14) |
| Deterministic-policy bypasses (all 125 scenarios) | 0/67 |
| Evidence tamper detection (hash chain + HMAC + anchor) | 100% of 1,000 trials (70% with the hash chain alone) |
| Concurrent token double-spends | 0 of 1,000 attempts |
| Decision latency | p95 0.25 ms |

## Automatic security repair (Phase 2)

AgentProof also **repairs** policies: it generates synthetic attacks against a policy, finds the
root cause of each successful one, synthesizes minimal policy repairs (data-flow rules, narrowed
grants, approvals, denies), proves each by counterfactual and regression replay, and applies it
only after a human approves, with versions, rollback and re-verifiable certificates. On a frozen
4-environment set it prevented 100% of vulnerabilities with 0 security regressions but completed
76.5% of legitimate tasks unattended (manual expert: 96.3% / 100%). See [REPAIR_ENGINE.md](REPAIR_ENGINE.md).

```sh
node src/repair/server.ts benchmarks/repair/dev-report.ts   # interactive repair dashboard
node benchmarks/repair.ts                                    # Phase 2 benchmark
```

## Documentation
[ARCHITECTURE](ARCHITECTURE.md) · [THREAT_MODEL](THREAT_MODEL.md) · [SECURITY](SECURITY.md) ·
[BENCHMARK_RESULTS](BENCHMARK_RESULTS.md) · [COMPETITOR_ANALYSIS](COMPETITOR_ANALYSIS.md) ·
[AGNTID_INTEGRATION](AGNTID_INTEGRATION.md) · [HACKATHON_DEMO](HACKATHON_DEMO.md) ·
[JUDGES_PITCH](JUDGES_PITCH.md) · [PROJECT_STATUS](PROJECT_STATUS.md) · [REPAIR_ENGINE](REPAIR_ENGINE.md)

**AgntID:** the adapter follows the official `agntid-python` SDK contract and is tested against a
labelled **mock** runtime only. A live run needs organizer-provided access ([details](AGNTID_INTEGRATION.md)).
**Not a sandbox:** AgentProof intercepts requests; a tool reachable directly bypasses it.

---

## Red/Blue agent lab and original policy proxy (Phases 0–6)

The original default-deny MCP proxy (`--policy` mode) and Red/Blue agent lab below are unchanged.
They were built for the Diwali Festiverse **Security: Attack & Defend** track. A Red agent probes an
agent's tool permissions through a real MCP proxy and hands its findings to a Blue
agent over BAND. Blue independently reproduces the findings, proposes a narrower
policy, and proves the fix by retesting through the same proxy.

### Try the lab offline (no keys, no network, about 3 s)

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run demo:e2e    # Gemini adapter -> BAND adapters -> real MCP retest (scripted, NOT AI)
npm test
```

## Verification status

| Claim | Status |
| --- | --- |
| MCP interception, policy enforcement, adversarial tests (Phases 0–3) | verified offline, [audit](docs/phase3-audit.md) |
| Red/Blue workflow over official BAND SDK adapters ([Phase 4](docs/phase4.md)) | verified offline |
| Live BAND Red ↔ Blue messaging ([Phase 4.1](docs/phase4.1.md)) | **verified live** (transport only, [redacted evidence](docs/phase4.1-band.redacted.json)) |
| Gemini adapter ([Phase 4.2](docs/phase4.2.md)) | verified with mocked HTTP only |
| Full offline chain Gemini adapter → BAND → MCP retest ([Phase 4.3](docs/phase4.3.md)) | verified offline, reproducible ([evidence](docs/phase4.3-e2e.json)) |
| Autonomous live Gemini → BAND → retest | **unverified**; requires an authorized operator |
| Guard pipeline, `--mandate` proxy mode, demo, dashboard, benchmark | verified offline (`npm test`, `npm run demo`, `npm run benchmark:guard`) |
| AgntID Runtime integration | adapter verified against a **mock** only; live run **unverified** |

In the offline demo, provider replies are scripted and BAND delivery uses the SDK's
`FakeAgentTools`. No result above is live AI output. The lab's `private/` overgrant
is a seeded configuration flaw, not a policy-engine exploit.

Phase 3: a default-deny permission simulator and audited MCP stdio proxy for agent file
reads, file writes, and network actions. All fixtures are dummy data. Apache-2.0 licensed.

[Phase 3 evidence and recommendation](docs/phase3-audit.md): official SDK end-to-end
tests, 2025/2026 compatibility boundaries, and a reproducible Microsoft SDK comparison.
The proxy supports a limited **2025-11-25** flow; **2026-07-28 is unsupported**.

## MCP stdio proxy

```sh
node src/mcp-proxy.ts --policy examples/mcp-policy.json -- node examples/dummy-mcp-server.ts
```

Configure an MCP client to launch that command, or send newline-delimited JSON-RPC
on stdin. Use Node directly: `npm run` prints banners that contaminate MCP stdout.
The command after `--` is a trusted operator-selected executable, launched without
a shell. The policy file uses the simulator's existing read/write/network grants.
Invalid policy stops startup before launching the server. Audit decisions go to
stderr; stdout contains protocol messages only. Upstream stderr is discarded.

The proxy actually intercepts `tools/call` messages before writing to the child
process. It supports three fixed tool contracts:

| Tool | Arguments | Policy |
| --- | --- | --- |
| `read_file` | `path` | `read` |
| `write_file` | `path`, string `data` | `write` |
| `network_request` | `url`, optional GET/HEAD `method` | `network` |

Unknown tools, extra arguments and unauthorized actions return an MCP tool result
with `isError: true` and are never forwarded. File paths are forwarded in canonical
lowercase/slash form. The upstream must honor these exact tool contracts and virtual
path semantics; this is not a generic adapter for arbitrary MCP tools. The dummy
server executes allowed operations against its own memory, with no real network
requests. Its optional `--journal PATH` records received messages and executions
for dummy-only integration tests; never use that payload journal with secrets.

Initialization, ping, tool listing, initialization/cancellation notifications,
progress, and tool responses are relayed. String/numeric request IDs remain distinct
and unchanged, including bidirectional ping IDs and concurrent out-of-order replies.
The proxy follows MCP's [stdio framing](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle),
and [tool messages](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
for this limited subset. The dummy negotiates protocol version `2025-11-25`.
Initialization capabilities are reduced to the supported subset: client capabilities
are empty, server capabilities retain tools only. Unknown-ID parse errors omit the
ID, matching the official MCP SDK schema. Result envelopes must contain objects.

Tool calls require completed initialization and a request ID. Batches, invalid
envelopes, null/unsafe-number IDs and tool-call notifications cannot execute tools.
Duplicate IDs terminate the session. Frames are limited to 1 MiB, pending requests
to 128 per direction, and request IDs to 10,000 per direction per session. Invalid
UTF-8, truncated/oversize frames, malformed upstream output and unexpected upstream
IDs close the session. Outstanding client requests receive a protocol error where
the connection remains writable. A server that stalls after client EOF is killed
after two seconds; this can interrupt an approved operation. Fatal failures exit 2.

**Limits:** This is real request interception, not an OS sandbox. Calling the
upstream directly bypasses the proxy. The server is trusted: it can ignore tool
arguments, access host files/network, spawn processes, follow symlinks, redirect
requests, or perform additional work inside an allowed call. No DNS/IP checks,
symlink race protection, process-tree containment, or data-flow tracking are added.
Permitted write payloads, IDs, progress tokens and other protocol metadata can carry
data; tool responses are not filtered. Existing exact-URL rules are not a general
exfiltration defense. Denial prevents dispatch, not side effects from earlier calls.

Resources, prompts, tasks, sampling and elicitation methods are refused. Only
server-to-client ping requests are supported. Only `_meta.progressToken` is accepted
on tool calls; other tool metadata is denied. This is a deliberately limited MCP
subset, not full MCP conformance or authentication. Use the dummy server until a
real server's semantics and containment have been independently established.

## Run

Requires Node.js 24 or newer. The simulator/proxy have no runtime dependencies,
API keys, or build step. SDK integration tests and benchmarks use pinned dev dependencies.
Node runs the TypeScript source using native type stripping; it does not type-check it.

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm test
npm run benchmark
npm run benchmark:stdio
node src/cli.ts --help
node src/cli.ts < examples/scenario.json
```

PowerShell example:

```powershell
Get-Content -Raw examples/scenario.json | node src/cli.ts
```

The example intentionally exits **1**: four allowed actions followed by three
denied actions. CLI output is one JSON audit record per action:

```json
{"sequence":1,"action":"read","decision":"allow","reason":"authorized"}
```

Exit codes: **0** all actions allowed (or no actions), **1** at least one denied,
**2** malformed input/configuration/arguments. Input is a single JSON document
on stdin, limited to 1 MiB. Invalid UTF-8 rejects before any action runs.
Audit logs go to stdout; input errors go to stderr.

## Scenario format

```json
{
  "policy": {
    "read": ["docs/"],
    "write": ["out/"],
    "network": ["https://api.example.test/health"]
  },
  "files": {"docs/hello.txt": "DUMMY_DATA"},
  "actions": [
    {"type": "read", "path": "docs/hello.txt"},
    {"type": "write", "path": "out/result.txt", "data": "DUMMY_RESULT"},
    {"type": "network", "url": "https://api.example.test/health", "method": "GET"}
  ]
}
```

`policy` and `files` default to empty objects; `actions` is required. A trusted
operator supplies policy and seed files. The simulated agent supplies actions.
Untrusted agents must never control policy in a future integration.

## Permission rules and boundaries

- Missing grants deny. Read and write grants are independent. A trailing `/`
  grants a directory subtree; other grants match one exact file. No wildcards.
- Paths are relative to a virtual root. Both slash styles work and names are
  case-insensitive. Duplicate seed aliases are rejected. ASCII names start with
  a letter, digit, or underscore; subsequent characters may also include spaces,
  periods and hyphens. Hidden dotfiles are deliberately outside Phase 0 scope.
- Absolute, drive-relative, UNC/device, traversal and ambiguous paths deny.
  Windows reserved names, alternate data streams, trailing dots/spaces, percent
  escapes, empty segments and non-ASCII names deny. Segments are at most 255
  characters; paths at most 1,024.
- Network grants match exact canonical HTTPS URLs, including port and path.
  Only GET/HEAD are supported. Bodies, headers, credentials, queries, fragments,
  encoded URLs and extra action properties deny, even on an allowed endpoint.
  Explicitly granted local/private endpoints are permitted in this simulation;
  this is not SSRF filtering or DNS validation.
  Authorized requests return a simulated status of 204.
- Audit records contain sequence, action kind, decision and reason. They exclude
  paths, URLs, payloads and file contents. The library returns authorized read
  data separately; the CLI prints only audit records. Logs are deterministic and
  append-only inside the simulator; they are not durable or cryptographically signed.

The original simulator is a permission-model test harness, **not an OS sandbox or production
exfiltration defense**. File contents live in memory and network actions never
open sockets. There is no real disk access, DNS, redirect handling, symlink
resolution or process execution in the simulator. The CLI reads stdin; tests
read dummy fixtures, create temporary dummy symlink/junction fixtures and spawn
the local CLI. A successful virtual write through a link-shaped path does not
touch the host link or target. Link metadata and link-creation actions reject.
The simulator has no tool interception. The separate Phase 2 proxy intercepts MCP
requests, but neither component intercepts filesystem calls or network calls.
Real integration would require filesystem containment with race-safe link handling,
DNS/IP and redirect checks, and a trusted policy boundary outside agent control.

The library rejects accessors, proxies, symbols, hidden properties, inherited
required fields and non-JSON grant arrays without evaluating user getters/traps.
The supported untrusted boundary remains JSON data; arbitrary code executing in
the same process can replace built-ins or directly invoke host tools. Covert
channels, process isolation, durable audit delivery and resource exhaustion are
outside scope. Do not attach real data or tools.

## Layout and development

- `src/guard/`: intent mandates, tool contracts, provenance/taint, injection signals, risk, firewall, evidence ledger, MCP guard adapter.
- `src/integrations/agntid.ts`: AgntID Runtime adapter (tested against `test/fixtures/mock-agntid-runtime.ts` only).
- `src/dashboard/`: read-only dashboard server, summary model and static export; `src/verify-evidence.ts`: verifier CLI.
- `demo/attack-demo.ts`: offline A/B demo; `benchmarks/guard.ts` + `benchmarks/guard/`: 125-scenario benchmark.
- `src/paths.ts`: portable path validation and canonicalization.
- `src/policy.ts`: grant validation and matching.
- `src/simulator.ts`: in-memory actions and immutable decision records.
- `src/validation.ts`: shared JSON object validation.
- `src/cli.ts`: stdin/JSONL interface and exit codes.
- `src/mcp-proxy.ts`: guarded subprocess transport and protocol lifecycle.
- `src/mcp-policy.ts`: fixed MCP tool adapters using the existing policy engine.
- `src/mcp-protocol.ts`: bounded UTF-8 framing and JSON-RPC envelope validation.
- `examples/dummy-mcp-server.ts`: independent dummy MCP tool execution and test journal.
- `agents/`: Red/Blue lab: BAND handlers, Gemini/Ollama adapters, workflow, offline demos (`e2e.ts`, `offline.ts`).
- `test/`: deterministic built-in Node tests, including CLI integration.
- `examples/scenario.json`: dummy allow/deny demonstration.

Before contributing, install dev dependencies with `npm ci --ignore-scripts` and run
`npm test`. Keep policy changes modular, add regression
cases for boundary changes, and use dummy data only. CI runs the same suite on
Ubuntu and Windows with Node 24. It uses the official
[checkout](https://github.com/actions/checkout) and
[setup-node](https://github.com/actions/setup-node) actions.

The package is marked private to prevent accidental npm publication. This
repository has no publishing or deployment workflow.

## License

Copyright 2026 AgentProof contributors. Licensed under the
[Apache License 2.0](LICENSE), obtained from the
[Apache Software Foundation](https://www.apache.org/licenses/LICENSE-2.0.txt).
