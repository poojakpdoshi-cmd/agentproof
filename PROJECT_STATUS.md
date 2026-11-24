# Project status (compact, for context recovery)

Branch `claude/lucid-brahmagupta-xeckcb`. Not merged to `main`. Last updated 2026-11-24.

## Done (verified locally)
| Area | State | Evidence |
| --- | --- | --- |
| Guard pipeline (`src/guard/`) | mandate, contracts, provenance, taint, injection signals, risk, firewall, binding, ledger | `test/guard.test.ts` |
| MCP proxy `--mandate` mode | intercept, canonical forward, tools/list filter, output redaction, evidence | `test/guard-proxy.test.ts` |
| AgntID adapter | SDK-derived contract; authorizer + executor; fail closed | `test/agntid.test.ts` (**mock only**) |
| Benchmark | 125 scenarios, dev + blind holdout, tamper, concurrency, integration, latency, memory | `docs/benchmark/guard-results.json` |
| Demo + dashboard + verifier | offline A/B, read-only dashboard, exit-coded verifier | `test/demo-dashboard.test.ts`, `docs/demo/` |
| Flaky SDK test | root-caused (MCP client microtask race), fixed | `test/sdk.test.ts` |
| Full suite | **157/157 pass** (Node 22.23.5 local); CI targets Node 24 Ubuntu + Windows | `npm test` |

## Not done / blockers
1. **Live AgntID run**: needs portal account + bootstrap token, Docker host with access to
   `runtime.agntid.ai`. Blocked in this environment (network policy, no account).
2. **Official AgntID challenge rules**: `luma.com` blocked here; verify judging criteria,
   submission method and existing-project rules manually.
3. Holdout miss H-A13 (protected content copied into a local file). Candidate fix in BENCHMARK_RESULTS.md.
4. Interactive approval channel in proxy mode (MCP elicitation is refused by design today).
5. Only stdio MCP; no Streamable HTTP proxy mode. Eight built-in tool contracts; custom contracts
   are code-level only (no JSON schema for operators yet).
6. Benchmark is self-authored; run external corpora (garak, PyRIT, AgentDojo-style) next.
7. Node type stripping does not type-check; no `tsc` gate in CI.

## Commands
`npm test` · `npm run demo` · `npm run dashboard` · `npm run verify -- FILE [--anchor SEQ:HASH]` ·
`npm run benchmark:guard` · `node src/mcp-proxy.ts --mandate M.json --evidence E.jsonl -- CMD`
