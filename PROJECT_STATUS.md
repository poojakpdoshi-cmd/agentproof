# Project status (compact, for context recovery)

Branch `claude/lucid-brahmagupta-xeckcb`. Not merged to `main`. Last updated 2026-11-24.

## Done (verified locally; CI on Ubuntu + Windows, Node 24)
| Area | Evidence |
| --- | --- |
| Phase 1 guard pipeline, `--mandate` proxy, AgntID adapter (**mock only**), dashboard, demo | `test/guard*.ts`, `test/agntid.test.ts`, `test/demo-dashboard.test.ts` |
| Phase 1 benchmark (unchanged results) | `docs/benchmark/guard-results.json` |
| Policy language: labelled data-flow rules, trusted targets, versioned hot swap | `test/repair.test.ts` |
| Repair engine: discover, root cause, operators, replay, rank, certificates, PolicyStore | `src/repair/`, `test/repair.test.ts` |
| H-A13 repaired without being shown to the engine | `test/repair.test.ts` |
| Phase 2 frozen eval (4 envs) vs manual / deny-all / deny-sinks | `docs/benchmark/repair-results.json`, REPAIR_ENGINE.md |
| Interactive repair dashboard; held proxy approvals (`--approvals`) | `src/repair/server.ts`, `test/guard-proxy.test.ts` |
| Responsive dashboards (390 px and 1366 px: no horizontal scroll, no clipped cells) | Playwright check |
| Strict `tsc` (6.0.3) in CI; 163/163 tests | `npm run typecheck`, `npm test` |

## Not done / blockers
1. Live AgntID run: needs portal account + bootstrap token; `agntid.ai` blocked here.
2. Official AgntID challenge rules: `luma.com` blocked here; verify manually.
3. Live LLM demo: this environment cannot hold credentials for Anthropic hosts; no other model key
   available. Run with a real model locally (not yet implemented as a script).
4. Repair: narrow-allow over-fits small legit suites (auto 76.5% vs manual 100% unattended legit).
5. Phase 1 holdout miss H-A13 stays in the Phase 1 numbers; fixed by repair policy, not by weights.
6. Proxy is stdio only; 8 built-in tool contracts.

## Commands
`npm test` · `npm run typecheck` · `npm run demo` · `npm run dashboard` · `npm run benchmark:guard` ·
`node benchmarks/repair.ts` · `node src/repair/cli.ts ENV` · `node src/repair/server.ts ENV` ·
`node src/mcp-proxy.ts --mandate M.json [--evidence E.jsonl] [--approvals PORT] -- CMD`
