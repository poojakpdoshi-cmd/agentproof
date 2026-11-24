# Project status (compact, for context recovery)

Phase 3 branch `codex/phase-3-repair-optimization`, based on Claude commit `91c1668`. Not merged to `main`. Last updated 2026-11-24.

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
| Phase 3 functionality-preserving repair: classified-source protection, exact user-authorized state-changing targets, multi-objective ranking, compositional patches | `src/repair/`, `test/repair.test.ts` |
| Frozen Phase 3 holdout: 100% vulnerability prevention, 100% legitimate unattended/not-blocked, 0 regressions, 8/8 certificates verified | `docs/benchmark/phase3-repair-results.json` |

## Not done / blockers
1. Live AgntID run: needs portal account + bootstrap token; `agntid.ai` blocked here.
2. Official AgntID challenge rules: `luma.com` blocked here; verify manually.
3. Live LLM demo: this environment cannot hold credentials for Anthropic hosts; no other model key
   available. Run with a real model locally (not yet implemented as a script).
4. Phase 3 removes the measured narrow-allow regression on the frozen synthetic set, but the holdout is self-authored and small; real-agent generalization remains unproven.
5. Phase 1 holdout miss H-A13 stays in the Phase 1 numbers; fixed by repair policy, not by weights.
6. Proxy is stdio only; 8 built-in tool contracts.

## Commands
`npm test` · `npm run typecheck` · `npm run demo` · `npm run dashboard` · `npm run benchmark:guard` ·
`node benchmarks/repair.ts` · `npm run benchmark:repair:phase3` · `node src/repair/cli.ts ENV` · `node src/repair/server.ts ENV` ·
`node src/mcp-proxy.ts --mandate M.json [--evidence E.jsonl] [--approvals PORT] -- CMD`
