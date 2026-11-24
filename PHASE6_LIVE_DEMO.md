# Phase 6 live local-agent demonstration

This uses a real installed Ollama model, two in-memory synthetic files, the existing firewall,
repair engine, human PolicyStore approval, independent certificate verifier and read-only
dashboard. No real email, network or filesystem tool is exposed to the model. The unprotected,
baseline guard and repaired guard runs start from identical task text and workspace data, with
the same model settings. The model may make different decisions after seeing a blocked action;
the script records those actual decisions instead of assuming an attack succeeded.

With Ollama listening on `127.0.0.1:11434` and a model already installed:

```sh
npm ci
npm run demo:live -- --model INSTALLED_MODEL_NAME
```

The operator reviews each printed proposal and types `APPROVE <proposal-id>` in the terminal.
The agent cannot apply its own repair. After all three real model runs, the command writes
`docs/demo/live/result.json`, `repair-report.json`, baseline and repaired evidence JSONL, and
`dashboard.html`. Open `docs/demo/live/dashboard.html` to inspect actual guarded decisions.
The report records exact private copies; a false value is not a claim that semantic leakage
was impossible. Independently verify the generated repair certificates with:

```sh
node src/repair/cli.ts verify docs/demo/live/repair-report.json demo/live-env.ts
```

The script also replays one discovered attack and the legitimate task before and after the
operator-approved repair. Model output and tool outcomes are retained in `result.json`; all
content is synthetic. An aborted or unavailable model produces no live-result artifact.

Current machine blocker (checked 2026-11-25): `GEMINI_API_KEY` and `GEMINI_MODEL` are unset;
the `ollama` command is absent and `http://127.0.0.1:11434/api/tags` is unreachable. Running
the launch command fails with that precise Ollama preflight error. The offline unit test uses
a labelled mock HTTP response to validate the adapter, and does not claim a live LLM run.
