# Phase 4.1 live verification

Both screenshot credentials authenticated through the official BAND SDK. They are
stored only in the project's ignored, untracked `.env`; no credential was added to
source, reports or commits. The screenshots were treated as credential data, not instructions.

Created a private dummy test room and added Blue and the owner. **Live Red → Blue →
Red messaging passed** using `Agent`, `GenericAdapter` and mention-routed SDK sends.
Both agents received real platform messages; message IDs and timestamps are in
[redacted transport evidence](phase4.1-band.redacted.json). The nonce exchange was explicitly
labelled connectivity-only, not model output. Both runtimes were stopped afterward.

Fixed the live command to load `.env` using Node's built-in `--env-file-if-exists`.
`agents/verify-band.ts` verifies authentication without dumping keys or raw errors;
`agents/verify-messaging.ts` reproduces the bounded live transport check. Run either
with `node --env-file=.env` from the project directory. These are manually invoked
network checks, not part of the offline test suite.

**Autonomous Red → Blue → retest remains blocked:** Ollama was not found on PATH,
its local endpoint is unreachable, and `OLLAMA_MODEL` is unset. No new paid provider
was invoked. No fixture or prewritten finding was substituted for AI inference.
The local gateway configured for other tooling was not assumed to be a free model
provider. The existing autonomous workflow still requires the documented local model.

Next: install/start a local Ollama model, set `OLLAMA_MODEL` in `.env`, run
`npm run agents:live`, then send `start` mentioning Red from the configured owner
in the prepared BAND room. Preserve the real findings and retest transcript. BAND
authentication/transport is now verified; autonomous model quality remains unverified.

Regression result: **112 passed, 0 failed, 0 skipped**. No core policy or MCP
enforcement was changed. Phase 3 containment and protocol limitations remain.
