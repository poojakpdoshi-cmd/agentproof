# Phase 4.3: reproducible offline E2E (Gemini adapter → BAND adapters → MCP retest)

Status: **offline end-to-end chain verified and reproducible. Live autonomous
Gemini → BAND → retest remains unverified**: no Gemini request has been made and
no live model output exists. Nothing here is AI output or live platform delivery.

```sh
npm run demo:e2e          # ~3 s, writes docs/phase4.3-e2e.json
node agents/e2e.ts --realtime   # same run with real 15 s Gemini spacing (~75 s)
```

## What is real and what is simulated

| Component | In this demo |
| --- | --- |
| `agents/band.ts` handlers inside the official `@band-ai/sdk` `GenericAdapter` (one per agent, as in `main()`) | real |
| `agents/gemini.ts` adapter: request contract, response parsing, size limits, shared 9-request budget, fail-closed latch | real |
| `agents/workflow.ts` Red loop, Blue independent reproduction and revision; `agents/lab.ts` policy safety checks | real |
| `src/mcp-proxy.ts` subprocess + `examples/dummy-mcp-server.ts` (real MCP requests and journal) | real |
| Gemini HTTP replies | **scripted** local stand-in; contract-checked, never sent; `fetch` restored afterwards |
| BAND delivery | **`FakeAgentTools`** (SDK test double), not the platform |
| Credentials | inline dummy values; `process.env`/`.env` are never read |
| Rate-limit clock | virtual by default (real spacing is covered by the existing unit test and `--realtime`) |

## Verified result ([evidence](phase4.3-e2e.json))

1. **Access control:** an intruder's `start` and an owner `start` from another room cause
   0 model requests and 0 messages; replaying the owner's message is ignored.
2. **Attack:** Red's adapter-driven loop (4 Gemini requests) probes the seeded lab
   misconfiguration. `read_file private/secret.txt` is **ALLOWED** under the seeded
   baseline; traversal and a body-carrying exfil request are already **DENIED**.
3. **Hand-off:** findings go Red → Blue by mention (`[{id:"blue"}]`, 694 bytes).
4. **Defend:** Blue reproduces every finding itself (it never trusts Red's claimed
   results). Its first scripted proposal expands grants and is **rejected before
   any retest**. Blue's next request receives a fixed, specific reason. The second
   proposal removes the `private/` overgrant.
5. **Retest:** fixed controls and Red's findings are replayed through the real proxy:
   public read stays ALLOWED, all six other calls are DENIED. The upstream server
   received 3 calls under the baseline and 1 after the fix. The report goes Blue → owner
   (`[{id:"owner"}]`). Gemini budget used: 6 of 9.
6. **Fail-closed:** a scripted HTTP 429 stops the session after 1 request. No message
   is sent to Blue, the SDK posts only the sanitized error event, a further request
   is refused without being sent, and the provider error body never appears.

The evidence is deterministic: the random run ID is normalized and two consecutive
runs produced byte-identical files (SHA-256 `b1d637f8…fc19`). The run aborts if the
evidence contains the dummy key, home, temp or working-directory paths.
`test/e2e.test.ts` reruns it and checks it against the committed evidence.

Sanitized publication copy of the Phase 4.1 transport evidence:
[phase4.1-band.redacted.json](phase4.1-band.redacted.json). BAND room/agent/message
IDs are replaced by labels plus truncated SHA-256 fingerprints. The raw file contained
identifiers only, no API keys.

## Integration review

No integration defect was found in the offline chain. Two live-readiness changes were
applied with operator approval (`agents/lab.ts`, `agents/workflow.ts`):

- **Red now receives the proxy's fixed tool contracts** (`tools` in its context):
  `read_file`, `write_file` and `network_request`, with their argument names. Before,
  a live model had to guess them. Red may still probe other tools, which the proxy denies.
- **Blue now receives a specific rejection reason**: grant expansion, a broken required
  boundary, or removed required grants. Reasons come from a fixed allowlist; validator
  text and proposal content are never echoed, and anything unknown maps to
  "invalid policy format".

These are risks for the live run that offline checks **cannot confirm**:

- **Thinking models:** `maxOutputTokens: 1500` may be consumed by thinking tokens on
  some Gemini models, giving a non-`STOP` finish and a fail-closed stop.
- **Content fidelity:** Blue runs `JSON.parse` on the raw message content. The SDK
  sends content verbatim, with mentions as a separate field (checked in the SDK source).
  The Phase 4.1 live check only matched a substring, so platform-side rewriting is
  unverified.
- **Error events:** the SDK posts handler error messages to the room. Gemini errors are
  sanitized. Rare local failures (for example filesystem errors) could include local
  temp paths, but only in the private room.
- **Turn duration:** a live Red turn waits at least 15 s between Gemini requests (at
  least 45 s for this script). BAND turn time limits were not measured.
- The 9-request budget allows one full run per process start; restart intentionally.

## Live run (operator only)

Unchanged from [Phase 4.2](phase4.2.md). An authorized, age-eligible operator must
first confirm free-tier eligibility for the project and model, keeping billing disabled.
The operator then sets `GEMINI_MODEL` and both opt-in flags in the ignored `.env`, runs
`npm run agents:live`, and mentions Red with `start` from the configured owner in the
private room. Record real message IDs, the model ID and the outcome, including failure.

Regression: **133 passed, 0 failed, 0 skipped** (130 preserved + 3 new). Existing tests
and BAND handlers/routing are unchanged; only the two approved workflow changes above. A secret scan of 49 publishable files
found no `.env` values, keys, personal paths or email. Phase 3 limitations remain.
