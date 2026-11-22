# Phase 4.2: Gemini provider (offline verified)

Gemini uses Node's built-in fetch and the official REST `generateContent` API.
No dependencies, model downloads or live Gemini calls were made. Existing BAND
routing, dummy MCP execution, policy validation and Ollama behavior are retained.
The two providers share the existing role prompts; there is no automatic fallback.

## Configuration

The supplied key is stored only in the ignored local `.env`. It has **not** been
authenticated. Current settings select Gemini but keep both live flags false and
leave the model unset. No API request is needed to validate configuration.

An authorized, age-eligible account operator must first confirm that the project
and selected model can be used without charges. Keep billing disabled; application
flags cannot verify account eligibility, billing state or guarantee free usage.
Only that operator should enable live use after those checks. In `.env`:

```dotenv
AI_PROVIDER=gemini
GEMINI_API_KEY=<local secret>
GEMINI_MODEL=<eligible free-tier model ID starting with gemini->
GEMINI_LIVE_ENABLED=false
GEMINI_FREE_TIER_CONFIRMED=false
```

Keep the existing six `BAND_*` values. After authorization and free-tier checks,
the operator may set both flags to `true`, run `npm run agents:live` and mention
Red with `start` in the configured private room. Startup makes no Gemini request;
inference starts only for authorized BAND messages. For optional local inference,
set `AI_PROVIDER=ollama` and `OLLAMA_MODEL` to an already installed local model.
An omitted provider continues to default to Ollama.

## Bounds and failure behavior

- Shared Red/Blue instance: one in-flight request, minimum 15 seconds between
  request starts, maximum nine requests for the process session (six Red + three
  Blue). Further runs need an intentional restart. These local limits do not
  coordinate other processes or other clients using the same Google project.
- HTTP 429 and other HTTP/network/timeout/parse/safety failures stop the session.
  No automatic retries, provider fallback or fixture substitution. Investigate
  failures before restarting; limits are not a billing cap.
- Fixed HTTPS endpoint, header-only key, redirects forbidden, 120-second timeout,
  64 KiB input/streamed-response limits and 1,500 output tokens per request.
- JSON text only; blocked/truncated results and tool calls fail closed. Thought
  parts are excluded. Existing workflow validation checks all actions and policies.
  Error messages never include provider bodies, keys, prompts or raw fetch errors.

## Evidence and remaining work

Full regression run: **130 passed, 0 failed, 0 skipped** (112 preserved + 18 new).
The existing Windows junction test required execution outside the restricted
runner; it passed without test changes. Secret scan found zero credential copies
outside ignored `.env`. Both live flags remain false.

Tests use dummy credentials, mocked fetch and controlled clocks. Coverage includes
the REST contract, opt-in gates, provider selection, HTTP failures (including 429),
timeouts, secret-safe errors, malformed/blocked/truncated output, size limits,
overlapping requests, spacing, budget and mocked Red -> Blue -> real MCP retest.
This is **not live Gemini or live autonomous-agent evidence**.

Remaining: operator eligibility/free-tier verification, model selection and then
an explicitly authorized live BAND/Gemini Red -> Blue -> retest transcript. Previous
[BAND transport evidence](phase4.1.md) remains valid; no new live run is claimed.

Official references: [REST generateContent](https://aistudio.google.com/api-reference/generate-content/generate-content),
[JSON generation configuration](https://aistudio.google.com/api-reference/generate-content),
[API-key authentication](https://aistudio.google.com/docs/api-key),
[project-level rate limits](https://aistudio.google.com/docs/rate-limits).
