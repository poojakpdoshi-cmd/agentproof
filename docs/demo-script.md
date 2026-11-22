# AgentProof: 2-minute demo script

Keep the three labels on screen whenever their part is shown:
**SCRIPTED GEMINI REPLIES: NOT AI** · **BAND TEST STAND-IN (FakeAgentTools): NOT PLATFORM DELIVERY** ·
**LIVE BAND TRANSPORT: VERIFIED (CONNECTIVITY ONLY)**.
Never show `.env`, the raw `docs/phase4.1-band.json`, or BAND screens that display IDs or keys.

| Time | Screen | Narration |
| --- | --- | --- |
| 0:00–0:15 | README title | "AI agents act through MCP tools. One overbroad permission can leak data. AgentProof makes a Red agent attack those permissions and a Blue agent prove the fix." |
| 0:15–0:35 | README status table | "A default-deny MCP proxy checks every tool call before it reaches the server. Red probes a dummy lab through it, hands findings to Blue over BAND, and Blue retests through the same proxy." |
| 0:35–0:50 | Terminal: `npm run demo:e2e` | "This is a reproducible offline run. The proxy, BAND handlers and Gemini adapter are real code. The Gemini replies are scripted, not AI, and BAND delivery uses the SDK's test stand-in." |
| 0:50–1:10 | `docs/phase4.3-e2e.json` → `attackDefend.red` and `blue.attempts` | "Red finds that `private/secret.txt` is readable: a seeded misconfiguration. Blue reproduces it itself instead of trusting Red. Its first proposal widens access and is rejected, with the reason fed back. Its second removes the overgrant." |
| 1:10–1:25 | `retest` table and `upstreamReceived` | "Retest through the real proxy: public docs are still readable and every attack call is denied. Calls reaching the server drop from three to one." |
| 1:25–1:35 | `failClosed` | "A provider rate-limit error stops the session. There are no retries or fallback, and no provider error details leak into the room." |
| 1:35–1:50 | `docs/phase4.1-band.redacted.json` | "Separately, we verified live BAND messaging between the two agents on the platform. That was a connectivity check, not AI output." |
| 1:50–2:00 | Terminal: `npm test` summary (133 pass) | "133 tests pass. The live autonomous Gemini run is not shown yet; we label it unverified rather than fake it." |
