# Phase 4: Red / Blue lab

Update: [Phase 4.3 offline E2E](phase4.3.md) verifies the Gemini adapter → BAND
adapters → real MCP retest chain with scripted provider replies (not AI, not live).

Update: [Phase 4.2 Gemini configuration](phase4.2.md) adds an optional cloud
provider, disabled pending eligible operator authorization and free-tier checks.

Update: [Phase 4.1 live verification](phase4.1.md) authenticated both agents and
verified live BAND messaging. Local-model execution remains blocked. The status
below records the original Phase 4 run.

Status: offline components implemented and tested. **Live autonomous AI and BAND
delivery are unverified**: no BAND credentials were configured and the local Ollama
endpoint was unreachable. No model output or sponsor activity is represented as live.

## Implemented

Red and Blue have separate roles, inference contexts and BAND identities. Red's
bounded model loop chooses probes from previous observations. Blue independently
reproduces them, asks its model for a narrower policy, validates it, and retries
unsafe proposals using feedback. They can run without per-step human choices after
an authorized start. This autonomous behavior still requires a live model verification.

The official `@band-ai/sdk@1.0.0` provides `Agent.create`, `GenericAdapter`, startup,
and `tools.sendMessage(content, [{id}])` mention routing. Red sends findings to Blue;
Blue sends the independently verified retest report to the configured owner. Only
the configured room, owner and Red identity are accepted. Duplicate messages,
concurrent turns, message sizes and reasoning steps are bounded. There are no shell
or host-file tools exposed to either model. Failed inference/delivery does not fall
back to fixture responses.

Each probe uses the existing MCP proxy and a fixed dummy-server subprocess. No
model can select another server, executable or real network tool. An intentionally
overbroad **lab-only** `private/` grant seeds the exercise; this is a configuration
weakness, not a newly discovered policy-engine exploit. Original policies are untouched.
Blue may only narrow grants and must preserve public read, output-write and approved
endpoint permissions. Changes exist in temporary lab files, not the production policy.
Retesting replays findings plus fixed allow/deny controls; the full project suite runs
separately with `npm test`.

## Offline evidence

`npm run agents:offline` uses deterministic decision fixtures clearly marked **NOT
AI**, actual SDK `GenericAdapter`/`FakeAgentTools`, and local test-harness message
delivery. It does not authenticate to BAND or invoke a model. It executes real MCP
requests through the proxy: baseline journal receives three calls (including the
private-file control and replay); candidate journal receives only the public read.
The remaining four calls are denied before dispatch. See [captured evidence](phase4-offline.json).

## Live verification prerequisites and command

1. Install a local Ollama model and run Ollama on `127.0.0.1:11434`. Cloud-tagged
   models are rejected; no model download or paid provider is invoked by this project.
2. Register two distinct remote agents on BAND's free plan and add both to one
   private test room. Set `BAND_RED_ID`, `BAND_RED_API_KEY`, `BAND_BLUE_ID`,
   `BAND_BLUE_API_KEY`, `BAND_ROOM_ID`, `BAND_OWNER_ID` and `OLLAMA_MODEL` locally.
   Never paste keys into reports or commit them. No credentials are created here.
3. Run `npm ci --ignore-scripts`, then `npm run agents:live`. From the configured
   owner, mention Red with `start`. BAND should deliver Red's findings to Blue;
   the owner should receive Blue's retest result. Keep the room transcript with
   actual message IDs, model identity and observed results as live evidence.
4. Run `npm test` before submission. A live model may fail to discover or fix the
   seeded flaw; record that failure honestly. Offline passing is not live proof.

The agent harness additionally requires the project's MCP development dependencies;
the standalone proxy still uses only Node built-ins. BAND is the sole new direct
dependency. No submission, publication, cloud-model call or external attack was made.

## Sources and remaining limits

[Event track](https://luma.com/pmntx4p4),
[BAND SDK installation](https://docs.band.ai/sdks/typescript/installation),
[BAND SDK example](https://github.com/band-ai/band-sdk-typescript),
[BAND lifecycle](https://docs.band.ai/sdks/typescript/agent-lifecycle),
[BAND mention routing](https://docs.band.ai/understand/how-band-works),
[Ollama chat API](https://docs.ollama.com/api/chat).

No claim of sponsor qualification or live autonomous success is made. Provider
quality, authentication, actual mention delivery and shutdown require live checks.
In-memory replay protection resets on restart. The lab does not provide OS isolation,
general exfiltration defense or MCP 2026 compatibility; Phase 3 limitations remain.
Only dummy findings may be sent into the configured BAND room.
