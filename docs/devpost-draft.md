# AgentProof: Devpost submission text

> For the Diwali Festiverse Agent-to-Agent Hackathon, Security: Attack & Defend track.
> Final submission: 24 Nov 2026, 10:00 PM IST (per the event page). The submission
> location and required items are not stated there; confirm them with the organizers.
> Fill in the bracketed links. Do not claim live AI results unless a live run is recorded.

## Tagline
Red finds the permission hole, Blue proves the fix: agent-to-agent security testing for MCP tools.

## Inspiration
AI agents increasingly act through MCP tools that read files and call the network. One
overbroad grant can leak data, and permissions are rarely tested against an adversary.
We wanted an agent-to-agent loop whose results are reproduced, not taken on trust.

## What it does
- **AgentProof proxy:** a default-deny MCP stdio proxy. It intercepts every `tools/call`
  and checks it against read/write/network grants. Denied calls never reach the server.
- **Red agent (attack):** knows the proxy's tool contracts and probes a dummy MCP lab
  through the real proxy. It sends findings to Blue over **BAND** with mention routing.
- **Blue agent (defend):** reproduces every finding itself rather than trusting Red's
  claims. It proposes a narrower policy and retests through the same proxy against fixed
  controls. Proposals that widen access or break legitimate access are rejected, with a
  specific reason. Blue then reports to the owner over BAND.

## How we built it
Node.js 24 TypeScript, the official MCP SDKs, and `@band-ai/sdk@1.0.0` (`Agent`,
`GenericAdapter`, mention-routed `sendMessage`). It includes an optional Gemini REST
adapter, which is off by default, needs explicit operator opt-in, and has not been
live-tested. The proxy itself has no runtime dependencies.

## Safety by design
Dummy data only, with no shell or host-file tools exposed to either model. Only the
configured room, owner and peer are accepted. Messages, turns and reasoning steps are
bounded, and duplicate messages are ignored. Policies can only narrow. The Gemini session
stops on the first failure (no retries or fallback), and its errors never include keys,
prompts or provider bodies.

## Proof: what is verified, and how
| Claim | Evidence | Status |
| --- | --- | --- |
| Live BAND messaging between the Red and Blue agents | real platform round trip, IDs redacted | **verified live: connectivity check only, not AI output** |
| Full chain: Gemini adapter → BAND adapters → real MCP proxy retest | `npm run demo:e2e`, deterministic evidence file | **verified offline.** Gemini replies are **scripted (not AI)**; BAND delivery uses the SDK's **FakeAgentTools test stand-in** (not the platform) |
| Proxy enforcement, adversarial and protocol tests | `npm test` | 133 passing on Node 24 |
| Autonomous live Gemini → BAND → retest | none yet | **not verified** [replace with a transcript link only if a live run is recorded] |

In the offline run, Red finds that `private/secret.txt` is readable (a seeded lab
misconfiguration, not an engine exploit). Blue's first proposal widens access and is
rejected; its second removes the overgrant. On retest, the public read is still allowed,
all six attack and control calls are denied, and calls reaching the server drop from 3
to 1. A simulated provider rate-limit error (HTTP 429) stops the session safely.

## Challenges
Making agent output untrusted by construction: Blue re-derives every result, and policy
proposals pass a validator that only allows narrowing. Keeping evidence honest: every
simulated part is labelled inside the evidence itself.

## What's next
Complete a live autonomous run, measure it across models, and add OS-level containment
(the proxy intercepts requests; it is not a sandbox).

## Built with
node.js, typescript, model-context-protocol, band, gemini-api (optional adapter, not live-tested)

## Links
- Repository: [public GitHub URL]
- Demo video: [URL]
- Try it: `npm ci --ignore-scripts && npm run demo:e2e`
