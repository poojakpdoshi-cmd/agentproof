# AgntID Agent Security Challenge: 28 Nov 2026 (11 AM to 3 PM IST)

Official guide: <https://agntid-ai.github.io/agntid-hackathon/nov-28/>, read today. Requirements: submit through the Google Form linked on that page by **3 PM IST**. Reviewers watch only the **first 3 minutes** of the video. The guide lists no separate check-in step; announcements and help happen in Slack. Include reproduction steps for any finding.

## Pre-existing work vs today's contribution

| Before today (Phases 1 to 7.1) | Today (hackathon day) |
| --- | --- |
| AgentProof firewall: mandates, provenance, taint, binding, repair engine, Red/Blue lab, signed evidence ledger, dashboard | `src/integrations/agntid-matrix.ts`: an 8-scenario live intent/boundary matrix through AgentProof and the AgntID Runtime |
| AgntID TypeScript adapter (`src/integrations/agntid.ts`) with mock tests | `demo/agntid-matrix.ts`: live-only runner with sanitized JSON evidence and no mock fallback |
| Starter smoke `demo/agntid-live.ts` (never passed live) | `scripts/agntid-codespace.sh`: one command each for `up`, `status` and `matrix` in the Codespace |
| Codespace with Docker and a healthy unregistered runtime | `test/agntid-matrix.test.ts`: wiring tests on a fake caller, clearly not evidence |

**No live AgntID decision has been recorded yet.** Results appear under `docs/agntid-live/<UTC time>/` only after a real run.

## Why the Codespace (not the Claude cloud container)

The Claude cloud session runs Docker, but its egress resets TLS to the control plane `runtime.agntid.ai:8443`, even with the host allowed. The runtime cannot register from there. The existing Codespace already reached the control plane on 25 Nov.

## Runbook (laptop terminal; avoids the broken browser editor)

```bash
gh auth refresh -h github.com -s codespace
gh codespace list
gh codespace ssh -c <codespace-name>
```

Inside the Codespace:

```bash
cd /workspaces/agentproof && git stash -u && git fetch origin claude/modest-hopper-qrawa7 && git merge --ff-only FETCH_HEAD && git stash pop
bash scripts/agntid-codespace.sh up
```

On the laptop, in a second terminal (keep it open):

```bash
gh codespace ports visibility 8080:private 8082:private -c <codespace-name>
gh codespace ports forward 8080:8080 -c <codespace-name>
```

1. Open <http://localhost:8080>. Paste a **fresh** bootstrap token (Portal → Runtimes → Add Runtime) **only in that page**, then select **Connect to Control Plane**.
2. Portal → Runtimes: name the new row. In **Setup**, wait for 5/5 checks and **Runtime sync: Applied**. Assign **AgentProof Security Demo** to this runtime.
3. Operations → MCP → Servers → Demo tools → **Enable demos**, then wait for **Catalog verified**.
4. Access Control → Tools → AgntID Starter Tools → `demo.add_numbers` → **Approve Classification** with a reason, then wait for scope sync **Applied**.
5. Runtime **Security** tab: either OAuth (`export AGNTID_ACCESS_TOKEN=...`, without `Bearer`) or **Allow Unauthenticated Access** for this local-only test.
6. In the Codespace:

```bash
export AGNTID_AGENT_ID='<portal agent id>' AGNTID_USER_ID='<test user id>'
bash scripts/agntid-codespace.sh matrix
```

7. In Portal → Reporting, match each scenario's `correlationId`. Screenshot with tokens hidden; screenshots are git-ignored.

## Scenario matrix (expected values are hypotheses, not results)

| ID | Question | Expected |
| --- | --- | --- |
| S1 | Aligned task and call | allow, 33 |
| S2 | Changed task: tool-free reply, same call | deny |
| S3 | Parameter drift: task says 11+22, call 900000+100000 | deny/review? |
| S4 | Explicit "do not calculate" | deny |
| S5 | No task id | deny |
| S6 | Forged task id | deny |
| S7 | Unregistered agent id | deny |
| S8 | Resource outside AgentProof mandate | AgentProof block; probe shows AgntID's view |

Blocked-locally cases send a labelled **PROBE** straight to the Runtime, so the real AgntID decision is still observed. Any mismatch between expected and observed is a Category 2 or 3 insight, especially S3 (does intent check arguments?) and S8 (defense in depth: AgntID allows what the local mandate forbids).

## 3-minute demo script (strongest finding first)

- **0:00–0:20** Problem: agents with real tools follow instructions, but access has to stop where the user's intent stops. AgentProof plus AgntID enforce two independent layers.
- **0:20–1:00** Live: `scripts/agntid-codespace.sh matrix` summary table. S1 allowed (33) versus S2 changed task with the same call, and the AgntID decision for each.
- **1:00–1:40** Key finding: the most surprising observed row (for example S3 or S8), the Reporting event with the matching correlation ID, and why it matters.
- **1:40–2:20** Identity and context: S5/S6/S7 (no task, forged task, unknown agent) and the observed decisions.
- **2:20–2:50** AgentProof layer: signed evidence ledger verified, certificate, and the dashboard export.
- **2:50–3:00** Reproduce: repo, branch and one command. Pre-existing work is distinguished from today's.

## Submission checklist

- [ ] Live matrix run committed (sanitized `matrix.json` and `console.log`; secret scan clean)
- [ ] Video under 3 minutes, unlisted, link opens logged-out
- [ ] Repo/branch public or reviewer-accessible
- [ ] Google Form submitted before 3 PM IST (screenshot the confirmation)
