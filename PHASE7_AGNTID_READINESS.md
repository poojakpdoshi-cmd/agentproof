# Phase 7 — AgntID live readiness

Checked 2026-11-25 from `51bb9ce`. Historical benchmarks and the guard/repair engine are unchanged.

## Official challenge requirements

The [organizer's event page](https://luma.com/voramom4) calls for an AI agent using real tools connected to AgntID, tests of allowed/denied or unexpected actions across tasks and contexts, a pushed project, and a **short recorded demo**. It names three equally awarded categories: real-world agent security use case, intent exploration, and security insight/product discovery. The page does **not** state a numerical scoring rubric or a video length. It describes a four-hour online, individual event. The existing scripted offline demo is useful rehearsal, but is not evidence of AgntID integration.

## Actual readiness checks

| Check | Observed result |
| --- | --- |
| Local AgntID Runtime health `127.0.0.1:8080` and MCP `127.0.0.1:8082/mcp` | Unreachable, checked with network access |
| AgntID environment variables | No `AGNTID_*` variables present; credential values were not read or logged |
| Docker executable | Not installed on this host |
| Installed local models | Ollama API listed only `qwen3:0.6b`; no stronger local model |
| Paid model authorization | No provider API key present; no paid calls made |
| AgentProof discovery/repair on synthetic live-demo environment | 17 initial vulnerabilities; one composite proposal; zero residual; attack replay executed before and blocked after; legitimate replay completed; certificate `504114e1…` verified |
| AgntID live authorization and protected tool execution | **Not run**: no registered runtime or access |

The existing [adapter](src/integrations/agntid.ts) uses the official MCP TypeScript transport. It opens an AgntID task, checks the prepared tool shortlist before an AgentProof execution token, and sends allowed calls through the runtime. The mock test exercises this wiring but is not a live AgntID result. The new `node demo/agntid-live.ts` command has no mock fallback. It runs AgentProof discovery, repair, replay and certificate verification, then uses the registered runtime's official `demo_add_numbers` starter tool through a reviewed local firewall contract. It reports the runtime decision, real execution status, sum check, and ledger verification. In this environment it exits before connecting with exact missing-variable instructions; its live success path remains unverified.

## Exact live setup

The [official SDK setup guide](https://github.com/AGNTID-AI/agntid-python/blob/main/examples/README.md) requires an AgntID portal account, Docker 20.10+ with Compose v2, approximately 4 GB RAM and 5 GB free disk, and HTTPS access to GHCR and the AgntID control plane. First runtime startup downloads an approximately **900 MB intent model**; this was not downloaded here.

1. Register for the challenge and obtain portal access. In the portal, open **Runtimes → Add Runtime → Generate Bootstrap Token**. Keep the one-time token out of source, shell commands and chat.
2. Clone `https://github.com/AGNTID-AI/agntid-python`, then from that checkout run `docker compose up -d`. Wait for `achr-runtime` and `achr-intent-parser` to be healthy and check `http://localhost:8080/health`.
3. Open `http://localhost:8080`, enter the bootstrap token, and connect to the control plane. In the portal, confirm the Medium/READ_WRITE profile, 5/5 setup checks and **Runtime sync: Applied**.
4. Enable demo tools under **Operations → MCP → Servers**. Approve the `demo.add_numbers` classification under **Access Control → Tools**, with a reason, then wait for catalog and scope synchronization. The protected MCP tool must appear as `demo_add_numbers`.
5. If client OAuth is required, obtain a current access token for the AgntID protected resource from the configured OAuth flow. The bootstrap token is **not** an MCP access token. Set `AGNTID_ACCESS_TOKEN` to the raw token without `Bearer`. The official guide also permits unauthenticated access for an approved local-only test.
6. Set `AGNTID_MCP_URL=http://localhost:8082/mcp`, `AGNTID_AGENT_ID` and `AGNTID_USER_ID` to the identities configured for the test. Run `node demo/agntid-live.ts` from this repository. A successful run must show a verified certificate, AgntID `allow`, execution `ok`, observed sum 33 and verified evidence. Retain the portal Reporting event with matching task/correlation for the recorded demo.

No Python SDK is required for AgentProof's TypeScript adapter. The [official Python SDK README](https://github.com/AGNTID-AI/agntid-python) remains the source for task lifecycle and current runtime setup. The adapter was written against its earlier 0.2.0 wire contract; live compatibility with the current runtime is an open check.

**Readiness:** not yet eligible to claim live AgntID integration or submit a compliant demo. A registered runtime, approved starter tool, optional OAuth access, actual decision evidence and a short recording are still required. Stronger-model recovery comparison was not run because only `qwen3:0.6b` is installed and no authorized stronger provider key is available.

## Host prerequisite check after download authorization

The user authorized the approximately 900 MB intent-model download **only if C: has enough space**. Read-only checks found Windows 11 Home build 26300, 15.19 GiB RAM, firmware virtualization enabled, and a hypervisor present. The WSL Store package is 2.6.3, but `wsl --version`, `--status`, and distro listing each timed out; WSL2 operation is therefore **unverified**. Querying optional-feature states requires administrator elevation. Docker Desktop is absent in both standard install locations and from PATH.

C: has **4.43 GiB free** (about 4.76 GB), below the [AgntID setup guide's 5 GB free requirement](https://github.com/AGNTID-AI/agntid-python/blob/main/examples/README.md). Docker's [Windows requirements](https://docs.docker.com/desktop/setup/install/windows-install/) call for at least 8 GB RAM, WSL 2.1.5+, virtualization and SLAT. Installation and downloads were **not started**. No files were deleted and D: was not used. Once the user has arranged more free space on C:, recheck storage and WSL2, then proceed with the official per-user Docker setup or request administrator elevation if Windows features need enabling.
