# Competitor analysis

Capabilities below come from public descriptions and, for AgntID, from reading its official
Python SDK source. Only AgentProof and Microsoft's agent-governance-sdk policy engine were run
hands-on here. "—" means not a primary capability per public material, not "impossible".

| Capability | AgentProof | AgntID | PyRIT | garak | Promptfoo | Lakera Guard | NeMo Guardrails | CaMeL (research) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Primary role | runtime action firewall + evidence | runtime access control for agent tool calls | red-team automation | LLM vulnerability scanner | evals / red-teaming | hosted prompt-attack & leak detection API | programmable rails | secure agent design (P-LLM/Q-LLM + interpreter) |
| Blocks tool calls before execution | yes (MCP proxy / library) | yes (customer-hosted MCP proxy) | — | — | — | indirectly (classifies text) | yes (execution rails) | yes |
| Intent / task-scoped authorization | mandate (deterministic) | task intent snapshot (LLM-assisted, per vendor) | — | — | — | — | via rails | from trusted query |
| Argument provenance (who chose the target) | deterministic string provenance | not described | — | — | — | — | — | rigorous capability tracking |
| Data-flow from tool output to outbound args | session taint, encoded copies | output filtering "on roadmap" (vendor) | — | — | — | output scanning | output rails | yes |
| Decision bound to executed action | one-time token over action digest | `arguments_digest` on approvals | — | — | — | — | — | interpreter-enforced |
| Human approval | library API; proxy returns pending | review verdicts | — | — | — | — | custom | confirmation prompts |
| Tamper-evident evidence + verifier | hash chain, HMAC, anchors | audit log (format not public) | — | — | reports | logs | logs | — |
| Short-lived credentials | — | yes | — | — | — | — | — | — |
| Offline adversarial benchmark | 125 scenarios + tamper/concurrency | — | core purpose | core purpose | core purpose | — | — | AgentDojo |
| Needs an LLM to decide | no | intent preparation uses an LLM (vendor compose file) | yes | partly | yes | classifier | often | yes (two LLMs) |
| Drop-in, no agent rewrite | yes (stdio proxy) | SDK task glue + runtime | n/a | n/a | n/a | API call | config | no (agent rewritten) |

## Differentiation (defensible, not a claim of global originality)
1. **Target provenance as an authorization signal, without an LLM.** AgentProof asks *who chose
   this recipient/host/path/command*: the user and mandate, or only untrusted content? CaMeL and
   information-flow-control research do this far more rigorously but need the agent rebuilt
   around their interpreter; AgentProof approximates it at a drop-in MCP boundary.
2. **Session data-flow taint at the proxy.** The proxy sees both what tools return and what the
   agent later sends, so it can block protected content leaving, including base64/hex/percent
   encodings, without instrumenting the agent.
3. **Decision-bound execution plus independently verifiable evidence**, measured: 0 double-spends
   under concurrency, 100% tamper detection with HMAC + anchor, with stated limits.
4. **Composable with AgntID.** AgentProof is provider-neutral; AgntID adds authenticated identity,
   task-intent shortlisting, runtime policy and short-lived credentials. Most restrictive wins.

We did not find another open-source drop-in MCP proxy that combines (1)–(3), but the search was
not exhaustive. Garak, PyRIT and Promptfoo are complementary: they find weaknesses offline;
AgentProof enforces at runtime and can be benchmarked with their attack corpora in future.

## Automatic repair: related work
See REPAIR_ENGINE.md ("Prior art"). The find → fix → replay → regression → approve loop exists in
program repair (SapFix, CodeMender, AIxCC) and, per abstracts, in guardrail/policy work (Lattice,
AutoSpec, VEPA, CloudFix). AgentProof's contribution is applying that loop to agent tool-call
authorization with provenance/data-flow root causes and mixed policy operators. It is not the
first policy-repair or least-privilege-synthesis system, and its synthesized policies under-perform
an expert on legitimate-task preservation in our own evaluation.
