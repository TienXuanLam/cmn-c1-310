# CMN-C1-310 — SSH Command Agent

> **Category**: Cat 1 (delivers a single technical capability, generic and use-case-agnostic)
> **Industry**: CMN (common / cross-industry)

## Overview

Executes one exact, allowlisted command over host-key-verified SSH against a target
described in plain English (e.g. "check disk space on db01.internal.example.com").
Azure OpenAI extracts a `{host, command}` candidate from the free-text request, which
is then validated against a fixed, deployment-time `command_allowlist` and an SSRF
blocklist (rejecting loopback, private, link-local, reserved, multicast, and
cloud-metadata addresses) — the LLM only proposes; the allowlist and blocklist are the
sole authorities on what may execute and where. Output is bounded, redacted, audited,
and returned as a Markdown summary, with a deterministic fallback when the
summarization LLM call is disabled, fails, or times out.

The SSH target is dynamic and caller-supplied per request, not a fixed deployment-time
host. SSH credentials (`ssh_private_key`, `ssh_known_hosts`) are likewise
caller-supplied per request via `input_context`, never stored as deployment secrets —
an accepted-risk design documented in `docs/02_design.md`. Host-key verification uses
Paramiko's `RejectPolicy`; TOFU/`AutoAddPolicy` is forbidden.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from PyPI as a dependency. |
| Python | >=3.11 |
| Azure OpenAI | A resource with a chat-capable deployment — `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT` |
| SSH credentials | Supplied by the caller per request (`ssh_private_key`, `ssh_known_hosts`), not a deployment secret |

```bash
pip install -e .
```

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## Project Structure

```
src/          agent implementation (nodes, services, schemas)
tests/        unit, integration and boundary tests
config/       agent configuration
docs/         design and operational documentation
```

See `docs/` for the design spec and test specification.

## Customising

1. Adjust `config/` for your own environment and policies.
2. Replace the knowledge sources and sample data with your own.
3. Review the node implementations under `src/nodes/` for domain-specific logic.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.
