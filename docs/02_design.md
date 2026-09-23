# Template Design Specification

## Position in AgentCore Architecture

- **Agent Class**: `Graph` (`src/graph/graph.py`)
- **L1 Base**: AgentBaseGraph
- **Three-Layer Separation**:
  - State: flat TypedDict composition (no Pydantic — msgpack incompatible)
  - Node: L1 inheritance (Template Method: `execute(self, state: dict) -> dict` override only)
  - Graph: composition (`register_nodes()` for node substitution)

## Architecture Overview

### Five Conceptual Steps → Three Pipeline Slots

`AgentBaseGraph` enforces a fixed 5-stage pipeline with exactly three
customizable slots (`pre_process`, `main`, `post_process`). The proposal's
5-step "Agent Workflow" (`InputValidateNode → AllowlistCheckNode →
SSHExecuteNode → AuditLogNode → ResponseValidateNode`) is implemented as
5 internal helper steps composed inside those 3 slots — not as 5 separate
graph nodes/slots.

| Conceptual Step | Implemented In | Slot |
|---|---|---|
| 1. `InputValidateNode` — validate host format + command syntax, reject injection patterns | `PreProcessNode` (step 1 of 2) | `pre_process` |
| 2. `AllowlistCheckNode` — check host/command against AgentState allowlists | `PreProcessNode` (step 2 of 2) | `pre_process` |
| 3. `SSHExecuteNode` — acquire SSH session, execute with timeout, capture stdout/stderr | `MainNode` | `main` |
| 4. `AuditLogNode` — write S-4 audit entry (host, command, caller identity, timestamp, exit code) | `PostProcessNode` (step 1 of 2) | `post_process` |
| 5. `ResponseValidateNode` — S-3 redaction of stdout/stderr (secrets, PII, internal hostnames) | `PostProcessNode` (step 2 of 2) | `post_process` |

Each conceptual step is implemented as a private helper method
(`_validate_input()`, `_check_allowlist()`, `_audit_log()`,
`_sanitize_output()`) on its owning node class, so each step remains
independently unit-testable per Issues 3-7 without violating the
3-slot graph contract.

### Node Configuration

| Node | Responsibility | Input State | Output State | Inherits/Overrides |
|------|---------------|-------------|--------------|-------------------|
| initialize | Set `schema_version`, `session_id`, `caller_trust_level` (via default `InitializeNode._setup()`); load `command_allowlist` from `config/config.yaml` (via `Graph(config=...)`) | — | `session_id`, `caller_trust_level`, `schema_version`, `command_allowlist` | CustomInitializeNode (overrides `on_initialize()`) |
| pre_process | Step 0: LLM (Azure OpenAI) extracts a `{host, command}` candidate from free-text `user_input`. Step 1: validate extracted host/command format, reject injection patterns (S-1/S-2). Step 2: check the extracted host against `_is_blocked_target` (SSRF guard — see "Dynamic SSH target" below) and the extracted command against `command_allowlist` in state; hard-reject on mismatch | free-text `user_input`, `command_allowlist` | `validated_host`, `validated_command`, `status` (ERROR on reject) | PreProcessNode |
| main | Acquire SSH session via `shared/services/ssh_service.py`, using `ssh_private_key`/`ssh_known_hosts` supplied by the caller per request in `input_context` (see "Dynamic SSH target" below), execute `validated_command` on `validated_host` with bounded timeout, capture stdout/stderr/exit_code | `validated_host`, `validated_command`, `timeout_sec`, `input_context.ssh_private_key`, `input_context.ssh_known_hosts` | `exit_code`, `raw_stdout`, `raw_stderr`, `executed_at`, `status` | MainNode |
| post_process | Step 1: emit S-4 audit trace (host, command, caller identity, timestamp, exit code) via `_emit_trace_event()`. Step 2: run `_security_gate_output()` (S-3) to redact secrets/PII/internal hostnames from stdout/stderr | `raw_stdout`, `raw_stderr`, `exit_code`, `validated_host`, `validated_command` | `stdout`, `stderr`, `result` | PostProcessNode |
| finalize | Build `response_metadata`, `total_time_ms` | all above | `response_metadata`, `total_time_ms` | FinalizeNode (default) |

### Data Flow

```
START → initialize → pre_process → main → {route} → post_process → finalize → END
                                            ↓ (retry, max 3)
                                          pre_process
```

`route()` retries from `pre_process` on `AgentStatus.RETRY` (e.g. transient
SSH connection failure surfaced from `main` as RETRY rather than ERROR, up
to `MAX_RETRY_CEILING`). Hard rejects (allowlist mismatch, invalid
host/command syntax) set `AgentStatus.ERROR` in `pre_process` and do not
retry.

### State Definition

| Field | Type | Purpose | Required |
|-------|------|---------|----------|
| `command_allowlist` | `list[str]` | Pre-approved command templates loaded from `config.yaml` at `initialize` | Yes |
| `validated_host` | `str` | Host confirmed against allowlist (set by `pre_process`) | Yes |
| `validated_command` | `str` | Command confirmed against allowlist, fully rendered (set by `pre_process`) | Yes |
| `timeout_sec` | `int` | Per-invocation SSH command timeout (caller-supplied, capped by config ceiling) | Yes |
| `exit_code` | `int` | SSH command exit code (set by `main`) | No |
| `raw_stdout` | `str` | Unredacted stdout (set by `main`, consumed and dropped by `post_process`) | No |
| `raw_stderr` | `str` | Unredacted stderr (set by `main`, consumed and dropped by `post_process`) | No |
| `stdout` | `str` | Redacted stdout (S-3 output, set by `post_process`) | No |
| `stderr` | `str` | Redacted stderr (S-3 output, set by `post_process`) | No |
| `executed_at` | `str` | ISO 8601 timestamp of command execution | No |

**State Constraints (mandatory):**
- Flat TypedDict only (primitives + JSON-serializable types)
- No JWT, API keys, credentials in State (checkpoint DB leakage)
- InvocationContext via `config["configurable"]` only (not in State)
- No Pydantic models, dataclass, arbitrary Python objects (msgpack incompatible)

**Explicit deviations from `01_proposal.md`:**
- The proposal's "SSH session pool" and "credential references" held in
  `AgentState` are **not implemented as state fields**. SSH connections are
  not msgpack-serializable (Rule 1.1) and credential handles must not be
  persisted to checkpoints (Rule 1.2/1.3). Instead:
  - SSH connection lifecycle is owned by `shared/services/ssh_service.py`,
    scoped to a single `main` invocation (connect → execute → close). No
    cross-invocation session pool in v1 — this also resolves Key Risk #3
    (session pool leak) by construction.
  - SSH credentials and server identity are **caller-supplied per request**
    (`input_context.ssh_private_key` / `input_context.ssh_known_hosts`), not
    resolved from the deployment secret provider — see "Dynamic SSH target"
    below for the accepted-risk rationale. They are read at the point of use
    inside `main` and never persisted to state.
- `raw_stdout`/`raw_stderr` vs `stdout`/`stderr` split is added (not in
  proposal) to make the S-3 redaction boundary explicit and testable.

### Dynamic SSH target (accepted-risk architecture)

This template was originally designed around a fixed, deployment-time
`host_allowlist` (`config.yaml`) plus `SSH_PRIVATE_KEY`/`SSH_KNOWN_HOSTS`
provisioned as deployment secrets — i.e. the agent could only ever reach one
pre-approved set of hosts. That model was deliberately replaced, with
explicit user sign-off, by a **caller-supplied SSH target and credentials
per request**, because operationally the agent needs to reach whatever host
the caller names, not a single fixed set decided at deploy time. This is an
accepted-risk architecture change, not a bug fix:

- **Host targeting**: `PreProcessNode` still extracts `{host, command}` from
  free-text `user_input` via an LLM, but the extracted host is no longer
  checked against a static allowlist. Instead every host is checked against
  `_is_blocked_target()` (`src/nodes/pre_process_node.py`) — an SSRF
  blocklist built on `ipaddress` + `socket.getaddrinfo` that rejects
  loopback, private, link-local, reserved, multicast, and cloud-metadata
  addresses (`169.254.169.254`, `metadata.google.internal`), whether the
  host is a literal IP or a hostname that *resolves* to one of those ranges.
  This stops the agent being used to pivot into the platform's own internal
  network, but it does **not** limit which legitimate external/customer
  hosts may be targeted — there is no fixed host allowlist any more.
- **Credentials**: `SSH_PRIVATE_KEY` / `SSH_KNOWN_HOSTS` are no longer
  deployment secrets resolved via `ctx.secrets.require(...)`. They ride in
  per-request `InvokeRequest.input_context` (`src/api/server.py`) as
  `ssh_private_key`/`ssh_known_hosts` keys, are read only at the point of
  use inside `MainNode.execute()`, and are never written into `AgentState`
  or a checkpoint. A request missing either value hard-rejects with
  `SSH_SECRET_MISSING`.
  **Known limitation**: `input` alone is plain text (Marketplace-chat
  friendly), but the credentials still require the caller to assemble a
  structured `input_context` object — not yet a fully plain-text-safe
  design for a person typing directly into a chat UI. A separate
  credential-storage mechanism decoupled from each request is documented
  future work (see `README.md` "Security Boundary"), not solved here.
- **What stays fixed**: `command_allowlist` is completely unaffected and
  remains the sole, deployment-time authority on which commands may run —
  see the "Public input parsing" row below. Host-key verification
  (`RejectPolicy`, no TOFU) is also unaffected: `ssh_known_hosts` is still
  required and still fails closed, it is simply supplied by the caller
  instead of provisioned ahead of time.
- **Net effect**: this agent is now best understood as a dynamic SSH command
  executor scoped by `command_allowlist` and the SSRF blocklist, not by
  host. Authorization to reach a given host is delegated to whichever
  `ssh_private_key`/`ssh_known_hosts` the caller supplies — if those
  credentials grant access to a host, this agent will use them, subject
  only to the SSRF blocklist and the command allowlist.

## Framework Utilization

### Shared Components Used
- [x] InvocationContext (correlation_id, session_id, permissions, credential handle) — used in `pre_process` to obtain the Azure OpenAI credentials via `ctx.secrets.require()`; SSH credentials are caller-supplied per request via `input_context` instead (see "Dynamic SSH target")
- [x] AuditSink (`_emit_trace_event`) — called by every node (`node_start`/`node_complete`/`node_error`); `post_process` additionally emits a business-level `ssh_command_executed` event (S-4)
- [x] ConnectionPolicy (retry/timeout strategy) — applied in `shared/services/ssh_service.py` for SSH connect/execute timeout bounds
- [x] `_validate_input()`/`_check_allowlist()` (S-1) — `pre_process` returns `AgentStatus.ERROR` with `error_log` on injection pattern detection or allowlist mismatch; nodes return state updates rather than raising `SecurityViolationError` (which in the installed SDK models trust-level authorization, not input/output validation)
- [ ] `_security_gate_input()` (PII detection on `command_template`/`host`) — not implemented; out of scope for Issues 3-7, candidate for a follow-up issue
- [x] `_sanitize_output()` (S-3, content safety — mandatory) — implemented in `post_process`; best-effort redaction of known secret patterns, PII, and internal hostnames from `raw_stdout`/`raw_stderr` into `stdout`/`stderr`, plus an advisory disclaimer in `result`. Always returns `AgentStatus.SUCCESS` — redaction is best-effort, not a hard gate that can fail the pipeline

### Composition Pattern

- **Pattern**: Standalone (no GraphNode/RemoteAgentNode composition in v1)
- **Composition target**: N/A — this template is itself the reusable Cat 1
  capability that downstream Cat 2 templates may compose via `GraphNode` in
  a future iteration. No subgraph composition is required for CMN-C1-310 itself.
- **Error propagation strategy**: propagate — `pre_process` allowlist/format
  failures and `main` SSH execution failures set `AgentStatus.ERROR` (hard
  reject) or `AgentStatus.RETRY` (transient connection failure) and propagate
  to the caller via `finalize`'s `response_metadata`; no error is silently
  swallowed.

## Import Isolation Confirmation
- [x] Template does not import agenticstar-platform SDK (Level 0)
- [x] Import targets: framework/ and shared/ only (no agents/base/ required)

## Design Decision Record

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| L1 base type | AgentBaseGraph | AutonomousBaseGraph | **AgentBaseGraph** | Fixed deterministic pipeline (validate → execute → audit/sanitize); no autonomous reasoning loop needed (per `01_proposal.md` Cat 1 judgment) |
| 5-step workflow → graph slots | 5 independent GraphNode subgraph steps | 5 conceptual steps composed into 3 mandatory slots (pre_process/main/post_process) | **3 mandatory slots** | `AgentBaseGraph.compile()` requires exactly `pre_process`/`main`/`post_process`; a 5-node subgraph adds an unnecessary composition layer for a single Cat 1 capability |
| SSH session lifecycle | Persistent session pool stored in AgentState | Per-invocation connect/execute/close via `shared/services/ssh_service.py` | **Per-invocation, service-layer** | AgentState must be msgpack-safe (Rule 1.1) — `paramiko.SSHClient` objects cannot be stored in state; per-invocation lifecycle also eliminates Key Risk #3 (session pool leak) by construction |
| Credential access (Azure OpenAI) | Credential reference stored in AgentState | `ctx.secrets.require(...)` via `InvocationContext` at point of use | **`ctx.secrets` at point of use** | Rule 1.2/1.3 and `04-credential-handling.md` Rule 4.1 prohibit credentials/credential handles in State |
| Credential access (SSH) | `ctx.secrets.require("SSH_PRIVATE_KEY"/"SSH_KNOWN_HOSTS")` as fixed deployment secrets | Caller-supplied per request via `input_context.ssh_private_key`/`ssh_known_hosts`, read at point of use inside `MainNode`, never stored in state | **Caller-supplied via `input_context`, at point of use** | Accepted-risk architecture change (explicit user sign-off): the agent must reach whatever host the caller names, not one fixed deployment target — see "Dynamic SSH target" above. Still never written into `AgentState`/checkpoints. |
| Composition pattern | GraphNode (subgraph) | Standalone | **Standalone** | No domain workflow to encapsulate; template is the reusable unit itself |
| SSH host key policy | Caller-supplied `known_hosts` with `RejectPolicy` | `AutoAddPolicy` (TOFU) | **Caller-supplied + `RejectPolicy`** | Neither the SSRF blocklist nor `command_allowlist` authenticate the server identity at the other end of the connection. `SSH_KNOWN_HOSTS` therefore provides the fail-closed MITM protection — a missing/mismatched entry always fails closed, regardless of who supplied it. |
| SSH failure handling | Framework retry | Single attempt + structured error | **Single attempt** | A remote command may have taken effect before the connection failed; automatic retry could duplicate side effects. |
| Output resource bound | Unbounded stream reads | Configured limit plus 1 MiB hard ceiling | **Bounded reads** | Prevents a permitted command from exhausting agent memory. |
| Output summarization | Return raw redacted stdout/stderr only | LLM (Azure OpenAI) summarizes redacted output into operator-facing Markdown, with deterministic raw-Markdown fallback | **LLM summary + deterministic fallback, in `PostProcessNode` only** | `SSHExecuteNode`/`MainNode`, the allowlist, and `RejectPolicy` host-key verification stay fully deterministic and untouched — the LLM call is confined to the last pipeline slot, after redaction. A provider failure/timeout degrades to the raw-Markdown rendering with `status` still `success` (controlled degrade, not a pipeline error); it never blocks or retries the underlying SSH execution. This does not change the Cat 1 judgment. |
| Public input parsing | Require `user_input` to be a JSON string (`{"host":...,"command":...}`) | LLM (Azure OpenAI) extracts a `{host, command}` candidate from free-text `user_input`, then the pre-existing format/injection/allowlist checks run unchanged on the extracted values | **LLM extraction in `PreProcessNode`, allowlist unchanged as the sole authority** | The JSON-string contract violated the public input contract (input must be plain text a user can paste directly). The extraction LLM is treated as fully untrusted input *and* untrusted output: its only effect is proposing two strings that then pass through the exact same `_HOSTNAME_RE`/`_IPV4_RE` format check, `_INJECTION_PATTERN` check, and (per "Dynamic SSH target" above) `_is_blocked_target` SSRF check plus exact-match `command_allowlist` check. A provider failure/timeout or an unparseable/incomplete extraction hard-rejects (`EXTRACTION_UNAVAILABLE` / `INPUT_UNCLEAR`) — unlike `PostProcessNode`'s summarization, there is no safe fallback that guesses a host/command by another means, so pre_process degrades to reject, not to a best-effort default. |

### Public output contract change

`formatted_output` was previously a `json.dumps()`-encoded envelope string —
this violated the public contract (plain Markdown, no double-encoded JSON;
see `BuildAndTestLLM.md` §5.3) and is now a plain Markdown string in both the
success and error paths: either the LLM-generated summary, or (on LLM
disable/failure, or on the pre-existing validation-error path) a
deterministic Markdown rendering. `stdout`/`stderr` (post-redaction) remain first-class state fields, as do the
already-existing `exit_code`/`validated_host`/`validated_command` fields set
earlier in the pipeline; none of the structured data is nested inside the
public `output` string anymore.

### Public input contract change

`user_input` was previously required to be a JSON string
(`{"host":"...","command":"..."}"`) — this also violated the public contract
(`BuildAndTestLLM.md` §5.1: input should be plain text, domain objects only
after internal parsing). `PreProcessNode` now accepts free-text natural
language (e.g. `"check disk space on db01.internal.example.com"`) and uses an
Azure OpenAI call to extract a `{host, command}` candidate before the
unchanged format/injection/allowlist pipeline runs. **The allowlist remains
the only security boundary** — the LLM is never trusted to authorize
execution, only to propose field values that are then checked exactly as
strictly as a hand-typed JSON payload was before. Verified live: colloquial
phrasing ("check disk space on db01...") correctly maps to the exact
allowlisted string `"df -h"`, and a genuinely ambiguous request ("do
something on the database") correctly degrades to `INPUT_UNCLEAR` rather than
guessing.

---

## Open Items Carried from `01_proposal.md`

| # | Item | Status |
|---|---|---|
| 1 | Architect review of allowlist config schema (`command_allowlist` in `config.yaml`) | Resolved in this design — `list[str]` loaded into state at `initialize`. `host_allowlist` was later removed entirely in favor of a caller-supplied target plus SSRF blocklist — see "Dynamic SSH target" |
| 2 | CoE confirmation that pure-execution (no LLM) agents are in Cat 1 scope | Superseded — the agent now calls an LLM (see "Output summarization" row above); the underlying question no longer applies to this template as designed |
