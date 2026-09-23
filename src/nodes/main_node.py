"""Per-invocation SSH execution node.

SSH_PRIVATE_KEY / SSH_KNOWN_HOSTS are caller-supplied per request (via
``input_context``), not resolved from the deployment secret provider -- this
agent SSHes into whatever environment the caller names, not a fixed host, so
there is no single credential to provision ahead of time. This is a deliberate
exception to the "secrets never ride in state" rule; see
docs/02_design.md "Dynamic SSH target" for the accepted-risk rationale.
Azure OpenAI credentials are unaffected and still resolve via ``ctx.secrets``
in PreProcessNode.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, cast

import paramiko

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import SSHCommandAgentState
from src.services import ssh_service
from src.services.ssh_service import SSHBackend


class MainNode(FunctionNode):
    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def __init__(self, backend: SSHBackend | None = None) -> None:
        super().__init__()
        self._backend = backend or cast(SSHBackend, ssh_service)

    def _extra_security_gate_input(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("error_code") and state.get("status") == AgentStatus.ERROR.value:
            bridged = dict(state)
            bridged["status"] = AgentStatus.PENDING.value
            return bridged
        return state

    def execute(self, state: SSHCommandAgentState) -> dict[str, Any]:
        if state.get("error_code"):
            emit_trace_event(
                event_type="upstream_error_forwarded",
                payload={"error_code": state.get("error_code")},
                state=state,
            )
            return {
                "error_code": state.get("error_code"),
                "error_message": state.get("error_message") or "Input validation rejected the request",
                "status": AgentStatus.SUCCESS.value,
            }

        host = state.get("validated_host", "")
        command = state.get("validated_command", "")
        if not host or not command:
            return self._failure(state, "INVALID_STATE", "Validated SSH target is missing")

        input_context = state.get("input_context", {})
        try:
            timeout_sec = min(
                max(int(input_context.get("timeout_sec", state.get("timeout_seconds", 10))), 1),
                ssh_service.HARD_TIMEOUT_CEILING_SEC,
            )
            max_output_bytes = min(
                max(int(state.get("max_output_bytes", ssh_service.DEFAULT_MAX_OUTPUT_BYTES)), 1),
                ssh_service.HARD_OUTPUT_CEILING_BYTES,
            )
        except (TypeError, ValueError):
            return self._failure(state, "INVALID_CONFIG", "SSH execution limits are invalid")

        private_key = input_context.get("ssh_private_key")
        known_hosts = input_context.get("ssh_known_hosts")
        if not isinstance(private_key, str) or not private_key.strip():
            return self._failure(state, "SSH_SECRET_MISSING", "ssh_private_key was not supplied in input_context")
        if not isinstance(known_hosts, str) or not known_hosts.strip():
            return self._failure(state, "SSH_SECRET_MISSING", "ssh_known_hosts was not supplied in input_context")

        client: Any = None
        try:
            client = self._backend.connect(
                host,
                private_key,
                known_hosts,
                username=state.get("ssh_username", "agentcore"),
                timeout_sec=timeout_sec,
            )
            exit_code, stdout, stderr = self._backend.execute(
                client,
                command,
                timeout_sec=timeout_sec,
                max_output_bytes=max_output_bytes,
            )
        except (paramiko.SSHException, OSError, ValueError):
            return self._failure(state, "SSH_EXECUTION_FAILED", "SSH execution failed")
        finally:
            if client is not None:
                self._backend.close(client)

        emit_trace_event(
            event_type="ssh_command_executed",
            payload={"host": host, "command": command, "exit_code": exit_code},
            state=state,
        )
        return {
            "exit_code": exit_code,
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "status": AgentStatus.SUCCESS.value,
        }

    def _failure(self, state: SSHCommandAgentState, code: str, message: str) -> dict[str, Any]:
        emit_trace_event(
            event_type="ssh_command_failed",
            payload={"error_code": code, "host": state.get("validated_host", "")},
            state=state,
        )
        return {
            "error_code": code,
            "error_message": message,
            "error_log": [f"MainNode: {message}"],
            "status": AgentStatus.SUCCESS.value,
        }
