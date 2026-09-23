"""Final output redaction, Markdown rendering, and LLM summarization."""

from __future__ import annotations

import re
from typing import Any

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from shared.security.pii_detector import detect_pii
from shared.services.llm.azure_openai_client import AzureOpenAIClient
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import SSHCommandAgentState

_REDACTED = "[REDACTED]"

# Kept local rather than swapped to framework.security.detect_credentials: verified
# via inspect.getsource() against agenticstar-agentcore==1.0.3 (BuildAndTestLLM.md
# §8.5) that the framework detector still has unbounded-quantifier patterns for
# bearer_token/conn_string/openai_key/jwt ({16,}/{20,}/{10,}/[^\s]{8,} — ReDoS risk
# on stdout/stderr of arbitrary length). detect_pii below IS reused per that same
# verification (framework's PII detector is fully bounded).
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+){1,2}"),
    re.compile(r"AKIA[A-Z0-9]{12,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._-]+", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"(?i)(?<![a-z0-9_])((?:[a-z0-9]+[_-])*(?:api[_-]?key|secret|token|password))\s*[=:]\s*\S+"),
]
_INTERNAL_HOST_RE = re.compile(
    r"\b[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?:\.internal|\.local|\.corp|\.lan)"
    r"(?:\.[A-Za-z0-9][A-Za-z0-9.-]*)?\b"
)
_DISCLAIMER = (
    "This command was executed by an automated agent. Output may have been "
    "truncated or redacted; verify exit_code before relying on it."
)

_SUMMARY_SYSTEM_PROMPT = (
    "You summarize the output of a single already-executed shell command for an "
    "operator. Be factual and concise. Do not speculate beyond what the output "
    "shows. Do not invent hostnames, credentials, or data not present in the "
    "output. If stderr is empty, do not mention errors."
)


class PostProcessNode(FunctionNode):
    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def __init__(
        self,
        llm_enabled: bool = True,
        llm_timeout_s: int = 20,
        llm_max_retries: int = 1,
        llm_max_summary_tokens: int = 512,
    ) -> None:
        super().__init__()
        self._llm_enabled = llm_enabled
        self._llm_timeout_s = llm_timeout_s
        self._llm_max_retries = llm_max_retries
        self._llm_max_summary_tokens = llm_max_summary_tokens

    def execute(self, state: SSHCommandAgentState) -> dict[str, Any]:
        if state.get("error_code"):
            error_code = state.get("error_code")
            error_message = state.get("error_message") or "Request failed"
            emit_trace_event(
                event_type="ssh_output_error",
                payload={"error_code": error_code},
                state=state,
            )
            return {
                "raw_stdout": "",
                "raw_stderr": "",
                "user_input": "",
                "formatted_output": self._render_error_markdown(error_code, error_message),
                "status": AgentStatus.ERROR.value,
            }

        host = state.get("validated_host", "")
        command = state.get("validated_command", "")
        exit_code = state.get("exit_code")
        stdout = self._redact(state.get("raw_stdout", ""), host)
        stderr = self._redact(state.get("raw_stderr", ""), host)

        fallback_markdown = self._render_raw_markdown(exit_code, host, command, stdout, stderr)
        summary, llm_error_reason = self._summarize_with_llm(state, exit_code, host, command, stdout, stderr)
        formatted_output = summary if summary is not None else fallback_markdown

        emit_trace_event(
            event_type="ssh_output_ready" if summary is not None else "ssh_output_ready_fallback",
            payload={
                "exit_code": exit_code,
                "host": host,
                "llm_used": summary is not None,
                "llm_fallback_reason": llm_error_reason,
            },
            state=state,
        )
        return {
            "stdout": stdout,
            "stderr": stderr,
            "raw_stdout": "",
            "raw_stderr": "",
            "user_input": "",
            "formatted_output": formatted_output,
            "status": AgentStatus.SUCCESS.value,
        }

    def _summarize_with_llm(
        self,
        state: SSHCommandAgentState,
        exit_code: int | None,
        host: str,
        command: str,
        stdout: str,
        stderr: str,
    ) -> tuple[str | None, str | None]:
        if not self._llm_enabled:
            return None, "disabled"
        try:
            ctx = InvocationContext.from_state(state)
            llm = AzureOpenAIClient(
                {
                    "api_key": ctx.secrets.require("AZURE_OPENAI_API_KEY"),
                    "azure_endpoint": ctx.secrets.require("AZURE_OPENAI_ENDPOINT"),
                    "azure_deployment": ctx.secrets.require("AZURE_OPENAI_DEPLOYMENT"),
                    # timeout/max_retries/max_tokens are AzureOpenAIClient
                    # constructor config, not complete() kwargs -- passing
                    # them to complete() raises TypeError (verified against
                    # the real wheel). Same fix pattern already applied elsewhere in the fleet.
                    "timeout": self._llm_timeout_s,
                    "max_retries": self._llm_max_retries,
                    "max_tokens": self._llm_max_summary_tokens,
                }
            )
        except Exception:
            emit_trace_event(
                event_type="llm_summary_error",
                payload={"node": self.__class__.__name__, "reason": "client_init_failed"},
                state=state,
            )
            return None, "client_init_failed"

        prompt = self._build_prompt(exit_code, host, command, stdout, stderr)
        try:
            response = llm.complete(
                [
                    {"role": "system", "content": _SUMMARY_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ]
            )
        except TimeoutError:
            emit_trace_event(
                event_type="llm_summary_timeout",
                payload={"node": self.__class__.__name__},
                state=state,
            )
            return None, "timeout"
        except Exception as exc:
            emit_trace_event(
                event_type="llm_summary_error",
                payload={"node": self.__class__.__name__, "error_type": type(exc).__name__},
                state=state,
            )
            return None, "provider_error"

        summary_text = self._extract_summary_text(response)
        if not summary_text:
            emit_trace_event(
                event_type="llm_summary_error",
                payload={"node": self.__class__.__name__, "reason": "empty_response"},
                state=state,
            )
            return None, "empty_response"
        return summary_text, None

    @staticmethod
    def _extract_summary_text(response: Any) -> str:
        if isinstance(response, str):
            return response.strip()
        if isinstance(response, dict):
            content = response.get("content")
            if isinstance(content, str):
                return content.strip()
        content = getattr(response, "content", None)
        if isinstance(content, str):
            return content.strip()
        return ""

    @staticmethod
    def _build_prompt(exit_code: int | None, host: str, command: str, stdout: str, stderr: str) -> str:
        return (
            f"Command: {command}\n"
            f"Host: {host}\n"
            f"Exit code: {exit_code}\n"
            f"--- stdout ---\n{stdout or '(empty)'}\n"
            f"--- stderr ---\n{stderr or '(empty)'}\n\n"
            "Summarize this command's result for an operator in 2-5 sentences of Markdown."
        )

    @staticmethod
    def _render_raw_markdown(exit_code: int | None, host: str, command: str, stdout: str, stderr: str) -> str:
        lines = [
            f"**Command:** `{command}`",
            f"**Host:** `{host}`",
            f"**Exit code:** {exit_code}",
            "",
            "**stdout:**",
            "```",
            stdout or "(empty)",
            "```",
        ]
        if stderr:
            lines += ["", "**stderr:**", "```", stderr, "```"]
        lines += ["", _DISCLAIMER]
        return "\n".join(lines)

    @staticmethod
    def _render_error_markdown(error_code: str | None, error_message: str) -> str:
        return (
            f"**Request failed** ({error_code}).\n\n"
            f"{error_message}\n\n"
            "Provide a host from the configured allowlist and one of the allowed "
            "commands, then retry."
        )

    def _extra_security_gate_output(self, result: dict[str, Any]) -> dict[str, Any]:
        output = result.get("formatted_output", "")
        if isinstance(output, str):
            for pattern in _SECRET_PATTERNS:
                if pattern.search(output):
                    return {
                        "error_code": "S3_BLOCKED",
                        "error_message": "Credential-like content remained after redaction",
                        "status": AgentStatus.ERROR.value,
                    }
        return result

    def _redact(self, text: str, validated_host: str) -> str:
        sanitized = text
        for pattern in _SECRET_PATTERNS:
            sanitized = pattern.sub(_REDACTED, sanitized)
        if validated_host:
            sanitized = re.sub(re.escape(validated_host), _REDACTED, sanitized, flags=re.IGNORECASE)
        sanitized = _INTERNAL_HOST_RE.sub(_REDACTED, sanitized)
        for finding in reversed(detect_pii(sanitized)):
            if finding["type"] == "name":
                continue
            sanitized = sanitized[: finding["start"]] + _REDACTED + sanitized[finding["end"] :]
        return sanitized
