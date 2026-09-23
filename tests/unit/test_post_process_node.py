from contextlib import contextmanager
from typing import Iterator
from unittest.mock import MagicMock, patch

import pytest
from framework.schemas.agent_status import AgentStatus
from framework.secrets.context import bound_secrets
from shared.secrets.inmemory_provider import InMemoryProvider

from src.nodes.post_process_node import PostProcessNode

_FAKE_SECRETS = {
    "AZURE_OPENAI_API_KEY": "test-key",
    "AZURE_OPENAI_ENDPOINT": "https://test.services.ai.azure.com",
    "AZURE_OPENAI_DEPLOYMENT": "test-deployment",
}


@pytest.fixture(autouse=True)
def _isolate_azure_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Any ambient Azure credentials from a prior real-invoke session in this
    # shell must never leak into a mocked assertion (BuildAndTestLLM.md §9).
    for key in _FAKE_SECRETS:
        monkeypatch.delenv(key, raising=False)


@contextmanager
def _bound_fake_secrets() -> Iterator[None]:
    with bound_secrets(InMemoryProvider(_FAKE_SECRETS)):
        yield


def _state(**overrides: object) -> dict:
    state = {
        "correlation_id": "corr-test-001",
        "session_id": "sess-test-001",
        "thread_id": "thread-test-001",
        "trace_id": "trace-test-001",
        "caller_trust_level": "VERIFIED_EXTERNAL",
        "validated_host": "db01.internal.example.com",
        "validated_command": "uptime",
        "exit_code": 0,
        "raw_stdout": "up 5 days\n",
        "raw_stderr": "",
        "executed_at": "2026-06-15T00:00:00+00:00",
    }
    state.update(overrides)
    return state


def _node(**kwargs: object) -> PostProcessNode:
    return PostProcessNode(**kwargs)  # type: ignore[arg-type]


def test_error_path_never_constructs_llm_client() -> None:
    with patch("src.nodes.post_process_node.AzureOpenAIClient") as mock_client, _bound_fake_secrets():
        result = _node().execute(_state(error_code="HOST_NOT_ALLOWED", error_message="denied"))
    mock_client.assert_not_called()
    assert result["status"] == AgentStatus.ERROR.value
    assert isinstance(result["formatted_output"], str)
    assert "HOST_NOT_ALLOWED" in result["formatted_output"]
    assert "denied" in result["formatted_output"]


def test_llm_disabled_falls_back_to_raw_markdown_without_constructing_client() -> None:
    with patch("src.nodes.post_process_node.AzureOpenAIClient") as mock_client, _bound_fake_secrets():
        result = _node(llm_enabled=False).execute(_state())
    mock_client.assert_not_called()
    assert result["status"] == AgentStatus.SUCCESS.value
    assert "up 5 days" in result["formatted_output"]
    assert "**Exit code:** 0" in result["formatted_output"]


def test_llm_happy_path_uses_summary_as_formatted_output() -> None:
    mock_instance = MagicMock()
    mock_instance.complete.return_value = {"content": "The host has been up for 5 days."}
    with patch("src.nodes.post_process_node.AzureOpenAIClient", return_value=mock_instance), _bound_fake_secrets():
        result = _node().execute(_state())
    assert result["status"] == AgentStatus.SUCCESS.value
    assert result["formatted_output"] == "The host has been up for 5 days."


def test_llm_timeout_falls_back_to_raw_markdown() -> None:
    mock_instance = MagicMock()
    mock_instance.complete.side_effect = TimeoutError("provider timeout")
    with patch("src.nodes.post_process_node.AzureOpenAIClient", return_value=mock_instance), _bound_fake_secrets():
        result = _node().execute(_state())
    assert result["status"] == AgentStatus.SUCCESS.value
    assert "up 5 days" in result["formatted_output"]
    assert "**Command:**" in result["formatted_output"]


def test_llm_client_init_failure_falls_back_to_raw_markdown() -> None:
    # No secrets bound at all -> ctx.secrets.require(...) raises -> client_init_failed.
    with patch("src.nodes.post_process_node.AzureOpenAIClient"):
        result = _node().execute(_state())
    assert result["status"] == AgentStatus.SUCCESS.value
    assert "up 5 days" in result["formatted_output"]


def test_llm_provider_error_falls_back_to_raw_markdown() -> None:
    mock_instance = MagicMock()
    mock_instance.complete.side_effect = RuntimeError("500 from provider")
    with patch("src.nodes.post_process_node.AzureOpenAIClient", return_value=mock_instance), _bound_fake_secrets():
        result = _node().execute(_state())
    assert result["status"] == AgentStatus.SUCCESS.value
    assert "up 5 days" in result["formatted_output"]


def test_llm_empty_response_falls_back_to_raw_markdown() -> None:
    mock_instance = MagicMock()
    mock_instance.complete.return_value = {"content": ""}
    with patch("src.nodes.post_process_node.AzureOpenAIClient", return_value=mock_instance), _bound_fake_secrets():
        result = _node().execute(_state())
    assert result["status"] == AgentStatus.SUCCESS.value
    assert "up 5 days" in result["formatted_output"]


@pytest.mark.parametrize(
    "raw",
    [
        "password=SuperSecret123",
        "Bearer abc.def",
        "Contact admin@example.com",
        "Connected to cache01.internal.example.com",
    ],
)
def test_sensitive_raw_output_is_redacted_before_llm_and_fallback(raw: str) -> None:
    # LLM disabled so the fallback (raw Markdown render of the redacted
    # stdout/stderr) is what's asserted against. `validated_host` itself is
    # intentionally shown unredacted in the fallback (the operator needs to
    # know which host the command ran on) — only the *content* of stdout/
    # stderr is redacted, including any internal-host-shaped substrings that
    # appear there.
    with patch("src.nodes.post_process_node.AzureOpenAIClient"):
        result = _node(llm_enabled=False).execute(_state(raw_stdout=raw))
    assert "[REDACTED]" in result["stdout"]
    assert "SuperSecret123" not in result["formatted_output"]
    assert "admin@example.com" not in result["formatted_output"]
    assert "cache01.internal.example.com" not in result["stdout"]


def test_llm_summary_containing_credential_pattern_is_blocked_by_output_gate() -> None:
    mock_instance = MagicMock()
    mock_instance.complete.return_value = {"content": "Here is your key: sk-abcdefgh12345678"}
    with patch("src.nodes.post_process_node.AzureOpenAIClient", return_value=mock_instance), _bound_fake_secrets():
        node = _node()
        result = node.execute(_state())
        gated = node._extra_security_gate_output(result)
    assert gated["status"] == AgentStatus.ERROR.value
    assert gated["error_code"] == "S3_BLOCKED"


def test_title_case_summary_is_not_falsely_redacted_as_pii() -> None:
    # Regression guard for the name-cue false-positive pattern documented in
    # BuildAndTestLLM.md §8.5 — an LLM-authored Markdown heading like "Disk
    # Usage Report" must not trip the PII 'name' finding inside _redact().
    node = _node()
    redacted = node._redact("## Disk Usage Report\nFilesystem Size Used Avail", "")
    assert "Disk Usage Report" in redacted
    assert "Filesystem Size Used Avail" in redacted
