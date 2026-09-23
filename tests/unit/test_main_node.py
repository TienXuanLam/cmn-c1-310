from typing import Any

from framework.schemas.agent_status import AgentStatus

from src.nodes.main_node import MainNode


class Backend:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.closed = False
        self.connect_args: tuple[Any, ...] = ()

    def connect(self, *args: Any, **kwargs: Any) -> object:
        self.connect_args = (*args, kwargs)
        if self.fail:
            raise OSError("sensitive backend detail")
        return object()

    def execute(self, _client: object, _command: str, **_kwargs: Any) -> tuple[int, str, str]:
        return 0, "up 5 days\n", ""

    def close(self, _client: object) -> None:
        self.closed = True


def _state(**overrides: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "validated_host": "db01.internal.example.com",
        "validated_command": "uptime",
        "timeout_seconds": 30,
        "max_output_bytes": 100,
        "ssh_username": "agentcore",
        "input_context": {},
        "caller_trust_level": "VERIFIED_EXTERNAL",
        "caller_id": "test-caller",
        "correlation_id": "test-correlation",
        "session_id": "test-session",
        "thread_id": "test-thread",
        "trace_id": "",
        "hitl_allowed": True,
        "node_history": [],
        "error_log": [],
    }
    state.update(overrides)
    return state


def _caller_supplied_ssh_context() -> dict[str, str]:
    return {"ssh_private_key": "private", "ssh_known_hosts": "known"}


def test_success_uses_both_secrets_and_closes() -> None:
    backend = Backend()
    result = MainNode(backend).execute(_state(input_context=_caller_supplied_ssh_context()))
    assert result["status"] == AgentStatus.SUCCESS
    assert result["raw_stdout"] == "up 5 days\n"
    assert backend.connect_args[1:3] == ("private", "known")
    assert backend.closed


def test_backend_failure_is_sanitized_and_not_retried() -> None:
    backend = Backend(fail=True)
    result = MainNode(backend).execute(_state(input_context=_caller_supplied_ssh_context()))
    assert result["status"] == AgentStatus.SUCCESS
    assert result["error_code"] == "SSH_EXECUTION_FAILED"
    assert "sensitive backend detail" not in str(result)


def test_missing_secret_becomes_structured_error() -> None:
    result = MainNode(Backend()).execute(_state(input_context={}))
    assert result["error_code"] == "SSH_SECRET_MISSING"


def test_missing_known_hosts_only_becomes_structured_error() -> None:
    result = MainNode(Backend()).execute(_state(input_context={"ssh_private_key": "private"}))
    assert result["error_code"] == "SSH_SECRET_MISSING"


def test_upstream_error_is_forwarded() -> None:
    result = MainNode(Backend()).execute(_state(error_code="HOST_NOT_ALLOWED", error_message="denied"))
    assert result["error_code"] == "HOST_NOT_ALLOWED"
