"""Flat, checkpoint-safe state for CMN-C1-310."""

from framework.schemas.agent_state import AgentState


class SSHCommandAgentState(AgentState):
    command_allowlist: list[str]
    timeout_seconds: int
    max_output_bytes: int
    ssh_username: str
    validated_host: str
    validated_command: str
    exit_code: int | None
    raw_stdout: str
    raw_stderr: str
    stdout: str
    stderr: str
    executed_at: str
    error_code: str
    error_message: str
