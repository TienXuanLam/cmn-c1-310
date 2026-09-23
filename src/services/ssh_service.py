"""Small, fail-closed Paramiko adapter used by one graph invocation."""

from __future__ import annotations

import io
from typing import Any, Protocol, cast

import paramiko

HARD_TIMEOUT_CEILING_SEC = 60
DEFAULT_TIMEOUT_SEC = 10
HARD_OUTPUT_CEILING_BYTES = 1_048_576
DEFAULT_MAX_OUTPUT_BYTES = 262_144
_TRUNCATION_MARKER = "\n[OUTPUT TRUNCATED]"


class SSHBackend(Protocol):
    def connect(
        self, host: str, private_key: str, known_hosts: str, username: str = "agentcore", timeout_sec: int = 10
    ) -> Any: ...

    def execute(
        self, client: Any, command: str, timeout_sec: int = 10, max_output_bytes: int = 262_144
    ) -> tuple[int, str, str]: ...

    def close(self, client: Any) -> None: ...


def _load_known_hosts(client: paramiko.SSHClient, known_hosts: str) -> None:
    loaded = 0
    for raw_line in known_hosts.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        entry = paramiko.hostkeys.HostKeyEntry.from_line(line)
        if entry is None or entry.key is None:
            raise ValueError("SSH_KNOWN_HOSTS contains an invalid entry")
        for hostname in entry.hostnames:
            client.get_host_keys().add(hostname, entry.key.get_name(), entry.key)
            loaded += 1
    if loaded == 0:
        raise ValueError("SSH_KNOWN_HOSTS contains no usable host keys")


def _parse_private_key(private_key: str) -> paramiko.PKey:
    """Parse the supported key families; the abstract PKey class cannot auto-detect."""
    key_types = (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey, paramiko.DSSKey)
    for key_type in key_types:
        try:
            return cast(paramiko.PKey, key_type.from_private_key(io.StringIO(private_key)))
        except paramiko.SSHException:
            continue
    raise paramiko.SSHException("SSH_PRIVATE_KEY has an unsupported or invalid format")


def connect(
    host: str,
    private_key: str,
    known_hosts: str,
    username: str = "agentcore",
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> paramiko.SSHClient:
    """Open an SSH connection only when the server key is pre-provisioned."""
    pkey = _parse_private_key(private_key)
    client = paramiko.SSHClient()
    _load_known_hosts(client, known_hosts)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(
        hostname=host,
        username=username,
        pkey=pkey,
        timeout=min(max(timeout_sec, 1), HARD_TIMEOUT_CEILING_SEC),
    )
    return client


def _bounded_decode(stream: object, max_output_bytes: int) -> str:
    reader = cast(Any, getattr(stream, "read"))
    raw = reader(max_output_bytes + 1)
    if not isinstance(raw, bytes):
        raw = bytes(raw)
    truncated = len(raw) > max_output_bytes
    text = raw[:max_output_bytes].decode("utf-8", errors="replace")
    return cast(str, text + (_TRUNCATION_MARKER if truncated else ""))


def execute(
    client: paramiko.SSHClient,
    command: str,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> tuple[int, str, str]:
    """Execute one exact allowlisted command with bounded time and output."""
    bounded_timeout = min(max(timeout_sec, 1), HARD_TIMEOUT_CEILING_SEC)
    bounded_output = min(max(max_output_bytes, 1), HARD_OUTPUT_CEILING_BYTES)
    _stdin, stdout, stderr = client.exec_command(command, timeout=bounded_timeout)
    exit_code = stdout.channel.recv_exit_status()
    return (
        exit_code,
        _bounded_decode(stdout, bounded_output),
        _bounded_decode(stderr, bounded_output),
    )


def close(client: paramiko.SSHClient) -> None:
    """Best-effort cleanup; callers invoke this from ``finally``."""
    try:
        client.close()
    except Exception:  # noqa: BLE001 - cleanup must not hide the primary failure
        pass
