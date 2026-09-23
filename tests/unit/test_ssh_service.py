from unittest.mock import MagicMock, patch

import paramiko

from src.services import ssh_service


class TestConnect:
    @patch("src.services.ssh_service.paramiko")
    def test_reject_policy_and_known_host_are_required(self, paramiko: MagicMock) -> None:
        parsed_key = MagicMock()
        paramiko.Ed25519Key.from_private_key.return_value = parsed_key
        entry = MagicMock()
        entry.hostnames = ["db01.internal.example.com"]
        entry.key.get_name.return_value = "ssh-ed25519"
        paramiko.hostkeys.HostKeyEntry.from_line.return_value = entry
        client = paramiko.SSHClient.return_value

        result = ssh_service.connect(
            "db01.internal.example.com",
            "private-key",
            "db01.internal.example.com ssh-ed25519 AAAAfixture",
        )

        client.get_host_keys.return_value.add.assert_called_once()
        client.set_missing_host_key_policy.assert_called_once_with(paramiko.RejectPolicy.return_value)
        assert client.connect.call_args.kwargs["pkey"] is parsed_key
        assert not paramiko.AutoAddPolicy.called
        assert result is client

    @patch("src.services.ssh_service.paramiko")
    def test_empty_known_hosts_fails_closed(self, paramiko: MagicMock) -> None:
        paramiko.Ed25519Key.from_private_key.return_value = MagicMock()
        client = paramiko.SSHClient.return_value
        try:
            ssh_service.connect("host", "private", "\n# only a comment")
        except ValueError as exc:
            assert "no usable host keys" in str(exc)
        else:
            raise AssertionError("empty known_hosts must fail")
        client.connect.assert_not_called()

    @patch("src.services.ssh_service.paramiko.RSAKey.from_private_key")
    @patch("src.services.ssh_service.paramiko.ECDSAKey.from_private_key")
    @patch("src.services.ssh_service.paramiko.Ed25519Key.from_private_key")
    def test_private_key_parser_falls_back_to_rsa(self, ed25519: MagicMock, ecdsa: MagicMock, rsa: MagicMock) -> None:
        ed25519.side_effect = paramiko.SSHException
        ecdsa.side_effect = paramiko.SSHException
        rsa_key = MagicMock()
        rsa.return_value = rsa_key

        assert ssh_service._parse_private_key("rsa-key") is rsa_key


class TestExecute:
    def _client(self, stdout_data: bytes, stderr_data: bytes = b"") -> MagicMock:
        stdout = MagicMock()
        stdout.read.return_value = stdout_data
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock()
        stderr.read.return_value = stderr_data
        client = MagicMock()
        client.exec_command.return_value = (MagicMock(), stdout, stderr)
        return client

    def test_timeout_and_output_are_bounded(self) -> None:
        client = self._client(b"0123456789")
        _code, stdout, _stderr = ssh_service.execute(client, "uptime", timeout_sec=999, max_output_bytes=4)
        assert stdout == "0123\n[OUTPUT TRUNCATED]"
        assert client.exec_command.call_args.kwargs["timeout"] == ssh_service.HARD_TIMEOUT_CEILING_SEC
        streams = client.exec_command.return_value
        streams[1].read.assert_called_once_with(5)


def test_close_suppresses_cleanup_error() -> None:
    client = MagicMock()
    client.close.side_effect = OSError("closed")
    ssh_service.close(client)
