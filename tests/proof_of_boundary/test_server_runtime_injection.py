"""Standalone adapter trust mapping and explicit Stage 5 backend injection."""

import importlib
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from framework.schemas.trust_level import TrustLevel

_AZURE_SECRETS = {
    "AZURE_OPENAI_API_KEY": "dummy-test-key",
    "AZURE_OPENAI_ENDPOINT": "https://example.services.ai.azure.com",
    "AZURE_OPENAI_DEPLOYMENT": "test-deployment",
}


def test_stage5_mock_mode_injects_no_network_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STG_MOCK_MODE", "true")
    import src.api.server as server

    importlib.reload(server)
    assert server._runtime_ready is True
    assert server._config["ssh_backend"].__class__.__name__ == "_MockSSHBackend"


def test_external_token_never_promotes_to_internal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STG_MOCK_MODE", "true")
    import src.api.server as server

    importlib.reload(server)
    trust = server._resolve_standalone_trust(
        TrustLevel.ANONYMOUS,
        "Bearer external",
        "external",
        "runner",
    )
    assert trust is TrustLevel.VERIFIED_EXTERNAL


def test_runner_token_maps_to_internal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STG_MOCK_MODE", "true")
    import src.api.server as server

    importlib.reload(server)
    trust = server._resolve_standalone_trust(
        TrustLevel.ANONYMOUS,
        "Bearer runner",
        "external",
        "runner",
    )
    assert trust is TrustLevel.INTERNAL


def test_invalid_configured_token_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STG_MOCK_MODE", "true")
    import src.api.server as server

    importlib.reload(server)
    with pytest.raises(HTTPException) as exc:
        server._resolve_standalone_trust(
            TrustLevel.ANONYMOUS,
            "Bearer wrong",
            "external",
            "runner",
        )
    assert exc.value.status_code == 401


class TestServerProvisionsInvocationSecrets:
    """server.py's InMemoryProvider construction must merge os.environ with
    the configured provider (namespace="cmn", agent_name="cmn-c1-310"),
    preferring os.environ -- this is what makes `podman/docker run -e
    AZURE_OPENAI_...` work when testing a built image locally, matching the
    fleet-standard pattern used elsewhere in the fleet's server.py files."""

    def test_configured_provider_reaches_standalone_secret_provider(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from shared.secrets.inmemory_provider import InMemoryProvider

        # A real Azure credential left in the test-runner's own environment
        # would otherwise silently win over this test's mock provider and
        # falsify the assertion below without indicating a real code bug.
        for key in _AZURE_SECRETS:
            monkeypatch.delenv(key, raising=False)

        monkeypatch.setattr(
            "shared.secrets.factory",
            lambda namespace, agent_name: InMemoryProvider(_AZURE_SECRETS),
        )

        import src.api.server as server

        importlib.reload(server)

        assert {key: server._secrets_provider.require(key) for key in _AZURE_SECRETS} == _AZURE_SECRETS

    def test_process_environment_reaches_standalone_secret_provider(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key, value in _AZURE_SECRETS.items():
            monkeypatch.setenv(key, value)

        import src.api.server as server

        importlib.reload(server)

        assert {key: server._secrets_provider.require(key) for key in _AZURE_SECRETS} == _AZURE_SECRETS


class TestPlainTextInputContract:
    """input is plain text; ssh_private_key/ssh_known_hosts/timeout_sec ride
    in the optional input_context dict, not as flat top-level fields."""

    def test_request_accepts_input_context_dict(self) -> None:
        from src.api.server import InvokeRequest

        request = InvokeRequest(
            input="run uptime on db01.internal.example.com",
            session_id="plain-text-001",
            input_context={
                "ssh_private_key": "fake-key",
                "ssh_known_hosts": "fake-known-hosts",
                "timeout_sec": 5,
            },
        )

        assert request.input == "run uptime on db01.internal.example.com"
        assert request.input_context["ssh_private_key"] == "fake-key"
        assert request.input_context["timeout_sec"] == 5

    def test_input_context_defaults_to_empty_dict(self) -> None:
        from src.api.server import InvokeRequest

        request = InvokeRequest(input="run uptime on db01.internal.example.com")

        assert request.input_context == {}

    def test_legacy_top_level_ssh_fields_are_ignored_not_forwarded(self) -> None:
        # Pydantic's default extra="ignore" silently drops unknown top-level
        # fields rather than raising -- confirms the old flat schema no
        # longer has any effect if a stale caller still sends it this way.
        from src.api.server import InvokeRequest

        request = InvokeRequest(
            input="run uptime on db01.internal.example.com",
            ssh_private_key="should-be-ignored",
        )

        assert not hasattr(request, "ssh_private_key")
        assert request.input_context == {}


class TestInvokeEndpointForwardsInputContext:
    """End-to-end /invoke over HTTP: input_context.ssh_private_key/
    ssh_known_hosts must reach MainNode exactly as the flat top-level fields
    used to. PreProcessNode's extraction LLM is mocked (same pattern as
    tests/integration/test_graph_smoke.py) so this runs without real Azure
    OpenAI secrets; PostProcessNode has no Azure secrets bound either, so it
    degrades to its deterministic raw-Markdown fallback -- status stays
    "success", a controlled degrade, not a pipeline error."""

    def test_invoke_with_input_context_reaches_main_node(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STG_MOCK_MODE", "true")
        monkeypatch.setenv("INVOKE_AUTH_TOKEN", "test-token")
        for key, value in _AZURE_SECRETS.items():
            monkeypatch.setenv(key, value)

        import src.api.server as server

        importlib.reload(server)

        mock_llm = MagicMock()
        mock_llm.complete.return_value = {"content": '{"host":"db01.internal.example.com","command":"uptime"}'}

        def fake_getaddrinfo(host: str, *_args: object, **_kwargs: object) -> list[tuple]:
            import socket as _socket

            if host == "db01.internal.example.com":
                return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
            raise OSError(f"[Errno 8] nodename nor servname provided, or not known: {host!r}")

        from fastapi.testclient import TestClient

        with (
            patch("src.nodes.pre_process_node.AzureOpenAIClient", return_value=mock_llm),
            patch("src.nodes.pre_process_node.socket.getaddrinfo", fake_getaddrinfo),
        ):
            client = TestClient(server.app)
            response = client.post(
                "/invoke",
                headers={"Authorization": "Bearer test-token"},
                json={
                    "input": "run uptime on db01.internal.example.com",
                    "session_id": "http-e2e-001",
                    "input_context": {
                        "ssh_private_key": "fake-key",
                        "ssh_known_hosts": "fake-known-hosts",
                    },
                },
            )

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "success"
        assert "mock execution succeeded: uptime" in body["output"]

    def test_invoke_missing_ssh_credentials_hard_rejects(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STG_MOCK_MODE", "true")
        monkeypatch.setenv("INVOKE_AUTH_TOKEN", "test-token")
        for key, value in _AZURE_SECRETS.items():
            monkeypatch.setenv(key, value)

        import src.api.server as server

        importlib.reload(server)

        mock_llm = MagicMock()
        mock_llm.complete.return_value = {"content": '{"host":"db01.internal.example.com","command":"uptime"}'}

        def fake_getaddrinfo(host: str, *_args: object, **_kwargs: object) -> list[tuple]:
            import socket as _socket

            return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

        from fastapi.testclient import TestClient

        with (
            patch("src.nodes.pre_process_node.AzureOpenAIClient", return_value=mock_llm),
            patch("src.nodes.pre_process_node.socket.getaddrinfo", fake_getaddrinfo),
        ):
            client = TestClient(server.app)
            response = client.post(
                "/invoke",
                headers={"Authorization": "Bearer test-token"},
                json={"input": "run uptime on db01.internal.example.com", "session_id": "http-e2e-002"},
            )

        assert response.status_code == 200
        body = response.json()
        # MainNode._failure returns AgentStatus.SUCCESS (a structured error
        # envelope, not a pipeline failure) -- but the top-level status here
        # reflects whatever downstream gate/finalize step maps it to; the
        # important, stable assertion is that SSH_SECRET_MISSING appears
        # somewhere in the response so the caller can see why the request
        # was rejected.
        assert "SSH_SECRET_MISSING" in str(body)
