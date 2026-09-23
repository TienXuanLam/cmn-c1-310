from unittest.mock import MagicMock, patch

import pytest
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from framework.secrets.context import bound_secrets
from shared.secrets.inmemory_provider import InMemoryProvider

from src.graph.graph import Graph

# db01.internal.example.com resolves to a public-looking address so the SSRF
# guard in PreProcessNode (src/nodes/pre_process_node.py::_is_blocked_target)
# lets it through -- this test is exercising the allowlist/pipeline, not DNS.
_FAKE_DNS = {"db01.internal.example.com": "93.184.216.34"}


@pytest.fixture(autouse=True)
def _fake_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, *_args: object, **_kwargs: object) -> list[tuple]:
        import socket as _socket

        if host in _FAKE_DNS:
            return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", (_FAKE_DNS[host], 0))]
        raise OSError(f"[Errno 8] nodename nor servname provided, or not known: {host!r}")

    monkeypatch.setattr("src.nodes.pre_process_node.socket.getaddrinfo", fake_getaddrinfo)


class MockBackend:
    def connect(self, *_args: object, **_kwargs: object) -> object:
        return object()

    def execute(self, _client: object, _command: str, **_kwargs: object) -> tuple[int, str, str]:
        return 0, "up 5 days\n", ""

    def close(self, _client: object) -> None:
        return None


def _agent() -> Graph:
    graph = Graph(
        config={
            "max_retry": 2,
            "command_allowlist": ["uptime"],
            "ssh_backend": MockBackend(),
        }
    )
    graph.compile()
    return graph


def _mock_extraction_llm(host: str, command: str) -> MagicMock:
    instance = MagicMock()
    instance.complete.return_value = {"content": f'{{"host":"{host}","command":"{command}"}}'}
    return instance


def _invoke(user_input: str, extraction_host: str, extraction_command: str) -> dict:
    context = InvocationContext(caller_trust_level=TrustLevel.VERIFIED_EXTERNAL)
    provider = InMemoryProvider(
        {
            # PreProcessNode needs these to construct its (mocked) extraction
            # client -- the mock intercepts AzureOpenAIClient itself, so these
            # values are never sent anywhere, only used to pass ctx.secrets
            # .require(). PostProcessNode uses the same secrets for its own
            # summarization client, which is NOT mocked here, so its real
            # AzureOpenAIClient construction succeeds but the actual network
            # call against this fake endpoint fails -- PostProcessNode
            # degrades to its raw-Markdown fallback (asserted below).
            "AZURE_OPENAI_API_KEY": "test-key",
            "AZURE_OPENAI_ENDPOINT": "https://test.services.ai.azure.com",
            "AZURE_OPENAI_DEPLOYMENT": "test-deployment",
        }
    )
    mock_llm = _mock_extraction_llm(extraction_host, extraction_command)
    with (
        patch("src.nodes.pre_process_node.AzureOpenAIClient", return_value=mock_llm),
        bound_secrets(provider),
    ):
        # SSH_PRIVATE_KEY / SSH_KNOWN_HOSTS are caller-supplied per request,
        # not deployment secrets -- see MainNode's module docstring.
        return _agent().invoke(
            user_input,
            input_context={"ssh_private_key": "private", "ssh_known_hosts": "known"},
            ctx=context,
        )


def test_allowed_command_returns_sanitized_result() -> None:
    # PreProcessNode's LLM extraction is mocked (see _mock_extraction_llm);
    # PostProcessNode has no Azure OpenAI secrets bound, so it falls back to
    # its deterministic raw-Markdown render (status stays SUCCESS — a
    # controlled degrade, not a pipeline error).
    output = _invoke("run uptime on db01.internal.example.com", "db01.internal.example.com", "uptime")
    assert output["status"] == "success"
    result = output["output"]
    assert isinstance(result, str)
    assert "**Exit code:** 0" in result
    assert "up 5 days" in result


def test_allowlist_rejection_returns_structured_error() -> None:
    output = _invoke("run uptime on evil.example.com", "evil.example.com", "uptime")
    assert output["status"] == "error"
    result = output["output"]
    assert isinstance(result, str)
    assert "HOST_NOT_ALLOWED" in result
