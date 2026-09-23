"""Standalone FastAPI adapter for CMN-C1-310."""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from langgraph.checkpoint.memory import MemorySaver
from pydantic import BaseModel, Field

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from framework.secrets.context import bound_secrets
from framework.utils.config_loader import load_config
from shared.secrets import factory as secrets_factory
from shared.secrets.inmemory_provider import InMemoryProvider

from src.graph.graph import Graph


class _MockSSHBackend:
    """No-network backend enabled only by explicit Stage 5 mock mode."""

    def connect(
        self, _host: str, _private_key: str, _known_hosts: str, username: str = "agentcore", timeout_sec: int = 10
    ) -> object:
        return object()

    def execute(
        self, _client: object, command: str, timeout_sec: int = 10, max_output_bytes: int = 262_144
    ) -> tuple[int, str, str]:
        return 0, f"mock execution succeeded: {command}\n", ""

    def close(self, _client: object) -> None:
        return None


_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_PATH = _ROOT / "config" / "config.yaml"
_config = cast(dict[str, Any], load_config(str(_CONFIG_PATH)) if _CONFIG_PATH.exists() else {})
_mock_mode = os.environ.get("STG_MOCK_MODE", "").lower() == "true"

if _mock_mode:
    _config["ssh_backend"] = _MockSSHBackend()

# SSH_PRIVATE_KEY / SSH_KNOWN_HOSTS are no longer deployment secrets -- callers
# supply them per request (see InvokeRequest below), so there is nothing to
# provision ahead of time and no readiness gate on them. Azure OpenAI
# credentials remain deployment secrets, resolved the normal way.
#
# Standalone Podman/Docker runs inject secrets through process environment,
# while the configured provider covers platform-managed execution. Merge both
# channels into the invocation-scoped provider without exposing secret values
# to state or telemetry -- PreProcessNode/PostProcessNode resolve them through
# InvocationContext.
_configured_secrets_provider = secrets_factory(namespace="cmn", agent_name="cmn-c1-310")
_azure_secret_keys = (
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_DEPLOYMENT",
)
_secrets_provider = InMemoryProvider(
    {
        key: value
        for key in _azure_secret_keys
        if (value := os.environ.get(key) or _configured_secrets_provider.get(key)) is not None
    },
    namespace="cmn",
    agent_name="cmn-c1-310",
)
_runtime_ready = True

agent = Graph(config=_config)
hitl = agent.config.get("hitl", {})
hitl_enabled = bool(hitl.get("enabled", False)) if isinstance(hitl, dict) else False
agent.compile(checkpointer=MemorySaver() if agent.config.get("memory_enabled") or hitl_enabled else None)
agent.provision_secrets(_secrets_provider)

app = FastAPI(title="CMN-C1-310 SSH Command Agent")


class InvokeRequest(BaseModel):
    # `input` is a plain-English request naming the host and command (e.g.
    # "run uptime on db01.internal.example.com") -- the primary,
    # Marketplace-chat-friendly field. `input_context` carries everything
    # else: `timeout_sec` and the caller-supplied SSH credentials for the
    # target environment named in `input`. Deliberate exception to "secrets
    # never ride in state" -- see docs/02_design.md "Dynamic SSH target".
    # Never logged: only forwarded into input_context, never echoed back in
    # a response.
    input: str
    session_id: str = ""
    input_context: dict[str, Any] = Field(default_factory=dict)


def _bearer_matches(supplied: str, expected: str) -> bool:
    return secrets.compare_digest(supplied.encode(), f"Bearer {expected}".encode())


def _resolve_standalone_trust(
    current: TrustLevel,
    authorization: str,
    invoke_auth_token: str | None,
    internal_runner_token: str | None,
) -> TrustLevel:
    if current is not TrustLevel.ANONYMOUS:
        return current
    if internal_runner_token and _bearer_matches(authorization, internal_runner_token):
        return TrustLevel.INTERNAL
    if invoke_auth_token and _bearer_matches(authorization, invoke_auth_token):
        return TrustLevel.VERIFIED_EXTERNAL
    if internal_runner_token or invoke_auth_token:
        raise HTTPException(status_code=401, detail="Token is invalid or expired.")
    return TrustLevel.ANONYMOUS


@app.post("/invoke")
async def invoke(req: InvokeRequest, request: Request) -> dict[str, Any]:
    if not _runtime_ready:
        raise HTTPException(status_code=503, detail="SSH secrets are not configured.")
    trust = _resolve_standalone_trust(
        getattr(request.state, "trust_level", TrustLevel.ANONYMOUS),
        request.headers.get("authorization", ""),
        os.environ.get("INVOKE_AUTH_TOKEN"),
        os.environ.get("STG_INTERNAL_RUNNER_TOKEN"),
    )
    ctx = InvocationContext(
        session_id=req.session_id or str(uuid4()),
        caller_trust_level=trust,
        caller_id=getattr(request.state, "caller_id", ""),
    )
    with bound_secrets(agent._secrets_provider):
        input_context = dict(req.input_context)
        input_context.setdefault("timeout_sec", 10)
        return cast(
            dict[str, Any],
            agent.invoke(
                req.input,
                input_context=input_context,
                ctx=ctx,
            ),
        )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok" if _runtime_ready else "not_ready", "agent": agent.name}
