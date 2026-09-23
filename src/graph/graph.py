"""CMN-C1-310 Cat 1 fixed-pipeline graph."""

from typing import Any, cast

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.nodes.defaults.initialize_node import InitializeNode
from framework.schemas.trust_level import TrustLevel

from src.nodes.main_node import MainNode
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.schemas.state import SSHCommandAgentState
from src.services.ssh_service import SSHBackend


class CustomInitializeNode(InitializeNode):
    def __init__(
        self,
        command_allowlist: list[str] | None = None,
        timeout_seconds: int = 10,
        max_output_bytes: int = 262_144,
        ssh_username: str = "agentcore",
    ) -> None:
        super().__init__()
        self._command_allowlist = list(command_allowlist or [])
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes
        self._ssh_username = ssh_username

    def on_initialize(self, _state: dict[str, Any]) -> dict[str, Any]:
        return {
            "command_allowlist": self._command_allowlist,
            "timeout_seconds": self._timeout_seconds,
            "max_output_bytes": self._max_output_bytes,
            "ssh_username": self._ssh_username,
        }


class Graph(AgentBaseGraph):
    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    @property
    def name(self) -> str:
        return "cmn_c1_ssh_command_agent"

    @property
    def state_schema(self) -> type[SSHCommandAgentState]:
        return SSHCommandAgentState

    def register_nodes(self) -> None:
        super().register_nodes()
        self._nodes["initialize"] = CustomInitializeNode(
            command_allowlist=cast(list[str], self.config.get("command_allowlist", [])),
            timeout_seconds=int(self.config.get("timeout_seconds", 10)),
            max_output_bytes=int(self.config.get("max_output_bytes", 262_144)),
            ssh_username=str(self.config.get("ssh_username", "agentcore")),
        )
        pre_llm_config = cast(dict[str, Any], self.config.get("pre_process_llm", {}))
        self._nodes["pre_process"] = PreProcessNode(
            llm_enabled=bool(pre_llm_config.get("enabled", True)),
            llm_timeout_s=int(pre_llm_config.get("timeout_s", 10)),
            llm_max_retries=int(pre_llm_config.get("max_retries", 1)),
            llm_max_extract_tokens=int(pre_llm_config.get("max_extract_tokens", 64)),
        )
        self._nodes["main"] = MainNode(backend=cast(SSHBackend | None, self.config.get("ssh_backend")))
        llm_config = cast(dict[str, Any], self.config.get("llm", {}))
        self._nodes["post_process"] = PostProcessNode(
            llm_enabled=bool(llm_config.get("enabled", True)),
            llm_timeout_s=int(llm_config.get("timeout_s", 20)),
            llm_max_retries=int(llm_config.get("max_retries", 1)),
            llm_max_summary_tokens=int(llm_config.get("max_summary_tokens", 512)),
        )
