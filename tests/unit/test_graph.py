# CMN-C1-310 — Unit Tests: Graph (graph composition)
#
# Verifies that Graph correctly wires all 5 pipeline slots and propagates
# config (command_allowlist) into CustomInitializeNode. There is no
# host_allowlist any more -- host targeting is caller-supplied per request
# and guarded by an SSRF blocklist in PreProcessNode, not by config loaded
# here. See docs/02_design.md "Dynamic SSH target".

from src.graph.graph import Graph
from src.nodes.initialize_node import CustomInitializeNode
from src.nodes.main_node import MainNode
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.schemas.state import SSHCommandAgentState


class TestGraphIdentity:
    def test_name_is_canonical_agent_identifier(self):
        assert Graph().name == "cmn_c1_ssh_command_agent"

    def test_state_schema_is_ssh_command_agent_state(self):
        assert Graph().state_schema is SSHCommandAgentState


class TestGraphSlotComposition:
    """After register_nodes(), all 5 pipeline slots must be filled with the
    correct node types per docs/02_design.md slot composition mapping."""

    def setup_method(self):
        self.graph = Graph(config={
            "command_allowlist": ["uptime"],
        })
        self.graph.register_nodes()

    def test_initialize_slot_is_custom_initialize_node(self):
        assert isinstance(self.graph._nodes["initialize"], CustomInitializeNode)

    def test_pre_process_slot_is_pre_process_node(self):
        assert isinstance(self.graph._nodes["pre_process"], PreProcessNode)

    def test_main_slot_is_main_node(self):
        assert isinstance(self.graph._nodes["main"], MainNode)

    def test_post_process_slot_is_post_process_node(self):
        assert isinstance(self.graph._nodes["post_process"], PostProcessNode)

    def test_all_three_domain_slots_are_non_none(self):
        for slot in ("pre_process", "main", "post_process"):
            assert self.graph._nodes[slot] is not None, f"slot '{slot}' must not be None"


class TestGraphConfigPropagation:
    """Config values from Graph(config=...) must be injected into
    CustomInitializeNode at register_nodes() time."""

    def test_command_allowlist_propagated_to_initialize_node(self):
        graph = Graph(config={
            "command_allowlist": ["uptime", "df -h"],
        })
        graph.register_nodes()

        init_node: CustomInitializeNode = graph._nodes["initialize"]
        assert init_node._command_allowlist == ["uptime", "df -h"]

    def test_timeout_seconds_propagated_to_initialize_node(self):
        graph = Graph(config={
            "command_allowlist": [],
            "timeout_seconds": 45,
        })
        graph.register_nodes()

        init_node: CustomInitializeNode = graph._nodes["initialize"]
        assert init_node._timeout_seconds == 45

    def test_empty_config_propagates_empty_command_allowlist(self):
        graph = Graph(config={})
        graph.register_nodes()

        init_node: CustomInitializeNode = graph._nodes["initialize"]
        assert init_node._command_allowlist == []

    def test_no_config_uses_default_timeout(self):
        graph = Graph()
        graph.register_nodes()

        init_node: CustomInitializeNode = graph._nodes["initialize"]
        assert init_node._command_allowlist == []
        assert init_node._timeout_seconds == 10  # service default

    def test_no_host_allowlist_attribute_exists(self):
        """CustomInitializeNode must not accept or expose host_allowlist at
        all -- host targeting is caller-supplied per request, guarded by the
        SSRF blocklist in PreProcessNode, not by a config-loaded allowlist."""
        graph = Graph(config={"command_allowlist": []})
        graph.register_nodes()

        init_node: CustomInitializeNode = graph._nodes["initialize"]
        assert not hasattr(init_node, "_host_allowlist")


class TestGraphCompiles:
    """Graph.compile() must succeed and produce a compiled state graph."""

    def test_compile_succeeds_with_valid_config(self):
        graph = Graph(config={
            "command_allowlist": ["uptime"],
        })
        graph.compile()

        assert graph._compiled is not None
