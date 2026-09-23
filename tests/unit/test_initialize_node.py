# CMN-C1-310 — Unit Tests: CustomInitializeNode
#
# CustomInitializeNode no longer accepts or emits host_allowlist -- host
# targeting is caller-supplied per request and guarded by the SSRF blocklist
# in PreProcessNode, not loaded from config here. See docs/02_design.md
# "Dynamic SSH target".

from src.nodes.initialize_node import CustomInitializeNode


def _base_state(**overrides) -> dict:
    state = {
        "input_context": {},
        "correlation_id": "test-corr",
        "session_id": "test-session",
        "thread_id": "test-thread",
        "trace_id": "",
        "caller_trust_level": "ANONYMOUS",
        "caller_id": "",
        "hitl_allowed": True,
    }
    state.update(overrides)
    return state


class TestCustomInitializeNode:
    def test_on_initialize_loads_command_allowlist_from_config(self):
        node = CustomInitializeNode(
            command_allowlist=["uptime"],
            timeout_seconds=30,
        )

        result = node.execute(_base_state())

        assert result["command_allowlist"] == ["uptime"]

    def test_on_initialize_loads_timeout_seconds_from_config(self):
        node = CustomInitializeNode(
            command_allowlist=[],
            timeout_seconds=45,
        )

        result = node.execute(_base_state())

        assert result["timeout_seconds"] == 45

    def test_empty_config_yields_empty_command_allowlist(self):
        node = CustomInitializeNode(command_allowlist=[], timeout_seconds=10)

        result = node.execute(_base_state())

        assert result["command_allowlist"] == []

    def test_preserves_default_initialize_behavior(self):
        """on_initialize() must not clobber InitializeNode._setup() output
        (schema_version, caller_trust_level, etc.)."""
        node = CustomInitializeNode(command_allowlist=["c"], timeout_seconds=10)

        result = node.execute(_base_state(caller_trust_level="VERIFIED_EXTERNAL"))

        assert result["caller_trust_level"] == "VERIFIED_EXTERNAL"
        assert "schema_version" in result

    def test_does_not_accept_host_allowlist_kwarg(self):
        """host_allowlist is not a constructor parameter any more -- passing
        it must fail rather than be silently accepted and ignored."""
        try:
            CustomInitializeNode(host_allowlist=["h"], command_allowlist=["c"], timeout_seconds=10)  # type: ignore[call-arg]
        except TypeError:
            pass
        else:
            raise AssertionError("CustomInitializeNode unexpectedly accepted host_allowlist")

    def test_no_host_allowlist_key_in_output(self):
        node = CustomInitializeNode(command_allowlist=["c"], timeout_seconds=10)

        result = node.execute(_base_state())

        assert "host_allowlist" not in result
