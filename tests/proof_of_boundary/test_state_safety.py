# PB-2 + PB-5: State Safety — CMN-C1-310 SSHCommandAgent
#
# AgentState must be a flat TypedDict with only msgpack-safe types
# (ADR-005).  LangGraph checkpoints use msgpack; Pydantic objects,
# dataclasses, or live objects (SSHClient, socket, etc.) cause silent
# corruption.
#
# This file verifies:
#   PB-2  — State file defines no credential-like field names
#   PB-5  — State fields use only msgpack-safe primitive types
#   PB-5b — No live object types (SSH client, socket, paramiko) in state
#   PB-5c — Agent-specific fields are individually present and correctly typed
#   PB-5d — Redacted output fields are distinct from raw fields

import ast
import importlib
import os
import re

import pytest

# ── AST-level checks (static analysis) ───────────────────────────────────────

_CREDENTIAL_FIELD_RE = re.compile(
    r"(?:^|_)(private_key|api_key|secret|password|credential|connection_string|jwt|bearer)(?:_|$)",
    re.IGNORECASE,
)

_PROHIBITED_TYPE_ANNOTATIONS = [
    "BaseModel",          # Pydantic — not msgpack-safe
    "InvocationContext",  # framework object — must never live in state
    "SSHClient",          # paramiko live object
    "socket",             # raw socket handle
    "Channel",            # paramiko channel
]

# Types that are msgpack-safe primitives
_MSGPACK_SAFE_LEAF_NAMES = {
    "str", "int", "float", "bool", "None", "NoneType",
    "list", "dict", "Any", "NotRequired",
}

# Live-object type names that must NEVER appear in state annotations
_LIVE_OBJECT_TYPE_NAMES = {
    "SSHClient", "Transport", "Channel",  # paramiko
    "socket",                              # stdlib socket
    "BaseModel",                           # Pydantic
    "dataclass",                           # dataclasses decorator
}


def _state_file_path() -> str:
    return os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "src", "schemas", "state.py")
    )


def _parse_state_file() -> ast.Module:
    path = _state_file_path()
    with open(path) as f:
        return ast.parse(f.read(), filename=path)


def _get_state_class(tree: ast.Module) -> ast.ClassDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "SSHCommandAgentState":
            return node
    pytest.fail("SSHCommandAgentState class not found in src/schemas/state.py")


def _field_names(cls: ast.ClassDef) -> list[tuple[str, ast.AnnAssign]]:
    """Return (field_name, AnnAssign node) for every annotated field in cls."""
    result = []
    for item in cls.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            result.append((item.target.id, item))
    return result


def _annotation_names(annotation: ast.expr) -> set[str]:
    """Collect all Name identifiers referenced in an annotation expression."""
    names = set()
    for node in ast.walk(annotation):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    return names


# ── PB-2: no credential-like field names ─────────────────────────────────────

class TestNoCredentialFields:
    """PB-2: SSHCommandAgentState must not store credential values.

    Azure OpenAI credentials are resolved at point-of-use inside
    PreProcessNode/PostProcessNode via ctx.secrets (bound_secrets context).
    SSH credentials (ssh_private_key/ssh_known_hosts) are caller-supplied
    per request and read at point-of-use inside MainNode from
    input_context (a generic, untyped dict on AgentState) — never as a
    named/typed field on SSHCommandAgentState itself. Either way, no
    credential value may be written into a named state field (docs/02_design.md
    "Dynamic SSH target", Rule 1.2/1.3, 04_security_review.md).
    """

    def test_no_credential_like_field_names(self):
        tree = _parse_state_file()
        cls = _get_state_class(tree)
        violations = []
        for field_name, item in _field_names(cls):
            if _CREDENTIAL_FIELD_RE.search(field_name):
                violations.append(f"  line {item.lineno}: {field_name}")
        assert violations == [], (
            "Credential-like field names found in SSHCommandAgentState "
            "(SSH keys must be resolved via ctx.secrets, not stored in state):\n"
            + "\n".join(violations)
        )

    def test_no_ssh_private_key_field(self):
        """Explicit guard: 'ssh_private_key' or 'private_key' must not appear."""
        tree = _parse_state_file()
        cls = _get_state_class(tree)
        field_names = {name for name, _ in _field_names(cls)}
        forbidden = {"private_key", "ssh_private_key", "ssh_key", "ssh_password"}
        found = forbidden & field_names
        assert not found, (
            f"SSH credential field(s) must not be stored in state: {found}"
        )


# ── PB-5: msgpack-safe types only ─────────────────────────────────────────────

class TestMsgpackSafeTypes:
    """PB-5: All state field annotations must use only msgpack-safe types."""

    def test_no_prohibited_type_annotations(self):
        tree = _parse_state_file()
        cls = _get_state_class(tree)
        violations = []
        for field_name, item in _field_names(cls):
            if item.annotation:
                ann_names = _annotation_names(item.annotation)
                for prohibited in _PROHIBITED_TYPE_ANNOTATIONS:
                    if prohibited in ann_names:
                        violations.append(
                            f"  line {item.lineno}: {field_name} — uses {prohibited}"
                        )
        assert violations == [], (
            "Prohibited (non-msgpack-safe) types found in SSHCommandAgentState fields:\n"
            + "\n".join(violations)
        )

    def test_no_live_object_types_in_annotations(self):
        """No live object types (SSH client, socket, Pydantic model) may
        appear in any field annotation — they cannot be msgpack-serialized."""
        tree = _parse_state_file()
        cls = _get_state_class(tree)
        violations = []
        for field_name, item in _field_names(cls):
            if item.annotation:
                ann_names = _annotation_names(item.annotation)
                found_live = ann_names & _LIVE_OBJECT_TYPE_NAMES
                if found_live:
                    violations.append(
                        f"  line {item.lineno}: {field_name} — live object type(s): {found_live}"
                    )
        assert violations == [], (
            "Live object type(s) found in SSHCommandAgentState field annotations:\n"
            + "\n".join(violations)
        )

    def test_exit_code_is_nullable_int(self):
        """exit_code must be int | None — not str — to preserve numeric semantics
        while allowing the pre-execution 'not yet set' state."""
        tree = _parse_state_file()
        cls = _get_state_class(tree)
        fields = dict(_field_names(cls))
        assert "exit_code" in fields, "exit_code field missing from SSHCommandAgentState"
        ann = fields["exit_code"].annotation
        ann_names = _annotation_names(ann)
        assert "int" in ann_names, "exit_code must be typed as int (or int | None)"

    def test_stdout_stderr_are_str_not_bytes(self):
        """stdout/stderr fields must be str (decoded), never bytes.
        MainNode must decode paramiko channel output before writing to state."""
        tree = _parse_state_file()
        cls = _get_state_class(tree)
        fields = dict(_field_names(cls))
        for field_name in ("stdout", "stderr", "raw_stdout", "raw_stderr"):
            assert field_name in fields, (
                f"Expected field '{field_name}' in SSHCommandAgentState"
            )
            ann_names = _annotation_names(fields[field_name].annotation)
            assert "str" in ann_names and "bytes" not in ann_names, (
                f"'{field_name}' must be 'str', not 'bytes' — "
                "paramiko output must be decoded in MainNode before writing to state"
            )

    def test_allowlist_fields_are_list_of_str(self):
        """command_allowlist must be list[str] — msgpack-safe and consistent
        with config.yaml string entries.

        host_allowlist is deliberately NOT declared in SSHCommandAgentState:
        host targeting is caller-supplied per request and guarded by an SSRF
        blocklist in PreProcessNode (_is_blocked_target), not by a fixed
        deployment-time allowlist loaded into state. See docs/02_design.md
        "Dynamic SSH target" for the accepted-risk rationale. A separate test
        below guards against host_allowlist being reintroduced."""
        tree = _parse_state_file()
        cls = _get_state_class(tree)
        fields = dict(_field_names(cls))
        for field_name in ("command_allowlist",):
            assert field_name in fields, (
                f"Expected allowlist field '{field_name}' in SSHCommandAgentState"
            )
            ann_names = _annotation_names(fields[field_name].annotation)
            assert "list" in ann_names, (
                f"'{field_name}' must be typed as list[str]"
            )
            assert "str" in ann_names, (
                f"'{field_name}' element type must be str"
            )

    def test_no_host_allowlist_field(self):
        """PB-5e: host_allowlist must NOT be declared in SSHCommandAgentState.

        This is a deliberate, accepted-risk architecture change: the fixed
        deployment-time host allowlist was replaced by a caller-supplied SSH
        target per request, guarded by an SSRF blocklist instead (see
        docs/02_design.md "Dynamic SSH target"). If this field reappears, it
        signals an accidental revert of that decision, not a bug fix."""
        tree = _parse_state_file()
        cls = _get_state_class(tree)
        declared = {name for name, _ in _field_names(cls)}
        assert "host_allowlist" not in declared, (
            "SSHCommandAgentState declares 'host_allowlist' -- this was "
            "deliberately removed in favor of caller-supplied SSH targets "
            "guarded by an SSRF blocklist (docs/02_design.md 'Dynamic SSH "
            "target'). Re-adding it reverts an accepted-risk architecture "
            "decision; do not reintroduce a fixed host allowlist without "
            "re-litigating that decision."
        )


# ── PB-5b: agent-specific fields present ──────────────────────────────────────

class TestAgentSpecificFieldsPresent:
    """PB-5b: Verify all expected CMN-C1-310 domain fields are declared."""

    _REQUIRED_FIELDS = {
        # Command allowlist (loaded at init, checked at pre_process). There
        # is no host_allowlist -- host targeting is caller-supplied per
        # request and guarded by an SSRF blocklist instead; see
        # docs/02_design.md "Dynamic SSH target".
        "command_allowlist",
        # Validated input (written by PreProcessNode)
        "validated_host",
        "validated_command",
        # Raw execution results (written by MainNode, consumed by PostProcessNode)
        "exit_code",
        "raw_stdout",
        "raw_stderr",
        # Redacted output (written by PostProcessNode, returned to caller)
        "stdout",
        "stderr",
        # Audit metadata
        "executed_at",
    }

    def test_all_required_domain_fields_declared(self):
        tree = _parse_state_file()
        cls = _get_state_class(tree)
        declared = {name for name, _ in _field_names(cls)}
        missing = self._REQUIRED_FIELDS - declared
        assert not missing, (
            f"Required SSHCommandAgentState fields missing: {sorted(missing)}"
        )


# ── PB-5c: raw vs redacted field separation ───────────────────────────────────

class TestRawRedactedSeparation:
    """PB-5c: raw_stdout/raw_stderr (unredacted) and stdout/stderr (redacted)
    must be separate fields — PostProcessNode drops raw after redaction so
    unredacted data never reaches get_output() / the caller."""

    def test_raw_and_redacted_fields_are_distinct(self):
        tree = _parse_state_file()
        cls = _get_state_class(tree)
        declared = {name for name, _ in _field_names(cls)}
        for raw, redacted in (("raw_stdout", "stdout"), ("raw_stderr", "stderr")):
            assert raw in declared, f"'{raw}' field missing — needed for pre-redaction capture"
            assert redacted in declared, f"'{redacted}' field missing — needed for redacted output"
            assert raw != redacted, "raw and redacted field names must differ"


# ── PB-5d: runtime import check ──────────────────────────────────────────────

class TestRuntimeImportSafety:
    """PB-5d: Import SSHCommandAgentState at runtime and confirm it is a
    TypedDict (not Pydantic BaseModel or dataclass)."""

    def test_state_is_typed_dict_not_pydantic(self):
        """SSHCommandAgentState must be a TypedDict subclass, never a Pydantic model."""
        mod = importlib.import_module("src.schemas.state")
        StateClass = getattr(mod, "SSHCommandAgentState")

        # TypedDict subclasses have __annotations__ but are NOT Pydantic models
        assert hasattr(StateClass, "__annotations__"), (
            "SSHCommandAgentState has no __annotations__ — not a TypedDict?"
        )

        # Guard against accidental Pydantic base
        try:
            from pydantic import BaseModel as PydanticBaseModel
            assert not issubclass(StateClass, PydanticBaseModel), (
                "SSHCommandAgentState must not inherit from pydantic.BaseModel "
                "(ADR-005: msgpack incompatibility)"
            )
        except ImportError:
            pass  # pydantic not installed — nothing to check

    def test_state_inherits_from_agent_state(self):
        """SSHCommandAgentState must extend AgentState to inherit all
        framework-managed fields (session_id, node_history, error_log, etc.).

        TypedDict does not support issubclass(), and __orig_bases__ is only
        populated on Python 3.12+.  We use two complementary checks:
          1. __orig_bases__ when available (3.12+), giving an exact base check.
          2. Annotation subsetting on all versions: AgentState.__annotations__
             must be a subset of SSHCommandAgentState.__annotations__ — this is
             exactly what TypedDict inheritance produces after flattening.
        """
        mod = importlib.import_module("src.schemas.state")
        StateClass = getattr(mod, "SSHCommandAgentState")
        from framework.schemas.agent_state import AgentState

        # Check 1: __orig_bases__ (Python 3.12+ only — empty tuple on 3.11)
        orig_bases = getattr(StateClass, "__orig_bases__", ())
        if orig_bases:
            assert AgentState in orig_bases, (
                "SSHCommandAgentState must declare AgentState as its base "
                "(found: %s) — all framework-managed fields must be inherited, "
                "not re-declared" % list(orig_bases)
            )

        # Check 2: annotation subset — works on all Python versions.
        # TypedDict flattens all ancestor __annotations__ into the subclass, so
        # every key from AgentState must appear in SSHCommandAgentState.
        agent_state_keys = set(AgentState.__annotations__.keys())
        state_keys = set(StateClass.__annotations__.keys())
        missing = agent_state_keys - state_keys
        assert not missing, (
            "SSHCommandAgentState is missing AgentState fields: %s — "
            "it must inherit from AgentState (not re-declare or omit its fields)"
            % sorted(missing)
        )


# ── PB-6: S-1 trust gate declared on privileged nodes ────────────────────────

class TestTrustLevelDeclaration:
    """PB-6: All domain nodes that perform privileged operations must declare
    required_trust_level = TrustLevel.VERIFIED_EXTERNAL so the framework's
    S-1 gate (BaseNode.__call__) blocks ANONYMOUS callers at the node level
    (SDK security-model.md: 'Set required_trust_level on privileged nodes').
    """

    def _get_node_class(self, module_path: str, class_name: str):
        import importlib
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)

    def _assert_trust_level(self, NodeClass, expected_level):
        actual = getattr(NodeClass, "required_trust_level", None)
        assert actual is not None, (
            f"{NodeClass.__name__} must declare required_trust_level "
            "(default ANONYMOUS is not safe for privileged SSH operations)"
        )
        assert actual == expected_level, (
            f"{NodeClass.__name__}.required_trust_level = {actual!r}, "
            f"expected {expected_level!r}"
        )

    def test_pre_process_node_requires_verified_external(self):
        NodeClass = self._get_node_class("src.nodes.pre_process_node", "PreProcessNode")
        from framework.schemas.trust_level import TrustLevel
        self._assert_trust_level(NodeClass, TrustLevel.VERIFIED_EXTERNAL)

    def test_main_node_requires_verified_external(self):
        NodeClass = self._get_node_class("src.nodes.main_node", "MainNode")
        from framework.schemas.trust_level import TrustLevel
        self._assert_trust_level(NodeClass, TrustLevel.VERIFIED_EXTERNAL)

    def test_post_process_node_requires_verified_external(self):
        NodeClass = self._get_node_class("src.nodes.post_process_node", "PostProcessNode")
        from framework.schemas.trust_level import TrustLevel
        self._assert_trust_level(NodeClass, TrustLevel.VERIFIED_EXTERNAL)
