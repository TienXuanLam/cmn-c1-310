# PB-4: Import Isolation — CMN-C1-310 SSHCommandAgent
#
# Architecture contract (docs/02_design.md):
#   L0 = agenticstar-platform SDK (agenticstar / agenticstar_agentcore)  ← PROHIBITED
#   L1 = framework.*                                                       ← ALLOWED
#   L2 = shared.*                                                          ← ALLOWED
#
# Agent source code must access the AgentCore SDK only through the L1/L2
# public surfaces; bypassing them by importing L0 directly couples agent
# code to internal SDK internals and breaks the upgrade contract.

import ast
import os

import pytest

# ── prohibited ────────────────────────────────────────────────────────────────
# Both spellings are tested: hyphen form is the pip install name;
# the importable distribution package uses underscores.
_L0_PROHIBITED = [
    "agenticstar",           # hypothetical top-level if ever exposed
    "agenticstar_agentcore", # actual importable distribution package (dist-info name)
]

# stdlib 'platform' is allowed; the bare string "platform" alone would collide
# with the stdlib module name, so we only block if it is an agenticstar sub-path.
_STDLIB_SAFE = {"platform"}


def _scan_imports(filepath: str) -> list[str]:
    """Return a list of L0-import violation strings found in *filepath*."""
    with open(filepath) as f:
        try:
            tree = ast.parse(f.read(), filename=filepath)
        except SyntaxError:
            return []  # non-Python or parse error — skip

    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                for prohibited in _L0_PROHIBITED:
                    if alias.name == prohibited or alias.name.startswith(f"{prohibited}."):
                        if alias.name in _STDLIB_SAFE:
                            continue
                        violations.append(
                            f"{filepath}:{node.lineno} — import {alias.name}"
                        )

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                for prohibited in _L0_PROHIBITED:
                    if node.module == prohibited or node.module.startswith(f"{prohibited}."):
                        if node.module in _STDLIB_SAFE:
                            continue
                        violations.append(
                            f"{filepath}:{node.lineno} — from {node.module} import ..."
                        )

    return violations


def _find_python_files(directory: str, exclude_dirs: set[str] | None = None) -> list[str]:
    exclude_dirs = exclude_dirs or set()
    py_files: list[str] = []
    for root, dirs, files in os.walk(directory):
        # Prune excluded sub-directories in-place so os.walk skips them
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))
    return py_files


def _project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


class TestImportIsolation:
    """PB-4: Agent code must not import L0 (agenticstar / agenticstar_agentcore)."""

    def test_no_l0_imports_in_src(self):
        """All production source files under src/ (excluding examples/) must
        not import any L0 package."""
        src_dir = os.path.join(_project_root(), "src")
        if not os.path.exists(src_dir):
            pytest.skip("src/ directory not found")

        violations: list[str] = []
        # examples/ are scaffold templates — not part of the agent's runtime
        for filepath in _find_python_files(src_dir, exclude_dirs={"examples"}):
            violations.extend(_scan_imports(filepath))

        assert violations == [], (
            "L0 import isolation violated in src/:\n" + "\n".join(violations)
        )

    def test_no_l0_imports_in_tests(self):
        """Test files must also use only L1/L2 imports — tests that bypass
        the layering boundary would validate code that couldn't run in prod."""
        tests_dir = os.path.join(_project_root(), "tests")
        if not os.path.exists(tests_dir):
            pytest.skip("tests/ directory not found")

        violations: list[str] = []
        # Exclude proof_of_boundary itself (this file) to avoid self-scanning
        for filepath in _find_python_files(
            tests_dir, exclude_dirs={"proof_of_boundary", "__pycache__"}
        ):
            violations.extend(_scan_imports(filepath))

        assert violations == [], (
            "L0 import isolation violated in tests/:\n" + "\n".join(violations)
        )

    def test_src_uses_l1_framework_imports(self):
        """Positive boundary check: agent src/ must import from framework.*
        (L1).  A codebase with zero L1 imports would pass the negative check
        trivially — this ensures the boundary is actually exercised."""
        src_dir = os.path.join(_project_root(), "src")
        if not os.path.exists(src_dir):
            pytest.skip("src/ directory not found")

        l1_found = False
        for filepath in _find_python_files(src_dir, exclude_dirs={"examples"}):
            with open(filepath) as f:
                try:
                    tree = ast.parse(f.read(), filename=filepath)
                except SyntaxError:
                    continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    if node.module.startswith("framework."):
                        l1_found = True
                        break
            if l1_found:
                break

        assert l1_found, (
            "No L1 (framework.*) imports found in src/ — "
            "agent must extend the SDK through L1, not bypass it"
        )

    def test_src_uses_l2_shared_imports(self):
        """Positive boundary check: agent src/ must import from shared.*
        (L2 utilities — audit_logger, pii_detector).  Same rationale as
        test_src_uses_l1_framework_imports."""
        src_dir = os.path.join(_project_root(), "src")
        if not os.path.exists(src_dir):
            pytest.skip("src/ directory not found")

        l2_found = False
        for filepath in _find_python_files(src_dir, exclude_dirs={"examples"}):
            with open(filepath) as f:
                try:
                    tree = ast.parse(f.read(), filename=filepath)
                except SyntaxError:
                    continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    if node.module.startswith("shared."):
                        l2_found = True
                        break
            if l2_found:
                break

        assert l2_found, (
            "No L2 (shared.*) imports found in src/ — "
            "agent must use shared utilities (audit_logger, pii_detector) "
            "through L2, not re-implement them"
        )

    def test_agenticstar_agentcore_package_not_imported_in_src(self):
        """Explicit check for the underscore-form distribution package name
        (agenticstar_agentcore).  The hyphen form (agenticstar-agentcore) is
        the pip install name; agents must never import the internal dist
        package directly."""
        src_dir = os.path.join(_project_root(), "src")
        if not os.path.exists(src_dir):
            pytest.skip("src/ directory not found")

        violations: list[str] = []
        for filepath in _find_python_files(src_dir, exclude_dirs={"examples"}):
            with open(filepath) as f:
                try:
                    tree = ast.parse(f.read(), filename=filepath)
                except SyntaxError:
                    continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "agenticstar_agentcore" or alias.name.startswith(
                            "agenticstar_agentcore."
                        ):
                            violations.append(
                                f"{filepath}:{node.lineno} — import {alias.name}"
                            )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    if node.module == "agenticstar_agentcore" or node.module.startswith(
                        "agenticstar_agentcore."
                    ):
                        violations.append(
                            f"{filepath}:{node.lineno} — from {node.module} import ..."
                        )

        assert violations == [], (
            "Direct agenticstar_agentcore package import found:\n"
            + "\n".join(violations)
        )
