"""Regression tests for YAML chain validation and safe execution contracts."""
from __future__ import annotations

import pytest

from talisman.engine.orchestrator import Chain, ChainOrchestrator


def _write_chain(tmp_path, body: str):
    path = tmp_path / "test-chain.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_all_builtin_chains_pass_schema_and_dependency_validation():
    chains = ChainOrchestrator.list_chains()

    assert chains
    assert all(chain["description"] != "Parse error" for chain in chains)


def test_chain_rejects_duplicate_step_ids(tmp_path):
    path = _write_chain(
        tmp_path,
        """
name: duplicate
steps:
  - id: first
    module: scanner.xss
  - id: first
    module: scanner.sqli
""",
    )

    with pytest.raises(ValueError, match="Duplicate chain step id"):
        Chain.from_yaml(path)


def test_chain_rejects_unknown_dependencies(tmp_path):
    path = _write_chain(
        tmp_path,
        """
name: unknown-dependency
steps:
  - id: first
    module: scanner.xss
    depends_on: [missing]
""",
    )

    with pytest.raises(ValueError, match="unknown step"):
        Chain.from_yaml(path)


def test_chain_rejects_dependency_cycles(tmp_path):
    path = _write_chain(
        tmp_path,
        """
name: cycle
steps:
  - id: first
    module: scanner.xss
    depends_on: [second]
  - id: second
    module: scanner.sqli
    depends_on: [first]
""",
    )

    with pytest.raises(ValueError, match="dependency cycle"):
        Chain.from_yaml(path)


def test_chain_rejects_reserved_assessment_arguments(tmp_path):
    path = _write_chain(
        tmp_path,
        """
name: reserved
steps:
  - id: first
    module: scanner.xss
    args:
      scope: null
""",
    )

    with pytest.raises(ValueError, match="assessment-controlled"):
        Chain.from_yaml(path)


def test_chain_rejects_unknown_error_policy_and_unsupported_condition(tmp_path):
    invalid_policy = _write_chain(
        tmp_path,
        """
name: policy
steps:
  - id: first
    module: scanner.xss
    on_error: ignore
""",
    )
    with pytest.raises(ValueError, match="on_error"):
        Chain.from_yaml(invalid_policy)

    invalid_condition = _write_chain(
        tmp_path,
        """
name: condition
steps:
  - id: first
    module: scanner.xss
    condition: steps.previous.ok
""",
    )
    with pytest.raises(ValueError, match="condition"):
        Chain.from_yaml(invalid_condition)


def test_chain_rejects_symlink_file(tmp_path):
    original = _write_chain(
        tmp_path,
        "name: original\nsteps:\n  - scanner.xss\n",
    )
    linked = tmp_path / "linked.yaml"
    try:
        linked.symlink_to(original)
    except OSError:
        pytest.skip("symlinks are not supported on this platform")

    with pytest.raises(ValueError, match="non-symlink"):
        Chain.from_yaml(linked)


def test_builtin_chain_loader_rejects_path_traversal(tmp_path):
    with pytest.raises(FileNotFoundError):
        ChainOrchestrator.load_chain("../../etc/passwd")
