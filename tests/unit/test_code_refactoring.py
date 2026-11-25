"""
tests/unit/test_code_refactoring.py
Validates autonomous code refactoring via FixerAgent upon breaking dependency upgrades.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from vulnflow.agents.fixer import FixerAgent, default_fixer_agent
from vulnflow.contracts.remediation_plan import (
    PolicyResult,
    RemediationAction,
    RemediationPlan,
    RiskTier,
)
from vulnflow.contracts.state import VulnFlowState
from vulnflow.orchestrator.nodes import test_node as orchestrator_test_node


def _init_test_git_repo(repo_dir: Path) -> None:
    """Initialize a mock git repository with user config for commit operations."""
    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "VulnFlow Bot"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "bot@vulnflow.dev"], cwd=str(repo_dir), check=True, capture_output=True)


def test_parse_test_failure_python_traceback() -> None:
    """Ensure parse_test_failure correctly extracts file, line, and symbol from Python tracebacks."""
    agent = FixerAgent()
    traceback_output = """
    Traceback (most recent call last):
      File "src/client.py", line 42, in <module>
        from urllib3.packages.six.moves import urllib
    ImportError: cannot import name 'urllib' from 'urllib3.packages.six.moves'
    """
    info = agent.parse_test_failure(traceback_output)
    assert len(info["failing_locations"]) >= 1
    assert info["failing_locations"][0]["file"] == "src/client.py"
    assert info["failing_locations"][0]["line"] == 42
    assert "ImportError" in info["error_type"]
    assert "urllib" in info["error_desc"]


def test_parse_test_failure_javascript_error() -> None:
    """Ensure parse_test_failure correctly extracts file and line from Node / JS error stacks."""
    agent = FixerAgent()
    js_output = """
    Error: Cannot find module 'lodash/pluck'
    Require stack:
    - /workspace/src/utils.js:15:2
    """
    info = agent.parse_test_failure(js_output)
    assert len(info["failing_locations"]) >= 1
    assert "utils.js" in info["failing_locations"][0]["file"]
    assert info["failing_locations"][0]["line"] == 15


def test_synthesize_refactor_deterministic_rules() -> None:
    """Verify built-in deterministic refactoring recipes for common breaking library shifts."""
    agent = FixerAgent()
    snippet = "from urllib3.packages.six.moves import urllib\nimport os"
    failure_info = {
        "file_path": "src/client.py",
        "line": 1,
        "error_type": "ImportError",
        "error_desc": "cannot import name 'urllib' from 'urllib3.packages.six.moves'",
        "raw_output": "cannot import name 'urllib' from 'urllib3.packages.six.moves'",
    }
    patch_spec = agent._synthesize_refactor(
        package="urllib3",
        target_version="2.0.0",
        file_rel="src/client.py",
        context_snippet=snippet,
        failure_info=failure_info,
    )
    assert patch_spec is not None
    assert patch_spec["old_code"] == "from urllib3.packages.six.moves import urllib"
    assert patch_spec["new_code"] == "import urllib"
    assert "urllib3 2.0" in patch_spec["rationale"]


def test_attempt_code_refactor_applies_patch_and_commits(tmp_path: Path) -> None:
    """Verify that attempt_code_refactor modifies repo file, records evidence, and commits to git."""
    _init_test_git_repo(tmp_path)

    # Create dummy source file with deprecated urllib3 six import
    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    test_file = src_dir / "client.py"
    test_file.write_text("from urllib3.packages.six.moves import urllib\n\ndef fetch():\n    return urllib.request\n", encoding="utf-8")

    # Initial commit
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(
        ["git", "branch", "vulnflow/fix-urllib3"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
    )

    plan = RemediationPlan(
        id="PLAN-URLLIB3",
        finding_ids=["FND-1"],
        root_cause_id="PKG-urllib3",
        action=RemediationAction.BUMP,
        target_package="urllib3",
        target_version="2.0.0",
        risk_tier=RiskTier.AUTO,
        policy_result=PolicyResult(status="approved"),
        rationale="Upgrade urllib3 to address high-severity vulnerability.",
    )

    test_failure = """
    Traceback (most recent call last):
      File "src/client.py", line 1, in <module>
        from urllib3.packages.six.moves import urllib
    ImportError: cannot import name 'urllib' from 'urllib3.packages.six.moves'
    """

    res = default_fixer_agent.attempt_code_refactor(
        plan=plan,
        test_output=test_failure,
        repo_path=str(tmp_path),
        branch="main",
    )

    assert res is not None
    assert res["type"] == "code_refactor"
    assert res["file"] == "src/client.py"

    # Verify file content was refactored
    new_content = test_file.read_text(encoding="utf-8")
    assert "from urllib3.packages.six.moves import urllib" not in new_content
    assert "import urllib" in new_content

    # Verify plan evidence and rationale were updated
    assert plan.evidence is not None
    assert any(ev.get("type") == "code_refactor" for ev in plan.evidence)
    assert "Automated Code Refactoring Applied" in plan.rationale


def test_test_node_heals_breaking_change_via_refactoring(tmp_path: Path) -> None:
    """Verify test_node orchestrates FixerAgent refactoring and converts failing build to passing."""
    _init_test_git_repo(tmp_path)

    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    test_file = src_dir / "client.py"
    test_file.write_text("from urllib3.packages.six.moves import urllib\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(
        ["git", "branch", "vulnflow/fix-urllib3"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
    )

    plan = RemediationPlan(
        id="PLAN-URLLIB3",
        finding_ids=["FND-1"],
        root_cause_id="PKG-urllib3",
        action=RemediationAction.BUMP,
        target_package="urllib3",
        target_version="2.0.0",
        risk_tier=RiskTier.AUTO,
        policy_result=PolicyResult(status="approved"),
        rationale="Upgrade urllib3",
    )

    state = VulnFlowState(
        run_id="run-refactor-1",
        repo_path=str(tmp_path),
        ecosystem="pip",
        approved_plans=[plan],
        patches=[{
            "plan_id": plan.id,
            "branch": "vulnflow/fix-urllib3",
            "file": "requirements.txt",
            "diff": "--- requirements.txt\n+++ requirements.txt\n- urllib3==1.26.5\n+ urllib3==2.0.0",
        }],
    )

    # Mock build_server: first call fails due to import error, second call (re-test) succeeds
    fail_output = """
    Traceback (most recent call last):
      File "src/client.py", line 1, in <module>
        from urllib3.packages.six.moves import urllib
    ImportError: cannot import name 'urllib' from 'urllib3.packages.six.moves'
    """
    call_counts = {"count": 0}

    def mock_build_test(repo: str, branch: str, eco: str):
        call_counts["count"] += 1
        if call_counts["count"] == 1:
            return {"passed": False, "build_clean": False, "output": fail_output, "exit_code": 1}
        return {"passed": True, "build_clean": True, "output": "Tests passed 100%", "exit_code": 0}

    with patch("vulnflow.orchestrator.nodes.build_server.build_test", side_effect=mock_build_test):
        final_state = orchestrator_test_node(state)

    # Build passed after refactoring
    assert len(final_state.test_results) == 1
    assert final_state.test_results[0]["passed"] is True
    assert final_state.test_results[0]["build_clean"] is True

    # Audit events trace refactoring
    audit_types = [a["event_type"] for a in final_state.audit_events]
    assert "CODE_REFACTORING_APPLIED" in audit_types
    assert "BUILD_TEST_EXECUTED" in audit_types

    # Ensure self-correction was NOT triggered since refactoring fixed the issue
    assert "SELF_CORRECTION_TRIGGERED" not in audit_types
