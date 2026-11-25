"""
tests/unit/test_campaign_pr.py
Validates multi-dependency campaign PR grouping, formatting, and branch isolation.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from vulnflow.contracts.remediation_plan import (
    PolicyResult,
    RemediationAction,
    RemediationPlan,
    RiskTier,
    VerificationResult,
)
from vulnflow.contracts.state import VulnFlowState
from vulnflow.orchestrator.nodes import fix_node as orchestrator_fix_node
from vulnflow.orchestrator.nodes import pr_node as orchestrator_pr_node
from vulnflow.reporting.pr_comment import format_campaign_pr_body


def _init_test_git_repo(repo_dir: Path) -> None:
    """Initialize a mock git repository with user config for commit operations."""
    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "VulnFlow Bot"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "bot@vulnflow.dev"], cwd=str(repo_dir), check=True, capture_output=True)


def test_format_campaign_pr_body_matrix_and_details() -> None:
    """Verify format_campaign_pr_body creates a clear remediation matrix and collapsible details."""
    plan1 = RemediationPlan(
        id="PLAN-LODASH",
        finding_ids=["FND-1", "FND-2"],
        root_cause_id="PKG-npm:lodash",
        action=RemediationAction.BUMP,
        target_package="lodash",
        target_version="4.17.21",
        risk_tier=RiskTier.AUTO,
        policy_result=PolicyResult(status="approved"),
        rationale="Update lodash to resolve prototype pollution.",
        evidence=[{
            "id": "GHSA-p6mc-m468-83gw",
            "cve": "CVE-2020-8203",
            "title": "Prototype Pollution in lodash",
            "cvss_score": 7.4,
        }],
    )
    plan2 = RemediationPlan(
        id="PLAN-EXPRESS",
        finding_ids=["FND-3"],
        root_cause_id="PKG-npm:express",
        action=RemediationAction.BUMP,
        target_package="express",
        target_version="4.18.2",
        risk_tier=RiskTier.AUTO,
        policy_result=PolicyResult(status="approved"),
        rationale="Update express to resolve open redirect.",
        evidence=[{
            "type": "code_refactor",
            "file": "server.js",
            "symbol": "app.use",
            "rationale": "Updated middleware signature for Express 4.18",
        }],
    )

    ver = VerificationResult(
        verified=True,
        rescan_clean=True,
        tests_passed=True,
        build_success=True,
        policy_recheck_passed=True,
    )

    body = format_campaign_pr_body(plans=[plan1, plan2], verification=ver)

    # Executive matrix assertions
    assert "## 🛡️ VulnFlow Consolidated Remediation Campaign" in body
    assert "resolves **3 vulnerability finding(s)** across **2 package(s)**" in body
    assert "| `lodash` | `BUMP` | `4.17.21` | `AUTO` | `APPROVED` | `2` |" in body
    assert "| `express` | `BUMP` | `4.18.2` | `AUTO` | `APPROVED` | `1` |" in body

    # Automated refactoring callout
    assert "🛠️ Automated Code Refactorings Applied" in body
    assert "server.js" in body
    assert "Updated middleware signature for Express 4.18" in body

    # Collapsible package details
    assert "<details><summary><strong>lodash</strong> (Target: 4.17.21)</summary>" in body
    assert "CVE-2020-8203" in body

    # Verification block
    assert "### 🧪 Verification & Build Evidence" in body
    assert "✅ PASSED" in body
    assert "✅ ZERO REMAINING FINDINGS" in body


def test_fix_node_batches_multiple_dependencies_into_campaign_branch(tmp_path: Path) -> None:
    """Verify fix_node groups multiple approved bump plans onto a single campaign branch."""
    _init_test_git_repo(tmp_path)

    # Create dummy package.json
    pkg_file = tmp_path / "package.json"
    pkg_content = {
        "name": "sample-app",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "4.17.15",
            "axios": "0.21.1",
        },
    }
    pkg_file.write_text(json.dumps(pkg_content, indent=2), encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial package.json"], cwd=str(tmp_path), check=True, capture_output=True)

    plan_lodash = RemediationPlan(
        id="PLAN-LODASH",
        finding_ids=["FND-1"],
        root_cause_id="PKG-npm:lodash",
        action=RemediationAction.BUMP,
        target_package="lodash",
        target_version="4.17.21",
        risk_tier=RiskTier.AUTO,
        policy_result=PolicyResult(status="approved"),
        rationale="Upgrade lodash",
    )
    plan_axios = RemediationPlan(
        id="PLAN-AXIOS",
        finding_ids=["FND-2"],
        root_cause_id="PKG-npm:axios",
        action=RemediationAction.BUMP,
        target_package="axios",
        target_version="1.6.0",
        risk_tier=RiskTier.AUTO,
        policy_result=PolicyResult(status="approved"),
        rationale="Upgrade axios",
    )

    state = VulnFlowState(
        run_id="run-campaign-test-123456",
        repo_path=str(tmp_path),
        ecosystem="npm",
        approved_plans=[plan_lodash, plan_axios],
    )

    final_state = orchestrator_fix_node(state)

    # Assert exactly 1 campaign branch created
    expected_branch = f"vulnflow/campaign-{state.run_id[:8]}"
    assert final_state.created_branches == [expected_branch]

    # Assert both plans were applied to the campaign branch
    assert len(final_state.patches) == 2
    for patch in final_state.patches:
        assert patch["branch"] == expected_branch
        assert patch["is_campaign"] is True

    # Check git log on the campaign branch
    log_res = subprocess.run(
        ["git", "log", expected_branch, "--oneline"],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        check=True,
    )
    assert "campaign remediation for lodash, axios" in log_res.stdout

    # Audit events
    audit_types = [a["event_type"] for a in final_state.audit_events]
    assert "BRANCH_CREATED" in audit_types
    assert "PATCH_APPLIED" in audit_types
    assert "COMMIT_CREATED" in audit_types


def test_fix_node_single_dependency_uses_single_branch(tmp_path: Path) -> None:
    """Verify fix_node preserves single-branch behavior when only 1 dependency is approved."""
    _init_test_git_repo(tmp_path)

    pkg_file = tmp_path / "package.json"
    pkg_file.write_text(json.dumps({"dependencies": {"lodash": "4.17.15"}}, indent=2), encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=str(tmp_path), check=True, capture_output=True)

    plan = RemediationPlan(
        id="PLAN-LODASH",
        finding_ids=["FND-1"],
        root_cause_id="PKG-npm:lodash",
        action=RemediationAction.BUMP,
        target_package="lodash",
        target_version="4.17.21",
        risk_tier=RiskTier.AUTO,
        policy_result=PolicyResult(status="approved"),
        rationale="Upgrade lodash",
    )

    state = VulnFlowState(
        run_id="run-single-123456",
        repo_path=str(tmp_path),
        ecosystem="npm",
        approved_plans=[plan],
    )

    final_state = orchestrator_fix_node(state)

    assert final_state.created_branches == ["vulnflow/fix-npm-lodash"]
    assert len(final_state.patches) == 1
    assert final_state.patches[0]["branch"] == "vulnflow/fix-npm-lodash"
    assert final_state.patches[0]["is_campaign"] is False


def test_pr_node_opens_single_campaign_pr_with_matrix(tmp_path: Path) -> None:
    """Verify pr_node consolidates campaign branch patches into exactly one Pull Request."""
    _init_test_git_repo(tmp_path)

    plan1 = RemediationPlan(
        id="PLAN-1",
        finding_ids=["FND-1"],
        root_cause_id="PKG-npm:lodash",
        action=RemediationAction.BUMP,
        target_package="lodash",
        target_version="4.17.21",
        risk_tier=RiskTier.AUTO,
        policy_result=PolicyResult(status="approved"),
        rationale="Upgrade lodash",
    )
    plan2 = RemediationPlan(
        id="PLAN-2",
        finding_ids=["FND-2"],
        root_cause_id="PKG-npm:axios",
        action=RemediationAction.BUMP,
        target_package="axios",
        target_version="1.6.0",
        risk_tier=RiskTier.AUTO,
        policy_result=PolicyResult(status="approved"),
        rationale="Upgrade axios",
    )

    campaign_branch = "vulnflow/campaign-abcd1234"
    state = VulnFlowState(
        run_id="run-campaign-abcd1234",
        repo_path=str(tmp_path),
        ecosystem="npm",
        approved_plans=[plan1, plan2],
        patches=[
            {"plan_id": plan1.id, "branch": campaign_branch, "file": "package.json", "is_campaign": True},
            {"plan_id": plan2.id, "branch": campaign_branch, "file": "package.json", "is_campaign": True},
        ],
        verification_results=[{
            "branch": campaign_branch,
            "revision": "test-verified-revision",
            "verified": True,
            "rescan_clean": True,
            "tests_passed": True,
            "policy_recheck_passed": True,
        }],
    )

    def confirm_pr(*, branch: str, title: str, body: str, repo_dir: str, expected_revision: str) -> dict:
        assert repo_dir == str(tmp_path)
        assert expected_revision == "test-verified-revision"
        assert "Consolidated Remediation Campaign" in body
        return {
            "status": "opened", "pr_url": "https://github.com/example/repo/pull/1",
            "branch": branch, "title": title, "pr_number": 1,
        }

    with (
        patch("vulnflow.orchestrator.nodes.git_server.pr_create", side_effect=confirm_pr),
        patch("vulnflow.orchestrator.nodes.registry_check", return_value={"confirmed": True}),
    ):
        final_state = orchestrator_pr_node(state)

    # Exactly 1 Pull Request created
    assert len(final_state.pull_requests) == 1
    pr_record = final_state.pull_requests[0]
    assert pr_record["branch"] == campaign_branch
    assert "campaign remediation for lodash, axios" in pr_record["title"]

    # PR Created audit event marked campaign=True
    pr_audits = [a for a in final_state.audit_events if a["event_type"] == "PR_CREATED"]
    assert len(pr_audits) == 1
    assert pr_audits[0]["payload"]["campaign"] is True
    assert pr_audits[0]["payload"]["plans_count"] == 2
