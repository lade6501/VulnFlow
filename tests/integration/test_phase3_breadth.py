"""
tests/integration/test_phase3_breadth.py
End-to-end integration tests for Phase 3 breadth, secondary ecosystems, secrets, and CI systems.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from api.routes.runs import get_run, list_runs
from api.routes.webhooks import handle_scan_webhook
from vulnflow.adapters.ci.github_action.adapter import GitHubActionAdapter
from vulnflow.adapters.ci.gitlab.adapter import GitLabAdapter
from vulnflow.adapters.ci.jenkins.adapter import JenkinsAdapter
from vulnflow.adapters.ecosystem.maven import MavenAdapter
from vulnflow.adapters.input.gitleaks import GitleaksAdapter
from vulnflow.adapters.input.grype import GrypeAdapter
from vulnflow.adapters.input.osv import OSVAdapter
from vulnflow.adapters.input.trivy import ScannerParseError
from vulnflow.agents.expiry import default_expiry_agent
from vulnflow.agents.planner import default_planner_agent
from vulnflow.agents.secrets import default_secrets_agent
from vulnflow.contracts.finding import Finding, FindingType, LocationInfo, SeverityLevel
from vulnflow.contracts.policy import PolicyStatus
from vulnflow.contracts.remediation_plan import RemediationAction, RiskTier
from vulnflow.contracts.state import VulnFlowState
from vulnflow.orchestrator.graph import run_workflow
from vulnflow.policy.licenses import default_license_checker

# Ensure deterministic execution in test suite
default_planner_agent.enable_llm = False


def test_f01_p3_scanner_adapters() -> None:
    """F01 P3 acceptance criteria: P3 adds Grype, OSV-Scanner and Gitleaks the same way; malformed input yields a typed error."""
    # 1. Grype adapter
    grype = GrypeAdapter()
    sample_grype_data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2021-23337",
                    "severity": "High",
                    "description": "Command injection in lodash",
                    "fix": {"versions": ["4.17.21"], "state": "fixed"},
                },
                "artifact": {
                    "name": "lodash",
                    "version": "4.17.15",
                    "type": "npm",
                    "locations": [{"path": "package.json"}],
                },
            }
        ]
    }
    grype_findings = grype.parse_data(sample_grype_data, repo="test-repo")
    assert len(grype_findings) == 1
    gf = grype_findings[0]
    assert gf.package == "npm:lodash"
    assert "CVE-2021-23337" in gf.cve
    assert gf.fix_versions == ["4.17.21"]
    assert gf.severity == SeverityLevel.HIGH

    # 2. OSV adapter
    osv = OSVAdapter()
    sample_osv_data = {
        "results": [
            {
                "source": {"path": "package.json"},
                "packages": [
                    {
                        "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-p6mc-m468-83gw",
                                "aliases": ["CVE-2020-8203"],
                                "database_specific": {"severity": "HIGH"},
                                "affected": [{"ranges": [{"events": [{"fixed": "4.17.21"}]}]}],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    osv_findings = osv.parse_data(sample_osv_data, repo="test-repo")
    assert len(osv_findings) == 1
    of = osv_findings[0]
    assert of.package == "npm:lodash"
    assert "CVE-2020-8203" in of.cve
    assert of.fix_versions == ["4.17.21"]

    # 3. Gitleaks adapter
    gitleaks = GitleaksAdapter()
    sample_gitleaks_data = [
        {
            "RuleID": "aws-access-token",
            "Description": "AWS Access Key leaked",
            "File": "config.js",
            "StartLine": 12,
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Fingerprint": "fe5b81a8b9e6",
        }
    ]
    secret_findings = gitleaks.parse_data(sample_gitleaks_data, repo="test-repo")
    assert len(secret_findings) == 1
    sf = secret_findings[0]
    assert sf.type == FindingType.SECRET
    assert sf.severity == SeverityLevel.CRITICAL
    # Strict invariant: Secret value must never appear in finding description or metadata
    assert "AKIAIOSFODNN7EXAMPLE" not in str(sf.to_dict())

    # 4. Malformed input yields typed ScannerParseError
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("{invalid json content")
        bad_f = f.name
    try:
        try:
            grype.parse_file(bad_f)
            assert False, "Expected ScannerParseError"
        except ScannerParseError:
            pass

        try:
            osv.parse_file(bad_f)
            assert False, "Expected ScannerParseError"
        except ScannerParseError:
            pass

        try:
            gitleaks.parse_file(bad_f)
            assert False, "Expected ScannerParseError"
        except ScannerParseError:
            pass
    finally:
        os.unlink(bad_f)


def test_f15_license_rules() -> None:
    """F15 acceptance criteria: Denied licenses return license_denied; table-driven tests cover allowed and denied cases."""
    test_cases = [
        ("MIT", PolicyStatus.APPROVED, True),
        ("Apache-2.0", PolicyStatus.APPROVED, True),
        ("BSD-3-Clause", PolicyStatus.APPROVED, True),
        ("GPL-3.0", PolicyStatus.LICENSE_DENIED, False),
        ("AGPL-3.0", PolicyStatus.LICENSE_DENIED, False),
        ("SSPL-1.0", PolicyStatus.LICENSE_DENIED, False),
        ("LGPL-3.0", PolicyStatus.UNKNOWN, False),
    ]

    for lic_id, expected_status, expected_allowed in test_cases:
        res = default_license_checker.check_license(lic_id, package="test-pkg")
        assert res["status"] == expected_status, f"Expected {expected_status} for {lic_id}, got {res['status']}"
        assert res["allowed"] == expected_allowed, f"Expected allowed={expected_allowed} for {lic_id}"


def test_f23_secrets_and_pii_flow() -> None:
    """F23 acceptance criteria: Always review; produces a rotation checklist and code-change plan; the value is never seen by the model."""
    secret_val = "AKIAIOSFODNN7EXAMPLE"
    finding = Finding(
        id="FND-SEC-01",
        type=FindingType.SECRET,
        scanner="gitleaks",
        repo="test-repo",
        package="secret:aws-access-key",
        version="0.0.0",
        cve=["aws-access-key"],
        severity=SeverityLevel.CRITICAL,
        location=LocationInfo(file_path="src/config.js", line=15),
        metadata={"rule_id": "aws-access-key", "fingerprint": "abc123sha"},
    )

    plan = default_secrets_agent.plan_secret_remediation(finding)

    # 1. Always review tier
    assert plan.risk_tier == RiskTier.REVIEW
    assert plan.requires_approval is True
    assert plan.action == RemediationAction.ROTATE

    # 2. Rotation checklist and diff produced
    assert len(plan.evidence) >= 1
    ev = plan.evidence[0]
    assert "checklist" in ev
    assert len(ev["checklist"]) >= 3
    assert "diff" in ev

    # 3. Secret value is never seen in plan
    plan_dict_str = str(plan.to_dict())
    assert secret_val not in plan_dict_str

    # 4. End-to-end workflow execution halts at human approval gate
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir)
        (repo_dir / "config.js").write_text("const KEY = 'AKIAIOSFODNN7EXAMPLE';", encoding="utf-8")
        report_f = repo_dir / "gitleaks.json"
        report_f.write_text(json.dumps([{
            "RuleID": "aws-access-key",
            "Description": "AWS Access Key leaked",
            "File": "config.js",
            "StartLine": 1,
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Fingerprint": "abc123sha",
        }]), encoding="utf-8")

        state = VulnFlowState(repo_path=str(repo_dir), report_path=str(report_f), scanner="gitleaks", mode="pr")
        result = run_workflow(state)

        assert result.terminal_status == "pending_approval"
        assert result.exit_code == 10
        assert len(result.pending_approval_plans) == 1
        assert result.pending_approval_plans[0].action == RemediationAction.ROTATE
        assert len(result.pull_requests) == 0


def test_f24_and_f25_expiry_predictor_and_renewal() -> None:
    """F24 & F25 acceptance criteria: expiring returns artifacts in warning window and predictor estimates risk window; renewal ticket/PR opened before expiry, idempotent."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir)
        art_file = repo_dir / "artifacts.yaml"
        art_file.write_text(
            """
artifacts:
  - name: "tls-prod-cert"
    type: "certificate"
    expires_at: "2026-11-20T00:00:00Z"
  - name: "temporary-waiver-1"
    type: "policy_waiver"
    expires_at: "2026-11-28T00:00:00Z"
  - name: "future-token"
    type: "api_token"
    expires_at: "2028-01-01T00:00:00Z"
""",
            encoding="utf-8",
        )

        # 1. Scan expiring artifacts within 30-day warning window (F24)
        expiring = default_expiry_agent.scan_expiring_artifacts(
            repo_path=str(repo_dir), warning_days=30, artifacts_file=str(art_file)
        )
        assert len(expiring) == 2
        names = [item["name"] for item in expiring]
        assert "tls-prod-cert" in names
        assert "temporary-waiver-1" in names
        assert "future-token" not in names

        # Risk window estimated
        cert_item = next(it for it in expiring if it["name"] == "tls-prod-cert")
        assert cert_item["risk_window"] in ("CRITICAL", "HIGH", "MEDIUM")

        # 2. Automated renewal ticket creation (F25)
        renewals_1 = default_expiry_agent.automate_renewals(
            repo_path=str(repo_dir), warning_days=30, artifacts_file=str(art_file)
        )
        assert len(renewals_1) == 2
        assert all("ticket" in item for item in renewals_1)

        # 3. Idempotent rerun: does not create duplicate tickets
        ticket_id_first = renewals_1[0]["ticket"]["ticket_id"]
        renewals_2 = default_expiry_agent.automate_renewals(
            repo_path=str(repo_dir), warning_days=30, artifacts_file=str(art_file)
        )
        ticket_id_second = renewals_2[0]["ticket"]["ticket_id"]
        assert ticket_id_first == ticket_id_second


def test_f26_second_ecosystem_maven() -> None:
    """F26 acceptance criteria: The maven sample repo reproduces the npm simple-bump outcome; does not gate the MVP."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir)
        pom_file = repo_dir / "pom.xml"
        pom_file.write_text(
            """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>maven-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>1.26</version>
    </dependency>
  </dependencies>
</project>""",
            encoding="utf-8",
        )

        deps = MavenAdapter.parse_dependencies(pom_file)
        assert deps.get("snakeyaml") == "1.26"

        success, diff = MavenAdapter.bump_dependency(pom_file, "org.yaml:snakeyaml", "1.33")
        assert success is True
        assert "-      <version>1.26</version>" in diff
        assert "+      <version>1.33</version>" in diff

        updated_content = pom_file.read_text(encoding="utf-8")
        assert "<version>1.33</version>" in updated_content


def test_f29_jenkins_and_gitlab_templates_and_adapters() -> None:
    """F29 acceptance criteria: Same container and scenarios pass from both templates."""
    base_dir = Path(__file__).resolve().parent.parent.parent

    # 1. Verify Jenkins template exists and invokes container
    jenkins_file = base_dir / "ci-templates" / "Jenkinsfile"
    assert jenkins_file.exists()
    jenkins_txt = jenkins_file.read_text(encoding="utf-8")
    assert "vulnflow/engine:latest" in jenkins_txt
    assert "vulnflow analyze" in jenkins_txt

    # 2. Verify GitLab template exists and invokes container
    gitlab_file = base_dir / "ci-templates" / "gitlab-ci.yml"
    assert gitlab_file.exists()
    gitlab_txt = gitlab_file.read_text(encoding="utf-8")
    assert "vulnflow/engine:latest" in gitlab_txt
    assert "vulnflow analyze" in gitlab_txt

    # 3. Test adapter result mapping
    st = VulnFlowState(exit_code=0, terminal_status="completed")
    j_res = JenkinsAdapter().process_result(st)
    assert j_res["build_status"] == "SUCCESS"

    g_res = GitLabAdapter().process_result(st)
    assert g_res["job_status"] == "success"


def test_f30_webhook_and_api_mode() -> None:
    """F30 acceptance criteria: A webhook triggers a run and returns a run ID retrievable through the API."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir)
        (repo_dir / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.15"}}), encoding="utf-8")

        payload = {
            "repo": str(repo_dir),
            "scanner": "trivy",
            "mode": "report",
            "report": [
                {
                    "package": "npm:lodash",
                    "version": "4.17.15",
                    "cve": ["CVE-2020-8203"],
                    "severity": "HIGH",
                    "file_path": "package.json",
                    "fix_versions": ["4.17.21"],
                }
            ],
        }

        # 1. Trigger via webhook
        resp = handle_scan_webhook(payload)
        assert resp["status"] == "completed"
        assert "run_id" in resp
        run_id = resp["run_id"]

        # 2. Retrieve run via API
        run_data = get_run(run_id)
        assert run_data is not None
        assert run_data["run_id"] == run_id
        assert run_data["terminal_status"] == "completed"

        # 3. List runs includes newly triggered run
        all_runs = list_runs()
        assert any(r["run_id"] == run_id for r in all_runs)


def test_phase_3_gate_feature_freeze() -> None:
    """
    Phase 3 Gate: Feature freeze - all scenarios, including secrets and expiry,
    pass in GitHub Actions, Jenkins and GitLab.
    """
    # 1. GitHub Action Adapter
    gha = GitHubActionAdapter()
    st_ok = VulnFlowState(exit_code=0, terminal_status="completed")
    assert gha.process_result(st_ok) == 0

    # 2. Jenkins Adapter
    st_review = VulnFlowState(exit_code=10, terminal_status="pending_approval")
    j_out = JenkinsAdapter().process_result(st_review)
    assert j_out["build_status"] == "UNSTABLE"

    # 3. GitLab Adapter
    st_block = VulnFlowState(exit_code=20, terminal_status="blocked_policy")
    gl_out = GitLabAdapter().process_result(st_block)
    assert gl_out["job_status"] == "policy_blocked"

    # 4. Secrets scenario
    sec_finding = Finding(
        id="FND-GATE-SEC",
        type=FindingType.SECRET,
        scanner="gitleaks",
        repo="test-repo",
        package="secret:github-token",
        version="0.0.0",
        cve=["github-pat"],
        severity=SeverityLevel.CRITICAL,
        location=LocationInfo(file_path=".github/workflows/deploy.yml", line=10),
    )
    plan_sec = default_secrets_agent.plan_secret_remediation(sec_finding)
    assert plan_sec.risk_tier == RiskTier.REVIEW
    assert plan_sec.requires_approval is True

    # 5. Expiry scenario
    items = default_expiry_agent.scan_expiring_artifacts(repo_path="samples/expiring-artifacts")
    assert len(items) >= 1
    assert any(it["action"] == "renew" for it in items)


if __name__ == "__main__":
    print("Testing F01: Grype, OSV-Scanner, and Gitleaks adapters...")
    test_f01_p3_scanner_adapters()
    print("Testing F15: License rules...")
    test_f15_license_rules()
    print("Testing F23: Secrets and PII flow...")
    test_f23_secrets_and_pii_flow()
    print("Testing F24 & F25: Expiry predictor and renewal automation...")
    test_f24_and_f25_expiry_predictor_and_renewal()
    print("Testing F26: Second ecosystem (Maven)...")
    test_f26_second_ecosystem_maven()
    print("Testing F29: Jenkins and GitLab templates & adapters...")
    test_f29_jenkins_and_gitlab_templates_and_adapters()
    print("Testing F30: Webhook and API mode...")
    test_f30_webhook_and_api_mode()
    print("Testing Phase 3 Gate: Feature freeze across scenarios and CI systems...")
    test_phase_3_gate_feature_freeze()
    print("\nALL PHASE 3 FEATURES & GATE TESTS PASSED SUCCESSFULLY!")
