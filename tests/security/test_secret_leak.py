"""
tests/security/test_secret_leak.py
Validates zero-secret-leak invariants across redaction, plans, audit logs, and traces.
"""

from __future__ import annotations

from vulnflow.agents.secrets import SecretsAgent
from vulnflow.contracts.finding import Finding, FindingType, LocationInfo, SeverityLevel
from vulnflow.contracts.remediation_plan import RiskTier
from vulnflow.core.redaction import contains_secrets, find_secrets, redact_secrets
from vulnflow.observability.audit_log import audit_logger


def test_secret_detection_and_redaction() -> None:
    """Verify regex patterns reliably identify and mask high-entropy secrets."""
    raw_credentials = [
        ("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY"),
        ("aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'", "AWS_SECRET_KEY"),
        ("ghp_1234567890abcdefghijklmnopqrstuvwxyz", "GITHUB_TOKEN"),
        ("xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx", "SLACK_TOKEN"),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y...\n-----END RSA PRIVATE KEY-----",
            "PRIVATE_KEY",
        ),
        ("postgres://app_user:SuperSecretPassword123!@db.internal:5432/prod", "CONNECTION_STRING_PASSWORD"),
    ]

    for cred, expected_type in raw_credentials:
        assert contains_secrets(cred), f"Failed to detect secret in: {cred}"
        found = find_secrets(cred)
        found_types = [t[0] for t in found]
        assert expected_type in found_types, f"Expected {expected_type} in {found_types} for {cred}"

        redacted = redact_secrets(cred)
        assert "[REDACTED_SECRET:" in redacted
        if expected_type == "AWS_ACCESS_KEY":
            assert "AKIAIOSFODNN7EXAMPLE" not in redacted
        elif expected_type == "GITHUB_TOKEN":
            assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in redacted


def test_secrets_agent_never_leaks_raw_value() -> None:
    """
    F23 & Phase 4 Gate: SecretsAgent replaces credential with env var,
    marks review tier, and ensures raw secret never enters plan evidence,
    rationale, or audit logs.
    """
    raw_secret = "AKIAIOSFODNN7EXAMPLE"
    run_id = "RUN-secret-leak-test"

    finding = Finding(
        id="FND-secret-leak-01",
        type=FindingType.SECRET,
        scanner="gitleaks",
        repo="sample-repo",
        severity=SeverityLevel.CRITICAL,
        package="secret:aws-access-key",
        version="plaintext",
        cve=[],
        location=LocationInfo(file_path="src/config.py", line=14),
        raw_ref=f"AWS Access Key ID exposed in config: {raw_secret}",
        metadata={"fingerprint": raw_secret, "run_id": run_id},
    )

    agent = SecretsAgent()
    plan = agent.formulate_rotation_plan(finding, repo_path=".")

    # 1. Verify strict plan properties
    assert plan.risk_tier == RiskTier.REVIEW
    assert plan.requires_approval is True

    # 2. Verify raw secret is NOT anywhere in the plan rationale
    assert raw_secret not in plan.rationale, "Raw secret leaked into plan rationale!"

    # 3. Verify raw secret is NOT in evidence diff or checklist
    for ev in plan.evidence:
        ev_str = str(ev)
        assert raw_secret not in ev_str, "Raw secret leaked into plan evidence!"

    # 4. Verify audit logger recorded sanitized audit events
    audit_events = audit_logger.get_events(run_id)
    for ev in audit_events:
        payload_str = str(ev.payload)
        assert raw_secret not in payload_str, f"Raw secret leaked into audit log payload: {payload_str}"


if __name__ == "__main__":
    test_secret_detection_and_redaction()
    test_secrets_agent_never_leaks_raw_value()
    print("ALL SECRET LEAK TESTS PASSED!")
