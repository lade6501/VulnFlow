"""
tests/security/test_reporting_security.py
Checks F43 outputs for secret leakage and active-content injection.
"""

from __future__ import annotations

import json

from tests.unit.test_reporting import FIXED_TIME, report_state
from vulnflow.reporting.builder import build_run_report
from vulnflow.reporting.html_report import generate_html_report
from vulnflow.reporting.json_report import generate_json_report
from vulnflow.reporting.markdown import generate_markdown_report


def test_secret_and_hostile_content_are_safe_in_every_output() -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    hostile = "<script>alert(1)</script> @security [approve](javascript:alert(1))"
    state = report_state()
    state.root_cause_groups[0]["root_cause_package"] = hostile
    state.root_cause_groups[0]["explanation"] = f"{hostile} token={secret}"
    state.plans[0].rationale = f"{hostile} {secret}"
    report = build_run_report(state, generated_at=FIXED_TIME)
    outputs = [
        json.dumps(generate_json_report(report)),
        generate_markdown_report(report),
        generate_html_report(report),
    ]
    assert all(secret not in output for output in outputs)
    html = outputs[2]
    markdown = outputs[1]
    assert "<script" not in html.lower()
    assert "&lt;script&gt;" in html
    assert "@\u200bsecurity" in markdown
    assert 'href="javascript:' not in html.lower()
    assert 'src="http' not in html.lower()
    assert "Content-Security-Policy" in html


def test_missing_ai_evidence_is_explicit() -> None:
    state = report_state()
    state.plans[0].evidence = []
    state.root_cause_groups[0]["findings"][0]["location"] = {}
    report = build_run_report(state, generated_at=FIXED_TIME)
    assert report.validation_notes.missing_evidence
    insight = report.root_causes[0].insights[1]
    assert "not evaluated" in insight.text.lower()
    assert insight.evidence_availability.value in {"not_evaluated", "missing"}
