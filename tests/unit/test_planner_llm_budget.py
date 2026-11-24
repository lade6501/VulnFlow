"""Verifies deterministic planning and run-batched model enrichment telemetry."""

from __future__ import annotations

from typing import Any

from tests.unit.test_reporting import FIXED_TIME, report_state
from vulnflow.agents.planner import PlannerAgent
from vulnflow.contracts.finding import Finding, FindingType, LocationInfo, SeverityLevel
from vulnflow.llm.base import LLMResponse, LLMUsage
from vulnflow.reporting.builder import build_run_report


class CountingPlannerClient:
    """Return deterministic structured enrichment while counting model requests."""

    default_model = "planner-test-model"

    def __init__(self) -> None:
        self.calls = 0

    def get_provider_name(self) -> str:
        return "test-provider"

    def structured_complete(self, **_kwargs: Any) -> LLMResponse:
        self.calls += 1
        return LLMResponse(
            content="structured",
            provider="test-provider",
            model=self.default_model,
            usage=LLMUsage(
                prompt_tokens=20,
                completion_tokens=10,
                total_tokens=30,
                cost_estimate_usd=0.003,
            ),
            structured_data=None,
        )


def _finding(current_version: str) -> Finding:
    return Finding(
        id=f"FND-{current_version}",
        type=FindingType.VULN,
        scanner="trivy",
        repo="sample",
        package="npm:lodash",
        version=current_version,
        cve=["CVE-2020-8203"],
        severity=SeverityLevel.HIGH,
        location=LocationInfo(file_path="package.json"),
        fix_versions=["4.17.21"],
    )


def _advisory() -> list[dict[str, Any]]:
    return [
        {
            "chunk_id": "ADV-LODASH",
            "package": "npm:lodash",
            "cve": "CVE-2020-8203",
            "title": "Prototype pollution",
        }
    ]


def test_selective_mode_skips_routine_dependency_model_call() -> None:
    client = CountingPlannerClient()
    planner = PlannerAgent(
        client=client,  # type: ignore[arg-type]
        enable_llm=True,
        enrichment_mode="selective",
    )

    plan = planner.plan_remediation(
        "npm:lodash", [_finding("4.17.15")], _advisory(), ecosystem="npm"
    )

    assert plan.target_version == "4.17.21"
    assert client.calls == 0
    assert planner.last_enrichment["reason"] == "deferred_to_run_batch"


def test_plan_generation_never_calls_model_per_dependency() -> None:
    client = CountingPlannerClient()
    planner = PlannerAgent(
        client=client,  # type: ignore[arg-type]
        enable_llm=True,
        enrichment_mode="selective",
    )

    first = planner.plan_remediation(
        "npm:lodash", [_finding("3.0.0")], _advisory(), ecosystem="npm"
    )
    second = planner.plan_remediation(
        "npm:lodash", [_finding("3.0.1")], _advisory(), ecosystem="npm"
    )

    assert first.target_version == "4.17.21"
    assert second.target_version == "4.17.21"
    assert client.calls == 0
    assert planner.last_enrichment["reason"] == "deferred_to_run_batch"
    assert planner.enrichment_stats()["model_calls"] == 0


def test_complex_dependency_without_sources_stays_deterministic() -> None:
    client = CountingPlannerClient()
    planner = PlannerAgent(
        client=client,  # type: ignore[arg-type]
        enable_llm=True,
        enrichment_mode="all",
    )

    planner.plan_remediation("npm:lodash", [_finding("3.0.0")], [], ecosystem="npm")

    assert client.calls == 0
    assert planner.last_enrichment["reason"] == "deferred_to_run_batch"


def test_report_aggregates_executed_planner_usage_from_audit() -> None:
    state = report_state()
    for prompt_tokens, completion_tokens, cost in ((20, 10, 0.003), (30, 15, 0.004)):
        state.audit_events.append(
            {
                "event_type": "PLAN_FORMULATED",
                "payload": {
                    "llm_enrichment": {
                        "state": "executed",
                        "provider": "test-provider",
                        "model": "planner-test-model",
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "total_tokens": prompt_tokens + completion_tokens,
                        "estimated_cost_usd": cost,
                    }
                },
            }
        )

    report = build_run_report(state, generated_at=FIXED_TIME)

    assert report.header.model == "planner-test-model"
    assert report.provenance.model_provider == "test-provider"
    assert report.provenance.token_usage.prompt_tokens == 50
    assert report.provenance.token_usage.completion_tokens == 25
    assert report.provenance.token_usage.total_tokens == 75
    assert report.provenance.estimated_cost_usd == 0.007


def test_report_counts_shared_batch_call_usage_once() -> None:
    state = report_state()
    enrichment = {
        "state": "executed",
        "strategy": "graph_rag_run_batch",
        "call_id": "BATCH-shared",
        "provider": "test-provider",
        "model": "planner-test-model",
        "prompt_tokens": 100,
        "completion_tokens": 50,
        "total_tokens": 150,
        "estimated_cost_usd": 0.01,
    }
    for plan_id in ("PLAN-one", "PLAN-two"):
        state.audit_events.append(
            {
                "event_type": "PLAN_FORMULATED",
                "payload": {"plan_id": plan_id, "llm_enrichment": enrichment},
            }
        )

    report = build_run_report(state, generated_at=FIXED_TIME)

    assert report.provenance.token_usage.total_tokens == 150
    assert report.provenance.estimated_cost_usd == 0.01
