"""Run-level Graph/RAG batch enrichment and cache behavior."""

from __future__ import annotations

import json
from typing import Any

import pytest

from vulnflow.agents.planner import (
    BatchPlanEnrichment,
    BatchPlannerOutput,
    PlannerAgent,
)
from vulnflow.contracts.remediation_plan import (
    PolicyResult,
    RemediationAction,
    RemediationPlan,
    RiskTier,
)
from vulnflow.core import console
from vulnflow.llm.base import (
    LLMMessage,
    LLMRateLimitError,
    LLMResponse,
    LLMStructuredOutputError,
    LLMUsage,
)
from vulnflow.orchestrator.nodes import _apply_graph_governance


class BatchPlannerClient:
    default_model = "batch-test-model"

    def __init__(self, plan_ids: list[str]) -> None:
        self.plan_ids = plan_ids
        self.calls = 0

    @staticmethod
    def get_provider_name() -> str:
        return "test-provider"

    def structured_complete(self, **_kwargs: Any) -> LLMResponse:
        self.calls += 1
        return LLMResponse(
            content="structured",
            provider="test-provider",
            model=self.default_model,
            usage=LLMUsage(
                prompt_tokens=100,
                completion_tokens=50,
                total_tokens=150,
                cost_estimate_usd=0.01,
            ),
            structured_data=BatchPlannerOutput(
                enrichments=[
                    BatchPlanEnrichment(
                        plan_id=plan_id,
                        breaking_change_assessment="Review public API changes before merging.",
                        migration_steps=["Update imports", "Run integration tests"],
                        repository_risks=["Shared runtime dependency"],
                        suggested_tests=["Unit tests", "Contract tests"],
                        cross_repository_sequence="Upgrade shared libraries before services.",
                        approval_summary="Security and product owner review are recommended.",
                        confidence=0.9,
                        missing_evidence=[],
                        cited_chunk_ids=[f"ADV-{plan_id}"],
                    )
                    for plan_id in self.plan_ids
                ]
            ),
        )


def _plan(
    plan_id: str, package: str, tier: RiskTier = RiskTier.REVIEW
) -> RemediationPlan:
    return RemediationPlan(
        id=plan_id,
        finding_ids=[f"FND-{plan_id}"],
        root_cause_id=package,
        target_package=package,
        target_version="2.0.0",
        action=RemediationAction.BUMP,
        policy_result=PolicyResult(status="unknown"),
        risk_tier=tier,
        requires_approval=tier != RiskTier.AUTO,
        rationale=f"Deterministically upgrade {package}.",
    )


def _context(plan: RemediationPlan) -> dict[str, Any]:
    return {
        "run_id": "RUN-batch",
        "current_version": "1.0.0",
        "is_direct": False,
        "dependency_path": ["npm:parent", plan.target_package],
        "campaign_id": "CAMPAIGN-shared",
        "owners": {
            "product_owner": "payments",
            "required_approver_groups": ["security", "product-owner"],
        },
        "graph": {
            "blast_radius_tier": "HIGH",
            "dependents": ["npm:parent"],
            "affected_services": ["payments-api", "checkout-api"],
            "affected_repos": ["acme/payments", "acme/checkout"],
        },
        "advisories": [
            {
                "chunk_id": f"ADV-{plan.id}",
                "cve": "CVE-2026-1234",
                "title": "Security update",
                "description": "Upgrade guidance and compatibility notes.",
                "fixed_versions": ["2.0.0"],
            }
        ],
        "previous_outcomes": [],
    }


def test_multiple_review_plans_use_one_batch_model_call() -> None:
    plans = [_plan("PLAN-one", "npm:one"), _plan("PLAN-two", "npm:two")]
    client = BatchPlannerClient([plan.id for plan in plans])
    planner = PlannerAgent(
        client=client,  # type: ignore[arg-type]
        enable_llm=True,
        enrichment_mode="selective",
    )

    original_controls = [
        (
            plan.action,
            plan.target_package,
            plan.target_version,
            plan.risk_tier,
            plan.requires_approval,
        )
        for plan in plans
    ]
    planner.enrich_plans_batch(
        plans,
        {plan.id: _context(plan) for plan in plans},
        repo_path="acme/payments",
    )

    assert client.calls == 1
    assert planner.enrichment_stats()["batch_calls"] == 1
    assert planner.enrichment_stats()["enriched_plans"] == 2
    assert all(plan.llm_enrichment for plan in plans)
    assert all("Graph/RAG batch enrichment" in plan.rationale for plan in plans)
    assert original_controls == [
        (
            plan.action,
            plan.target_package,
            plan.target_version,
            plan.risk_tier,
            plan.requires_approval,
        )
        for plan in plans
    ]


def test_equivalent_second_run_uses_enrichment_cache() -> None:
    first_plan = _plan("PLAN-one", "npm:one")
    client = BatchPlannerClient([first_plan.id])
    planner = PlannerAgent(
        client=client,  # type: ignore[arg-type]
        enable_llm=True,
        enrichment_mode="selective",
    )
    planner.enrich_plans_batch(
        [first_plan], {first_plan.id: _context(first_plan)}, repo_path="acme/payments"
    )

    planner.reset_circuit_breaker()
    second_plan = _plan("PLAN-one", "npm:one")
    planner.enrich_plans_batch(
        [second_plan],
        {second_plan.id: _context(second_plan)},
        repo_path="acme/payments",
    )

    assert client.calls == 1
    assert planner.enrichment_stats()["model_calls"] == 0
    assert planner.enrichment_stats()["cached_plans"] == 1
    assert second_plan.llm_enrichment is not None
    assert second_plan.llm_enrichment["cached"] is True


def test_cache_key_ignores_run_ids_and_duplicate_equivalent_outcomes() -> None:
    plan = _plan("PLAN-one", "npm:one")
    first_context = _context(plan)
    first_context["previous_outcomes"] = [
        {
            "run_id": "RUN-one",
            "target_version": "2.0.0",
            "terminal_status": "completed",
            "tests_passed": True,
            "prs_opened": 1,
        }
    ]
    second_context = _context(plan)
    second_context["previous_outcomes"] = [
        {
            "run_id": "RUN-two",
            "target_version": "2.0.0",
            "terminal_status": "completed",
            "tests_passed": True,
            "prs_opened": 1,
        },
        {
            "run_id": "RUN-three",
            "target_version": "2.0.0",
            "terminal_status": "completed",
            "tests_passed": True,
            "prs_opened": 1,
        },
    ]

    assert PlannerAgent._batch_cache_key(
        plan, first_context
    ) == PlannerAgent._batch_cache_key(plan, second_context)


def test_auto_tier_plans_consume_no_batch_budget() -> None:
    plan = _plan("PLAN-auto", "npm:auto", tier=RiskTier.AUTO)
    client = BatchPlannerClient([plan.id])
    planner = PlannerAgent(
        client=client,  # type: ignore[arg-type]
        enable_llm=True,
        enrichment_mode="all",
    )

    planner.enrich_plans_batch(
        [plan], {plan.id: _context(plan)}, repo_path="acme/payments"
    )

    assert client.calls == 0
    assert plan.llm_enrichment is None


def test_large_run_calls_once_per_batch_not_once_per_dependency(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("VULNFLOW_BATCH_ENRICHMENT_MAX_PLANS", "20")
    monkeypatch.setattr(console, "USE_COLOR", True)
    monkeypatch.setattr(console, "GREEN", "\033[92m")
    monkeypatch.setattr(console, "RESET", "\033[0m")
    caplog.set_level("INFO", logger="vulnflow.agents.planner")
    plans = [_plan(f"PLAN-{index}", f"npm:package-{index}") for index in range(45)]
    client = BatchPlannerClient([plan.id for plan in plans])
    planner = PlannerAgent(
        client=client,  # type: ignore[arg-type]
        enable_llm=True,
        enrichment_mode="selective",
    )

    planner.enrich_plans_batch(
        plans,
        {plan.id: _context(plan) for plan in plans},
        repo_path="acme/payments",
    )

    assert client.calls == 3
    assert planner.enrichment_stats()["batch_calls"] == 3
    assert sum(plan.llm_enrichment is not None for plan in plans) == 45
    assert [message for message in caplog.messages if "Enrichment batch " in message] == [
        f"\033[92mEnrichment batch {number} of 3\033[0m" for number in range(1, 4)
    ]


def test_failed_batch_records_safe_diagnostics_for_attempted_plans(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    class RateLimitedClient(BatchPlannerClient):
        def structured_complete(self, **_kwargs: Any) -> LLMResponse:
            self.calls += 1
            raise LLMRateLimitError(
                "private provider response body", provider="test-provider", status_code=429
            )

    monkeypatch.setenv("VULNFLOW_BATCH_ENRICHMENT_MAX_PLANS", "2")
    plans = [_plan(f"PLAN-{index}", f"npm:package-{index}") for index in range(3)]
    client = RateLimitedClient([])
    planner = PlannerAgent(client=client, enable_llm=True)  # type: ignore[arg-type]
    original_rationales = [plan.rationale for plan in plans]

    planner.enrich_plans_batch(
        plans, {plan.id: _context(plan) for plan in plans}, repo_path="acme/payments"
    )

    stats = planner.enrichment_stats()
    assert client.calls == stats["failed_calls"] == stats["model_calls"] == 1
    failure = stats["batch_failure"]
    assert failure["reason"] == "rate_limited"
    assert failure["stage"] == "structured_completion"
    assert failure["status_code"] == 429
    assert failure["requested_plans"] == 2
    assert planner.plan_enrichment(plans[0].id) == failure
    assert planner.plan_enrichment(plans[1].id) == failure
    assert planner.plan_enrichment(plans[2].id) == {
        "state": "not_run",
        "reason": "earlier_batch_failed",
        "blocked_by_call_id": failure["call_id"],
    }
    assert [plan.rationale for plan in plans] == original_rationales
    assert "private provider response body" not in caplog.text
    assert "private provider response body" not in str(stats)


def test_prompt_preparation_failure_does_not_count_as_a_model_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan("PLAN-one", "npm:package-one")
    client = BatchPlannerClient([plan.id])
    planner = PlannerAgent(client=client, enable_llm=True)  # type: ignore[arg-type]

    def invalid_prompt(_batch: Any) -> None:
        raise ValueError("prompt validation failure")

    monkeypatch.setattr(planner, "_batch_prompt", invalid_prompt)
    planner.enrich_plans_batch([plan], {plan.id: _context(plan)}, repo_path="acme/payments")

    stats = planner.enrichment_stats()
    assert client.calls == stats["model_calls"] == stats["failed_calls"] == 0
    assert stats["batch_failure"]["reason"] == "prompt_preparation_failed"
    assert planner.plan_enrichment(plan.id)["state"] == "failed"


def test_invalid_output_splits_once_and_preserves_later_batches(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    class FormattingFailureClient(BatchPlannerClient):
        def __init__(self) -> None:
            super().__init__([])
            self.attempts: list[list[str]] = []

        def structured_complete(self, **kwargs: Any) -> LLMResponse:
            self.plan_ids = json.loads(kwargs["messages"][0].content)
            self.attempts.append(self.plan_ids)
            if "PLAN-0" in self.plan_ids:
                raise LLMStructuredOutputError("Invalid JSON")
            return super().structured_complete(**kwargs)

    monkeypatch.setenv("VULNFLOW_BATCH_ENRICHMENT_MAX_PLANS", "3")
    monkeypatch.setattr(console, "USE_COLOR", False)
    caplog.set_level("INFO", logger="vulnflow.agents.planner")
    plans = [_plan(f"PLAN-{index}", f"npm:package-{index}") for index in range(5)]
    client = FormattingFailureClient()
    planner = PlannerAgent(client=client, enable_llm=True)  # type: ignore[arg-type]
    monkeypatch.setattr(
        planner,
        "_batch_prompt",
        lambda batch: [
            LLMMessage(role="user", content=json.dumps([plan.id for plan, _, _ in batch]))
        ],
    )

    planner.enrich_plans_batch(
        plans, {plan.id: _context(plan) for plan in plans}, repo_path="acme/payments"
    )

    assert client.attempts == [
        ["PLAN-0", "PLAN-1", "PLAN-2"], ["PLAN-0"], ["PLAN-1", "PLAN-2"], ["PLAN-3", "PLAN-4"],
    ]
    assert [message for message in caplog.messages if "Enrichment batch " in message] == [
        "Enrichment batch 1 of 2",
        "Enrichment batch 2 of 4",
        "Enrichment batch 3 of 4",
        "Enrichment batch 4 of 4",
    ]
    stats = planner.enrichment_stats()
    assert stats["batch_splits"] == 1
    assert stats["failed_calls"] == 2
    assert stats["enriched_plans"] == 4
    assert planner.plan_enrichment("PLAN-0")["state"] == "failed"
    assert all(planner.plan_enrichment(p.id)["state"] == "executed" for p in plans[1:])


def test_high_graph_blast_radius_escalates_auto_plan_to_review() -> None:
    plan = _plan("PLAN-auto", "npm:auto", tier=RiskTier.AUTO)

    changed = _apply_graph_governance(plan, {"blast_radius_tier": "HIGH"})

    assert changed is True
    assert plan.risk_tier is RiskTier.REVIEW
    assert plan.requires_approval is True
    assert "Graph Governance" in plan.rationale
