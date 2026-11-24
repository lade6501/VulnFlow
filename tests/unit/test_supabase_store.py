"""Unit coverage for durable approval identity and Supabase RPC payloads."""

from __future__ import annotations

from typing import Any, Self

import vulnflow.store.supabase_store as supabase_module
from vulnflow.contracts.remediation_plan import (
    PolicyResult,
    RemediationAction,
    RemediationPlan,
    RiskTier,
)
from vulnflow.contracts.state import VulnFlowState
from vulnflow.store.supabase_store import (
    SupabaseConfig,
    SupabaseStore,
    approval_identity,
    explicit_repository_identity,
    repository_identity,
)


def _plan(plan_id: str, target_version: str = "2.0.0") -> RemediationPlan:
    return RemediationPlan(
        id=plan_id,
        finding_ids=["CVE-2026-1234"],
        root_cause_id="npm:example",
        target_package="example",
        action=RemediationAction.BUMP,
        target_version=target_version,
        risk_tier=RiskTier.REVIEW,
        requires_approval=True,
        policy_result=PolicyResult(
            status="unknown",
            rule_matched="unknown_package:require_approval",
        ),
    )


def test_approval_identity_ignores_random_plan_occurrence_id() -> None:
    first = approval_identity(_plan("PLAN-first"), ecosystem="npm")
    second_plan = _plan("PLAN-second")
    second_plan.finding_ids = ["FND-created-in-another-checkout"]
    second = approval_identity(second_plan, ecosystem="npm")

    assert first == second
    assert first != approval_identity(_plan("PLAN-third", "3.0.0"), ecosystem="npm")


def test_repository_identity_prefers_configured_provider_key(tmp_path: Any) -> None:
    assert repository_identity(str(tmp_path), "Acme/Payments") == "acme/payments"
    assert (
        explicit_repository_identity("Acme/Identity", "acme/payments")
        == "acme/identity"
    )


def test_claim_approval_sends_tenant_run_and_required_groups(monkeypatch: Any) -> None:
    monkeypatch.setenv("VULNFLOW_APPROVER_GROUPS", "security,product-owner,vp,security")
    config = SupabaseConfig(
        url="https://example.supabase.co",
        key="secret-test-key",
        organization_slug="acme",
        repository_key="acme/payments",
    )
    store = SupabaseStore(config)
    captured: dict[str, Any] = {}

    def fake_rpc(function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        captured["function_name"] = function_name
        captured["payload"] = payload
        return {"status": "pending", "approval_request_id": "request-1"}

    monkeypatch.setattr(store, "_rpc", fake_rpc)
    state = VulnFlowState(
        run_id="RUN-1",
        repo_path="/ephemeral/checkout",
        ecosystem="npm",
        terminal_status="running",
    )
    result = store.claim_approval(state, _plan("PLAN-1"))

    assert result["status"] == "pending"
    assert captured["function_name"] == "vulnflow_claim_approval"
    payload = captured["payload"]
    assert payload["p_organization_slug"] == "acme"
    assert payload["p_repository_key"] == "acme/payments"
    assert payload["p_run_id"] == "RUN-1"
    assert payload["p_required_groups"] == ["security", "product-owner", "vp"]


def test_secret_key_is_not_sent_as_bearer_token(monkeypatch: Any) -> None:
    captured: list[dict[str, str]] = []

    class FakeResponse:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        @staticmethod
        def read() -> bytes:
            return b"{}"

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        del timeout
        captured.append({key.lower(): value for key, value in request.header_items()})
        return FakeResponse()

    monkeypatch.setattr(supabase_module, "urlopen", fake_urlopen)
    secret_store = SupabaseStore(
        SupabaseConfig("https://example.supabase.co", "sb_secret_test", "acme")
    )
    secret_store._request("GET", "example")

    legacy_store = SupabaseStore(
        SupabaseConfig(
            "https://example.supabase.co", "header.payload.signature", "acme"
        )
    )
    legacy_store._request("GET", "example")

    assert captured[0]["apikey"] == "sb_secret_test"
    assert "authorization" not in captured[0]
    assert captured[1]["authorization"] == "Bearer header.payload.signature"


def test_enrichment_cache_uses_bulk_rpcs(monkeypatch: Any) -> None:
    store = SupabaseStore(
        SupabaseConfig(
            url="https://example.supabase.co",
            key="sb_secret_test",
            organization_slug="acme",
            repository_key="acme/payments",
        )
    )
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_rpc(function_name: str, payload: dict[str, Any]) -> Any:
        calls.append((function_name, payload))
        if function_name == "vulnflow_get_enrichment_cache":
            return [
                {
                    "cache_key": "ENRICH-1",
                    "enrichment": {"plan_id": "PLAN-1"},
                    "provider": "test",
                }
            ]
        return None

    monkeypatch.setattr(store, "_rpc", fake_rpc)
    cached = store.get_enrichment_cache("/checkout", ["ENRICH-1", "ENRICH-1"])
    store.save_enrichment_cache(
        "/checkout",
        [{"cache_key": "ENRICH-1", "enrichment": {"plan_id": "PLAN-1"}}],
    )

    assert cached["ENRICH-1"]["enrichment"]["plan_id"] == "PLAN-1"
    assert calls[0][1]["p_cache_keys"] == ["ENRICH-1"]
    assert calls[1][0] == "vulnflow_save_enrichment_cache"
