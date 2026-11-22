"""
src/vulnflow/contracts/report.py
Defines the immutable canonical enterprise run report contract.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class ReportModel(BaseModel):
    """Strict immutable base for every report schema component."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ExecutionMode(str, Enum):
    REPORT = "report"
    PR = "pr"
    DRY_RUN = "dry-run"


class RepoChanges(str, Enum):
    NONE = "none"
    SIMULATED = "simulated"
    MADE = "made"


class StepState(str, Enum):
    NOT_RUN = "not_run"
    SIMULATED = "simulated"
    EXECUTED = "executed"
    FAILED = "failed"


class EvidenceAvailability(str, Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    UNKNOWN = "unknown"
    NOT_EVALUATED = "not_evaluated"


class GeneratedBy(str, Enum):
    RULES = "rules"
    LLM = "llm"


class DependencyOrigin(str, Enum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    OTHER = "other"


class CompletionStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    UNKNOWN = "unknown"


class SeverityCounts(ReportModel):
    """Finding totals by normalized scanner severity; null means unknown."""

    critical: int | None = Field(default=None, ge=0)
    high: int | None = Field(default=None, ge=0)
    medium: int | None = Field(default=None, ge=0)
    low: int | None = Field(default=None, ge=0)
    info: int | None = Field(default=None, ge=0)
    total: int | None = Field(default=None, ge=0)


class ReportHeader(ReportModel):
    run_id: str
    generated_at: datetime
    repository_name: str
    commit_sha: str | None = None
    branch: str | None = None
    scanner_name: str
    scanner_version: str | None = None
    policy_file_hash: str | None = None
    model: str | None = None
    prompt_version: str | None = None
    vulnflow_version: str
    execution_mode: ExecutionMode
    outcome: str
    exit_code: int
    repo_changes: RepoChanges


class ExecutiveSummary(ReportModel):
    summary_sentence: str
    severity_counts_before: SeverityCounts
    severity_counts_after: SeverityCounts
    findings_analyzed: int = Field(ge=0)
    root_causes_identified: int = Field(ge=0)
    remediation_plans_proposed: int = Field(ge=0)
    expected_cves_addressed: int = Field(ge=0)
    verified_cves_resolved: int = Field(ge=0)
    fixes_applied: int = Field(ge=0)
    prs_actually_created: int = Field(ge=0)
    unresolved_findings: int | None = Field(default=None, ge=0)


class ActionRequired(ReportModel):
    action_type: str
    priority: str
    target_root_cause: str | None = None
    description: str
    required_actor: str
    completion_status: CompletionStatus


class SourceReference(ReportModel):
    source_id: str
    source_type: str
    title: str | None = None
    url: str | None = None


class AdvisoryEvidence(ReportModel):
    evidence_id: str
    package: str
    ecosystem: str
    cves: tuple[str, ...] = ()
    title: str | None = None
    affected_ranges: tuple[str, ...] = ()
    fixed_versions: tuple[str, ...] = ()
    source_url: str | None = None
    validated: bool = False
    rejection_reason: str | None = None


class RemediationOption(ReportModel):
    action: str
    target_version: str | None = None
    description: str
    accepted: bool
    reason: str
    source_references: tuple[str, ...] = ()


class SecurityInsight(ReportModel):
    category: str
    text: str
    generated_by: GeneratedBy
    source_references: tuple[str, ...] = ()
    evidence_availability: EvidenceAvailability
    uncertainty: str | None = None


class FileChange(ReportModel):
    path: str
    state: StepState
    lines_added: int | None = Field(default=None, ge=0)
    lines_removed: int | None = Field(default=None, ge=0)


class DependencyChange(ReportModel):
    package: str
    previous_version: str | None = None
    target_version: str | None = None
    change_type: str


class VerificationResult(ReportModel):
    check: str
    state: StepState
    passed: bool | None = None
    details: str | None = None
    source_event: str | None = None


class RootCauseReport(ReportModel):
    root_cause_id: str
    package: str
    ecosystem: str
    installed_version: str | None = None
    origin: DependencyOrigin
    dependency_chain: tuple[str, ...] = ()
    affected_services: tuple[str, ...] = ()
    associated_finding_ids: tuple[str, ...] = ()
    associated_cves: tuple[str, ...] = ()
    advisory_evidence: tuple[AdvisoryEvidence, ...] = ()
    impact_explanation: str
    options_considered: tuple[RemediationOption, ...] = ()
    recommended_change: str
    target_version: str | None = None
    bump_class: str | None = None
    modified_files: tuple[FileChange, ...] = ()
    transitive_dependencies: tuple[DependencyChange, ...] = ()
    risk_tier: str
    risk_reason: str
    insights: tuple[SecurityInsight, ...] = ()
    breaking_change_notes: str | None = None
    breaking_change_source_urls: tuple[str, ...] = ()
    migration_notes: str | None = None
    proposed_remediation_steps: tuple[str, ...] = ()
    actual_execution_steps: tuple[str, ...] = ()
    verification_results: tuple[VerificationResult, ...] = ()
    remaining_developer_actions: tuple[str, ...] = ()


class EvaluatedRule(ReportModel):
    rule: str
    status: str
    evidence: str | None = None


class ApprovalDecision(ReportModel):
    plan_id: str
    decision: str
    actor: str | None = None
    reason: str | None = None


class PolicyCompliance(ReportModel):
    policy_status: str
    evaluated_rules: tuple[EvaluatedRule, ...] = ()
    approvals_required: tuple[str, ...] = ()
    approval_decisions: tuple[ApprovalDecision, ...] = ()
    exceptions: tuple[str, ...] = ()
    unresolved_policy_issues: tuple[str, ...] = ()


class ResidualRisk(ReportModel):
    unresolved_vulnerabilities: tuple[str, ...] = ()
    blocked_remediation: tuple[str, ...] = ()
    accepted_exceptions: tuple[str, ...] = ()
    unverified_remediation: tuple[str, ...] = ()
    exposure_uncertainty: tuple[str, ...] = ()
    remaining_manual_review: tuple[str, ...] = ()


class TokenUsage(ReportModel):
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)


class Provenance(ReportModel):
    input_scanner_file_sha256: str | None = None
    audit_chain_head_hash: str | None = None
    model_provider: str | None = None
    model: str | None = None
    prompt_version: str | None = None
    token_usage: TokenUsage = TokenUsage()
    estimated_cost_usd: float | None = Field(default=None, ge=0)
    trace_reference: str | None = None
    source_evidence_references: tuple[SourceReference, ...] = ()


class ValidationNotes(ReportModel):
    missing_evidence: tuple[str, ...] = ()
    rejected_advisories: tuple[str, ...] = ()
    unknown_values: tuple[str, ...] = ()
    incomplete_execution: tuple[str, ...] = ()
    unsupported_claims: tuple[str, ...] = ()


class ExecutionEvidence(ReportModel):
    patch: StepState = StepState.NOT_RUN
    tests: StepState = StepState.NOT_RUN
    pull_request: StepState = StepState.NOT_RUN
    rescan: StepState = StepState.NOT_RUN


class RunReport(ReportModel):
    """Canonical report snapshot consumed unchanged by every renderer."""

    schema_version: str = "1.0.0"
    header: ReportHeader
    executive_summary: ExecutiveSummary
    action_required: tuple[ActionRequired, ...] = ()
    root_causes: tuple[RootCauseReport, ...] = ()
    policy_and_compliance: PolicyCompliance
    residual_risk: ResidualRisk
    provenance: Provenance
    validation_notes: ValidationNotes
    execution_evidence: ExecutionEvidence
