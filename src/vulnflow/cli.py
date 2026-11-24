"""
src/vulnflow/cli.py
Entrypoint CLI providing command line commands to scan, plan, and remediate.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

# Ensure src root is on sys.path when invoked directly
src_dir = str(Path(__file__).resolve().parent.parent)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from vulnflow.agents.planner import default_planner_agent
from vulnflow.contracts.state import VulnFlowState
from vulnflow.core import console
from vulnflow.observability.langsmith_tracer import langsmith_tracer
from vulnflow.orchestrator.graph import run_workflow
from vulnflow.reporting.builder import build_run_report
from vulnflow.reporting.html_report import write_html_report
from vulnflow.reporting.json_report import write_json_report
from vulnflow.reporting.markdown import write_markdown_report
from vulnflow.store.run_store import default_run_store

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("vulnflow.cli")


def _requested_report_formats(args: argparse.Namespace) -> list[str]:
    """Resolve new multi-format and legacy single-format CLI options."""
    legacy_format = getattr(args, "format", None)
    if legacy_format:
        return ["md" if legacy_format == "markdown" else legacy_format]
    raw = getattr(args, "output_format", None) or "html,md,json"
    aliases = {"markdown": "md", "htm": "html"}
    formats: list[str] = []
    for item in str(raw).split(","):
        normalized = aliases.get(item.strip().lower(), item.strip().lower())
        if normalized in {"html", "md", "json"} and normalized not in formats:
            formats.append(normalized)
    return formats or ["html", "md", "json"]


def _write_run_reports(result: VulnFlowState, args: argparse.Namespace) -> list[Path]:
    """Build one immutable snapshot and isolate failures from workflow exit status."""
    try:
        snapshot = build_run_report(result)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Run report snapshot could not be built: %s", exc)
        return []

    requested = _requested_report_formats(args)
    names = {"json": "run-report.json", "html": "report.html", "md": "report.md"}
    writers = {"json": write_json_report, "html": write_html_report, "md": write_markdown_report}

    legacy_output = getattr(args, "output", None)
    targets: list[tuple[str, Path]] = []

    if legacy_output:
        path = Path(legacy_output)
        suffix = path.suffix.lower()
        if suffix in {".json", ".html", ".htm", ".md"}:
            primary_fmt = "json" if suffix == ".json" else "html" if suffix in {".html", ".htm"} else "md"
            targets.append((primary_fmt, path))
            # Also output any other requested formats into the same parent directory
            base_dir = path.parent
            for fmt in requested:
                if fmt != primary_fmt:
                    target_name = names[fmt] if path.stem in {"report", "run-report"} else f"{path.stem}.{fmt}"
                    targets.append((fmt, base_dir / target_name))
        else:
            # path is a directory (e.g. --output /repo/.vulnflow/reports)
            for fmt in requested:
                targets.append((fmt, path / names[fmt]))
    else:
        env_reports = os.environ.get("VULNFLOW_REPORTS_DIR")
        if env_reports:
            base = Path(env_reports)
        elif getattr(args, "out_dir", None):
            base = Path(args.out_dir) / result.run_id
        else:
            repo_base = Path(getattr(args, "repo", ".")) if getattr(args, "repo", None) and str(args.repo) != "." else Path(".")
            if (repo_base / ".vulnflow" / "reports").exists():
                base = repo_base / ".vulnflow" / "reports"
            else:
                base = Path("vulnflow-report") / result.run_id

        for fmt in requested:
            targets.append((fmt, base / names[fmt]))

    # If markdown report is generated, make sure report.html is always generated alongside it
    # so that links to report.html in markdown are never broken
    has_md = any(fmt == "md" for fmt, _ in targets)
    has_html = any(fmt == "html" for fmt, _ in targets)
    if has_md and not has_html:
        md_target = next(p for fmt, p in targets if fmt == "md")
        html_target = md_target.parent / "report.html"
        targets.append(("html", html_target))

    # Ensure canonical json evidence is always persisted alongside reports
    has_json = any(fmt == "json" for fmt, _ in targets)
    if not has_json and targets:
        ref_path = targets[0][1]
        json_target = ref_path.parent / "run-report.json"
        targets.append(("json", json_target))

    written: list[Path] = []
    seen: set[Path] = set()
    for report_format, path in targets:
        if path in seen:
            continue
        seen.add(path)
        try:
            written.append(writers[report_format](snapshot, path))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not write %s run report to %s: %s", report_format, path, exc)
    return written


def _print_execution_summary(result: VulnFlowState) -> None:
    """Print structured, developer-friendly, colorful execution report to stdout."""
    width = 72
    try:
        report_snapshot = build_run_report(result)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not build evidence snapshot for console summary: %s", exc)
        report_snapshot = None
    print("\n" + console.box_header(f"🛡️  VulnFlow Execution Summary  [Run: {result.run_id}]", width=width))

    pending_cnt = (
        len(result.pending_approval_plans)
        if getattr(result, "pending_approval_plans", None)
        else len([p for p in result.plans if p.requires_approval and p not in result.approved_plans])
    )
    status_badge = console.status_badge(result.terminal_status, result.exit_code)

    print(f"  {console.gray('Execution Status:')} {status_badge}")
    print(f"  {console.gray('Target Repo:')}      {console.bold(console.white(result.repo_path))}")
    print(f"  {console.gray('Discovered:')}       {console.bold(str(len(result.findings)))} raw findings ({console.green(str(len(result.deduped_findings)))} unique deduped)")
    print(f"  {console.gray('Root Causes:')}      {console.cyan(console.bold(str(len(result.root_cause_groups))))} dependency cluster(s)")
    print(f"  {console.gray('Remediations:')}     {console.yellow(console.bold(str(len(result.plans))))} plans generated ({console.green(str(len(result.approved_plans)))} approved, {console.yellow(str(pending_cnt))} pending review)")
    applied_count = report_snapshot.executive_summary.fixes_applied if report_snapshot else 0
    pr_count = report_snapshot.executive_summary.prs_actually_created if report_snapshot else 0
    print(f"  {console.gray('Patches Applied:')}  {console.cyan(console.bold(str(applied_count)))}")
    print(f"  {console.gray('Pull Requests:')}    {console.green(console.bold(str(pr_count)))} opened")

    # 1. Pending approval warning
    if result.terminal_status == "pending_approval" or (getattr(result, "pending_approval_plans", None) and not result.approved_plans):
        pending = result.pending_approval_plans or [p for p in result.plans if p.requires_approval and p not in result.approved_plans]
        print(console.section_divider("⚡ Human Security Approval Required (Exit Code: 10)", width=width, color_fn=console.yellow))
        print(f"  {console.yellow('• Status:')}      {console.bold(str(len(pending)))} plan(s) paused awaiting human authorization.")
        print(f"  {console.yellow('• Reason:')}      Review-tier remediations (secrets, PII, or unvetted dependencies).")
        print(f"  {console.yellow('• Safeguard:')}   PR creation withheld to prevent merging unvetted changes.")
        print(f"\n  {console.bold(console.yellow('👉 Action Required - Next Steps to Approve & Resume:'))}")
        for idx, p in enumerate(pending, 1):
            target = p.target_package or p.root_cause_id
            print(f"    [{console.bold(str(idx))}] Plan ID: {console.cyan(p.id)} ({console.bold(target)})")
            print(f"        {console.dim('CLI Command:')} {console.green(f'vulnflow approve --plan-id {p.id} --resume --repo {result.repo_path}')}")
            print(f"        {console.dim('Web UI:')}     Open {console.cyan('http://localhost:8000/#/approval')} to authorize with 1 click")
    # 2. Blocking reason and exception guidance if run halted
    elif result.terminal_status == "blocked_policy" or result.blocking_reason or result.exception_ticket:
        t_id = result.exception_ticket.get("ticket_id", "SEC-UNKNOWN") if result.exception_ticket else "SEC-ESCALATED"
        t_url = result.exception_ticket.get("ticket_url", "#") if result.exception_ticket else "#"
        print(console.section_divider("✖ Policy Safety Gate Blocked Execution (Exit Code: 20)", width=width, color_fn=console.red))
        print(f"  {console.red('• Blocking Reason:')} {result.blocking_reason or 'Policy safety gate blocked automated PR opening.'}")
        print(f"  {console.red('• Ticket:')}          {console.bold(t_id)} ({t_url})")
        print(f"  {console.red('• Safeguard:')}       PR creation halted to protect codebase integrity.")
        print(f"  {console.red('• Next Action:')}     Review failing tests or request approval via security ticket.")

    # 3. Findings Breakdown
    if result.deduped_findings:
        print(console.section_divider("📌 Discovered Vulnerabilities", width=width))
        for idx, f in enumerate(result.deduped_findings, 1):
            cves = ", ".join(f.cve) if f.cve else "N/A"
            sev = f.severity.value.upper() if hasattr(f.severity, "value") else str(f.severity).upper()
            fixes = ", ".join(f.fix_versions) if f.fix_versions else "None"
            sev_pill = console.severity_badge(sev)
            print(f"  [{console.bold(str(idx))}] {console.bold(f.package)}@{console.dim(f.version)} {sev_pill} | {console.gray('CVE:')} {console.yellow(cves)} | {console.gray('Fix:')} {console.green(fixes)}")

    # 4. AI Remediation Plans
    if result.plans:
        print(console.section_divider("🧠 AI Remediation Plans & Strategy", width=width))
        for idx, plan in enumerate(result.plans, 1):
            act = plan.action.value.upper() if hasattr(plan.action, "value") else str(plan.action).upper()
            tier = plan.risk_tier.value.upper() if hasattr(plan.risk_tier, "value") else str(plan.risk_tier).upper()
            pol = plan.policy_result.status.upper() if plan.policy_result else "APPROVED"

            pol_str = console.green(pol) if pol == "APPROVED" else console.red(pol)
            tier_str = console.green(tier) if tier == "AUTO" else console.yellow(tier)
            act_badge = console.action_badge(act)

            print(f"  {console.bold(f'Plan #{idx}:')} [{act_badge}] {console.bold(console.white(plan.target_package or plan.root_cause_id))}")
            print(f"    • {console.gray('Plan ID:')}        {console.cyan(plan.id)}")
            print(f"    • {console.gray('Target Version:')} {console.green(plan.target_version or 'N/A')}")
            print(f"    • {console.gray('Risk Tier:')}      {tier_str} (Requires Approval: {plan.requires_approval})")
            print(f"    • {console.gray('Policy Check:')}   {pol_str}")
            print(f"    • {console.gray('AI Guidance:')}")
            for line in plan.rationale.strip().split("\n"):
                print(f"        {console.dim(line)}")

    # 5. Pull Requests Opened
    if result.mode == "pr" and pr_count and result.pull_requests:
        print(console.section_divider("🚀 Opened Pull Request(s)", width=width, color_fn=console.green))
        for pr in result.pull_requests:
            title = pr.get("title", "Pull Request")
            branch = pr.get("branch", "unknown")
            url = pr.get("pr_url", "#")
            print(f"  • {console.bold(title)}")
            print(f"    {console.gray('Branch:')} {console.cyan(branch)}")
            print(f"    {console.gray('PR URL:')} {console.blue(console.underline(url))}")

    # 6. Verification
    if result.verification_results and report_snapshot:
        evidence = report_snapshot.execution_evidence
        ver = result.verification_results[0]
        if evidence.rescan.value == "executed":
            clean = console.green("✔ RESOLVED (0 remaining vulnerabilities)") if ver.get("rescan_clean") else console.yellow("⚠ RESIDUAL FINDINGS REMAIN")
        else:
            clean = console.yellow("UNKNOWN (no executed rescan evidence)")
        if evidence.tests.value == "executed":
            tests = console.green("✔ PASSED")
        elif evidence.tests.value == "failed":
            tests = console.red("✖ FAILED")
        else:
            tests = console.yellow("UNKNOWN (no executed test evidence)")
        print(console.section_divider("🧪 Verification & Build Evidence", width=width))
        print(f"  • {console.gray('Sandbox Test Suite:')}  {tests}")
        print(f"  • {console.gray('Rescan Verification:')} {clean}")

    # 7. LangSmith Distributed Tracing & Observability
    print(console.section_divider("🌐 Distributed Tracing & Observability", width=width))
    if langsmith_tracer.is_enabled():
        trace_url = langsmith_tracer.get_run_url(result.run_id)
        print(f"  • {console.gray('LangSmith Engine:')}  {console.green(console.bold('● CONNECTED'))} [Project: {console.cyan(langsmith_tracer.project)}]")
        if trace_url:
            print(f"  • {console.gray('Trace Deep-Link:')}   {console.blue(console.underline(trace_url))}")
    else:
        hint = console.dim("export LANGSMITH_API_KEY='<your-api-key>' to stream traces live")
        print(f"  • {console.gray('LangSmith Engine:')}  {console.dim('○ INACTIVE (Local audit logging active)')}")
        print(f"  • {console.gray('Enable Tracing:')}    {hint}")

    if result.audit_events:
        audit_file = f".vulnflow/audit/audit_{result.run_id}.jsonl"
        print(f"  • {console.gray('Local Audit Log:')}   {console.cyan(audit_file)} ({console.bold(str(len(result.audit_events)))} events logged)")
        print(f"  • {console.gray('Action Sequence:')}")
        for idx, ev in enumerate(result.audit_events, 1):
            ev_name = ev.get("event_type", "UNKNOWN")
            actor = ev.get("actor", "system")
            payload = ev.get("payload", {})
            summary_info = ""
            if "findings_count" in payload:
                summary_info = f"({payload['findings_count']} findings parsed)"
            elif "plans_count" in payload:
                summary_info = f"({payload['plans_count']} plans generated)"
            elif "target_package" in payload and "target_version" in payload:
                summary_info = f"({payload.get('target_package')} -> {payload.get('target_version')})"
            elif "branch" in payload and "file" in payload:
                summary_info = f"({payload.get('file')} on {payload.get('branch')})"
            elif "pr_url" in payload:
                summary_info = f"({payload.get('pr_url')})"
            elif "rescan_clean" in payload:
                summary_info = "(clean rescan)" if payload["rescan_clean"] else "(residual findings)"
            print(f"    [{console.cyan(f'{idx:02d}')}] {console.bold(ev_name):<30} | {console.gray(actor):<16} {console.dim(summary_info)}")

    print(f"\n{console.cyan('─' * width)}\n")


def _detect_scanner_format(report_path: str) -> str:
    """Sniff report file content or filename to determine scanner format automatically."""
    p = Path(report_path)
    p_lower = str(report_path).lower()
    if "gitleaks" in p_lower:
        return "gitleaks"
    if p_lower.endswith(".sarif") or "sarif" in p_lower:
        return "sarif"
    if "grype" in p_lower:
        return "grype"
    if "snyk" in p_lower:
        return "snyk"
    if "osv" in p_lower:
        return "osv"
    if p.exists() and p.is_file():
        try:
            with open(p, "r", encoding="utf-8") as f:
                snippet = f.read(3000)
            if '"runs"' in snippet and '"tool"' in snippet:
                return "sarif"
            if '"Secret"' in snippet or '"RuleID"' in snippet or '"Fingerprint"' in snippet:
                return "gitleaks"
            if '"matches"' in snippet and '"artifact"' in snippet:
                return "grype"
            if '"SchemaVersion"' in snippet or '"Results"' in snippet:
                return "trivy"
            if '"vulnerabilities"' in snippet and "snyk" in snippet.lower():
                return "snyk"
        except (OSError, UnicodeDecodeError):
            pass
    return "trivy"


def cmd_analyze(args: argparse.Namespace) -> int:
    """Execute vulnerability analysis, planning, and optional remediation."""
    if getattr(args, "no_llm", False):
        default_planner_agent.enable_llm = False
    else:
        default_planner_agent.enable_llm = True

    # Configure LangSmith overrides if specified
    if getattr(args, "langsmith_project", None):
        os.environ["LANGCHAIN_PROJECT"] = args.langsmith_project
        langsmith_tracer.project = args.langsmith_project
    if getattr(args, "langsmith", False):
        os.environ["LANGCHAIN_TRACING_V2"] = "true"
        langsmith_tracer.init_from_env()
    elif getattr(args, "no_langsmith", False):
        os.environ["LANGCHAIN_TRACING_V2"] = "false"
        langsmith_tracer.enabled = False

    report_path = args.report
    scanner = getattr(args, "scanner", None)

    # If report was provided without an explicit scanner, auto-detect the scanner format from file
    if report_path and not scanner:
        scanner = _detect_scanner_format(report_path)
        logger.info("Auto-detected scanner format '%s' from report: %s", scanner, report_path)

    # Auto-detect scanner report if not explicitly provided
    if not report_path:
        repo_p = Path(args.repo)
        candidates = [
            (repo_p / "scan-results.json", None),
            (repo_p / "trivy.json", "trivy"),
            (repo_p / "trivy-results.json", "trivy"),
            (repo_p / "trivy-report.json", "trivy"),
            (repo_p / "results.sarif", "sarif"),
            (repo_p / "report.sarif", "sarif"),
            (repo_p / "gitleaks.json", "gitleaks"),
            (repo_p / "grype.json", "grype"),
            (repo_p / "snyk.json", "snyk"),
        ]
        for c_path, c_scanner in candidates:
            if c_path.exists():
                report_path = str(c_path)
                if not scanner:
                    scanner = c_scanner or _detect_scanner_format(report_path)
                logger.info("Auto-detected security report at %s (scanner: %s)", report_path, scanner)
                break

    # If still no scanner, default to trivy
    if not scanner:
        scanner = "trivy"

    state = VulnFlowState(
        repo_path=args.repo,
        report_path=report_path,
        scanner=scanner,
        mode=args.mode,
        ecosystem=args.ecosystem,
        auto_approve=getattr(args, "auto_approve", False),
    )
    result = run_workflow(state)
    default_run_store.save_run(result)
    _print_execution_summary(result)

    # Export all renderers from one immutable evidence snapshot. Failures do not alter exit_code.
    written_reports = _write_run_reports(result, args)
    for report_path in written_reports:
        print(f"Report written to: {report_path}")
    if written_reports:
        print()

    repo_base = Path(args.repo) if getattr(args, "repo", None) and str(args.repo) != "." else Path(".")

    # Also persist audit events into repo_base/.vulnflow/audit
    env_audit = os.environ.get("VULNFLOW_AUDIT_DIR")
    audit_dir = Path(env_audit) if env_audit else (repo_base / ".vulnflow" / "audit")
    try:
        audit_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(audit_dir.parent, 0o755)
            os.chmod(audit_dir, 0o755)
        except OSError:
            pass
        if result.audit_events:
            audit_file = audit_dir / f"audit_{result.run_id}.jsonl"
            with open(audit_file, "w", encoding="utf-8") as f:
                f.writelines(json.dumps(ev) + "\n" for ev in result.audit_events)
            try:
                os.chmod(audit_file, 0o644)
            except OSError:
                pass
    except (OSError, TypeError) as exc:
        logger.debug("Could not write audit events to %s: %s", audit_dir, exc)

    # Ensure all LangSmith traces are flushed before exit
    if langsmith_tracer.is_enabled():
        langsmith_tracer.flush(timeout=4.0)

    return result.exit_code


def cmd_report(args: argparse.Namespace) -> int:
    """Render findings and proposed plan summary without applying code changes."""
    args.mode = "report"
    return cmd_analyze(args)


def cmd_fix(args: argparse.Namespace) -> int:
    """Execute an approved remediation plan."""
    logger.info("Executing fix for plan %s on repository %s", args.plan_id, args.repo)
    state = VulnFlowState(repo_path=args.repo, mode="pr")
    result = run_workflow(state)
    default_run_store.save_run(result)
    return result.exit_code


def cmd_verify(args: argparse.Namespace) -> int:
    """Rescan a branch and confirm finding resolution."""
    logger.info("Verifying branch %s against baseline findings", args.branch)
    state = VulnFlowState(repo_path=args.repo, mode="report")
    result = run_workflow(state)
    return result.exit_code


def cmd_approve(args: argparse.Namespace) -> int:
    """Record human approval or rejection for review-tier plan(s) and optionally resume execution."""
    from vulnflow.orchestrator.approval import global_approval_gate, load_run_state

    raw_plan_id = getattr(args, "plan_id", None)
    approve_all = getattr(args, "all", False) or (raw_plan_id and raw_plan_id.lower() in ("all", "*"))
    is_reject = getattr(args, "reject", False)
    reviewer = getattr(args, "reviewer", "security-lead")
    reason = getattr(args, "reason", None)
    repo = getattr(args, "repo", ".")

    target_plan_ids = []
    if approve_all:
        target_plan_ids = ["all"]
        pending_list = global_approval_gate.list_pending()
        if pending_list:
            target_plan_ids.extend(pending_list)
    elif raw_plan_id:
        target_plan_ids = [pid.strip() for pid in raw_plan_id.split(",") if pid.strip()]

    if not target_plan_ids:
        print("\n❌ Error: Please specify --plan-id <ID> (or comma-separated list), or pass --all.\n")
        return 1

    # Record decisions in persistent approval gate (F21)
    for pid in target_plan_ids:
        global_approval_gate.record_decision(
            plan_id=pid,
            approved=(not is_reject),
            reviewer=reviewer,
            reason=reason,
            repo_path=repo,
        )

    summary_targets = "ALL pending plans" if approve_all else ", ".join(target_plan_ids)
    if is_reject:
        print(f"\n🛑 Plan(s) {summary_targets} REJECTED by {reviewer}. Reason: {reason or 'No reason provided'}\n")
        return 0

    print(f"\n✅ Plan(s) {summary_targets} APPROVED by {reviewer}.")

    # Resume workflow if requested
    if getattr(args, "resume", False):
        print(f"🔄 Resuming workflow execution for repository {repo}...")
        saved_state = load_run_state(repo_path=repo)
        if saved_state:
            result = run_workflow(saved_state)
        else:
            state = VulnFlowState(repo_path=repo, mode="pr")
            result = run_workflow(state)
        default_run_store.save_run(result)
        _print_execution_summary(result)

        written_reports = _write_run_reports(result, args)
        for report_p in written_reports:
            print(f"Report written to: {report_p}")

        repo_base = Path(repo) if repo and str(repo) != "." else Path(".")
        env_audit = os.environ.get("VULNFLOW_AUDIT_DIR")
        audit_dir = Path(env_audit) if env_audit else (repo_base / ".vulnflow" / "audit")
        try:
            audit_dir.mkdir(parents=True, exist_ok=True)
            if result.audit_events:
                audit_file = audit_dir / f"audit_{result.run_id}.jsonl"
                with open(audit_file, "w", encoding="utf-8") as f:
                    f.writelines(json.dumps(ev) + "\n" for ev in result.audit_events)
        except (OSError, TypeError) as exc:
            logger.debug("Could not write audit events to %s: %s", audit_dir, exc)

        return result.exit_code

    print(f"Run 'vulnflow analyze --repo {repo}' to apply approved plan(s).\n")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Inspect and trace audit events for a given run."""
    import datetime

    from vulnflow.observability.audit_log import audit_logger

    run_id = args.run_id
    events: list[dict[str, Any]] = []

    # 1. Search in-memory events
    mem_events = audit_logger.get_events(run_id)
    events.extend([e.to_dict() for e in mem_events])

    # 2. Search persistent disk files in .vulnflow/audit
    audit_dir = Path(".vulnflow/audit")
    if audit_dir.exists():
        files_to_check = []
        if run_id:
            target_f = audit_dir / f"audit_{run_id}.jsonl"
            if target_f.exists():
                files_to_check.append(target_f)
        else:
            files_to_check = sorted(audit_dir.glob("audit_*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)[:1]

        for f in files_to_check:
            try:
                with open(f, "r", encoding="utf-8") as fp:
                    for line in fp:
                        if line.strip():
                            events.append(json.loads(line))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Could not read audit file %s: %s", f, exc)

    if not events:
        print(f"No audit records found for run {run_id or 'latest'}.")
        return 1

    width = 75
    effective_run = run_id or events[0].get("run_id", "latest")
    print("\n" + "=" * width)
    print(f"📋 VulnFlow Audit Trail [Run: {effective_run}]")
    print("=" * width)
    seen = set()
    counter = 1
    for e in events:
        ts = e.get("timestamp", 0)
        ev_type = e.get("event_type", "UNKNOWN")
        actor = e.get("actor", "system")
        key = (ts, ev_type, actor)
        if key in seen:
            continue
        seen.add(key)

        dt_str = datetime.datetime.fromtimestamp(ts, tz=datetime.UTC).strftime("%H:%M:%S.%f")[:-3]
        print(f"[{counter:02d}] {dt_str} | {ev_type:<26} | by {actor:<15}")
        payload = e.get("payload", {})
        if payload:
            for k, v in payload.items():
                if k == "node":
                    continue
                v_str = str(v)
                if len(v_str) > 75:
                    v_str = v_str[:72] + "..."
                print(f"     • {k}: {v_str}")
        counter += 1
    print("=" * width + "\n")
    return 0


def cmd_watch_expiry(args: argparse.Namespace) -> int:
    """Inspect and alert on expiring certificates, tokens, or policy waivers."""
    from vulnflow.agents.expiry import default_expiry_agent

    logger.info("Scanning repository %s for expiring artifacts (warning window: %d days)", args.repo, args.days)
    if getattr(args, "auto_renew", False):
        results = default_expiry_agent.automate_renewals(repo_path=args.repo, warning_days=args.days)
    else:
        results = default_expiry_agent.scan_expiring_artifacts(repo_path=args.repo, warning_days=args.days)

    print("\n" + "=" * 68)
    print(f"⏳  VulnFlow Expiry Monitor [{len(results)} artifact(s) found]")
    print("=" * 68)
    for idx, item in enumerate(results, 1):
        status = item.get("status", "EXPIRING").upper()
        print(f"  [{idx}] {item.get('name')} ({item.get('type')}) - Expires in {item.get('days_remaining')} day(s) [{status}]")
        print(f"      • Expiry Date:  {item.get('expires_at')}")
        print(f"      • Risk Window:  {item.get('risk_window')}")
        if item.get("action"):
            print(f"      • Action:       {item.get('action')}")
        if item.get("ticket"):
            print(f"      • Ticket:       {item.get('ticket', {}).get('ticket_id')}")
    print("=" * 68 + "\n")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Launch unified VulnFlow API and Web Dashboard server."""
    import os
    import subprocess
    import threading
    import time
    import webbrowser

    host = getattr(args, "host", "0.0.0.0")
    port = getattr(args, "port", 8000)
    dev_mode = getattr(args, "dev", False)
    build_ui = getattr(args, "build_ui", False)
    auto_open = getattr(args, "open", False)
    reload_backend = getattr(args, "reload", False)

    # Locate directories relative to source
    repo_root = Path(__file__).resolve().parent.parent.parent
    ui_dir = repo_root / "ui"
    dist_dir = ui_dir / "dist"

    # Build UI bundle if requested or if missing in production mode
    use_shell = sys.platform == "win32"
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    if (build_ui or (not dev_mode and not (dist_dir / "index.html").exists())) and (ui_dir / "package.json").exists():
        print("\n📦 Building frontend Web Dashboard bundle (Vite + React)...")
        try:
            subprocess.run([npm_cmd, "run", "build"], cwd=str(ui_dir), check=True, shell=use_shell)
            print("✅ Frontend dashboard built successfully.\n")
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("Could not build frontend bundle: %s", exc)

    vite_proc = None
    if dev_mode and (ui_dir / "package.json").exists():
        print(f"\n🚀 Launching Vite Dev Server (connecting to API on http://localhost:{port})...")
        env = os.environ.copy()
        env["VITE_API_BASE_URL"] = f"http://localhost:{port}"
        try:
            vite_proc = subprocess.Popen([npm_cmd, "run", "dev"], cwd=str(ui_dir), env=env, shell=use_shell)
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("Could not start Vite dev process: %s", exc)

    target_url = "http://localhost:5173" if (dev_mode and vite_proc) else f"http://localhost:{port}"

    width = 68
    print("\n" + "=" * width)
    print("🛡️   VulnFlow AI Autonomous Remediation Platform")
    print("=" * width)
    print(f"  • Web Dashboard:     {target_url}")
    print(f"  • REST API Endpoint: http://localhost:{port}/api/runs")
    print(f"  • OpenAPI Docs:      http://localhost:{port}/docs")
    print(f"  • Engine Mode:       {'Development (Vite HMR + API)' if dev_mode else 'Production (Unified UI + API)'}")
    print("=" * width)
    print("  👉 Open Web Dashboard in your browser to inspect runs & approvals.")
    print("  👉 Press Ctrl+C to terminate the server.\n")

    if auto_open:
        def _open():
            time.sleep(1.2)
            webbrowser.open(target_url)
        threading.Thread(target=_open, daemon=True).start()

    # Ensure repository root is on sys.path so api.main can be imported
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    try:
        try:
            import uvicorn  # type: ignore[import-not-found]
            uvicorn.run("api.main:app", host=host, port=port, reload=reload_backend)
        except ImportError:
            print("ℹ️  Running on built-in multi-threaded HTTP server (zero pip packages required).")
            print("   Tip: For optional high-concurrency ASGI, install uvicorn: pip install uvicorn\n")
            from vulnflow.api.builtin_server import run_builtin_server
            run_builtin_server(host=host, port=port, dist_dir=dist_dir)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down VulnFlow server...")
    finally:
        if vite_proc:
            print("Stopping Vite dev server...")
            vite_proc.terminate()
            try:
                vite_proc.wait(timeout=3)
            except (subprocess.SubprocessError, OSError):
                vite_proc.kill()

    return 0


CLI_EPILOG = """
Commands:
  scan, analyze      Scan repository, deduplicate findings, and formulate/apply fixes
  report             Generate vulnerability assessment report only (read-only, no code changes)
  serve              Start unified Web Dashboard & REST API on http://localhost:8000
  approve            Authorize or reject review-tier remediation plan
  fix                Apply patch for an approved plan
  verify             Verify that a branch resolves target findings
  audit              Inspect chronological audit trail of a run
  watch-expiry       Inspect and alert on expiring certificates, tokens, or waivers

Attributes & Options for scan / analyze / report:
  --repo PATH               Target repository directory path (default: .)
  --mode {report,pr,dry-run} Execution mode (default: pr for scan, report for report)
                            • report:  read-only assessment, no code changes
                            • pr:      fix, test in sandbox, and open GitHub PR
                            • dry-run: local patch & test without remote PR
  --report PATH             Path to scanner JSON or SARIF report (auto-detected if omitted)
  --scanner {trivy,grype,snyk,gitleaks}
                            Scanner engine format (default: trivy)
  --ecosystem {npm,maven,pip}
                            Primary package ecosystem (default: npm)
  --output, -o PATH         Destination file path to save report (e.g. report.md, report.json)
  --output-format FORMATS   Comma-separated html,md,json (default: html,md,json)
  --out-dir PATH            Output root (default: ./vulnflow-report/<run-id>/)
  --format {markdown,json}  Legacy single-format option
  --auto-approve            Auto-approve review-tier plans without waiting for human sign-off
  --no-llm                  Skip remote LLM calls and use fast deterministic rule planner
  --langsmith               Enable LangSmith distributed tracing
  --no-langsmith            Explicitly disable LangSmith distributed tracing
  --langsmith-project NAME  LangSmith project name (default: vulnflow)

Web Dashboard & Server (serve):
  --port PORT               Port to listen on (default: 8000)
  --host HOST               Binding host address (default: 0.0.0.0)
  --dev                     Launch Vite development server with hot module reloading on :5173
  --build-ui                Rebuild frontend React bundle before starting
  --open                    Automatically open browser to Dashboard URL

Governance & Approvals (approve):
  --plan-id ID              Remediation plan ID (required)
  --resume                  Automatically resume workflow execution and create PR upon approval
  --reviewer EMAIL/NAME     Reviewer identifier or email (default: security-lead)
  --reason TEXT             Explanation or justification for decision
  --reject                  Reject the remediation plan instead of approving

Quick Recipes:
  vulnflow scan --repo fake-vuln-repo --mode report
  vulnflow scan --repo fake-vuln-repo --mode pr
  vulnflow scan --repo fake-vuln-repo --mode pr --auto-approve
  vulnflow report --repo fake-vuln-repo --format json -o audit.json
  vulnflow approve --plan-id PLAN-SEC-FND-e750 --resume --repo fake-vuln-repo
  vulnflow serve
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulnflow",
        description="🛡️ VulnFlow AI - Autonomous Vulnerability Remediation & Security Fabric",
        epilog=CLI_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Friendly quick start when invoked with no arguments
    raw_args = argv if argv is not None else sys.argv[1:]
    if not raw_args:
        parser.print_help()
        return 0

    subparsers = parser.add_subparsers(dest="command", required=True)

    # serve
    p_serve = subparsers.add_parser("serve", help="Launch unified VulnFlow API and Web Dashboard server")
    p_serve.add_argument("--host", default="0.0.0.0", help="Binding host address (default: 0.0.0.0)")
    p_serve.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    p_serve.add_argument("--dev", action="store_true", help="Launch Vite in development mode with HMR")
    p_serve.add_argument("--build-ui", action="store_true", help="Rebuild frontend bundle before starting")
    p_serve.add_argument("--reload", action="store_true", help="Auto-reload backend on Python file modifications")
    p_serve.add_argument("--open", action="store_true", help="Automatically open browser to Dashboard URL")
    p_serve.set_defaults(func=cmd_serve)

    # scan (convenient alias for analyze)
    p_scan = subparsers.add_parser("scan", help="Scan repository, deduplicate findings, and generate remediation plans")
    p_scan.add_argument("--repo", default=".", help="Target repository directory path")
    p_scan.add_argument("--report", help="Path to scanner JSON or SARIF report (auto-detected if omitted)")
    p_scan.add_argument("--scanner", default=None, help="Security scanner name (auto-detected if --report is provided; defaults to trivy)")
    p_scan.add_argument("--mode", choices=["report", "pr", "dry-run"], default="pr", help="Execution mode (default: pr)")
    p_scan.add_argument("--ecosystem", default="npm", help="Primary package ecosystem (npm, maven)")
    p_scan.add_argument("--output", "-o", help="File path to save the generated report")
    p_scan.add_argument("--format", choices=["markdown", "json"], default=None, help="Legacy single report format")
    p_scan.add_argument("--output-format", default="html,md,json", help="Comma-separated report formats: html,md,json")
    p_scan.add_argument("--out-dir", help="Report output root (default: ./vulnflow-report)")
    p_scan.add_argument("--no-llm", action="store_true", help="Skip remote LLM calls and use fast deterministic planner")
    p_scan.add_argument("--auto-approve", action="store_true", help="Auto-approve review-tier plans without waiting for human sign-off")
    p_scan.add_argument("--langsmith", action="store_true", help="Enable LangSmith distributed tracing")
    p_scan.add_argument("--no-langsmith", action="store_true", help="Explicitly disable LangSmith tracing")
    p_scan.add_argument("--langsmith-project", help="LangSmith project name (default: vulnflow)")
    p_scan.set_defaults(func=cmd_analyze)

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Ingest a report, group, plan, and remediate")
    p_analyze.add_argument("--repo", default=".", help="Target repository directory path")
    p_analyze.add_argument("--report", help="Path to scanner JSON or SARIF report (auto-detected if omitted)")
    p_analyze.add_argument("--scanner", default=None, help="Security scanner name (auto-detected if --report is provided; defaults to trivy)")
    p_analyze.add_argument("--mode", choices=["report", "pr", "dry-run"], default="pr", help="Execution mode (default: pr)")
    p_analyze.add_argument("--ecosystem", default="npm", help="Primary package ecosystem (npm, maven)")
    p_analyze.add_argument("--output", "-o", help="File path to save the generated report (e.g., report.md or report.json)")
    p_analyze.add_argument("--format", choices=["markdown", "json"], default=None, help="Legacy single report format")
    p_analyze.add_argument("--output-format", default="html,md,json", help="Comma-separated report formats: html,md,json")
    p_analyze.add_argument("--out-dir", help="Report output root (default: ./vulnflow-report)")
    p_analyze.add_argument("--no-llm", action="store_true", help="Skip remote LLM calls and use fast deterministic planner")
    p_analyze.add_argument("--auto-approve", action="store_true", help="Auto-approve review-tier plans without waiting for human sign-off")
    p_analyze.add_argument("--langsmith", action="store_true", help="Enable LangSmith distributed tracing")
    p_analyze.add_argument("--no-langsmith", action="store_true", help="Explicitly disable LangSmith tracing")
    p_analyze.add_argument("--langsmith-project", help="LangSmith project name (default: vulnflow)")
    p_analyze.set_defaults(func=cmd_analyze)

    # report
    p_report = subparsers.add_parser("report", help="Analyze and output report only without code changes")
    p_report.add_argument("--repo", default=".", help="Target repository directory path")
    p_report.add_argument("--report", help="Path to scanner JSON or SARIF report")
    p_report.add_argument("--scanner", default=None, help="Security scanner name (auto-detected if --report is provided; defaults to trivy)")
    p_report.add_argument("--ecosystem", default="npm", help="Package ecosystem")
    p_report.add_argument("--output", "-o", help="File path to save the generated report")
    p_report.add_argument("--format", choices=["markdown", "json"], default=None, help="Legacy single report format")
    p_report.add_argument("--output-format", default="html,md,json", help="Comma-separated report formats: html,md,json")
    p_report.add_argument("--out-dir", help="Report output root (default: ./vulnflow-report)")
    p_report.add_argument("--no-llm", action="store_true", help="Skip remote LLM calls and use fast deterministic planner")
    p_report.set_defaults(func=cmd_report)

    # fix
    p_fix = subparsers.add_parser("fix", help="Execute an approved plan")
    p_fix.add_argument("--plan-id", required=True, help="ID of the approved remediation plan")
    p_fix.add_argument("--repo", default=".", help="Repository directory path")
    p_fix.set_defaults(func=cmd_fix)

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify that a branch resolves target findings")
    p_verify.add_argument("--branch", required=True, help="Remediated branch name")
    p_verify.add_argument("--repo", default=".", help="Repository directory path")
    p_verify.set_defaults(func=cmd_verify)

    # approve
    p_approve = subparsers.add_parser("approve", help="Record human approval or rejection for review-tier plan(s)")
    p_approve.add_argument("--plan-id", default=None, help="Remediation plan ID (or 'all', or comma-separated list)")
    p_approve.add_argument("--all", action="store_true", help="Authorize all pending plans in the repository")
    p_approve.add_argument("--reject", action="store_true", help="Reject the remediation plan instead of approving")
    p_approve.add_argument("--reviewer", default="security-lead", help="Reviewer identifier or email")
    p_approve.add_argument("--reason", help="Explanation or justification for decision")
    p_approve.add_argument("--resume", action="store_true", help="Automatically resume workflow execution on approval")
    p_approve.add_argument("--repo", default=".", help="Repository directory path")
    p_approve.set_defaults(func=cmd_approve)

    # audit
    p_audit = subparsers.add_parser("audit", help="Inspect chronological audit trail of a run")
    p_audit.add_argument("--run-id", help="Run ID to inspect (defaults to latest)")
    p_audit.set_defaults(func=cmd_audit)

    # watch-expiry
    p_watch = subparsers.add_parser("watch-expiry", help="Inspect and alert on expiring certificates, tokens, or waivers")
    p_watch.add_argument("--repo", default=".", help="Repository directory path")
    p_watch.add_argument("--days", type=int, default=30, help="Warning window in days (default: 30)")
    p_watch.add_argument("--auto-renew", action="store_true", help="Automatically open renewal tickets for expiring artifacts")
    p_watch.set_defaults(func=cmd_watch_expiry)

    parsed = parser.parse_args(argv)
    return parsed.func(parsed)


if __name__ == "__main__":
    sys.exit(main())
