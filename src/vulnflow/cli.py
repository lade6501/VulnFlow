"""
src/vulnflow/cli.py
Entrypoint CLI providing command line commands to scan, plan, and remediate.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Ensure src root is on sys.path when invoked directly
src_dir = str(Path(__file__).resolve().parent.parent)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from vulnflow.agents.planner import default_planner_agent
from vulnflow.contracts.state import VulnFlowState
from vulnflow.orchestrator.graph import run_workflow
from vulnflow.reporting.json_report import write_json_report
from vulnflow.reporting.markdown import write_markdown_report
from vulnflow.store.run_store import default_run_store

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("vulnflow.cli")


def _print_execution_summary(result: VulnFlowState) -> None:
    """Print structured, developer-friendly execution report to stdout."""
    width = 68
    print("\n" + "=" * width)
    print(f"🛡️  VulnFlow Execution Summary [Run: {result.run_id}]")
    print("=" * width)
    print(f"Status:       {result.terminal_status.upper()}")
    print(f"Exit Code:    {result.exit_code}")
    print(f"Findings:     {len(result.findings)} discovered ({len(result.deduped_findings)} deduped)")
    print(f"Root Causes:  {len(result.root_cause_groups)} group(s)")
    pending_cnt = len(result.pending_approval_plans) if getattr(result, "pending_approval_plans", None) else len([p for p in result.plans if p.requires_approval and p not in result.approved_plans])
    print(f"Plans:        {len(result.plans)} generated ({len(result.approved_plans)} approved, {pending_cnt} pending review)")
    print(f"Patches:      {len(result.patches)} applied")
    print(f"Pull Requests:{len(result.pull_requests)} opened")

    # Pending approval warning
    if result.terminal_status == "pending_approval" or (getattr(result, "pending_approval_plans", None) and not result.approved_plans):
        pending = result.pending_approval_plans or [p for p in result.plans if p.requires_approval and p not in result.approved_plans]
        print("\n" + "-" * width)
        print("⚠️  Human Security Approval Required (Exit Code: 10):")
        print(f"  • Status:      {len(pending)} plan(s) paused awaiting human authorization.")
        print(f"  • Reason:      Review-tier remediations (secrets, PII, or unvetted dependencies).")
        print(f"  • Safeguard:   PR creation withheld to prevent merging unvetted changes.")
        print("\n  👉 Next Steps to Approve & Resume:")
        for idx, p in enumerate(pending, 1):
            target = p.target_package or p.root_cause_id
            print(f"    [{idx}] Plan ID: {p.id} ({target})")
            print(f"        Command: python3 src/vulnflow/cli.py approve --plan-id {p.id} --reviewer \"<your-email>\" --resume --repo {result.repo_path}")
    # Blocking reason and exception guidance if run halted
    elif result.terminal_status == "blocked_policy" or result.blocking_reason or result.exception_ticket:
        t_id = result.exception_ticket.get("ticket_id", "SEC-UNKNOWN") if result.exception_ticket else "SEC-ESCALATED"
        t_url = result.exception_ticket.get("ticket_url", "#") if result.exception_ticket else "#"
        print("\n" + "-" * width)
        print("🛑 Execution Blocked & Exception Escalated:")
        print(f"  • Reason:      {result.blocking_reason or 'Policy safety gate blocked automated PR opening.'}")
        print(f"  • Ticket:      {t_id} ({t_url})")
        print(f"  • Safeguard:   PR creation halted to protect codebase integrity.")
        print(f"  • Next Action: Review failing tests or request approval via security ticket.")

    # 1. Findings Breakdown
    if result.deduped_findings:
        print("\n" + "-" * width)
        print("📌 Discovered Vulnerabilities:")
        for idx, f in enumerate(result.deduped_findings, 1):
            cves = ", ".join(f.cve) if f.cve else "N/A"
            sev = f.severity.value.upper() if hasattr(f.severity, "value") else str(f.severity).upper()
            fixes = ", ".join(f.fix_versions) if f.fix_versions else "None"
            print(f"  [{idx}] {f.package}@{f.version} [{sev}] | CVE: {cves} | Fix: {fixes}")

    # 2. AI Remediation Plans
    if result.plans:
        print("\n" + "-" * width)
        print("🧠 AI Remediation Plan(s) & Rationale:")
        for idx, plan in enumerate(result.plans, 1):
            act = plan.action.value.upper() if hasattr(plan.action, "value") else str(plan.action).upper()
            tier = plan.risk_tier.value.upper() if hasattr(plan.risk_tier, "value") else str(plan.risk_tier).upper()
            pol = plan.policy_result.status.upper() if plan.policy_result else "APPROVED"
            print(f"  Plan #{idx}: [{act}] {plan.target_package or plan.root_cause_id}")
            print(f"    • Plan ID:        {plan.id}")
            print(f"    • Target Version: {plan.target_version or 'N/A'}")
            print(f"    • Risk Tier:      {tier} (Requires Approval: {plan.requires_approval})")
            print(f"    • Policy Check:   {pol}")
            print(f"    • AI Rationale:")
            for line in plan.rationale.strip().split("\n"):
                print(f"        {line}")

    # 3. Pull Requests Opened
    if result.pull_requests:
        print("\n" + "-" * width)
        print("🚀 Opened Pull Request(s):")
        for pr in result.pull_requests:
            print(f"  • Title:  {pr.get('title')}")
            print(f"  • Branch: {pr.get('branch')}")
            print(f"  • URL:    {pr.get('pr_url')}")
            body = pr.get("body")
            if body:
                print(f"  • PR Description Preview:")
                for line in body.split("\n")[:18]:
                    print(f"      {line}")
                if len(body.split("\n")) > 18:
                    print(f"      ... [Full Markdown description submitted with PR]")

    # 4. Verification
    if result.verification_results:
        ver = result.verification_results[0]
        clean = "✅ RESOLVED (0 remaining vulnerabilities)" if ver.get("rescan_clean") else "⚠️ RESIDUAL FINDINGS REMAIN"
        tests = "✅ PASSED" if ver.get("tests_passed") else "❌ FAILED"
        print("\n" + "-" * width)
        print("🧪 Verification & Build Evidence:")
        print(f"  • Sandbox Test Suite:  {tests}")
        print(f"  • Rescan Verification: {clean}")

    # 5. Observability & Audit Trail
    if result.audit_events:
        print("\n" + "-" * width)
        audit_file = f".vulnflow/audit/audit_{result.run_id}.jsonl"
        print(f"📋 Observability & Audit Trail ({len(result.audit_events)} actions traced):")
        print(f"  • Audit Log File: {audit_file}")
        print("  • Action Sequence:")
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
            print(f"    [{idx:02d}] {ev_name:<25} | {actor:<14} {summary_info}")

    print("=" * width + "\n")


def cmd_analyze(args: argparse.Namespace) -> int:
    """Execute vulnerability analysis, planning, and optional remediation."""
    if getattr(args, "no_llm", False):
        default_planner_agent.enable_llm = False
    else:
        default_planner_agent.enable_llm = True

    report_path = args.report
    scanner = args.scanner

    # Auto-detect scanner report if not explicitly provided
    if not report_path:
        repo_p = Path(args.repo)
        candidates = [
            (repo_p / "gitleaks.json", "gitleaks"),
            (repo_p / "trivy.json", "trivy"),
            (repo_p / "trivy-results.json", "trivy"),
            (repo_p / "grype.json", "grype"),
            (repo_p / "snyk.json", "snyk"),
            (Path("data/fixtures/sample_gitleaks_report.json"), "gitleaks"),
            (Path("vulnflow/data/fixtures/sample_gitleaks_report.json"), "gitleaks"),
        ]
        for c_path, c_scanner in candidates:
            if c_path.exists():
                report_path = str(c_path)
                scanner = c_scanner
                logger.info("Auto-detected security report at %s (scanner: %s)", report_path, scanner)
                break

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

    # Export report to disk
    out_arg = getattr(args, "output", None)
    out_format = getattr(args, "format", "markdown")

    if out_arg:
        out_path = Path(out_arg)
    else:
        reports_dir = Path(".vulnflow/reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        ext = "json" if out_format == "json" else "md"
        out_path = reports_dir / f"report_{result.run_id}.{ext}"

    if str(out_path).endswith(".json") or out_format == "json":
        write_json_report(result, out_path)
        print(f"📄 Structured JSON report written to: {out_path}\n")
    else:
        write_markdown_report(result, out_path)
        print(f"📄 Executive Markdown report written to: {out_path}\n")

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
    """Record human approval or rejection for a review-tier plan and optionally resume execution."""
    from vulnflow.orchestrator.approval import global_approval_gate, load_run_state

    plan_id = args.plan_id
    is_reject = getattr(args, "reject", False)
    reviewer = getattr(args, "reviewer", "security-lead")
    reason = getattr(args, "reason", None)
    repo = getattr(args, "repo", ".")

    # Record decision in persistent approval gate (F21)
    global_approval_gate.record_decision(
        plan_id=plan_id,
        approved=(not is_reject),
        reviewer=reviewer,
        reason=reason,
        repo_path=repo,
    )

    if is_reject:
        print(f"\n🛑 Plan {plan_id} REJECTED by {reviewer}. Reason: {reason or 'No reason provided'}\n")
        return 0

    print(f"\n✅ Plan {plan_id} APPROVED by {reviewer}.")

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
        return result.exit_code

    print(f"Run 'vulnflow analyze --repo {repo}' or 'vulnflow fix --plan-id {plan_id} --repo {repo}' to apply approved plan.\n")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Inspect and trace audit events for a given run."""
    import datetime
    from vulnflow.observability.audit_log import audit_logger

    run_id = args.run_id
    events: List[Dict[str, Any]] = []

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
            except Exception as exc:
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

        dt_str = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%H:%M:%S.%f")[:-3]
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
    if (build_ui or (not dev_mode and not (dist_dir / "index.html").exists())) and (ui_dir / "package.json").exists():
        print("\n📦 Building frontend Web Dashboard bundle (Vite + React)...")
        try:
            subprocess.run(["npm", "run", "build"], cwd=str(ui_dir), check=True)
            print("✅ Frontend dashboard built successfully.\n")
        except Exception as exc:
            logger.warning("Could not build frontend bundle: %s", exc)

    vite_proc = None
    if dev_mode and (ui_dir / "package.json").exists():
        print(f"\n🚀 Launching Vite Dev Server (connecting to API on http://localhost:{port})...")
        env = os.environ.copy()
        env["VITE_API_BASE_URL"] = f"http://localhost:{port}"
        try:
            vite_proc = subprocess.Popen(["npm", "run", "dev"], cwd=str(ui_dir), env=env)
        except Exception as exc:
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
            import uvicorn
            uvicorn.run("api.main:app", host=host, port=port, reload=reload_backend)
        except ImportError:
            logger.error("uvicorn is not installed. Run: pip install 'uvicorn[standard]' or pip install 'vulnflow[all]'")
            return 1
    except KeyboardInterrupt:
        print("\n🛑 Shutting down VulnFlow server...")
    finally:
        if vite_proc:
            print("Stopping Vite dev server...")
            vite_proc.terminate()
            try:
                vite_proc.wait(timeout=3)
            except Exception:
                vite_proc.kill()

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulnflow",
        description="🛡️ VulnFlow AI - Autonomous Vulnerability Remediation & Security Fabric",
    )

    # Friendly quick start when invoked with no arguments
    raw_args = argv if argv is not None else sys.argv[1:]
    if not raw_args:
        parser.print_help()
        print("\nQuick Start Guide:")
        print("  vulnflow serve                 # Start unified Web Dashboard & API on http://localhost:8000")
        print("  vulnflow serve --dev           # Start development mode with Vite hot-reload on :5173")
        print("  vulnflow scan --repo <path>    # Scan and auto-remediate a repository")
        print("  vulnflow report --repo <path>  # Generate assessment report without making code changes")
        print("  vulnflow approve --plan-id <id> --resume --repo <path>  # Authorize review-tier plan\n")
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
    p_scan.add_argument("--scanner", default="trivy", help="Security scanner name (trivy, grype, snyk, gitleaks)")
    p_scan.add_argument("--mode", choices=["report", "pr", "dry-run"], default="pr", help="Execution mode")
    p_scan.add_argument("--ecosystem", default="npm", help="Primary package ecosystem (npm, maven)")
    p_scan.add_argument("--output", "-o", help="File path to save the generated report")
    p_scan.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Report format")
    p_scan.add_argument("--no-llm", action="store_true", help="Skip remote LLM calls and use fast deterministic planner")
    p_scan.add_argument("--auto-approve", action="store_true", help="Auto-approve review-tier plans without waiting for human sign-off")
    p_scan.set_defaults(func=cmd_analyze)

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Ingest a report, group, plan, and remediate")
    p_analyze.add_argument("--repo", default=".", help="Target repository directory path")
    p_analyze.add_argument("--report", help="Path to scanner JSON or SARIF report (auto-detected if omitted)")
    p_analyze.add_argument("--scanner", default="trivy", help="Security scanner name (trivy, grype, snyk, gitleaks)")
    p_analyze.add_argument("--mode", choices=["report", "pr", "dry-run"], default="pr", help="Execution mode")
    p_analyze.add_argument("--ecosystem", default="npm", help="Primary package ecosystem (npm, maven)")
    p_analyze.add_argument("--output", "-o", help="File path to save the generated report (e.g., report.md or report.json)")
    p_analyze.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Report format")
    p_analyze.add_argument("--no-llm", action="store_true", help="Skip remote LLM calls and use fast deterministic planner")
    p_analyze.add_argument("--auto-approve", action="store_true", help="Auto-approve review-tier plans without waiting for human sign-off")
    p_analyze.set_defaults(func=cmd_analyze)

    # report
    p_report = subparsers.add_parser("report", help="Analyze and output report only without code changes")
    p_report.add_argument("--repo", default=".", help="Target repository directory path")
    p_report.add_argument("--report", help="Path to scanner JSON or SARIF report")
    p_report.add_argument("--scanner", default="trivy", help="Security scanner name")
    p_report.add_argument("--ecosystem", default="npm", help="Package ecosystem")
    p_report.add_argument("--output", "-o", help="File path to save the generated report")
    p_report.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Report format")
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
    p_approve = subparsers.add_parser("approve", help="Record human approval or rejection for a review-tier plan")
    p_approve.add_argument("--plan-id", required=True, help="Remediation plan ID")
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
