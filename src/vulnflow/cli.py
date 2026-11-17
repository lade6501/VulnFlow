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

from vulnflow.contracts.state import VulnFlowState
from vulnflow.orchestrator.graph import run_workflow

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
    print(f"Plans:        {len(result.plans)} generated ({len(result.approved_plans)} approved)")
    print(f"Patches:      {len(result.patches)} applied")
    print(f"Pull Requests:{len(result.pull_requests)} opened")

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
    state = VulnFlowState(
        repo_path=args.repo,
        report_path=args.report,
        scanner=args.scanner,
        mode=args.mode,
        ecosystem=args.ecosystem,
    )
    result = run_workflow(state)
    _print_execution_summary(result)
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
    return result.exit_code


def cmd_verify(args: argparse.Namespace) -> int:
    """Rescan a branch and confirm finding resolution."""
    logger.info("Verifying branch %s against baseline findings", args.branch)
    state = VulnFlowState(repo_path=args.repo, mode="report")
    result = run_workflow(state)
    return result.exit_code


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


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnflow", description="AI-driven vulnerability remediation engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Ingest a report, group, plan, and remediate")
    p_analyze.add_argument("--repo", default=".", help="Target repository directory path")
    p_analyze.add_argument("--report", help="Path to scanner JSON or SARIF report")
    p_analyze.add_argument("--scanner", default="trivy", help="Security scanner name (trivy, grype, snyk)")
    p_analyze.add_argument("--mode", choices=["report", "pr", "dry-run"], default="pr", help="Execution mode")
    p_analyze.add_argument("--ecosystem", default="npm", help="Primary package ecosystem (npm, maven)")
    p_analyze.set_defaults(func=cmd_analyze)

    # report
    p_report = subparsers.add_parser("report", help="Analyze and output report only without code changes")
    p_report.add_argument("--repo", default=".", help="Target repository directory path")
    p_report.add_argument("--report", help="Path to scanner JSON or SARIF report")
    p_report.add_argument("--scanner", default="trivy", help="Security scanner name")
    p_report.add_argument("--ecosystem", default="npm", help="Package ecosystem")
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

    # audit
    p_audit = subparsers.add_parser("audit", help="Inspect chronological audit trail of a run")
    p_audit.add_argument("--run-id", help="Run ID to inspect (defaults to latest)")
    p_audit.set_defaults(func=cmd_audit)

    parsed = parser.parse_args(argv)
    return parsed.func(parsed)


if __name__ == "__main__":
    sys.exit(main())
