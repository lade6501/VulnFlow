"""
src/vulnflow/agents/rootcause.py
Agent that traces transitive vulnerabilities through dependency graphs to their root cause parents.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any

from vulnflow.contracts.finding import Finding, FindingType
from vulnflow.knowledge.graph.build_from_tree import DependencyGraph
from vulnflow.knowledge.graph.queries import find_root_cause
from vulnflow.llm import LLMClient

logger = logging.getLogger("vulnflow.agents.rootcause")


@dataclass
class RootCauseResult:
    """Analysis result identifying the root cause dependency for a finding."""

    root_cause_id: str
    root_cause_package: str
    is_direct: bool
    dependency_chain: list[str]
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RootCauseAgent:
    """
    Reasoning agent that traces findings through dependency graphs to identify
    the responsible direct manifest dependency.
    """

    def __init__(self, client: LLMClient | None = None) -> None:
        self.client = client

    def analyze_finding(
        self,
        finding: Finding,
        graph: DependencyGraph | None = None,
        repo_path: str | None = None,
        ecosystem: str = "npm",
    ) -> RootCauseResult:
        """
        Identify the root cause parent dependency and generate an engineering explanation.
        """
        if getattr(finding, "type", None) == FindingType.SECRET or str(getattr(finding, "type", "")).lower() == "secret":
            file_path = finding.location.file_path if finding.location else "unknown file"
            meta = getattr(finding, "metadata", {}) or {}
            rule_id = meta.get("rule_id") or finding.id
            desc = meta.get("description") or getattr(finding, "raw_ref", "") or "Hardcoded secret or credential"
            return RootCauseResult(
                root_cause_id=f"SECRET-{rule_id}",
                root_cause_package="secret:credentials",
                is_direct=True,
                dependency_chain=[f"secret:{file_path}"],
                explanation=f"Hardcoded credential exposure detected in {file_path} ({desc}).",
            )

        dep_path = finding.location.dependency_path if finding.location else []
        res = find_root_cause(
            package=finding.package,
            version=finding.version,
            graph=graph,
            repo_path=repo_path,
            dependency_path=dep_path,
            ecosystem=ecosystem,
        )

        rc_id = res["root_cause_id"]
        rc_pkg = res["root_cause_package"]
        is_direct = res["is_direct"]
        chain = res.get("dependency_chain", [finding.package])

        if is_direct:
            explanation = f"Package {finding.package}@{finding.version} is directly declared in repository manifest."
        else:
            chain_str = " -> ".join(chain)
            explanation = (
                f"Vulnerability in transitive dependency {finding.package}@{finding.version} "
                f"was introduced via direct parent {rc_pkg} (dependency path: {chain_str}). "
                f"Remediating {rc_pkg} or applying a dependency resolution override is required."
            )

        return RootCauseResult(
            root_cause_id=rc_id,
            root_cause_package=rc_pkg,
            is_direct=is_direct,
            dependency_chain=chain,
            explanation=explanation,
        )

    def group_findings(
        self,
        findings: list[Finding],
        graph: DependencyGraph | None = None,
        repo_path: str | None = None,
        ecosystem: str = "npm",
    ) -> list[dict[str, Any]]:
        """
        Group multiple findings by their common root cause parent dependency.
        Collapses deep transitive findings under the single direct parent that brought them in.
        """
        groups: dict[str, dict[str, Any]] = {}

        for f in findings:
            analysis = self.analyze_finding(f, graph=graph, repo_path=repo_path, ecosystem=ecosystem)
            rc_id = analysis.root_cause_id

            if rc_id not in groups:
                groups[rc_id] = {
                    "root_cause_id": rc_id,
                    "root_cause_package": analysis.root_cause_package,
                    "is_direct": analysis.is_direct,
                    "dependency_chain": analysis.dependency_chain,
                    "explanation": analysis.explanation,
                    "findings": [],
                }
            groups[rc_id]["findings"].append(f.to_dict())

        logger.info(
            "RootCauseAgent grouped %d finding(s) into %d root cause cluster(s)",
            len(findings),
            len(groups),
        )
        return list(groups.values())


# Global default instance
default_rootcause_agent = RootCauseAgent()
