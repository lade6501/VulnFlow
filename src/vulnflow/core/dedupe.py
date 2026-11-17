"""
src/vulnflow/core/dedupe.py
Deduplicates scanner findings based on CVE ID, package, and file location.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Set, Tuple

from vulnflow.contracts.finding import Finding, SeverityLevel

logger = logging.getLogger("vulnflow.core.dedupe")

SEVERITY_ORDER = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH: 4,
    SeverityLevel.MEDIUM: 3,
    SeverityLevel.LOW: 2,
    SeverityLevel.INFO: 1,
}


class DeduplicationEngine:
    """Collapses duplicate findings across multiple scanners or recurring runs into canonical records."""

    def __init__(self) -> None:
        self.raw_count = 0
        self.deduped_count = 0

    @property
    def dedupe_ratio(self) -> float:
        """Calculate deduplication ratio (raw / deduped)."""
        if self.deduped_count == 0:
            return 1.0
        return round(self.raw_count / float(self.deduped_count), 2)

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """
        Merge duplicate findings based on (package, file_path, and common CVE identifiers).
        Merges fix versions and retains the highest reported severity.
        """
        self.raw_count = len(findings)
        if not findings:
            self.deduped_count = 0
            return []

        # Group by package and file path
        grouped: Dict[Tuple[str, str], List[Finding]] = {}
        for f in findings:
            key = (f.package.lower(), f.location.file_path)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(f)

        deduped: List[Finding] = []

        for (pkg, fpath), group in grouped.items():
            # Sub-cluster by overlapping CVEs
            clusters: List[List[Finding]] = []
            for item in group:
                item_cves = set(item.cve)
                matched_cluster = None
                for cluster in clusters:
                    cluster_cves: Set[str] = set()
                    for c_item in cluster:
                        cluster_cves.update(c_item.cve)
                    # If any CVE overlaps or both have identical version without CVE
                    if (item_cves and cluster_cves and not item_cves.isdisjoint(cluster_cves)) or (
                        not item_cves and not cluster_cves and cluster[0].version == item.version
                    ):
                        matched_cluster = cluster
                        break

                if matched_cluster is not None:
                    matched_cluster.append(item)
                else:
                    clusters.append([item])

            # Merge each cluster into a single canonical Finding
            for cluster in clusters:
                canonical = self._merge_cluster(cluster)
                deduped.append(canonical)

        self.deduped_count = len(deduped)
        logger.info(
            "Deduplicated %d finding(s) down to %d unique finding(s) (ratio: %.2f)",
            self.raw_count,
            self.deduped_count,
            self.dedupe_ratio,
        )
        return deduped

    def _merge_cluster(self, cluster: List[Finding]) -> Finding:
        """Merge a list of equivalent findings into the highest-priority canonical record."""
        primary = cluster[0]
        if len(cluster) == 1:
            return primary

        # Union CVEs and fix versions
        merged_cves: Set[str] = set()
        merged_fix_versions: Set[str] = set()
        highest_severity = primary.severity
        all_raw_refs: List[str] = []

        for item in cluster:
            merged_cves.update(item.cve)
            merged_fix_versions.update(item.fix_versions)
            if SEVERITY_ORDER.get(item.severity, 0) > SEVERITY_ORDER.get(highest_severity, 0):
                highest_severity = item.severity
            if item.raw_ref:
                all_raw_refs.append(item.raw_ref)

        merged_cve_list = sorted(list(merged_cves))
        merged_fix_list = sorted(list(merged_fix_versions))

        return Finding(
            id=primary.id,
            type=primary.type,
            scanner=primary.scanner if len(set(x.scanner for x in cluster)) == 1 else "multi-scanner",
            repo=primary.repo,
            package=primary.package,
            version=primary.version,
            cve=merged_cve_list,
            severity=highest_severity,
            location=primary.location,
            fix_versions=merged_fix_list,
            raw_ref=";".join(all_raw_refs),
            redacted=any(x.redacted for x in cluster),
            metadata=primary.metadata,
        )


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Convenience function for finding deduplication."""
    engine = DeduplicationEngine()
    return engine.deduplicate(findings)
