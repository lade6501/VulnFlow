"""
src/vulnflow/knowledge/graph/queries.py
Executes graph queries for root cause analysis and blast radius calculation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from vulnflow.adapters.ecosystem.maven import MavenAdapter
from vulnflow.knowledge.graph.build_from_tree import (
    DependencyGraph,
    build_graph_from_manifest,
    get_active_graph,
)

logger = logging.getLogger("vulnflow.knowledge.graph.queries")


def _build_graph_for_repo(repo_path: Path, ecosystem: str) -> DependencyGraph | None:
    """Build the best available direct-dependency graph for a repository ecosystem."""
    normalized = ecosystem.lower()
    if normalized == "maven" and (repo_path / "pom.xml").exists():
        graph = DependencyGraph()
        for package, version in MavenAdapter.parse_dependencies(
            repo_path / "pom.xml"
        ).items():
            if ":" not in package:
                continue
            full_package = f"maven:{package}"
            graph.get_or_create_node(full_package, version=version, is_direct=True)
            graph.get_or_create_node(package, version=version, is_direct=True)
        return graph
    package_json = repo_path / "package.json"
    if package_json.exists():
        return build_graph_from_manifest(package_json, ecosystem=ecosystem)
    return None


def find_root_cause(
    package: str,
    version: Optional[str] = None,
    graph: Optional[DependencyGraph] = None,
    repo_path: Optional[str] = None,
    dependency_path: Optional[List[str]] = None,
    ecosystem: str = "npm",
) -> Dict[str, Any]:
    """
    Find the root cause direct dependency responsible for introducing a package finding.

    Args:
        package: Package name (e.g., 'npm:lodash' or 'lodash').
        version: Optional installed version string.
        graph: Optional pre-constructed DependencyGraph.
        repo_path: Path to repository to build graph from manifest if graph is not supplied.
        dependency_path: Chain of packages from manifest to finding, if known from scanner.
        ecosystem: Ecosystem identifier ('npm', 'maven').

    Returns:
        Structured root cause payload conforming to Section 6.2 of the specification.
    """
    clean_pkg = package.replace("PKG-", "")
    full_pkg = f"{ecosystem}:{clean_pkg}" if ":" not in clean_pkg else clean_pkg

    # 1. Check explicit dependency_path provided by scanner finding
    if dependency_path and len(dependency_path) > 1:
        top_ancestor = dependency_path[0]
        full_top = f"{ecosystem}:{top_ancestor}" if ":" not in top_ancestor else top_ancestor
        is_direct = (full_top == full_pkg)
        return {
            "root_cause_id": f"PKG-{full_top}",
            "root_cause_package": full_top,
            "is_direct": is_direct,
            "affected_package": full_pkg,
            "affected_version": version or "0.0.0",
            "dependency_chain": dependency_path,
            "depth": len(dependency_path) - 1,
        }

    # 2. Build graph from repo if graph is not provided
    active_graph = graph
    if active_graph is None and repo_path:
        active_graph = _build_graph_for_repo(Path(repo_path), ecosystem)

    # 3. Query the dependency graph
    if active_graph:
        ancestor = active_graph.find_direct_ancestor(full_pkg) or active_graph.find_direct_ancestor(clean_pkg)
        if ancestor:
            full_ancestor = f"{ecosystem}:{ancestor}" if ":" not in ancestor else ancestor
            is_direct = (full_ancestor == full_pkg or ancestor == clean_pkg)
            chain = [full_ancestor, full_pkg] if not is_direct else [full_pkg]
            return {
                "root_cause_id": f"PKG-{full_ancestor}",
                "root_cause_package": full_ancestor,
                "is_direct": is_direct,
                "affected_package": full_pkg,
                "affected_version": version or "0.0.0",
                "dependency_chain": chain,
                "depth": 0 if is_direct else 1,
            }

    # 4. Fallback: treat package as its own direct root cause
    return {
        "root_cause_id": f"PKG-{full_pkg}",
        "root_cause_package": full_pkg,
        "is_direct": True,
        "affected_package": full_pkg,
        "affected_version": version or "0.0.0",
        "dependency_chain": [full_pkg],
        "depth": 0,
    }


def find_blast_radius(
    package: str,
    version: Optional[str] = None,
    graph: Optional[DependencyGraph] = None,
    repo_path: Optional[str] = None,
    ecosystem: str = "npm",
) -> Dict[str, Any]:
    """
    Calculate the organizational blast radius of altering a given package.

    Returns:
        Dictionary detailing direct/transitive dependents, affected services, and repositories.
    """
    clean_pkg = package.replace("PKG-", "")
    full_pkg = f"{ecosystem}:{clean_pkg}" if ":" not in clean_pkg else clean_pkg
    bare_pkg = clean_pkg.split(":", 1)[1] if ":" in clean_pkg else clean_pkg

    active_graph = graph
    if active_graph is None:
        if repo_path:
            active_graph = _build_graph_for_repo(Path(repo_path), ecosystem)
        if active_graph is None:
            active_graph = get_active_graph()

    dependents: List[str] = []
    affected_services: List[str] = []
    affected_repos: List[str] = []

    if active_graph:
        deps_set = active_graph.find_all_dependents(full_pkg) or active_graph.find_all_dependents(bare_pkg)
        dependents = sorted(list(deps_set))
        affected_services, affected_repos = active_graph.find_affected_services_and_repos(full_pkg)

    total_affected = len(dependents) + len(affected_services)
    if len(affected_services) >= 3 or total_affected >= 5:
        tier = "HIGH"
    elif len(affected_services) >= 1 or total_affected >= 1:
        tier = "MEDIUM"
    else:
        tier = "LOW"

    return {
        "package": full_pkg,
        "version": version or "latest",
        "total_affected_dependents": len(dependents),
        "dependents": dependents,
        "services": affected_services,
        "repos": affected_repos,
        "affected_services": affected_services,
        "affected_repos": affected_repos,
        "blast_radius_tier": tier,
    }


# Convenience aliases for query interfaces
root_cause = find_root_cause
blast_radius = find_blast_radius
