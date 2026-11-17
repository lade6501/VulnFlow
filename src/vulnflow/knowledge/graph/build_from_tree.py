"""
src/vulnflow/knowledge/graph/build_from_tree.py
Constructs dependency graph nodes and edges from package dependency trees and lockfiles.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

logger = logging.getLogger("vulnflow.knowledge.graph.build_from_tree")


@dataclass
class DependencyNode:
    """Represents a single package version node in the dependency graph."""

    name: str  # e.g., "npm:lodash" or "lodash"
    version: str = "0.0.0"
    is_direct: bool = False
    dependencies: Dict[str, str] = field(default_factory=dict)  # child_name -> version_constraint
    dependents: Set[str] = field(default_factory=set)  # parent node names that depend on this


class DependencyGraph:
    """
    In-memory directed dependency graph modeling package dependencies.
    Directed edges point from parent (dependent) to child (dependency).
    """

    def __init__(self, root_name: str = "root") -> None:
        self.root_name = root_name
        self.nodes: Dict[str, DependencyNode] = {}
        self.direct_dependencies: Set[str] = set()
        self.services: Dict[str, Set[str]] = {}  # service_name -> set of dependent packages
        self.repos: Dict[str, Set[str]] = {}  # repo_name -> set of services
        self.service_to_repo: Dict[str, str] = {}  # service_name -> repo_name

    def register_service(
        self,
        service_name: str,
        repo_name: str,
        packages: Optional[List[str]] = None,
    ) -> None:
        """Register an organizational microservice and its repository and package dependencies."""
        if service_name not in self.services:
            self.services[service_name] = set()
        if repo_name not in self.repos:
            self.repos[repo_name] = set()

        self.repos[repo_name].add(service_name)
        self.service_to_repo[service_name] = repo_name

        if packages:
            for pkg in packages:
                clean_pkg = pkg.replace("PKG-", "")
                self.services[service_name].add(clean_pkg)
                bare = clean_pkg.split(":", 1)[1] if ":" in clean_pkg else clean_pkg
                self.services[service_name].add(bare)

    def find_affected_services_and_repos(self, package_name: str) -> tuple[List[str], List[str]]:
        """
        Given a package, find all organizational microservices and repositories affected,
        either directly or transitively.
        """
        all_affected_pkgs = self.find_all_dependents(package_name)
        clean = package_name.replace("PKG-", "")
        bare = clean.split(":", 1)[1] if ":" in clean else clean
        all_affected_pkgs.add(clean)
        all_affected_pkgs.add(bare)
        all_affected_pkgs.add(f"npm:{bare}")

        affected_services: Set[str] = set()
        affected_repos: Set[str] = set()

        for s_name, s_pkgs in self.services.items():
            if any(p in s_pkgs for p in all_affected_pkgs):
                affected_services.add(s_name)
                repo = self.service_to_repo.get(s_name)
                if repo:
                    affected_repos.add(repo)

        return sorted(list(affected_services)), sorted(list(affected_repos))

    def get_or_create_node(self, name: str, version: str = "0.0.0", is_direct: bool = False) -> DependencyNode:
        """Retrieve existing node or create a new node."""
        clean_name = name.replace("PKG-", "")
        if clean_name not in self.nodes:
            self.nodes[clean_name] = DependencyNode(name=clean_name, version=version, is_direct=is_direct)
        node = self.nodes[clean_name]
        if is_direct:
            node.is_direct = True
            self.direct_dependencies.add(clean_name)
        if version and version != "0.0.0":
            node.version = version
        return node

    def add_edge(self, parent_name: str, child_name: str, version_constraint: str = "*") -> None:
        """Add directed dependency edge: parent -> child."""
        parent_node = self.get_or_create_node(parent_name)
        child_node = self.get_or_create_node(child_name)
        parent_node.dependencies[child_node.name] = version_constraint
        child_node.dependents.add(parent_node.name)

    def add_chain(self, chain: List[str]) -> None:
        """
        Register a linear dependency path, e.g. ['npm:frontend-ui@1.0.0', 'npm:lodash@4.17.15'].
        The first element is treated as direct unless already specified.
        """
        if not chain:
            return

        prev_name: Optional[str] = None
        for idx, item in enumerate(chain):
            # Parse name and version if formatted as name@version
            if "@" in item and not item.startswith("@"):
                name_part, ver_part = item.split("@", 1)
            elif item.startswith("@") and "@" in item[1:]:
                # Scoped package e.g. @org/pkg@1.0.0
                parts = item[1:].split("@", 1)
                name_part = "@" + parts[0]
                ver_part = parts[1] if len(parts) > 1 else "0.0.0"
            else:
                name_part = item
                ver_part = "0.0.0"

            is_direct = (idx == 0)
            self.get_or_create_node(name_part, version=ver_part, is_direct=is_direct)

            if prev_name:
                self.add_edge(prev_name, name_part)
            prev_name = name_part

    def find_direct_ancestor(self, package_name: str) -> Optional[str]:
        """
        Trace backwards from package_name through dependents to find the top-level
        direct dependency that introduced it.
        """
        clean_target = package_name.replace("PKG-", "")
        # Normalize ecosystem prefix
        ecosystem = "npm"
        bare_target = clean_target.split(":", 1)[1] if ":" in clean_target else clean_target
        names_to_try = {clean_target, bare_target, f"{ecosystem}:{bare_target}"}

        matched_node = None
        for n in names_to_try:
            if n in self.nodes:
                matched_node = self.nodes[n]
                break

        if not matched_node:
            return None

        # If it is already direct, it is its own root cause
        if matched_node.is_direct:
            return matched_node.name

        # Breadth-first search backwards through dependents
        queue: List[str] = list(matched_node.dependents)
        visited: Set[str] = set(queue)

        while queue:
            current_name = queue.pop(0)
            node = self.nodes.get(current_name)
            if not node:
                continue

            if node.is_direct:
                return node.name

            for parent_name in node.dependents:
                if parent_name not in visited:
                    visited.add(parent_name)
                    queue.append(parent_name)

        return None

    def find_all_dependents(self, package_name: str) -> Set[str]:
        """Find all direct and transitive dependents of a package (for blast radius)."""
        clean_target = package_name.replace("PKG-", "")
        bare_target = clean_target.split(":", 1)[1] if ":" in clean_target else clean_target
        names_to_try = {clean_target, bare_target, f"npm:{bare_target}"}

        start_name = None
        for n in names_to_try:
            if n in self.nodes:
                start_name = n
                break

        if not start_name:
            return set()

        dependents: Set[str] = set()
        queue: List[str] = list(self.nodes[start_name].dependents)

        while queue:
            curr = queue.pop(0)
            if curr not in dependents:
                dependents.add(curr)
                if curr in self.nodes:
                    queue.extend(self.nodes[curr].dependents)

        return dependents


def build_graph_from_manifest(
    package_json_path: Union[str, Path],
    package_lock_path: Optional[Union[str, Path]] = None,
    ecosystem: str = "npm",
) -> DependencyGraph:
    """
    Construct a DependencyGraph from package.json manifest and optional package-lock.json.
    """
    pkg_path = Path(package_json_path)
    graph = DependencyGraph()

    if not pkg_path.exists():
        logger.warning("Manifest not found at %s", pkg_path)
        return graph

    try:
        with open(pkg_path, "r", encoding="utf-8") as f:
            pkg_data = json.load(f)
    except Exception as exc:
        logger.error("Failed to parse package.json: %s", exc)
        return graph

    # Register direct dependencies
    deps = pkg_data.get("dependencies", {})
    dev_deps = pkg_data.get("devDependencies", {})
    all_direct = {**deps, **dev_deps}

    for dep_name, dep_version in all_direct.items():
        full_name = f"{ecosystem}:{dep_name}" if ":" not in dep_name else dep_name
        graph.get_or_create_node(full_name, version=str(dep_version), is_direct=True)
        # Also store bare name for lookup flexibility
        graph.get_or_create_node(dep_name, version=str(dep_version), is_direct=True)

    # If lockfile is not provided, look in same directory
    if package_lock_path is None:
        candidate_lock = pkg_path.parent / "package-lock.json"
        if candidate_lock.exists():
            package_lock_path = candidate_lock

    if package_lock_path:
        lock_p = Path(package_lock_path)
        if lock_p.exists():
            try:
                with open(lock_p, "r", encoding="utf-8") as f:
                    lock_data = json.load(f)
                _parse_npm_lockfile(graph, lock_data, ecosystem)
            except Exception as exc:
                logger.warning("Failed to parse lockfile at %s: %s", lock_p, exc)

    return graph


def _parse_npm_lockfile(graph: DependencyGraph, lock_data: Dict[str, Any], ecosystem: str) -> None:
    """Parse npm lockfile version 1, 2, or 3 into graph nodes and edges."""
    # Version 2 & 3: packages dictionary
    packages = lock_data.get("packages", {})
    if packages:
        for pkg_key, pkg_info in packages.items():
            if not pkg_key or pkg_key == "":
                continue

            # Keys look like: "node_modules/foo" or "node_modules/foo/node_modules/bar"
            parts = [p for p in pkg_key.split("node_modules/") if p]
            if not parts:
                continue

            child_bare = parts[-1].rstrip("/")
            child_name = f"{ecosystem}:{child_bare}"
            child_ver = pkg_info.get("version", "0.0.0")

            if len(parts) == 1:
                # Direct or top-level hoisted package
                is_direct = child_bare in graph.direct_dependencies or child_name in graph.direct_dependencies
                graph.get_or_create_node(child_name, version=child_ver, is_direct=is_direct)
                graph.get_or_create_node(child_bare, version=child_ver, is_direct=is_direct)
            else:
                # Nested package: parts[-2] is parent
                parent_bare = parts[-2].rstrip("/")
                parent_name = f"{ecosystem}:{parent_bare}"
                graph.get_or_create_node(child_name, version=child_ver, is_direct=False)
                graph.get_or_create_node(child_bare, version=child_ver, is_direct=False)
                graph.add_edge(parent_name, child_name)
                graph.add_edge(parent_bare, child_bare)

            # Process explicit dependencies dict inside pkg_info
            inner_deps = pkg_info.get("dependencies", {})
            for sub_dep, sub_ver in inner_deps.items():
                sub_name = f"{ecosystem}:{sub_dep}"
                graph.get_or_create_node(sub_name, version=str(sub_ver), is_direct=False)
                graph.get_or_create_node(sub_dep, version=str(sub_ver), is_direct=False)
                graph.add_edge(child_name, sub_name)
                graph.add_edge(child_bare, sub_dep)

    # Version 1 dependencies structure fallback
    v1_deps = lock_data.get("dependencies", {})
    if v1_deps and not packages:
        _parse_v1_deps(graph, v1_deps, parent_name=None, ecosystem=ecosystem)


def _parse_v1_deps(
    graph: DependencyGraph,
    deps: Dict[str, Any],
    parent_name: Optional[str],
    ecosystem: str,
) -> None:
    """Recursively parse npm lockfile v1 nested dependencies."""
    for dep_bare, dep_info in deps.items():
        dep_name = f"{ecosystem}:{dep_bare}"
        ver = dep_info.get("version", "0.0.0")
        is_direct = (parent_name is None) and (
            dep_bare in graph.direct_dependencies or dep_name in graph.direct_dependencies
        )
        graph.get_or_create_node(dep_name, version=ver, is_direct=is_direct)
        graph.get_or_create_node(dep_bare, version=ver, is_direct=is_direct)

        if parent_name:
            graph.add_edge(parent_name, dep_name)
            bare_parent = parent_name.split(":", 1)[1] if ":" in parent_name else parent_name
            graph.add_edge(bare_parent, dep_bare)

        nested = dep_info.get("dependencies", {})
        if nested:
            _parse_v1_deps(graph, nested, parent_name=dep_name, ecosystem=ecosystem)


def build_graph_from_tree_dict(tree_dict: Dict[str, Any], ecosystem: str = "npm") -> DependencyGraph:
    """
    Build DependencyGraph from `npm ls --json` output.
    """
    graph = DependencyGraph(root_name=tree_dict.get("name", "root"))
    top_deps = tree_dict.get("dependencies", {})

    def recurse(deps: Dict[str, Any], parent: Optional[str], is_top: bool) -> None:
        for name_bare, info in deps.items():
            name_full = f"{ecosystem}:{name_bare}"
            ver = info.get("version", "0.0.0")
            graph.get_or_create_node(name_full, version=ver, is_direct=is_top)
            graph.get_or_create_node(name_bare, version=ver, is_direct=is_top)

            if parent:
                graph.add_edge(parent, name_full)
                bare_p = parent.split(":", 1)[1] if ":" in parent else parent
                graph.add_edge(bare_p, name_bare)

            sub_deps = info.get("dependencies", {})
            if sub_deps:
                recurse(sub_deps, parent=name_full, is_top=False)

    recurse(top_deps, parent=None, is_top=True)
    return graph


def seed_default_graph() -> DependencyGraph:
    """
    Construct a seeded multi-service organizational dependency graph
    conforming to Neo4j schema relationships in schema.cypher.
    """
    graph = DependencyGraph(root_name="enterprise-monorepo")

    # Seed core packages and version nodes
    graph.get_or_create_node("npm:express", version="4.17.1", is_direct=True)
    graph.get_or_create_node("npm:body-parser", version="1.19.0", is_direct=False)
    graph.get_or_create_node("npm:qs", version="6.7.0", is_direct=False)
    graph.add_edge("npm:express", "npm:body-parser")
    graph.add_edge("npm:body-parser", "npm:qs")

    graph.get_or_create_node("npm:frontend-ui", version="1.0.0", is_direct=True)
    graph.get_or_create_node("npm:lodash", version="4.17.15", is_direct=False)
    graph.add_edge("npm:frontend-ui", "npm:lodash")

    graph.get_or_create_node("npm:axios", version="0.21.1", is_direct=True)
    graph.get_or_create_node("npm:moment", version="2.29.1", is_direct=True)

    # Register services and repositories
    graph.register_service(
        service_name="payment-api",
        repo_name="payment-service",
        packages=["npm:express", "npm:axios", "npm:lodash"],
    )
    graph.register_service(
        service_name="order-worker",
        repo_name="order-service",
        packages=["npm:lodash", "npm:moment"],
    )
    graph.register_service(
        service_name="report-generator",
        repo_name="reporting-service",
        packages=["npm:frontend-ui"],  # Transitively depends on lodash
    )
    graph.register_service(
        service_name="auth-api",
        repo_name="auth-service",
        packages=["npm:express", "npm:axios"],
    )

    return graph


_active_graph: Optional[DependencyGraph] = None


def get_active_graph() -> DependencyGraph:
    """Return the global active dependency graph, lazily initialized with seeded data."""
    global _active_graph
    if _active_graph is None:
        _active_graph = seed_default_graph()
    return _active_graph

