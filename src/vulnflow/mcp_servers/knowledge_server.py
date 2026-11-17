"""
src/vulnflow/mcp_servers/knowledge_server.py
MCP tool server providing vector retrieval and dependency graph queries.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from vulnflow.knowledge.graph.build_from_tree import DependencyGraph, get_active_graph
from vulnflow.knowledge.graph.queries import find_blast_radius, find_root_cause
from vulnflow.knowledge.vector.retriever import advisory_search as vector_advisory_search
from vulnflow.mcp_servers.fastmcp import FastMCP

logger = logging.getLogger("vulnflow.mcp_servers.knowledge")

# Initialize formal FastMCP server instance
mcp = FastMCP(
    name="vulnflow-knowledge",
    description="MCP server providing dependency graph queries (root cause, blast radius) and advisory vector retrieval.",
)


class KnowledgeServer:
    """
    MCP Server providing tools for dependency graph queries (root cause, blast radius)
    and organizational knowledge intelligence.
    """

    def __init__(self, graph: Optional[DependencyGraph] = None) -> None:
        self._graph = graph
        self.mcp = mcp

    @property
    def graph(self) -> DependencyGraph:
        if self._graph is None:
            self._graph = get_active_graph()
        return self._graph

    def root_cause(
        self,
        package: str,
        version: Optional[str] = None,
        dependency_path: Optional[List[str]] = None,
        repo_path: Optional[str] = None,
        ecosystem: str = "npm",
    ) -> Dict[str, Any]:
        """Query root cause parent dependency for a given finding."""
        logger.info("KnowledgeServer root_cause query for %s (version: %s)", package, version)
        return find_root_cause(
            package=package,
            version=version,
            graph=self.graph,
            repo_path=repo_path,
            dependency_path=dependency_path,
            ecosystem=ecosystem,
        )

    def blast_radius(
        self,
        package: str,
        version: Optional[str] = None,
        repo_path: Optional[str] = None,
        ecosystem: str = "npm",
    ) -> Dict[str, Any]:
        """Query services and repositories affected by bumping or modifying a package."""
        logger.info("KnowledgeServer blast_radius query for %s (version: %s)", package, version)
        return find_blast_radius(
            package=package,
            version=version,
            graph=self.graph,
            repo_path=repo_path,
            ecosystem=ecosystem,
        )

    def advisory_search(
        self,
        query: str,
        package: Optional[str] = None,
        ecosystem: str = "npm",
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """Retrieve security advisories and changelog chunks for vulnerability context."""
        logger.info("KnowledgeServer advisory_search query='%s' package='%s'", query, package)
        return vector_advisory_search(query=query, package=package, ecosystem=ecosystem, limit=limit)

    def graph_query(
        self,
        name: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Dispatcher for graph query tools."""
        p = params or {}
        if name == "root_cause":
            return self.root_cause(
                package=p.get("package", ""),
                version=p.get("version"),
                dependency_path=p.get("dependency_path"),
                repo_path=p.get("repo_path"),
                ecosystem=p.get("ecosystem", "npm"),
            )
        elif name == "blast_radius":
            return self.blast_radius(
                package=p.get("package", ""),
                version=p.get("version"),
                repo_path=p.get("repo_path"),
                ecosystem=p.get("ecosystem", "npm"),
            )
        else:
            return {"error": f"Unknown graph query '{name}'"}


# Global knowledge server instance
knowledge_server = KnowledgeServer()


@mcp.tool(
    name="advisory_search",
    description="Retrieve security advisories, fixed versions, and release notes filtered by package.",
)
def advisory_search(
    query: str,
    package: Optional[str] = None,
    ecosystem: str = "npm",
    limit: int = 5,
) -> List[Dict[str, Any]]:
    return knowledge_server.advisory_search(query, package, ecosystem, limit)


@mcp.tool(
    name="graph_query",
    description="Executes graph query patterns ('root_cause', 'blast_radius') on dependency graph.",
)
def graph_query(name: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return knowledge_server.graph_query(name, params)


@mcp.tool(
    name="root_cause",
    description="Identifies top-level direct manifest root cause parent for a transitive vulnerable package.",
)
def root_cause(
    package: str,
    version: Optional[str] = None,
    dependency_path: Optional[List[str]] = None,
    repo_path: Optional[str] = None,
    ecosystem: str = "npm",
) -> Dict[str, Any]:
    return knowledge_server.root_cause(package, version, dependency_path, repo_path, ecosystem)


@mcp.tool(
    name="blast_radius",
    description="Calculates dependent services, repositories, and downstream components affected by upgrading a package.",
)
def blast_radius(
    package: str,
    version: Optional[str] = None,
    repo_path: Optional[str] = None,
    ecosystem: str = "npm",
) -> Dict[str, Any]:
    return knowledge_server.blast_radius(package, version, repo_path, ecosystem)


if __name__ == "__main__":
    mcp.run()
