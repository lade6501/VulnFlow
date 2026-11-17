"""
api/routes/graph.py
API endpoints for dependency graph, root cause, and blast radius queries.
"""

from __future__ import annotations

from typing import Any, Dict

from vulnflow.knowledge.graph.queries import blast_radius, root_cause


def get_graph_data(package: str = "npm:lodash", repo: str = "workspace") -> Dict[str, Any]:
    """Return dependency graph nodes and edges for root-cause and blast radius visualization."""
    rc = root_cause(transitive_package=package, repo=repo)
    br = blast_radius(package=package)

    return {
        "package": package,
        "root_cause": rc,
        "blast_radius": br,
        "nodes": [
            {"id": package, "label": package, "type": "vulnerability"},
            {"id": rc.get("root_cause_package", "direct-parent"), "label": "Direct Parent", "type": "dependency"},
            {"id": repo, "label": repo, "type": "repository"},
        ],
        "edges": [
            {"source": repo, "target": rc.get("root_cause_package", "direct-parent"), "relation": "DEPENDS_ON"},
            {"source": rc.get("root_cause_package", "direct-parent"), "target": package, "relation": "TRANSITIVE_REQUIRES"},
        ],
    }
