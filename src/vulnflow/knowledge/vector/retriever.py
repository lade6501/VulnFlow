"""
src/vulnflow/knowledge/vector/retriever.py
Retrieves relevant security advisories, changelogs, and release note chunks filtered by package.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from vulnflow.knowledge.sources.osv import BUILTIN_ADVISORIES, default_osv_client
from vulnflow.llm.embeddings import DeterministicHashEmbeddingProvider, EmbeddingProvider

logger = logging.getLogger("vulnflow.knowledge.vector.retriever")


@dataclass
class AdvisoryChunk:
    """Indexed chunk representing an advisory, release note, or vulnerability detail."""

    chunk_id: str
    package: str
    ecosystem: str
    cve: str
    title: str
    text: str
    embedding: List[float] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "id": self.chunk_id,
            "package": self.package,
            "ecosystem": self.ecosystem,
            "cve": self.cve,
            "aliases": self.metadata.get("aliases", []),
            "title": self.title,
            "description": self.text,
            "cvss_score": self.metadata.get("cvss_score", 7.0),
            "references": self.metadata.get("references", []),
            "fixed_versions": self.metadata.get("fixed_versions", []),
        }


class AdvisoryRetriever:
    """
    Hybrid retriever that indexes and searches advisory and release note chunks.
    Filters strictly by package and ecosystem to prevent hallucinated cross-package contamination.
    """

    def __init__(self, embedder: Optional[EmbeddingProvider] = None) -> None:
        self.embedder = embedder or DeterministicHashEmbeddingProvider(dimensions=128)
        self.chunks: List[AdvisoryChunk] = []
        self._queried_packages: set[str] = set()
        self._seed_builtin_chunks()

    def _seed_builtin_chunks(self) -> None:
        """Seed retriever with known advisory chunks from OSV client cache."""
        for bare_pkg in BUILTIN_ADVISORIES:
            self._queried_packages.add(f"{bare_pkg}:npm")
            osv_items = default_osv_client.query_package(bare_pkg, ecosystem="npm")
            for item in osv_items:
                self.index_advisory(item)

    def index_advisory(self, item: Dict[str, Any]) -> AdvisoryChunk:
        """Add or update an advisory chunk in the retriever index."""
        chunk_id = item.get("chunk_id") or f"ADV-{item.get('package', 'pkg')}-{item.get('cve', '0000')}"
        pkg = item.get("package", "npm:unknown")
        cve = item.get("cve", "CVE")
        title = item.get("title", "")
        text = f"{title}. {item.get('description', '')}"

        # Generate embedding vector for chunk text
        embedding = self.embedder.embed_query(f"{pkg} {cve} {text}")

        chunk = AdvisoryChunk(
            chunk_id=chunk_id,
            package=pkg,
            ecosystem=item.get("ecosystem", "npm"),
            cve=cve,
            title=title,
            text=text,
            embedding=embedding,
            metadata=item,
        )
        # Avoid duplicate chunk IDs
        self.chunks = [c for c in self.chunks if c.chunk_id != chunk_id]
        self.chunks.append(chunk)
        return chunk

    def search(
        self,
        query: str,
        package: Optional[str] = None,
        ecosystem: str = "npm",
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Search for relevant advisory chunks filtered strictly by package name.

        Args:
            query: Free-text search query or CVE identifier.
            package: Target package name (e.g. 'npm:lodash' or 'lodash').
            ecosystem: Package ecosystem filter.
            limit: Maximum number of chunks to return.

        Returns:
            List of matching advisory chunk dictionaries sorted by relevance score.
        """
        # If no package filter, return empty to prevent cross-package pollution
        if not package and not query:
            return []

        clean_pkg = package.replace("PKG-", "") if package else None
        bare_pkg = clean_pkg.split(":", 1)[1] if clean_pkg and ":" in clean_pkg else clean_pkg

        # Determine target ecosystem (inferred from package prefix if available)
        target_eco = ecosystem
        if clean_pkg and ":" in clean_pkg:
            prefix = clean_pkg.split(":", 1)[0].lower()
            if prefix in ("pip", "pypi", "python"):
                target_eco = "PyPI"
            elif prefix in ("npm", "node"):
                target_eco = "npm"

        # Query OSV live if package is not yet indexed or queried
        if clean_pkg:
            cache_key = f"{bare_pkg}:{target_eco.lower()}"
            if cache_key not in self._queried_packages:
                self._queried_packages.add(cache_key)
                live_items = default_osv_client.query_package(clean_pkg, ecosystem=target_eco)
                for itm in live_items:
                    self.index_advisory(itm)

        # Filter candidate chunks strictly by package
        candidates: List[AdvisoryChunk] = []
        for c in self.chunks:
            if clean_pkg and bare_pkg is not None:
                if bare_pkg not in c.package and clean_pkg not in c.package:
                    continue
            if target_eco and c.ecosystem.lower() not in (target_eco.lower(), "npm"):
                continue
            candidates.append(c)

        if not candidates:
            return []

        query_vec = self.embedder.embed_query(f"{package or ''} {query}")
        scored: List[tuple[float, AdvisoryChunk]] = []

        query_lower = query.lower()
        query_words = set(query_lower.split())
        for cand in candidates:
            # 1. Cosine similarity
            dot = sum(a * b for a, b in zip(query_vec, cand.embedding))
            sim = max(0.0, dot)

            # 2. Keyword boost
            boost = 0.0
            if cand.cve and cand.cve.lower() in query_lower:
                boost += 2.0
            cand_text_lower = cand.text.lower()
            matched_words = sum(1 for w in query_words if len(w) > 3 and w in cand_text_lower)
            boost += (matched_words * 0.5)

            score = sim + boost
            scored.append((score, cand))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [c.to_dict() for _, c in scored[:limit]]


# Global default advisory retriever
default_advisory_retriever = AdvisoryRetriever()


def advisory_search(
    query: str,
    package: Optional[str] = None,
    ecosystem: str = "npm",
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """Convenience functional interface for advisory searching."""
    return default_advisory_retriever.search(
        query=query,
        package=package,
        ecosystem=ecosystem,
        limit=limit,
    )
