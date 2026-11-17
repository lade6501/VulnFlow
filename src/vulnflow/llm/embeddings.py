"""
llm/embeddings.py
Defines embedding provider abstraction and provider selection.
"""

from __future__ import annotations

import abc
import hashlib
import json
import logging
import math
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vulnflow.llm.embeddings")


class EmbeddingProvider(abc.ABC):
    """Abstract interface for text embedding generation used by RAG and vector search."""

    @abc.abstractmethod
    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        """Generate embedding vectors for a list of input documents."""
        raise NotImplementedError

    def embed_query(self, text: str) -> List[float]:
        """Generate an embedding vector for a single query string."""
        results = self.embed_texts([text])
        if not results:
            raise ValueError("No embeddings returned for query")
        return results[0]

    @abc.abstractmethod
    def get_dimensions(self) -> int:
        """Return the vector dimensionality of this embedding model."""
        raise NotImplementedError


class DeterministicHashEmbeddingProvider(EmbeddingProvider):
    """
    Offline, zero-network embedding provider generating deterministic normalized pseudo-vectors.
    Used for local tests, air-gapped environments, and CI runs.
    """

    def __init__(self, dimensions: int = 384) -> None:
        self.dimensions = dimensions

    def get_dimensions(self) -> int:
        return self.dimensions

    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        vectors: List[List[float]] = []
        for text in texts:
            # Deterministic projection using repeated hashing
            vals: List[float] = []
            seed = text.encode("utf-8")
            h = hashlib.sha256(seed).digest()
            while len(vals) < self.dimensions:
                for b in h:
                    # Convert byte 0-255 to float -1.0 to 1.0
                    vals.append((float(b) / 127.5) - 1.0)
                    if len(vals) == self.dimensions:
                        break
                h = hashlib.sha256(h).digest()

            # L2 normalize
            norm = math.sqrt(sum(x * x for x in vals)) or 1.0
            vectors.append([round(x / norm, 6) for x in vals])
        return vectors


class OpenAIEmbeddingProvider(EmbeddingProvider):
    """Generates embeddings via OpenAI v1/embeddings API."""

    def __init__(
        self,
        model: str = "text-embedding-3-small",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        dimensions: int = 1536,
        timeout: float = 30.0,
    ) -> None:
        self.model = model
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.base_url = (base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.dimensions = dimensions
        self.timeout = timeout

    def get_dimensions(self) -> int:
        return self.dimensions

    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        if not self.api_key:
            logger.warning("No OPENAI_API_KEY provided; falling back to deterministic hash embeddings.")
            fallback = DeterministicHashEmbeddingProvider(self.dimensions)
            return fallback.embed_texts(texts)

        url = f"{self.base_url}/embeddings"
        payload = json.dumps({"model": self.model, "input": texts}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            data_items = sorted(data.get("data", []), key=lambda x: x.get("index", 0))
            return [item["embedding"] for item in data_items]
        except Exception as exc:
            logger.error("OpenAI embedding API failed: %s; using deterministic fallback", exc)
            fallback = DeterministicHashEmbeddingProvider(self.dimensions)
            return fallback.embed_texts(texts)


class OllamaEmbeddingProvider(EmbeddingProvider):
    """Generates embeddings via local Ollama instance."""

    def __init__(
        self,
        model: str = "nomic-embed-text",
        base_url: Optional[str] = None,
        dimensions: int = 768,
        timeout: float = 30.0,
    ) -> None:
        self.model = model
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.dimensions = dimensions
        self.timeout = timeout

    def get_dimensions(self) -> int:
        return self.dimensions

    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        url = f"{self.base_url}/api/embeddings"
        vectors: List[List[float]] = []

        for text in texts:
            payload = json.dumps({"model": self.model, "prompt": text}).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                vectors.append(data.get("embedding", []))
            except Exception as exc:
                logger.warning("Ollama embedding failed for '%s': %s; using fallback", text[:20], exc)
                fallback = DeterministicHashEmbeddingProvider(self.dimensions)
                vectors.extend(fallback.embed_texts([text]))

        return vectors


def create_embedding_provider(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    **kwargs: Any,
) -> EmbeddingProvider:
    """Factory creating the appropriate EmbeddingProvider based on config or availability."""
    target = (provider or os.getenv("VULNFLOW_EMBEDDING_PROVIDER", "hash")).lower()

    if target == "openai":
        return OpenAIEmbeddingProvider(model=model or "text-embedding-3-small", **kwargs)
    elif target == "ollama":
        return OllamaEmbeddingProvider(model=model or "nomic-embed-text", **kwargs)
    else:
        dims = kwargs.get("dimensions", 384)
        return DeterministicHashEmbeddingProvider(dimensions=dims)
