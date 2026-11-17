"""
llm/__init__.py
Centralized, provider-agnostic LLM abstraction layer and provider adapters.
"""

from vulnflow.llm.base import (
    LLMAuthenticationError,
    LLMClient,
    LLMError,
    LLMMessage,
    LLMProviderError,
    LLMRateLimitError,
    LLMResponse,
    LLMStructuredOutputError,
    LLMTimeoutError,
    LLMUsage,
)
from vulnflow.llm.embeddings import (
    DeterministicHashEmbeddingProvider,
    EmbeddingProvider,
    OllamaEmbeddingProvider,
    OpenAIEmbeddingProvider,
    create_embedding_provider,
)
from vulnflow.llm.factory import create_llm_client
from vulnflow.llm.guard import RedactionGuard, default_guard
from vulnflow.llm.recorder import LLMRecorder
from vulnflow.llm.structured import extract_json, validate_structured_output

__all__ = [
    "DeterministicHashEmbeddingProvider",
    "EmbeddingProvider",
    "LLMAuthenticationError",
    "LLMClient",
    "LLMError",
    "LLMMessage",
    "LLMProviderError",
    "LLMRateLimitError",
    "LLMRecorder",
    "LLMResponse",
    "LLMStructuredOutputError",
    "LLMTimeoutError",
    "LLMUsage",
    "OllamaEmbeddingProvider",
    "OpenAIEmbeddingProvider",
    "RedactionGuard",
    "create_embedding_provider",
    "create_llm_client",
    "default_guard",
    "extract_json",
    "validate_structured_output",
]
