"""
llm/base.py
LLMClient interface for completions, structured output, and usage reporting.
"""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type, Union

from vulnflow.observability.cost import calculate_cost, global_cost_tracker
from vulnflow.observability.tracing import global_tracer


@dataclass
class LLMMessage:
    """Represents a message in a conversation sequence."""

    role: str  # 'system', 'user', 'assistant', 'tool'
    content: str
    name: Optional[str] = None
    refusal: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to a standard dictionary payload."""
        data: Dict[str, Any] = {"role": self.role, "content": self.content}
        if self.name:
            data["name"] = self.name
        if self.tool_calls:
            data["tool_calls"] = self.tool_calls
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LLMMessage:
        """Create an LLMMessage from a dictionary."""
        return cls(
            role=data.get("role", "user"),
            content=data.get("content", ""),
            name=data.get("name"),
            refusal=data.get("refusal"),
            tool_calls=data.get("tool_calls"),
        )


@dataclass
class LLMUsage:
    """Token consumption and financial cost metrics for an LLM response."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_estimate_usd: float = 0.0
    raw_usage: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    """Standardized response object produced by any LLM provider adapter."""

    content: str
    role: str = "assistant"
    model: str = ""
    provider: str = ""
    usage: LLMUsage = field(default_factory=LLMUsage)
    structured_data: Optional[Any] = None
    finish_reason: Optional[str] = None
    latency_ms: float = 0.0
    raw_response: Dict[str, Any] = field(default_factory=dict)
    cached: bool = False


class LLMError(Exception):
    """Base exception for all LLM client failures."""

    def __init__(self, message: str, provider: str = "", status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.provider = provider
        self.status_code = status_code


class LLMAuthenticationError(LLMError):
    """Raised when an API key is missing or invalid."""


class LLMRateLimitError(LLMError):
    """Raised when a provider rejects a request due to rate or quota limits."""


class LLMTimeoutError(LLMError):
    """Raised when an HTTP request to a provider times out."""


class LLMStructuredOutputError(LLMError):
    """Raised when structured response parsing or validation exhausts retries."""


class LLMProviderError(LLMError):
    """Raised when an upstream provider returns a 5xx or unhandled error."""


class LLMClient(abc.ABC):
    """
    Abstract Base Class defining the provider-agnostic interface for LLM operations.
    All vendor adapters (OpenAI, Anthropic, Bedrock, Ollama, Nvidia, OpenRouter) inherit from this.
    """

    def __init__(
        self,
        default_model: str,
        timeout: float = 60.0,
        max_retries: int = 3,
        **kwargs: Any,
    ) -> None:
        self.default_model = default_model
        self.timeout = timeout
        self.max_retries = max_retries
        self.extra_kwargs = kwargs

    @abc.abstractmethod
    def get_provider_name(self) -> str:
        """Return the unique provider name (e.g. 'openai', 'anthropic', 'nvidia', 'openrouter', etc.)."""
        raise NotImplementedError

    @abc.abstractmethod
    def complete(
        self,
        messages: List[Union[LLMMessage, Dict[str, str]]],
        model: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Execute a completion request against the LLM provider."""
        raise NotImplementedError

    def structured_complete(
        self,
        messages: List[Union[LLMMessage, Dict[str, str]]],
        response_schema: Union[Type[Any], Dict[str, Any]],
        model: Optional[str] = None,
        max_retries: int = 3,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Execute completion and validate output against a schema/Pydantic model with bounded retry.
        Delegates to the structured validation engine in `vulnflow.llm.structured`.
        """
        from vulnflow.llm.structured import validate_structured_output

        return validate_structured_output(
            client=self,
            messages=messages,
            response_schema=response_schema,
            model=model or self.default_model,
            max_retries=max_retries,
            temperature=temperature,
            **kwargs,
        )

    def _normalize_messages(
        self, messages: List[Union[LLMMessage, Dict[str, str]]]
    ) -> List[LLMMessage]:
        """Convert any dict-like messages into standard LLMMessage instances."""
        normalized: List[LLMMessage] = []
        for msg in messages:
            if isinstance(msg, LLMMessage):
                normalized.append(msg)
            elif isinstance(msg, dict):
                normalized.append(LLMMessage.from_dict(msg))
            else:
                raise ValueError(f"Unsupported message type: {type(msg)}")
        return normalized

    def _record_telemetry(
        self,
        response: LLMResponse,
        start_time: float,
        status: str = "OK",
        error: Optional[str] = None,
    ) -> None:
        """Record span and financial cost metrics into observability system."""
        latency_ms = round((time.time() - start_time) * 1000.0, 2)
        response.latency_ms = latency_ms

        cost_usd = calculate_cost(
            provider=self.get_provider_name(),
            model=response.model,
            prompt_tokens=response.usage.prompt_tokens,
            completion_tokens=response.usage.completion_tokens,
        )
        response.usage.cost_estimate_usd = cost_usd

        global_cost_tracker.record_usage(
            provider=self.get_provider_name(),
            model=response.model,
            prompt_tokens=response.usage.prompt_tokens,
            completion_tokens=response.usage.completion_tokens,
        )

        global_tracer.record_llm_call(
            provider=self.get_provider_name(),
            model=response.model,
            prompt_tokens=response.usage.prompt_tokens,
            completion_tokens=response.usage.completion_tokens,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
            status=status,
            error=error,
        )
