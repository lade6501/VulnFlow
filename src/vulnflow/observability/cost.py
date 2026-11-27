"""
src/vulnflow/observability/cost.py
Tracks token usage and calculates financial costs of LLM agent executions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

# Pricing table: (prompt_cost_per_million_tokens, completion_cost_per_million_tokens) in USD
DEFAULT_PRICING: Dict[str, Tuple[float, float]] = {
    # OpenAI
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-2024-08-06": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4-turbo": (10.00, 30.00),
    "o1": (15.00, 60.00),
    "o1-mini": (3.00, 12.00),
    "o3-mini": (1.10, 4.40),
    # Anthropic
    "claude-3-5-sonnet-20241022": (3.00, 15.00),
    "claude-3-5-sonnet-latest": (3.00, 15.00),
    "claude-3-5-haiku-20241022": (0.80, 4.00),
    "claude-3-opus-20240229": (15.00, 75.00),
    # Nvidia NIM (standard catalog estimates per 1M tokens)
    "minimaxai/minimax-m3.1-flash": (0.20, 0.20),
    "meta/llama-3.1-405b-instruct": (3.00, 3.00),
    "mistralai/mixtral-8x22b-instruct-v0.1": (0.90, 0.90),
    # Bedrock Converse mappings
    "anthropic.claude-3-5-sonnet-20241022-v2:0": (3.00, 15.00),
    "anthropic.claude-3-haiku-20240307-v1:0": (0.25, 1.25),
    "amazon.titan-text-express-v1": (0.20, 0.60),
    # OpenRouter passthrough / typical
    "openrouter/auto": (2.00, 8.00),
    # Ollama / Local (zero direct cost)
    "ollama/default": (0.00, 0.00),
}


def calculate_cost(
    provider: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
) -> float:
    """
    Calculate the estimated cost in USD for a given LLM call.

    Args:
        provider: Provider identifier (e.g., 'openai', 'anthropic', 'ollama', 'nvidia', 'openrouter', 'bedrock')
        model: Model name/identifier.
        prompt_tokens: Number of prompt/input tokens.
        completion_tokens: Number of completion/output tokens.

    Returns:
        Estimated cost in USD rounded to 6 decimal places.
    """
    if provider.lower() in ("ollama", "local"):
        return 0.0

    # Look up pricing by exact model name
    rates: Optional[Tuple[float, float]] = None
    clean_model = model.lower()

    if clean_model in DEFAULT_PRICING:
        rates = DEFAULT_PRICING[clean_model]
    else:
        # Fuzzy prefix match
        for key, value in DEFAULT_PRICING.items():
            if key in clean_model or clean_model in key:
                rates = value
                break

    if rates is None:
        # Default fallback estimate ($1.50 / $6.00 per 1M tokens)
        rates = (1.50, 6.00)

    prompt_rate, completion_rate = rates
    cost = (prompt_tokens / 1_000_000.0 * prompt_rate) + (
        completion_tokens / 1_000_000.0 * completion_rate
    )
    return round(cost, 6)


@dataclass
class CostTracker:
    """In-memory aggregator for tracking cumulative token usage and costs."""

    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_cost_usd: float = 0.0
    calls_by_model: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def record_usage(
        self,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> float:
        """Record an execution and return its incremental cost."""
        cost = calculate_cost(provider, model, prompt_tokens, completion_tokens)
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_cost_usd = round(self.total_cost_usd + cost, 6)

        key = f"{provider}:{model}"
        if key not in self.calls_by_model:
            self.calls_by_model[key] = {
                "calls": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "cost_usd": 0.0,
            }

        rec = self.calls_by_model[key]
        rec["calls"] += 1
        rec["prompt_tokens"] += prompt_tokens
        rec["completion_tokens"] += completion_tokens
        rec["cost_usd"] = round(rec["cost_usd"] + cost, 6)

        return cost

    def get_summary(self) -> Dict[str, Any]:
        """Return a structured summary of all tracked token consumption and costs."""
        return {
            "total_tokens": self.total_prompt_tokens + self.total_completion_tokens,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "breakdown": self.calls_by_model,
        }


# Global shared instance
global_cost_tracker = CostTracker()
