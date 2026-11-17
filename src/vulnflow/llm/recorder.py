"""
llm/recorder.py
Records and replays LLM responses for testing and demonstrations.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from vulnflow.llm.base import LLMMessage, LLMResponse, LLMUsage

logger = logging.getLogger("vulnflow.llm.recorder")


class LLMRecorder:
    """
    Manages deterministic recording and playback of LLM requests and responses.
    Allows integration tests and benchmark evaluations to run offline without API tokens.
    """

    def __init__(
        self,
        mode: str = "LIVE",  # LIVE, RECORD, REPLAY, AUTO
        record_dir: str = "evals/recorded_llm",
    ) -> None:
        self.mode = mode.upper()
        self.record_dir = Path(record_dir)
        if self.mode in ("RECORD", "AUTO"):
            self.record_dir.mkdir(parents=True, exist_ok=True)

    def compute_key(
        self,
        provider: str,
        model: str,
        messages: List[Union[LLMMessage, Dict[str, Any]]],
        **kwargs: Any,
    ) -> str:
        """Generate a deterministic SHA256 digest identifying the exact request parameters."""
        serialized_messages = []
        for msg in messages:
            if isinstance(msg, LLMMessage):
                serialized_messages.append(msg.to_dict())
            else:
                serialized_messages.append(msg)

        payload = {
            "provider": provider.lower(),
            "model": model,
            "messages": serialized_messages,
            "temperature": kwargs.get("temperature", 0.0),
            "max_tokens": kwargs.get("max_tokens"),
        }
        raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw_bytes).hexdigest()

    def _fixture_path(self, key: str) -> Path:
        return self.record_dir / f"{key[:16]}_{key[-8:]}.json"

    def has_recording(
        self,
        provider: str,
        model: str,
        messages: List[Union[LLMMessage, Dict[str, Any]]],
        **kwargs: Any,
    ) -> bool:
        """Check if a fixture exists for this request."""
        key = self.compute_key(provider, model, messages, **kwargs)
        return self._fixture_path(key).exists()

    def load_response(
        self,
        provider: str,
        model: str,
        messages: List[Union[LLMMessage, Dict[str, Any]]],
        **kwargs: Any,
    ) -> Optional[LLMResponse]:
        """Load and deserialize a recorded LLM response from disk."""
        key = self.compute_key(provider, model, messages, **kwargs)
        path = self._fixture_path(key)

        if not path.exists():
            return None

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            resp_data = data["response"]
            usage_data = resp_data.get("usage", {})
            usage = LLMUsage(
                prompt_tokens=usage_data.get("prompt_tokens", 0),
                completion_tokens=usage_data.get("completion_tokens", 0),
                total_tokens=usage_data.get("total_tokens", 0),
                cost_estimate_usd=usage_data.get("cost_estimate_usd", 0.0),
                raw_usage=usage_data.get("raw_usage", {}),
            )

            return LLMResponse(
                content=resp_data.get("content", ""),
                role=resp_data.get("role", "assistant"),
                model=resp_data.get("model", model),
                provider=resp_data.get("provider", provider),
                usage=usage,
                finish_reason=resp_data.get("finish_reason", "stop"),
                latency_ms=resp_data.get("latency_ms", 1.0),
                raw_response=resp_data.get("raw_response", {}),
                cached=True,
            )
        except Exception as exc:
            logger.error("Failed to load recorded fixture at %s: %s", path, exc)
            return None

    def save_response(
        self,
        provider: str,
        model: str,
        messages: List[Union[LLMMessage, Dict[str, Any]]],
        response: LLMResponse,
        **kwargs: Any,
    ) -> None:
        """Serialize and persist an LLM request/response pair to disk."""
        key = self.compute_key(provider, model, messages, **kwargs)
        path = self._fixture_path(key)
        self.record_dir.mkdir(parents=True, exist_ok=True)

        serialized_messages = []
        for msg in messages:
            if isinstance(msg, LLMMessage):
                serialized_messages.append(msg.to_dict())
            else:
                serialized_messages.append(msg)

        fixture_data = {
            "key": key,
            "request": {
                "provider": provider,
                "model": model,
                "messages": serialized_messages,
                "kwargs": {k: str(v) for k, v in kwargs.items() if not k.startswith("_")},
            },
            "response": {
                "content": response.content,
                "role": response.role,
                "model": response.model,
                "provider": response.provider,
                "finish_reason": response.finish_reason,
                "latency_ms": response.latency_ms,
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                    "cost_estimate_usd": response.usage.cost_estimate_usd,
                    "raw_usage": response.usage.raw_usage,
                },
                "raw_response": response.raw_response,
            },
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(fixture_data, f, indent=2)

        logger.info("Saved LLM fixture to %s", path)
