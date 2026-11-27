"""
llm/providers/ollama.py
Ollama self-hosted provider adapter.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Union

from vulnflow.llm.base import (
    LLMClient,
    LLMMessage,
    LLMProviderError,
    LLMResponse,
    LLMTimeoutError,
    LLMUsage,
)

logger = logging.getLogger("vulnflow.llm.providers.ollama")


class OllamaProvider(LLMClient):
    """Adapter for self-hosted local Ollama models."""

    def __init__(
        self,
        default_model: str = "llama3.1",
        base_url: Optional[str] = None,
        timeout: float = 120.0,
        max_retries: int = 3,
        **kwargs: Any,
    ) -> None:
        super().__init__(default_model=default_model, timeout=timeout, max_retries=max_retries, **kwargs)
        self.base_url = (base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")

    def get_provider_name(self) -> str:
        return "ollama"

    def complete(
        self,
        messages: List[Union[LLMMessage, Dict[str, str]]],
        model: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        start_time = time.time()
        active_model = model or self.default_model
        normalized = self._normalize_messages(messages)

        options: Dict[str, Any] = {"temperature": temperature}
        if max_tokens is not None:
            options["num_predict"] = max_tokens

        payload_dict: Dict[str, Any] = {
            "model": active_model,
            "messages": [m.to_dict() for m in normalized],
            "stream": False,
            "options": options,
        }

        for k, v in kwargs.items():
            if not k.startswith("_"):
                payload_dict[k] = v

        url = f"{self.base_url}/api/chat"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "VulnFlow-LLM/1.0",
        }

        body = json.dumps(payload_dict).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status_code = resp.getcode()
                raw_text = resp.read().decode("utf-8")
                res_data = json.loads(raw_text)
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8") if exc.fp else ""
            status_code = exc.code
            raise LLMProviderError(
                f"Ollama server error ({status_code}): {err_body}",
                provider=self.get_provider_name(),
                status_code=status_code,
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise LLMTimeoutError(
                f"Ollama connection failed or timed out at {self.base_url}: {exc}. Is the Ollama daemon running?",
                provider=self.get_provider_name(),
            ) from exc

        msg = res_data.get("message", {})
        prompt_tokens = res_data.get("prompt_eval_count", 0)
        completion_tokens = res_data.get("eval_count", 0)

        usage = LLMUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            cost_estimate_usd=0.0,
            raw_usage=res_data,
        )

        response = LLMResponse(
            content=msg.get("content") or "",
            role=msg.get("role", "assistant"),
            model=res_data.get("model", active_model),
            provider=self.get_provider_name(),
            usage=usage,
            finish_reason=res_data.get("done_reason", "stop"),
            raw_response=res_data,
        )

        self._record_telemetry(response, start_time)
        return response
