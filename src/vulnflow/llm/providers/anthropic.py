"""
llm/providers/anthropic.py
Anthropic provider adapter.
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
    LLMAuthenticationError,
    LLMClient,
    LLMError,
    LLMMessage,
    LLMProviderError,
    LLMRateLimitError,
    LLMResponse,
    LLMTimeoutError,
    LLMUsage,
)

logger = logging.getLogger("vulnflow.llm.providers.anthropic")


class AnthropicProvider(LLMClient):
    """Adapter for Anthropic Messages API."""

    def __init__(
        self,
        default_model: str = "claude-3-5-sonnet-20241022",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        anthropic_version: str = "2023-06-01",
        timeout: float = 60.0,
        max_retries: int = 3,
        **kwargs: Any,
    ) -> None:
        super().__init__(default_model=default_model, timeout=timeout, max_retries=max_retries, **kwargs)
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.base_url = (base_url or os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1")).rstrip("/")
        self.anthropic_version = anthropic_version

    def get_provider_name(self) -> str:
        return "anthropic"

    def complete(
        self,
        messages: List[Union[LLMMessage, Dict[str, str]]],
        model: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        start_time = time.time()
        active_model = model or self.default_model
        normalized = self._normalize_messages(messages)

        if not self.api_key:
            raise LLMAuthenticationError(
                "ANTHROPIC_API_KEY is not set. Please set the environment variable or pass api_key.",
                provider=self.get_provider_name(),
            )

        # Anthropic separates top-level system prompt from user/assistant turns
        system_prompts: List[str] = []
        anthropic_messages: List[Dict[str, Any]] = []

        for msg in normalized:
            if msg.role == "system":
                system_prompts.append(msg.content)
            elif msg.role in ("user", "assistant"):
                anthropic_messages.append({"role": msg.role, "content": msg.content})

        # Anthropic requires at least one user message
        if not anthropic_messages:
            anthropic_messages.append({"role": "user", "content": "Hello"})

        # Merge multiple consecutive messages with same role if needed
        merged_messages: List[Dict[str, Any]] = []
        for message in anthropic_messages:
            if merged_messages and merged_messages[-1]["role"] == message["role"]:
                merged_messages[-1]["content"] += "\n\n" + message["content"]
            else:
                merged_messages.append(message)

        payload_dict: Dict[str, Any] = {
            "model": active_model,
            "messages": merged_messages,
            "max_tokens": max_tokens or 4096,
            "temperature": temperature,
        }
        if system_prompts:
            payload_dict["system"] = "\n\n".join(system_prompts)
        if tools:
            payload_dict["tools"] = tools

        for k, v in kwargs.items():
            if not k.startswith("_"):
                payload_dict[k] = v

        url = f"{self.base_url}/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": self.anthropic_version,
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
            if status_code in (401, 403):
                raise LLMAuthenticationError(
                    f"Anthropic Authentication failed ({status_code}): {err_body}",
                    provider=self.get_provider_name(),
                    status_code=status_code,
                ) from exc
            elif status_code == 429:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                raise LLMRateLimitError(
                    f"Anthropic Rate limit exceeded ({status_code}): {err_body}",
                    provider=self.get_provider_name(),
                    status_code=status_code,
                    retry_after=float(retry_after) if retry_after and retry_after.replace(".", "", 1).isdigit() else None,
                ) from exc
            elif status_code >= 500:
                raise LLMProviderError(
                    f"Anthropic server error ({status_code}): {err_body}",
                    provider=self.get_provider_name(),
                    status_code=status_code,
                ) from exc
            raise LLMError(
                f"Anthropic API error ({status_code}): {err_body}",
                provider=self.get_provider_name(),
                status_code=status_code,
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise LLMTimeoutError(
                f"Anthropic request timed out or network unreachable: {exc}",
                provider=self.get_provider_name(),
            ) from exc

        # Extract textual response
        text_parts: List[str] = []
        for block in res_data.get("content", []):
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))

        content = "".join(text_parts)
        usage_dict = res_data.get("usage", {})
        prompt_tokens = usage_dict.get("input_tokens", 0)
        completion_tokens = usage_dict.get("output_tokens", 0)

        usage = LLMUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            raw_usage=usage_dict,
        )

        response = LLMResponse(
            content=content,
            role=res_data.get("role", "assistant"),
            model=res_data.get("model", active_model),
            provider=self.get_provider_name(),
            usage=usage,
            finish_reason=res_data.get("stop_reason"),
            raw_response=res_data,
        )

        self._record_telemetry(response, start_time)
        return response
