"""
llm/providers/openai.py
OpenAI provider adapter.
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

logger = logging.getLogger("vulnflow.llm.providers.openai")


class OpenAIProvider(LLMClient):
    """Adapter for OpenAI Chat Completions API."""

    def __init__(
        self,
        default_model: str = "gpt-4o",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 60.0,
        max_retries: int = 3,
        organization: Optional[str] = None,
        project: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(default_model=default_model, timeout=timeout, max_retries=max_retries, **kwargs)
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.organization = organization or os.getenv("OPENAI_ORG_ID")
        self.project = project or os.getenv("OPENAI_PROJECT_ID")

    def get_provider_name(self) -> str:
        return "openai"

    def complete(
        self,
        messages: List[Union[LLMMessage, Dict[str, str]]],
        model: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[Union[str, Dict[str, Any]]] = None,
        response_format: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        start_time = time.time()
        active_model = model or self.default_model
        normalized_messages = self._normalize_messages(messages)

        if not self.api_key:
            raise LLMAuthenticationError(
                "OPENAI_API_KEY is not set. Please set the environment variable or pass api_key.",
                provider=self.get_provider_name(),
            )

        payload_dict: Dict[str, Any] = {
            "model": active_model,
            "messages": [m.to_dict() for m in normalized_messages],
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload_dict["max_tokens"] = max_tokens
        if tools:
            payload_dict["tools"] = tools
        if tool_choice:
            payload_dict["tool_choice"] = tool_choice
        if response_format:
            payload_dict["response_format"] = response_format

        # Add any extra kwargs
        for k, v in kwargs.items():
            if not k.startswith("_"):
                payload_dict[k] = v

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "VulnFlow-LLM/1.0",
        }
        if self.organization:
            headers["OpenAI-Organization"] = self.organization
        if self.project:
            headers["OpenAI-Project"] = self.project

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
                    f"OpenAI Authentication failed ({status_code}): {err_body}",
                    provider=self.get_provider_name(),
                    status_code=status_code,
                ) from exc
            elif status_code == 429:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                raise LLMRateLimitError(
                    f"OpenAI Rate limit exceeded ({status_code}): {err_body}",
                    provider=self.get_provider_name(),
                    status_code=status_code,
                    retry_after=float(retry_after) if retry_after and retry_after.replace(".", "", 1).isdigit() else None,
                ) from exc
            elif status_code >= 500:
                raise LLMProviderError(
                    f"OpenAI server error ({status_code}): {err_body}",
                    provider=self.get_provider_name(),
                    status_code=status_code,
                ) from exc
            raise LLMError(
                f"OpenAI API error ({status_code}): {err_body}",
                provider=self.get_provider_name(),
                status_code=status_code,
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise LLMTimeoutError(
                f"OpenAI request timed out or network unreachable: {exc}",
                provider=self.get_provider_name(),
            ) from exc

        choice = res_data.get("choices", [{}])[0]
        msg = choice.get("message", {})
        usage_dict = res_data.get("usage", {})

        usage = LLMUsage(
            prompt_tokens=usage_dict.get("prompt_tokens", 0),
            completion_tokens=usage_dict.get("completion_tokens", 0),
            total_tokens=usage_dict.get("total_tokens", 0),
            raw_usage=usage_dict,
        )

        response = LLMResponse(
            content=msg.get("content") or "",
            role=msg.get("role", "assistant"),
            model=res_data.get("model", active_model),
            provider=self.get_provider_name(),
            usage=usage,
            finish_reason=choice.get("finish_reason"),
            raw_response=res_data,
        )

        self._record_telemetry(response, start_time)
        return response
