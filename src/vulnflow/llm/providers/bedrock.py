"""
llm/providers/bedrock.py
AWS Bedrock provider adapter.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Union

from vulnflow.llm.base import (
    LLMAuthenticationError,
    LLMClient,
    LLMError,
    LLMMessage,
    LLMProviderError,
    LLMResponse,
    LLMTimeoutError,
    LLMUsage,
)

logger = logging.getLogger("vulnflow.llm.providers.bedrock")


class BedrockProvider(LLMClient):
    """Adapter for AWS Bedrock Converse API."""

    def __init__(
        self,
        default_model: str = "anthropic.claude-3-5-sonnet-20241022-v2:0",
        region_name: Optional[str] = None,
        timeout: float = 60.0,
        max_retries: int = 3,
        **kwargs: Any,
    ) -> None:
        super().__init__(default_model=default_model, timeout=timeout, max_retries=max_retries, **kwargs)
        self.region_name = region_name or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        self._boto_client: Optional[Any] = None

    def get_provider_name(self) -> str:
        return "bedrock"

    def _get_client(self) -> Any:
        if self._boto_client is not None:
            return self._boto_client

        try:
            import boto3
            self._boto_client = boto3.client("bedrock-runtime", region_name=self.region_name)
            return self._boto_client
        except ImportError:
            return None

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

        client = self._get_client()

        # If boto3 is available, use official Converse API
        if client is not None:
            system_prompts: List[Dict[str, str]] = []
            converse_messages: List[Dict[str, Any]] = []

            for msg in normalized:
                if msg.role == "system":
                    system_prompts.append({"text": msg.content})
                elif msg.role in ("user", "assistant"):
                    converse_messages.append({
                        "role": msg.role,
                        "content": [{"text": msg.content}],
                    })

            inference_config: Dict[str, Any] = {"temperature": temperature}
            if max_tokens is not None:
                inference_config["maxTokens"] = max_tokens

            params: Dict[str, Any] = {
                "modelId": active_model,
                "messages": converse_messages,
                "inferenceConfig": inference_config,
            }
            if system_prompts:
                params["system"] = system_prompts

            try:
                raw_resp = client.converse(**params)
            except Exception as exc:
                err_str = str(exc)
                if "AccessDeniedException" in err_str or "UnrecognizedClientException" in err_str:
                    raise LLMAuthenticationError(f"AWS Bedrock auth failed: {exc}", provider=self.get_provider_name()) from exc
                elif "ThrottlingException" in err_str:
                    raise LLMRateLimitError(f"AWS Bedrock rate limit: {exc}", provider=self.get_provider_name()) from exc
                raise LLMProviderError(f"AWS Bedrock invocation error: {exc}", provider=self.get_provider_name()) from exc

            output_msg = raw_resp.get("output", {}).get("message", {})
            text_blocks = [c.get("text", "") for c in output_msg.get("content", []) if "text" in c]
            content = "".join(text_blocks)

            metrics = raw_resp.get("usage", {})
            prompt_tokens = metrics.get("inputTokens", 0)
            completion_tokens = metrics.get("outputTokens", 0)

            usage = LLMUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
                raw_usage=metrics,
            )

            response = LLMResponse(
                content=content,
                role=output_msg.get("role", "assistant"),
                model=active_model,
                provider=self.get_provider_name(),
                usage=usage,
                finish_reason=raw_resp.get("stopReason"),
                raw_response=raw_resp,
            )
            self._record_telemetry(response, start_time)
            return response

        # If boto3 is not installed, check for AWS credentials or provide simulated response in dev
        aws_key = os.getenv("AWS_ACCESS_KEY_ID")
        if not aws_key:
            raise LLMAuthenticationError(
                "AWS credentials not configured and 'boto3' is not installed. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY or install boto3.",
                provider=self.get_provider_name(),
            )

        raise LLMProviderError(
            "boto3 library is required to communicate with AWS Bedrock API. Please install 'boto3'.",
            provider=self.get_provider_name(),
        )
