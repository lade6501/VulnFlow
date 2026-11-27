"""
llm/factory.py
Selects provider and model based on agent role and configuration.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Type, Union

from vulnflow.config import settings
from vulnflow.llm.base import LLMClient, LLMMessage, LLMResponse
from vulnflow.llm.guard import RedactionGuard, default_guard
from vulnflow.llm.providers.anthropic import AnthropicProvider
from vulnflow.llm.providers.bedrock import BedrockProvider
from vulnflow.llm.providers.nvidia import NvidiaProvider
from vulnflow.llm.providers.ollama import OllamaProvider
from vulnflow.llm.providers.openai import OpenAIProvider
from vulnflow.llm.providers.openrouter import OpenRouterProvider
from vulnflow.llm.recorder import LLMRecorder

logger = logging.getLogger("vulnflow.llm.factory")

# Provider class registry
PROVIDER_REGISTRY: Dict[str, Type[LLMClient]] = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "bedrock": BedrockProvider,
    "ollama": OllamaProvider,
    "nvidia": NvidiaProvider,
    "openrouter": OpenRouterProvider,
}

# Default models recommended for specific agent roles across supported providers
ROLE_MODEL_DEFAULTS: Dict[str, Dict[str, str]] = {
    "openai": {
        "triage": "gpt-4o-mini",
        "planner": "gpt-4o",
        "fixer": "gpt-4o",
        "rootcause": "gpt-4o",
        "verifier": "gpt-4o",
        "explainer": "gpt-4o-mini",
        "default": "gpt-4o",
    },
    "anthropic": {
        "triage": "claude-3-5-haiku-20241022",
        "planner": "claude-3-5-sonnet-20241022",
        "fixer": "claude-3-5-sonnet-20241022",
        "rootcause": "claude-3-5-sonnet-20241022",
        "verifier": "claude-3-5-sonnet-20241022",
        "explainer": "claude-3-5-haiku-20241022",
        "default": "claude-3-5-sonnet-20241022",
    },
    "nvidia": {
        "triage": "nvidia/nemotron-3.5-lightning-30b-a3b",
        "planner": "nvidia/nemotron-3.5-lightning-30b-a3b",
        "fixer": "nvidia/nemotron-3.5-lightning-30b-a3b",
        "rootcause": "nvidia/nemotron-3.5-lightning-30b-a3b",
        "verifier": "nvidia/nemotron-3.5-lightning-30b-a3b",
        "explainer": "nvidia/nemotron-3.5-lightning-30b-a3b",
        "default": "nvidia/nemotron-3.5-lightning-30b-a3b",
    },
    "openrouter": {
        "triage": "meta-llama/llama-3.1-8b-instruct",
        "planner": "anthropic/claude-3.5-sonnet",
        "fixer": "anthropic/claude-3.5-sonnet",
        "rootcause": "anthropic/claude-3.5-sonnet",
        "verifier": "anthropic/claude-3.5-sonnet",
        "explainer": "meta-llama/llama-3.1-8b-instruct",
        "default": "anthropic/claude-3.5-sonnet",
    },
    "bedrock": {
        "triage": "anthropic.claude-3-haiku-20240307-v1:0",
        "planner": "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "fixer": "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "rootcause": "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "verifier": "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "explainer": "anthropic.claude-3-haiku-20240307-v1:0",
        "default": "anthropic.claude-3-5-sonnet-20241022-v2:0",
    },
    "ollama": {
        "triage": "llama3.1",
        "planner": "llama3.1",
        "fixer": "llama3.1",
        "rootcause": "llama3.1",
        "verifier": "llama3.1",
        "explainer": "llama3.1",
        "default": "llama3.1",
    },
}


class GuardedRecorderClient(LLMClient):
    """
    Wrapper around an underlying LLMClient that automatically applies:
    1. RedactionGuard: Scans and masks outbound credentials before making API requests.
    2. LLMRecorder: Replays cached responses or records live responses for tests/evals.
    """

    def __init__(
        self,
        inner_client: LLMClient,
        guard: Optional[RedactionGuard] = None,
        recorder: Optional[LLMRecorder] = None,
    ) -> None:
        super().__init__(
            default_model=inner_client.default_model,
            timeout=inner_client.timeout,
            max_retries=inner_client.max_retries,
        )
        self.inner_client = inner_client
        self.guard = guard
        self.recorder = recorder

    def get_provider_name(self) -> str:
        return self.inner_client.get_provider_name()

    def complete(
        self,
        messages: List[Union[LLMMessage, Dict[str, str]]],
        model: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        active_model = model or self.default_model

        # 1. Apply Redaction Guard if enabled
        if self.guard:
            messages = list(self.guard.sanitize_messages(messages))

        # 2. Check recorder replay mode
        if self.recorder and self.recorder.mode in ("REPLAY", "AUTO"):
            cached_resp = self.recorder.load_response(
                provider=self.get_provider_name(),
                model=active_model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs,
            )
            if cached_resp is not None:
                return cached_resp
            if self.recorder.mode == "REPLAY":
                raise FileNotFoundError(
                    f"No recorded fixture found in REPLAY mode for {self.get_provider_name()}:{active_model}"
                )

        # 3. Call underlying provider client with bounded rate-limit/timeout retries
        response = self.inner_client.complete_with_retry(
            messages=messages,
            model=active_model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )

        # 4. Record if recording mode is active
        if self.recorder and self.recorder.mode in ("RECORD", "AUTO"):
            self.recorder.save_response(
                provider=self.get_provider_name(),
                model=active_model,
                messages=messages,
                response=response,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs,
            )

        return response


def create_llm_client(
    role: str = "default",
    provider: Optional[str] = None,
    model: Optional[str] = None,
    enable_guard: Optional[bool] = None,
    recorder_mode: Optional[str] = None,
    recorder_dir: Optional[str] = None,
    **kwargs: Any,
) -> LLMClient:
    """
    Factory function resolving provider, model, and middleware for a given agent role.

    Args:
        role: Agent role name (e.g., 'triage', 'planner', 'rootcause', 'verifier', 'explainer', 'default').
        provider: Provider identifier override ('openai', 'anthropic', 'nvidia', 'openrouter', 'ollama', 'bedrock').
        model: Model identifier override.
        enable_guard: Whether to attach RedactionGuard (defaults to settings.llm.enable_guard).
        recorder_mode: Optional 'LIVE', 'RECORD', 'REPLAY', or 'AUTO' mode override.
        recorder_dir: Directory path for recording fixtures.
        **kwargs: Additional provider-specific kwargs.

    Returns:
        Configured LLMClient instance ready for execution.
    """
    clean_role = role.lower()

    # Determine provider: parameter override -> role config -> global config -> 'ollama'
    target_provider = (
        provider
        or settings.role_providers.get(clean_role)
        or settings.llm.provider
        or "ollama"
    ).lower()

    if target_provider not in PROVIDER_REGISTRY:
        raise ValueError(
            f"Unsupported LLM provider '{target_provider}'. Supported: {list(PROVIDER_REGISTRY.keys())}"
        )

    # Check for configured provider-specific or global model in environment/settings
    prov_model_env = (
        settings.provider_models.get(target_provider)
        or os.getenv(f"{target_provider.upper()}_MODEL")
        or os.getenv(f"VULNFLOW_{target_provider.upper()}_MODEL")
    )
    global_model_env = os.getenv("VULNFLOW_LLM_MODEL") or os.getenv("LLM_MODEL")

    # Determine model resolution:
    # 1. Parameter override ('model')
    # 2. Role-specific model override (e.g., VULNFLOW_ROLE_MODEL_PLANNER)
    # 3. Provider-specific model from .env (e.g. OPENROUTER_MODEL, NVIDIA_MODEL, OPENAI_MODEL)
    # 4. Global model from .env (VULNFLOW_LLM_MODEL, LLM_MODEL)
    # 5. Role default recommended for this provider (from ROLE_MODEL_DEFAULTS)
    # 6. Global fallback from settings or provider default
    target_model = (
        model
        or settings.role_models.get(clean_role)
        or prov_model_env
        or global_model_env
        or ROLE_MODEL_DEFAULTS.get(target_provider, {}).get(clean_role)
        or ROLE_MODEL_DEFAULTS.get(target_provider, {}).get("default")
        or settings.llm.model
    )

    provider_cls = PROVIDER_REGISTRY[target_provider]

    # Resolve provider credentials and endpoint
    creds = settings.get_provider_credentials(target_provider)
    resolved_api_key = kwargs.pop("api_key", creds.get("api_key") or settings.llm.api_key)
    resolved_base_url = kwargs.pop("base_url", creds.get("base_url") or settings.llm.base_url)

    # Instantiate the base adapter
    base_client = provider_cls(
        default_model=target_model,
        api_key=resolved_api_key,
        base_url=resolved_base_url,
        timeout=kwargs.pop("timeout", settings.llm.timeout),
        max_retries=kwargs.pop("max_retries", settings.llm.max_retries),
        **kwargs,
    )

    # Attach guard middleware if enabled
    guard_active = enable_guard if enable_guard is not None else settings.llm.enable_guard
    guard = default_guard if guard_active else None

    # Attach recorder middleware if enabled
    rec_mode = (recorder_mode or settings.llm.recorder_mode or "LIVE").upper()
    rec_dir = recorder_dir or settings.llm.recorder_dir
    recorder = LLMRecorder(mode=rec_mode, record_dir=rec_dir) if rec_mode != "LIVE" else None

    if guard or recorder:
        return GuardedRecorderClient(inner_client=base_client, guard=guard, recorder=recorder)

    return base_client
