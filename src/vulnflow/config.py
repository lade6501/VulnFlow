"""
src/vulnflow/config.py
Loads and validates runtime configuration settings and environment options.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional


def load_dotenv(env_path: Optional[str] = None) -> None:
    """Load key-value pairs from a local .env file into os.environ."""
    candidates = [
        Path(env_path) if env_path else None,
        Path.cwd() / ".env",
        Path(__file__).resolve().parent.parent.parent / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]
    for p in candidates:
        if p and p.exists() and p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
            except Exception:
                pass
            break


# Automatically load from .env if present
load_dotenv()


@dataclass
class LLMProviderConfig:
    """Configuration options for a specific LLM provider or general fallback."""

    provider: str = "ollama"
    model: str = "llama3"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    timeout: float = 60.0
    max_retries: int = 3
    temperature: float = 0.0
    enable_guard: bool = True
    recorder_mode: str = "LIVE"  # LIVE, RECORD, REPLAY, AUTO
    recorder_dir: str = "evals/recorded_llm"
    extra_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class VulnFlowConfig:
    """Master runtime configuration for VulnFlow system components."""

    env: str = "development"
    log_level: str = "INFO"
    llm: LLMProviderConfig = field(default_factory=LLMProviderConfig)
    role_models: Dict[str, str] = field(default_factory=dict)
    role_providers: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def load_from_env(cls) -> VulnFlowConfig:
        """Construct configuration object reading environment variables with sensible defaults."""
        load_dotenv()

        env = os.getenv("VULNFLOW_ENV", "development")
        log_level = os.getenv("VULNFLOW_LOG_LEVEL", "INFO")

        # Determine default provider: prioritize explicitly set provider, then infer by present keys
        provider = os.getenv("VULNFLOW_LLM_PROVIDER")
        if not provider:
            if os.getenv("OPENAI_API_KEY"):
                provider = "openai"
            elif os.getenv("ANTHROPIC_API_KEY"):
                provider = "anthropic"
            elif os.getenv("NVIDIA_API_KEY") or os.getenv("NVCF_AUTH_TOKEN"):
                provider = "nvidia"
            elif os.getenv("OPENROUTER_API_KEY"):
                provider = "openrouter"
            elif os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_REGION"):
                provider = "bedrock"
            else:
                provider = "ollama"

        # Default model based on provider
        default_models = {
            "openai": "gpt-4o",
            "anthropic": "claude-3-5-sonnet-20241022",
            "nvidia": "minimaxai/minimax-m3.1-flash",
            "openrouter": "anthropic/claude-3.5-sonnet",
            "bedrock": "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "ollama": "llama3.1",
        }

        model = os.getenv("VULNFLOW_LLM_MODEL", default_models.get(provider.lower(), "llama3.1"))
        timeout = float(os.getenv("VULNFLOW_LLM_TIMEOUT", "60.0"))
        max_retries = int(os.getenv("VULNFLOW_LLM_MAX_RETRIES", "3"))
        enable_guard = os.getenv("VULNFLOW_LLM_REDACTION_GUARD", "true").lower() in ("1", "true", "yes")
        recorder_mode = os.getenv("VULNFLOW_LLM_RECORDER_MODE", "LIVE").upper()
        recorder_dir = os.getenv("VULNFLOW_LLM_RECORD_DIR", "evals/recorded_llm")

        # Resolve provider-specific keys and base URLs
        api_key = None
        base_url = None

        prov_clean = provider.lower()
        if prov_clean == "openai":
            api_key = os.getenv("OPENAI_API_KEY")
            base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        elif prov_clean == "anthropic":
            api_key = os.getenv("ANTHROPIC_API_KEY")
            base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1")
        elif prov_clean == "nvidia":
            api_key = os.getenv("NVIDIA_API_KEY") or os.getenv("NVCF_AUTH_TOKEN")
            base_url = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
        elif prov_clean == "openrouter":
            api_key = os.getenv("OPENROUTER_API_KEY")
            base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        elif prov_clean == "ollama":
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        elif prov_clean == "bedrock":
            api_key = os.getenv("AWS_SECRET_ACCESS_KEY")

        llm_config = LLMProviderConfig(
            provider=prov_clean,
            model=model,
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            enable_guard=enable_guard,
            recorder_mode=recorder_mode,
            recorder_dir=recorder_dir,
        )

        # Role mappings
        role_models = {
            "triage": os.getenv("VULNFLOW_ROLE_MODEL_TRIAGE", ""),
            "planner": os.getenv("VULNFLOW_ROLE_MODEL_PLANNER", ""),
            "rootcause": os.getenv("VULNFLOW_ROLE_MODEL_ROOTCAUSE", ""),
            "verifier": os.getenv("VULNFLOW_ROLE_MODEL_VERIFIER", ""),
            "explainer": os.getenv("VULNFLOW_ROLE_MODEL_EXPLAINER", ""),
        }
        role_providers = {
            "triage": os.getenv("VULNFLOW_ROLE_PROVIDER_TRIAGE", ""),
            "planner": os.getenv("VULNFLOW_ROLE_PROVIDER_PLANNER", ""),
            "rootcause": os.getenv("VULNFLOW_ROLE_PROVIDER_ROOTCAUSE", ""),
            "verifier": os.getenv("VULNFLOW_ROLE_PROVIDER_VERIFIER", ""),
            "explainer": os.getenv("VULNFLOW_ROLE_PROVIDER_EXPLAINER", ""),
        }

        return cls(
            env=env,
            log_level=log_level,
            llm=llm_config,
            role_models={k: v for k, v in role_models.items() if v},
            role_providers={k: v for k, v in role_providers.items() if v},
        )


# Global default settings
settings = VulnFlowConfig.load_from_env()
