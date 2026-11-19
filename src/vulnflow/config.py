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
    """Load key-value pairs from local .env files into os.environ."""
    candidates = [
        Path(env_path) if env_path else None,
        Path.cwd() / ".env",
        Path.cwd() / "vulnflow" / ".env",
        Path(__file__).resolve().parent.parent.parent / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]
    seen_paths = set()
    for p in candidates:
        if p and p.exists() and p.is_file():
            resolved = p.resolve()
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
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
class LangSmithConfig:
    """Configuration options for LangSmith distributed tracing and observability."""

    enabled: bool = False
    api_key: Optional[str] = None
    project: str = "vulnflow"
    endpoint: str = "https://api.smith.langchain.com"


@dataclass
class VulnFlowConfig:
    """Master runtime configuration for VulnFlow system components."""

    env: str = "development"
    log_level: str = "INFO"
    llm: LLMProviderConfig = field(default_factory=LLMProviderConfig)
    langsmith: LangSmithConfig = field(default_factory=LangSmithConfig)
    provider_models: Dict[str, str] = field(default_factory=dict)
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
            "nvidia": "nvidia/nemotron-3.5-lightning-30b-a3b",
            "openrouter": "anthropic/claude-3.5-sonnet",
            "bedrock": "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "ollama": "llama3.1",
        }

        prov_clean = provider.lower()

        # Collect configured provider-specific models from environment
        # e.g., OPENROUTER_MODEL, NVIDIA_MODEL, OPENAI_MODEL, ANTHROPIC_MODEL, OLLAMA_MODEL, BEDROCK_MODEL
        provider_models: Dict[str, str] = {}
        for prov_name in ("openai", "anthropic", "nvidia", "openrouter", "bedrock", "ollama"):
            m = (
                os.getenv(f"{prov_name.upper()}_MODEL")
                or os.getenv(f"VULNFLOW_{prov_name.upper()}_MODEL")
                or ""
            ).strip()
            if m:
                provider_models[prov_name] = m

        # Check for any dynamic provider model env (e.g., MISTRAL_MODEL, GROQ_MODEL)
        for k, v in os.environ.items():
            k_upper = k.upper()
            if k_upper.endswith("_MODEL") and not k_upper.startswith("VULNFLOW_ROLE_") and not k_upper.startswith("ROLE_"):
                cand = k_upper.replace("VULNFLOW_", "").replace("_MODEL", "").lower()
                if cand not in ("llm", "role", "") and cand not in provider_models:
                    clean_v = v.strip().strip("'\"")
                    if clean_v:
                        provider_models[cand] = clean_v

        global_model_env = (
            os.getenv("VULNFLOW_LLM_MODEL")
            or os.getenv("LLM_MODEL")
            or ""
        ).strip()

        model = (
            provider_models.get(prov_clean)
            or (global_model_env if global_model_env else None)
            or default_models.get(prov_clean, "llama3.1")
        )

        timeout = float(os.getenv("VULNFLOW_LLM_TIMEOUT", "60.0"))
        max_retries = int(os.getenv("VULNFLOW_LLM_MAX_RETRIES", "3"))
        enable_guard = os.getenv("VULNFLOW_LLM_REDACTION_GUARD", "true").lower() in ("1", "true", "yes")
        recorder_mode = os.getenv("VULNFLOW_LLM_RECORDER_MODE", "LIVE").upper()
        recorder_dir = os.getenv("VULNFLOW_LLM_RECORD_DIR", "evals/recorded_llm")

        # Resolve provider-specific keys and base URLs
        api_key = None
        base_url = None

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
        known_roles = ("triage", "planner", "fixer", "rootcause", "verifier", "explainer")
        role_models: Dict[str, str] = {}
        for r in known_roles:
            m = (
                os.getenv(f"VULNFLOW_ROLE_MODEL_{r.upper()}")
                or os.getenv(f"ROLE_MODEL_{r.upper()}")
                or ""
            ).strip()
            if m:
                role_models[r] = m

        role_providers: Dict[str, str] = {}
        for r in known_roles:
            p = (
                os.getenv(f"VULNFLOW_ROLE_PROVIDER_{r.upper()}")
                or os.getenv(f"ROLE_PROVIDER_{r.upper()}")
                or ""
            ).strip()
            if p:
                role_providers[r] = p

        ls_key = (
            os.getenv("LANGSMITH_API_KEY")
            or os.getenv("LANGCHAIN_API_KEY")
            or os.getenv("VULNFLOW_LANGSMITH_API_KEY")
        )
        ls_project = (
            os.getenv("LANGCHAIN_PROJECT")
            or os.getenv("LANGSMITH_PROJECT")
            or os.getenv("VULNFLOW_LANGSMITH_PROJECT")
            or "vulnflow"
        )
        ls_endpoint = (
            os.getenv("LANGCHAIN_ENDPOINT")
            or os.getenv("LANGSMITH_ENDPOINT")
            or "https://api.smith.langchain.com"
        )
        ls_enabled = bool(ls_key) and os.getenv("LANGCHAIN_TRACING_V2", "").lower() != "false"

        langsmith_config = LangSmithConfig(
            enabled=ls_enabled,
            api_key=ls_key,
            project=ls_project,
            endpoint=ls_endpoint,
        )

        return cls(
            env=env,
            log_level=log_level,
            llm=llm_config,
            langsmith=langsmith_config,
            provider_models=provider_models,
            role_models=role_models,
            role_providers=role_providers,
        )

    def get_provider_credentials(self, provider_name: str) -> Dict[str, Optional[str]]:
        """Return credentials and base URL for a given provider name."""
        prov = provider_name.lower()
        if prov == "openai":
            return {
                "api_key": os.getenv("OPENAI_API_KEY"),
                "base_url": os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            }
        elif prov == "anthropic":
            return {
                "api_key": os.getenv("ANTHROPIC_API_KEY"),
                "base_url": os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1"),
            }
        elif prov == "nvidia":
            return {
                "api_key": os.getenv("NVIDIA_API_KEY") or os.getenv("NVCF_AUTH_TOKEN"),
                "base_url": os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"),
            }
        elif prov == "openrouter":
            return {
                "api_key": os.getenv("OPENROUTER_API_KEY"),
                "base_url": os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
            }
        elif prov == "ollama":
            return {
                "api_key": None,
                "base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            }
        elif prov == "bedrock":
            return {
                "api_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
                "base_url": None,
            }
        return {"api_key": None, "base_url": None}

    def reload(self) -> None:
        """Reload configuration from environment variables."""
        new_cfg = VulnFlowConfig.load_from_env()
        self.env = new_cfg.env
        self.log_level = new_cfg.log_level
        self.llm = new_cfg.llm
        self.langsmith = new_cfg.langsmith
        self.provider_models = new_cfg.provider_models
        self.role_models = new_cfg.role_models
        self.role_providers = new_cfg.role_providers


# Global default settings
settings = VulnFlowConfig.load_from_env()
