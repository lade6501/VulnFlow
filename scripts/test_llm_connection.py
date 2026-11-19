"""
scripts/test_llm_connection.py
Tests live connection, latency, token usage, and completions with configured LLM provider.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vulnflow.config import settings
from vulnflow.llm import LLMMessage, create_llm_client


def main() -> None:
    provider = (os.getenv("VULNFLOW_LLM_PROVIDER") or settings.llm.provider or "nvidia").lower()
    creds = settings.get_provider_credentials(provider)
    api_key = creds.get("api_key") or settings.llm.api_key
    base_url = creds.get("base_url") or settings.llm.base_url

    print("=" * 65)
    print("VulnFlow LLM Provider Connectivity Test")
    print("=" * 65)
    print(f"Target Provider:  {provider.upper()}")

    if api_key:
        masked_key = f"{api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else "***"
        print(f"Detected API Key: {masked_key}")
    else:
        print(f"Detected API Key: NONE (Please export {provider.upper()}_API_KEY or set in .env)")

    print(f"Base URL:         {base_url or 'Default vendor endpoint'}")
    active_model = (
        settings.provider_models.get(provider)
        or os.getenv(f"{provider.upper()}_MODEL")
        or os.getenv("VULNFLOW_LLM_MODEL")
        or os.getenv("LLM_MODEL")
        or settings.llm.model
    )
    print(f"Configured Model: {active_model}")
    print("-" * 65)

    if not api_key and provider not in ("ollama", "local"):
        print("\n❌ Error: No API key detected!")
        print(f"To test {provider.upper()}, please run:")
        print(f"  export {provider.upper()}_API_KEY=\"your-key-here\"")
        print("  python3 scripts/test_llm_connection.py\n")
        print("Or add it to a .env file in the vulnflow directory:")
        print(f"  echo '{provider.upper()}_API_KEY=\"your-key\"' >> .env")
        sys.exit(1)

    print("Sending live test prompt to model...")
    test_prompt = "In 2 concise sentences, what is prototype pollution vulnerability CVE-2020-8203 in lodash?"

    try:
        client = create_llm_client(role="planner", provider=provider, api_key=api_key)
        start_time = time.time()

        response = client.complete(
            messages=[
                LLMMessage(role="system", content="You are a security intelligence assistant."),
                LLMMessage(role="user", content=test_prompt),
            ],
            temperature=0.1,
            max_tokens=250,
        )
        duration_ms = (time.time() - start_time) * 1000.0

        print("\n✅ Live LLM Response Received Successfully!")
        print("=" * 65)
        print(f"Provider:        {response.provider}")
        print(f"Model:           {response.model}")
        print(f"Latency:         {response.latency_ms:.1f} ms")
        print(f"Tokens Used:     {response.usage.total_tokens} total ({response.usage.prompt_tokens} prompt, {response.usage.completion_tokens} completion)")
        print(f"Estimated Cost:  ${response.usage.cost_estimate_usd:.6f} USD")
        print("-" * 65)
        print("Response Content:")
        print(response.content.strip())
        print("=" * 65)

    except Exception as exc:
        print(f"\n❌ LLM Call Failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
