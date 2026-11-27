"""
llm/structured.py
Validates LLM output against Pydantic schemas with bounded retries.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import is_dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Type, Union

from vulnflow.llm.base import LLMMessage, LLMResponse, LLMStructuredOutputError

if TYPE_CHECKING:
    from vulnflow.llm.base import LLMClient

logger = logging.getLogger("vulnflow.llm.structured")

_JSON_START = re.compile(r'\{\s*(?=["}])|\[\s*(?=[\[\]{}"0-9-]|true\b|false\b|null\b)')


def extract_json(raw_text: str) -> str:
    """Extract one complete JSON value from a plain or wrapped response."""
    text = raw_text.strip()
    text = re.sub(r"^(?:<think>.*?</think>\s*)+", "", text, flags=re.DOTALL)

    fence = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, re.IGNORECASE | re.DOTALL)
    if fence:
        return fence.group(1)

    if text.startswith(("{", "[")):
        start = 0
    else:
        match = _JSON_START.search(text)
        if not match:
            return text
        start = match.start()
    # Decode the outer container as supplied. A truncated object must fail, even
    # if some of its nested objects happen to be complete.
    _, end = json.JSONDecoder().raw_decode(text, start)
    if _JSON_START.search(text, end):
        raise json.JSONDecodeError("Multiple JSON values", text, end)
    return text[start:end]


def get_schema_representation(response_schema: Union[Type[Any], Dict[str, Any]]) -> str:
    """Generate a clean JSON representation or description of the schema for LLM prompting."""
    if isinstance(response_schema, dict):
        return json.dumps(response_schema, indent=2)

    # Check for Pydantic v2 / v1 model_json_schema or schema
    if hasattr(response_schema, "model_json_schema"):
        try:
            return json.dumps(response_schema.model_json_schema(), indent=2)
        except Exception:
            pass
    elif hasattr(response_schema, "schema"):
        try:
            return json.dumps(response_schema.schema(), indent=2)
        except Exception:
            pass

    # Dataclass or standard class inspection
    if hasattr(response_schema, "__annotations__"):
        annotations = {k: str(v) for k, v in response_schema.__annotations__.items()}
        return json.dumps(annotations, indent=2)

    return str(response_schema)


def parse_and_validate(
    raw_content: str,
    response_schema: Union[Type[Any], Dict[str, Any]],
) -> Any:
    """Parse JSON string and validate against target schema, Pydantic model, or dataclass."""
    json_str = extract_json(raw_content)
    parsed = json.loads(json_str)

    # 1. Pydantic Model (v1 / v2 compatible)
    if hasattr(response_schema, "model_validate"):
        return response_schema.model_validate(parsed)
    elif hasattr(response_schema, "parse_obj"):
        return response_schema.parse_obj(parsed)

    # 2. Dataclass
    if is_dataclass(response_schema):
        if isinstance(parsed, dict):
            return response_schema(**parsed)
        raise ValueError(f"Expected dict to instantiate dataclass {response_schema}, got {type(parsed)}")

    # 3. Dict / JSON Schema basic validation
    if response_schema is dict:
        if not isinstance(parsed, dict):
            raise ValueError(f"Expected JSON object (dict), got {type(parsed).__name__}")
        return parsed
    if response_schema is list:
        if not isinstance(parsed, list):
            raise ValueError(f"Expected JSON array (list), got {type(parsed).__name__}")
        return parsed

    # 4. Standard callable or class instantiation
    if callable(response_schema) and isinstance(response_schema, type):
        try:
            return response_schema(parsed) if not isinstance(parsed, dict) else response_schema(**parsed)
        except TypeError:
            pass

    return parsed


def validate_structured_output(
    client: "LLMClient",
    messages: List[Union[LLMMessage, Dict[str, str]]],
    response_schema: Union[Type[Any], Dict[str, Any]],
    model: Optional[str] = None,
    max_retries: int = 3,
    temperature: float = 0.0,
    *,
    retry_on_length: bool = True,
    **kwargs: Any,
) -> LLMResponse:
    """
    Execute an LLM completion with automatic JSON extraction and bounded validation retries.
    If the model produces malformed or invalid JSON, feedback is fed back to the model for correction.
    Callers that can shrink the request may disable retries after output-token exhaustion.
    """
    active_messages = client._normalize_messages(messages)

    # Add schema instruction to prompt if not already present
    schema_spec = get_schema_representation(response_schema)
    format_instruction = (
        f"\n\nCRITICAL REQUIREMENT: Your output must be a valid JSON object matching the following schema:\n"
        f"```json\n{schema_spec}\n```\n"
        f"Do not include any prose, explanations, or commentary outside the JSON block."
    )

    # Ensure format instruction is included in the last message
    if active_messages:
        last_msg = active_messages[-1]
        active_messages[-1] = LLMMessage(
            role=last_msg.role,
            content=last_msg.content + format_instruction,
            name=last_msg.name,
            tool_calls=last_msg.tool_calls,
        )

    last_error: Optional[str] = None
    request_messages: list[LLMMessage | dict[str, str]] = list(active_messages)
    attempts_made = 0
    attempt_limit = max_retries + 1

    while attempts_made < attempt_limit:
        attempts_made += 1
        response = client.complete(
            messages=request_messages,
            model=model,
            temperature=temperature,
            **kwargs,
        )

        try:
            validated = parse_and_validate(response.content, response_schema)
            response.structured_data = validated
            return response
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            hit_token_limit = response.finish_reason in {"length", "max_tokens"}
            if hit_token_limit:
                last_error = "Response reached the output-token limit before it validated"
            elif isinstance(exc, json.JSONDecodeError):
                last_error = f"JSONDecodeError: {exc.msg} at line {exc.lineno}, column {exc.colno}"
            else:
                last_error = f"{type(exc).__name__}: response does not match the required schema"
            logger.warning(
                "Structured output validation failed on attempt %d/%d: %s",
                attempts_made,
                attempt_limit,
                last_error,
            )

            if hit_token_limit and not retry_on_length:
                break

            if attempts_made < attempt_limit:
                # Retry from the original request without replaying malformed output.
                request_messages = [
                    *active_messages,
                    LLMMessage(
                        role="user",
                        content=(
                            f"The previous output could not be validated: {last_error}.\n"
                            "Return one concise, complete JSON value matching the supplied schema. "
                            "Do not include reasoning, Markdown fences, or additional text."
                        ),
                    ),
                ]

    raise LLMStructuredOutputError(
        f"Failed to produce structured output adhering to schema after {attempts_made} attempts. Last error: {last_error}",
        provider=client.get_provider_name(),
    )
