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


def extract_json(raw_text: str) -> str:
    """
    Extract a valid JSON string from raw text that may include markdown code blocks
    or conversational commentary.
    """
    text = raw_text.strip()

    # Look for markdown code fence with json or generic syntax
    fence_pattern = r"```(?:json)?\s*([\s\S]*?)\s*```"
    match = re.search(fence_pattern, text, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    # If no fence found, find outermost JSON object { ... } or array [ ... ]
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    first_bracket = text.find("[")
    last_bracket = text.rfind("]")

    if first_brace != -1 and last_brace != -1 and (first_bracket == -1 or first_brace < first_bracket):
        return text[first_brace : last_brace + 1].strip()
    elif first_bracket != -1 and last_bracket != -1:
        return text[first_bracket : last_bracket + 1].strip()

    return text


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
    if response_schema is dict or response_schema == dict:
        if not isinstance(parsed, dict):
            raise ValueError(f"Expected JSON object (dict), got {type(parsed).__name__}")
        return parsed
    if response_schema is list or response_schema == list:
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
    **kwargs: Any,
) -> LLMResponse:
    """
    Execute an LLM completion with automatic JSON extraction and bounded validation retries.
    If the model produces malformed or invalid JSON, feedback is fed back to the model for correction.
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
    response: Optional[LLMResponse] = None

    for attempt in range(max_retries + 1):
        response = client.complete(
            messages=active_messages,
            model=model,
            temperature=temperature,
            **kwargs,
        )

        try:
            validated = parse_and_validate(response.content, response_schema)
            response.structured_data = validated
            return response
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            last_error = f"{exc.__class__.__name__}: {str(exc)}"
            logger.warning(
                "Structured output validation failed on attempt %d/%d: %s",
                attempt + 1,
                max_retries + 1,
                last_error,
            )

            if attempt < max_retries:
                # Add failure context and retry
                active_messages.append(LLMMessage(role="assistant", content=response.content))
                active_messages.append(
                    LLMMessage(
                        role="user",
                        content=(
                            f"The output could not be validated against the required schema.\n"
                            f"Error details: {last_error}\n"
                            f"Please correct the error and return ONLY the valid JSON object conforming strictly "
                            f"to the schema:\n```json\n{schema_spec}\n```"
                        ),
                    )
                )

    raise LLMStructuredOutputError(
        f"Failed to produce structured output adhering to schema after {max_retries + 1} attempts. Last error: {last_error}",
        provider=client.get_provider_name(),
    )
