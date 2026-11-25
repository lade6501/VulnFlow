"""Regression tests for extracting and retrying structured model responses."""

from __future__ import annotations

import json
from typing import Any

import pytest

from vulnflow.llm.base import LLMClient, LLMMessage, LLMResponse, LLMStructuredOutputError
from vulnflow.llm.structured import parse_and_validate


@pytest.mark.parametrize(
    "reply",
    [
        '{"enrichments": []}',
        '```json\n{"enrichments": []}\n```',
        'Result [checked]: {"enrichments": []}\nSee {notes} below.',
        '<think>Example: {"enrichments": [{"plan_id": "example"}]}</think>\n'
        '{"enrichments": []}',
    ],
)
def test_single_json_object_survives_common_response_wrappers(reply: str) -> None:
    assert parse_and_validate(reply, dict) == {"enrichments": []}


@pytest.mark.parametrize(
    "reply",
    [
        '{"enrichments": [{"plan_id": "PLAN-one"}',
        '{"enrichments": []}\nAlternative: {"enrichments": []}',
    ],
)
def test_ambiguous_or_truncated_json_still_fails(reply: str) -> None:
    with pytest.raises(json.JSONDecodeError):
        parse_and_validate(reply, dict)


class RecordedClient(LLMClient):
    def __init__(self, *responses: LLMResponse) -> None:
        super().__init__(default_model="test-model")
        self.responses = iter(responses)
        self.requests: list[list[LLMMessage]] = []

    def get_provider_name(self) -> str:
        return "test-provider"

    def complete(self, messages: list[LLMMessage | dict[str, str]], **_kwargs: Any) -> LLMResponse:
        self.requests.append(self._normalize_messages(messages))
        return next(self.responses)


def test_json_retry_omits_the_invalid_response_and_reports_length_limit() -> None:
    broken = '{"enrichments": [{"plan_id": "malformed-response-content"'
    client = RecordedClient(
        LLMResponse(content=broken, finish_reason="length"),
        LLMResponse(content=broken, finish_reason="length"),
    )

    with pytest.raises(LLMStructuredOutputError, match="output-token limit"):
        client.structured_complete(
            [LLMMessage(role="user", content="Return an object")], dict, max_retries=1
        )

    assert len(client.requests) == 2
    assert "output-token limit" in client.requests[1][-1].content
    assert all("malformed-response-content" not in m.content for m in client.requests[1])
