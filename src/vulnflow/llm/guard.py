"""
llm/guard.py
Prevents secrets in outbound prompts and safely wraps untrusted text.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from vulnflow.core.redaction import contains_secrets, find_secrets, redact_secrets
from vulnflow.llm.base import LLMMessage

logger = logging.getLogger("vulnflow.llm.guard")

# Delimiters for untrusted data injection isolation
UNTRUSTED_START = "<<<UNTRUSTED_CONTENT source=\"{source}\">>>"
UNTRUSTED_END = "<<</UNTRUSTED_CONTENT>>>"


class RedactionGuard:
    """
    Security middleware that sanitizes outbound prompts to prevent secret leakage
    and safely wraps untrusted data against prompt injection attacks.
    """

    def __init__(self, mask_template: str = "[REDACTED_SECRET:{type}]") -> None:
        self.mask_template = mask_template
        self.redaction_count = 0
        self.audit_log: List[Dict[str, Any]] = []

    def sanitize_text(self, text: str) -> str:
        """
        Redact any detected API keys, passwords, or tokens in text.
        Returns the sanitized string.
        """
        if not text:
            return text

        found = find_secrets(text)
        if found:
            self.redaction_count += len(found)
            for secret_type, _ in found:
                self.audit_log.append({"type": secret_type, "action": "redacted"})
            logger.warning(
                "RedactionGuard sanitized %d sensitive token(s) from prompt: %s",
                len(found),
                [s[0] for s in found],
            )
            return redact_secrets(text, mask_template=self.mask_template)
        return text

    def sanitize_message(self, message: Union[LLMMessage, Dict[str, Any]]) -> LLMMessage:
        """Sanitize content within an individual LLMMessage."""
        if isinstance(message, dict):
            msg = LLMMessage.from_dict(message)
        else:
            msg = LLMMessage(
                role=message.role,
                content=message.content,
                name=message.name,
                refusal=message.refusal,
                tool_calls=message.tool_calls,
            )

        msg.content = self.sanitize_text(msg.content)
        return msg

    def sanitize_messages(
        self, messages: List[Union[LLMMessage, Dict[str, Any]]]
    ) -> List[LLMMessage]:
        """Sanitize an entire list of messages before sending to any external LLM provider."""
        return [self.sanitize_message(m) for m in messages]

    @staticmethod
    def wrap_untrusted(text: str, source: str = "scanner") -> str:
        """
        Safely wrap untrusted user or scanner input within hardened delimiter boundaries
        to defend against prompt injection breakout attempts.

        Any attempts to close the delimiter within the text itself are neutralized.
        """
        if not text:
            return ""

        # Escape existing boundary markers to prevent delimiter collision/breakout
        neutralized = text.replace("<<<UNTRUSTED_CONTENT", "[ESCAPED_UNTRUSTED_START]")
        neutralized = neutralized.replace("<<</UNTRUSTED_CONTENT>>>", "[ESCAPED_UNTRUSTED_END]")

        header = UNTRUSTED_START.format(source=source)
        return f"{header}\n{neutralized}\n{UNTRUSTED_END}"

    def is_safe(self, text: str) -> bool:
        """Check whether the given text is free from detectable secrets."""
        return not contains_secrets(text)


# Default global guard instance
default_guard = RedactionGuard()
