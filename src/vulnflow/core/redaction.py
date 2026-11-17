"""
src/vulnflow/core/redaction.py
Redacts secrets, tokens, and credentials from findings and agent logs.
"""

from __future__ import annotations

import re
from typing import Dict, List, Pattern, Tuple

# Comprehensive regex patterns for credentials, tokens, and private keys
SECRET_PATTERNS: Dict[str, Pattern[str]] = {
    "AWS_ACCESS_KEY": re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    "AWS_SECRET_KEY": re.compile(
        r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
    ),
    "GITHUB_TOKEN": re.compile(
        r"\b(?:ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b"
    ),
    "SLACK_TOKEN": re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"),
    "PRIVATE_KEY": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    "JWT_TOKEN": re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-.+/=]{10,}\b"
    ),
    "GENERIC_SECRET_ASSIGNMENT": re.compile(
        r"(?i)\b(api_key|apikey|auth_token|access_token|secret_key|password|client_secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-.]{16,})['\"]?"
    ),
    "BEARER_AUTH": re.compile(
        r"(?i)\bBearer\s+([a-zA-Z0-9_\-.]{20,})\b"
    ),
    "CONNECTION_STRING_PASSWORD": re.compile(
        r"(?i)(?:postgres|postgresql|mysql|mongodb|redis)://[^:]+:([^@]+)@"
    ),
}


def find_secrets(text: str) -> List[Tuple[str, str]]:
    """Scan text and return detected secrets as a list of (secret_type, matched_string) tuples."""
    if not text:
        return []
    matches: List[Tuple[str, str]] = []
    for secret_type, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            # If pattern has groups, capture the secret group value, otherwise entire match
            if match.groups():
                secret_val = match.group(1) or match.group(0)
            else:
                secret_val = match.group(0)
            matches.append((secret_type, secret_val))
    return matches


def contains_secrets(text: str) -> bool:
    """Return True if any known secret or credential pattern is detected in text."""
    if not text:
        return False
    return any(pattern.search(text) is not None for pattern in SECRET_PATTERNS.values())


def redact_secrets(text: str, mask_template: str = "[REDACTED_SECRET:{type}]") -> str:
    """
    Redact all detected secrets, tokens, and private keys from the given text.

    Args:
        text: Input string potentially containing sensitive credentials.
        mask_template: Formatting template for redaction marker, e.g. '[REDACTED_SECRET:{type}]'.

    Returns:
        Sanitized string with sensitive tokens replaced with redaction placeholders.
    """
    if not text:
        return text

    sanitized = text
    for secret_type, pattern in SECRET_PATTERNS.items():
        replacement = mask_template.format(type=secret_type)

        def _replace_match(m: re.Match[str]) -> str:
            # If groups exist (e.g. key=val), only mask the credential portion
            if secret_type == "GENERIC_SECRET_ASSIGNMENT":
                key_name = m.group(1)
                return f"{key_name}={replacement}"
            elif secret_type == "AWS_SECRET_KEY":
                return f"aws_secret_access_key={replacement}"
            elif secret_type == "BEARER_AUTH":
                return f"Bearer {replacement}"
            elif secret_type == "CONNECTION_STRING_PASSWORD":
                full = m.group(0)
                pwd = m.group(1)
                return full.replace(pwd, replacement)
            return replacement

        sanitized = pattern.sub(_replace_match, sanitized)

    return sanitized
