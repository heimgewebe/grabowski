from __future__ import annotations

import re


_SECRET_KEY_PREFIX = "s" + "k-"
_OPENAI_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    + re.escape(_SECRET_KEY_PREFIX)
    + r"(?:(?:proj|svcacct|admin)-[A-Za-z0-9._-]{20,}|[A-Za-z0-9]{24,})(?![A-Za-z0-9._-])"
)
_ANTHROPIC_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    + re.escape(_SECRET_KEY_PREFIX)
    + r"ant-[A-Za-z0-9._-]{20,}(?![A-Za-z0-9._-])"
)
_GITHUB_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})"
    r"(?![A-Za-z0-9_])",
    re.I,
)
SECRET_REDACTIONS = (
    (_OPENAI_SECRET_PATTERN, "<REDACTED_OPENAI_KEY>"),
    (_ANTHROPIC_SECRET_PATTERN, "<REDACTED_ANTHROPIC_KEY>"),
    (_GITHUB_SECRET_PATTERN, "<REDACTED_GITHUB_TOKEN>"),
    (
        re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]{12,}=*", re.I),
        "Bearer <REDACTED>",
    ),
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.S,
        ),
        "<REDACTED_PRIVATE_KEY>",
    ),
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "<REDACTED_AWS_ACCESS_KEY_ID>",
    ),
    (
        re.compile(
            r"(?im)^(\s*[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|APIKEY|"
            r"PRIVATE_KEY|CLIENT_KEY_DATA|AWS_ACCESS_KEY_ID|"
            r"AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)"
            r"[A-Z0-9_]*\s*[:=]\s*).+$"
        ),
        r"\1<REDACTED>",
    ),
    (
        re.compile(
            r"(?im)^(\s*(?:token|password|client-key-data|client-certificate-data|"
            r"aws_access_key_id|aws_secret_access_key|aws_session_token)"
            r"\s*[:=]\s*).+$"
        ),
        r"\1<REDACTED>",
    ),
)


def redact_sensitive_text(
    text: str,
    extra_secrets: list[str] | None = None,
) -> tuple[str, int]:
    result = text
    redactions = 0
    for pattern, replacement in SECRET_REDACTIONS:
        result, count = pattern.subn(replacement, result)
        redactions += count

    for secret in sorted(set(extra_secrets or []), key=len, reverse=True):
        if not secret:
            continue
        count = result.count(secret)
        if count:
            result = result.replace(secret, "<REDACTED>")
            redactions += count

    return result, redactions