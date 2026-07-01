import re
from dataclasses import dataclass
from typing import List, Optional, Set


@dataclass(frozen=True)
class CleartextTransmissionFinding:
    verdict: str
    start: int
    code: str
    rationale: str


IDENTIFIER_PATTERN = r"[A-Za-z_]\w*"
SENSITIVE_NAME_PATTERN = (
    r"(?:password|passwd|pwd|secret|token|apiKey|api_key|credential|"
    r"auth(?:entication|orization)?|sessionId|session_id|ssn|cardNumber|"
    r"privateKey|private_key)"
)


def analyze_cleartext_transmission(
    code: str,
) -> Optional[CleartextTransmissionFinding]:
    sensitive_names = _collect_sensitive_names(code)
    sink = _find_sensitive_network_sink(code, sensitive_names)
    if not sink:
        return None

    secure_channel = _has_secure_channel(code)
    cleartext_channel = _has_cleartext_channel(code)
    if secure_channel and not cleartext_channel:
        return CleartextTransmissionFinding(
            "safe",
            sink.start(),
            sink.group(0),
            "Sensitive data is transmitted through an HTTPS or TLS-protected channel.",
        )
    if cleartext_channel and not secure_channel:
        return CleartextTransmissionFinding(
            "vulnerable",
            sink.start(),
            sink.group(0),
            "Sensitive data reaches a plaintext HTTP, socket, or other unencrypted network channel.",
        )
    if secure_channel and cleartext_channel:
        return CleartextTransmissionFinding(
            "ambiguous",
            sink.start(),
            sink.group(0),
            "Both protected and cleartext channel indicators are present; the sensitive value's effective route requires review.",
        )
    return CleartextTransmissionFinding(
        "ambiguous",
        sink.start(),
        sink.group(0),
        "Sensitive data reaches a network sink whose transport security cannot be resolved locally.",
    )


def _collect_sensitive_names(code: str) -> Set[str]:
    names = {
        match.group(0)
        for match in re.finditer(IDENTIFIER_PATTERN, code)
        if re.fullmatch(SENSITIVE_NAME_PATTERN, match.group(0), re.I)
    }
    assignments = list(
        re.finditer(
            rf"\b(?P<target>{IDENTIFIER_PATTERN})\s*=\s*"
            r"(?P<expression>[\s\S]*?);",
            code,
            re.I,
        )
    )
    changed = True
    while changed:
        changed = False
        for assignment in assignments:
            target = assignment.group("target")
            expression = assignment.group("expression")
            if target in names:
                continue
            if any(
                re.search(rf"\b{re.escape(name)}\b", expression)
                for name in names
            ):
                names.add(target)
                changed = True
    return names


def _find_sensitive_network_sink(
    code: str, sensitive_names: Set[str]
) -> Optional[re.Match]:
    if not sensitive_names:
        return None
    names = "|".join(re.escape(name) for name in sorted(sensitive_names))
    patterns: List[str] = [
        rf"\.\s*(?:write|print|println|send|sendText|sendBinary)\s*"
        rf"\([^;]*\b(?:{names})\b[^;]*\)",
        rf"\bBodyPublishers\s*\.\s*ofString\s*\([^;]*\b(?:{names})\b[^;]*\)",
        rf"\.\s*(?:header|setHeader|setRequestProperty)\s*\("
        rf"[^;]*(?:Authorization|Cookie|Token|Secret|Password)[^;]*\b(?:{names})\b[^;]*\)",
        rf"\b(?:URL|URI)\s*(?:\.\s*create)?\s*\([^;]*\b(?:{names})\b[^;]*\)",
        rf"\bnew\s+URL\s*\([^;]*\b(?:{names})\b[^;]*\)",
        rf"\b(?:GET|POST|PUT|PATCH)\s*\([^;]*\b(?:{names})\b[^;]*\)",
    ]
    for pattern in patterns:
        match = re.search(pattern, code, re.I | re.S)
        if match:
            return match
    return None


def _has_secure_channel(code: str) -> bool:
    https_literal = re.search(r"\bhttps://", code, re.I)
    tls_api = re.search(
        r"\b(?:HttpsURLConnection|SSLSocket|SSLSocketFactory|SSLContext|"
        r"TLSv1(?:\.[23])?|wss://)\b",
        code,
        re.I,
    )
    scheme_rejection = re.search(
        r"!\s*[\"']https[\"']\s*\.\s*equalsIgnoreCase\s*\("
        r"[^)]*\.getScheme\s*\(\s*\)\s*\)"
        r"[\s\S]{0,180}(?:throw\s+new|return\b)",
        code,
        re.I,
    )
    prefix_rejection = re.search(
        r"!\s*\w+\s*\.\s*(?:startsWith|matches)\s*\(\s*[\"']https",
        code,
        re.I,
    )
    return bool(https_literal or tls_api or scheme_rejection or prefix_rejection)


def _has_cleartext_channel(code: str) -> bool:
    cleartext_uri = re.search(r"\b(?:http|ftp|telnet)://", code, re.I)
    raw_socket = re.search(
        r"\bnew\s+(?!SSL)(?:java\s*\.\s*net\s*\.\s*)?Socket\s*\(",
        code,
        re.I,
    )
    raw_server_socket = re.search(
        r"\bnew\s+(?!SSL)(?:java\s*\.\s*net\s*\.\s*)?ServerSocket\s*\(",
        code,
        re.I,
    )
    return bool(cleartext_uri or raw_socket or raw_server_socket)
