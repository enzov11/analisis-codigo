import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class HttpResponseSplittingFinding:
    verdict: str
    start: int
    code: str
    rationale: str


STRING_LITERAL_PATTERN = r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
IDENTIFIER_PATTERN = r"[A-Za-z_]\w*"


def analyze_http_response_splitting(
    code: str,
) -> Optional[HttpResponseSplittingFinding]:
    assignments = _collect_assignments(code)
    local_mitigation = _has_local_crlf_mitigation(code)

    for sink in _iter_header_sinks(code):
        expression = str(sink["argument"]).strip()
        if not expression:
            continue
        classification = _classify_expression(expression, assignments, local_mitigation)
        if classification == "safe":
            return HttpResponseSplittingFinding(
                "safe",
                int(sink["start"]),
                str(sink["code"]),
                "Header, redirect, content-type, or cookie output is protected by local CRLF rejection, removal, allowlisting, or encoding.",
            )
        if classification == "vulnerable":
            return HttpResponseSplittingFinding(
                "vulnerable",
                int(sink["start"]),
                str(sink["code"]),
                "A dynamic value reaches an HTTP response header sink without locally resolved CRLF protection.",
            )
        if classification == "ambiguous":
            return HttpResponseSplittingFinding(
                "ambiguous",
                int(sink["start"]),
                str(sink["code"]),
                "A response header sink receives a dynamic value whose CRLF handling cannot be resolved locally.",
            )

    return None


def _iter_header_sinks(code: str) -> List[Dict[str, object]]:
    sinks: List[Dict[str, object]] = []
    patterns = [
        r"\.\s*(?:setHeader|addHeader|setDateHeader|addDateHeader|setIntHeader|addIntHeader)\s*\(\s*(?P<name>[^,]+)\s*,\s*(?P<arg>[\s\S]*?)\s*\)",
        r"\.\s*sendRedirect\s*\(\s*(?P<arg>[\s\S]*?)\s*\)",
        r"\.\s*setContentType\s*\(\s*(?P<arg>[\s\S]*?)\s*\)",
        r"\b(?:HttpHeaders|headers)\s*\.\s*(?:add|set)\s*\(\s*(?P<name>[^,]+)\s*,\s*(?P<arg>[\s\S]*?)\s*\)",
        r"\bnew\s+(?:[\w]+\.)*Cookie\s*\(\s*(?P<name>[^,]+)\s*,\s*(?P<arg>[\s\S]*?)\s*\)",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, code, re.I):
            sinks.append(
                {
                    "start": match.start(),
                    "code": match.group(0),
                    "argument": match.group("arg"),
                }
            )
    return sorted(sinks, key=lambda item: int(item["start"]))


def _collect_assignments(code: str) -> Dict[str, List[str]]:
    assignments: Dict[str, List[str]] = {}
    pattern = re.compile(
        rf"\b(?:(?:String|CharSequence|URI|URL)\s+)?(?P<name>{IDENTIFIER_PATTERN})\s*"
        r"(?P<operator>\+=|=)\s*(?P<expression>[\s\S]*?);",
        re.I,
    )
    for match in pattern.finditer(code):
        name = match.group("name")
        expression = match.group("expression").strip()
        if match.group("operator") == "+=" and name in assignments:
            assignments[name].append(expression)
        else:
            assignments[name] = [expression]
    return assignments


def _classify_expression(
    expression: str,
    assignments: Dict[str, List[str]],
    has_local_mitigation: bool,
    visited: Optional[set] = None,
) -> str:
    expression = expression.strip()
    visited = set() if visited is None else visited
    if _has_header_encoding_or_crlf_removal(expression):
        return "safe"
    if _uses_unresolved_header_helper(expression):
        return "ambiguous"
    if re.fullmatch(IDENTIFIER_PATTERN, expression):
        if expression in visited:
            return "ambiguous"
        if expression not in assignments:
            return "safe" if has_local_mitigation else "vulnerable"
        visited.add(expression)
        states = [
            _classify_expression(value, assignments, has_local_mitigation, visited.copy())
            for value in assignments[expression]
        ]
        if states and all(state == "safe" for state in states):
            return "safe"
        if "vulnerable" in states:
            return "vulnerable"
        if "ambiguous" in states:
            return "ambiguous"
        return "safe" if has_local_mitigation else "ambiguous"

    if _is_hardcoded_literal(expression):
        return "safe"
    if _contains_dynamic_value(expression):
        return "safe" if has_local_mitigation else "vulnerable"
    return "ambiguous"


def _is_hardcoded_literal(expression: str) -> bool:
    return bool(re.fullmatch(rf"\s*{STRING_LITERAL_PATTERN}\s*", expression, re.S))


def _contains_dynamic_value(expression: str) -> bool:
    without_literals = re.sub(STRING_LITERAL_PATTERN, "", expression, flags=re.S)
    return bool(re.search(IDENTIFIER_PATTERN, without_literals))


def _has_header_encoding_or_crlf_removal(expression: str) -> bool:
    return bool(
        re.search(
            r"(?:URLEncoder\s*\.\s*encode|Base64\s*\.\s*getUrlEncoder|"
            r"encodeRedirect\w*|encodeHeader\w*|"
            r"stripCrlf\w*|stripCRLF\w*|removeCrlf\w*|removeCRLF\w*|"
            r"\.replace(?:All)?\s*\(\s*(?:\"\\r\"|'\\r'|\"\\n\"|'\\n'|\"\[\\r\\n\]\")\s*,)",
            expression,
            re.I,
        )
    )


def _uses_unresolved_header_helper(expression: str) -> bool:
    return bool(
        re.search(
            r"\b(?:validateHeader\w*|sanitizeHeader\w*|cleanHeader\w*|safeHeader\w*|"
            r"validateRedirect\w*|sanitizeRedirect\w*)\s*\(",
            expression,
            re.I,
        )
    )


def _has_local_crlf_mitigation(code: str) -> bool:
    explicit_rejection = re.search(
        r"(?:contains|indexOf)\s*\(\s*(?:\"\\r\"|'\\r'|\"\\n\"|'\\n')\s*\)"
        r"[\s\S]{0,160}(?:throw\s+new|return\b)",
        code,
        re.I,
    )
    regex_rejection = re.search(
        r"\.(?:matches|find)\s*\([^;]*(?:\\r|\\n|\[\\r\\n\])[^;]*\)"
        r"[\s\S]{0,160}(?:throw\s+new|return\b)",
        code,
        re.I,
    )
    allowlist = re.search(
        r"\.matches\s*\(\s*\"(?:\^)?\[[A-Za-z0-9_\- .:/?=&%]+\][+*](?:\$)?\"\s*\)",
        code,
        re.I,
    )
    removal = re.search(
        r"\.replace(?:All)?\s*\(\s*(?:\"\\r\"|'\\r'|\"\\n\"|'\\n'|\"\[\\r\\n\]\")\s*,",
        code,
        re.I,
    )
    encoding = re.search(
        r"\b(?:URLEncoder\s*\.\s*encode|Base64\s*\.\s*getUrlEncoder)\s*\(",
        code,
        re.I,
    )
    return bool(explicit_rejection or regex_rejection or allowlist or removal or encoding)
