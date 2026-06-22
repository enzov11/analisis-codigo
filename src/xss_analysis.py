import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class XssFinding:
    verdict: str
    start: int
    code: str
    rationale: str


STRING_LITERAL_PATTERN = r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
IDENTIFIER_PATTERN = r"[A-Za-z_]\w*"


def analyze_xss(code: str) -> Optional[XssFinding]:
    assignments = _collect_assignments(code)
    escaped_values = _collect_locally_escaped_values(code)

    for match in _iter_html_sinks(code):
        argument = match.group("arg").strip()
        if not argument:
            continue
        classification = _classify_expression(argument, assignments, escaped_values)
        if classification == "safe":
            return XssFinding(
                "safe",
                match.start(),
                match.group(0),
                "Untrusted data appears to be HTML-escaped or sanitized before reaching an HTML output sink.",
            )
        if classification == "dynamic_html":
            return XssFinding(
                "vulnerable",
                match.start(),
                match.group(0),
                "A dynamic value is inserted into HTML output without locally resolved escaping.",
            )
        if classification == "unknown_dynamic":
            return XssFinding(
                "ambiguous",
                match.start(),
                match.group(0),
                "HTML output receives a dynamic value whose escaping cannot be resolved locally.",
            )

    return None


def _iter_html_sinks(code: str):
    builder_names = set(re.findall(r"\bStringBuilder\s+([A-Za-z_]\w*)\s*=", code))
    patterns = [
        r"\breturn\s+(?P<arg>[^;]+);",
        rf"(?P<receiver>{IDENTIFIER_PATTERN})?\s*\.\s*(?P<method>write|print|println|append)\s*\(\s*(?P<arg>[\s\S]*?)\s*\)",
        r"ResponseEntity\s*\.\s*ok\s*\(\s*(?P<arg>[\s\S]*?)\s*\)",
    ]
    matches = []
    for pattern in patterns:
        for match in re.finditer(pattern, code, re.I):
            if (
                match.groupdict().get("method")
                and match.group("method").lower() == "append"
                and match.groupdict().get("receiver") in builder_names
            ):
                continue
            matches.append(match)
    return sorted(matches, key=lambda item: item.start())


def _collect_assignments(code: str) -> Dict[str, List[str]]:
    assignments: Dict[str, List[str]] = {}
    pattern = re.compile(
        rf"\b(?:(?:String|CharSequence|StringBuilder)\s+)?(?P<name>{IDENTIFIER_PATTERN})\s*"
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

    append_pattern = re.compile(
        rf"\b(?P<name>{IDENTIFIER_PATTERN})\s*\.\s*append\s*\(\s*(?P<expression>[\s\S]*?)\s*\)\s*;",
        re.I,
    )
    for match in append_pattern.finditer(code):
        assignments.setdefault(match.group("name"), []).append(match.group("expression").strip())
    return assignments


def _classify_expression(
    expression: str,
    assignments: Dict[str, List[str]],
    escaped_values: set,
    visited: Optional[set] = None,
) -> str:
    expression = expression.strip()
    visited = set() if visited is None else visited
    if _has_html_escaping(expression):
        return "safe"
    if re.fullmatch(IDENTIFIER_PATTERN, expression):
        if expression in escaped_values:
            return "safe"
        if expression in visited:
            return "unknown_dynamic"
        if expression not in assignments:
            return "unknown_dynamic" if _looks_like_html_value_name(expression) else "unknown"
        visited.add(expression)
        states = [
            _classify_expression(value, assignments, escaped_values, visited.copy())
            for value in assignments[expression]
        ]
        if "safe" in states and "dynamic_html" not in states:
            return "safe"
        if "dynamic_html" in states:
            return "dynamic_html"
        if "unknown_dynamic" in states:
            return "unknown_dynamic"
        return "unknown"

    without_literals = re.sub(STRING_LITERAL_PATTERN, "", expression, flags=re.S)
    identifiers = re.findall(IDENTIFIER_PATTERN, without_literals)
    has_dynamic_value = bool(identifiers)
    if _contains_html_literal(expression) and has_dynamic_value:
        states = [
            _classify_expression(identifier, assignments, escaped_values, visited.copy())
            for identifier in identifiers
        ]
        return "safe" if states and all(state == "safe" for state in states) else "dynamic_html"
    if _contains_html_literal(expression):
        return "unknown"
    if re.search(r"\b(?:sanitize|clean|filter|renderSafe|safeHtml)\w*\s*\(", expression, re.I):
        return "unknown_dynamic"
    if has_dynamic_value and _looks_like_html_value_name(expression):
        return "unknown_dynamic"
    return "unknown"


def _collect_locally_escaped_values(code: str) -> set:
    escaped = set()
    builder_names = set(re.findall(r"\bStringBuilder\s+([A-Za-z_]\w*)\s*=", code))
    for builder in builder_names:
        appends = re.findall(
            rf"\b{re.escape(builder)}\s*\.\s*append\s*\(\s*({STRING_LITERAL_PATTERN})\s*\)",
            code,
            re.I | re.S,
        )
        entities = {"&amp;", "&lt;", "&gt;", "&quot;", "&#x27;", "&#39;"}
        if len({entity for literal in appends for entity in entities if entity in literal}) >= 3:
            escaped.add(builder)
    return escaped


def _contains_html_literal(expression: str) -> bool:
    for literal in re.findall(STRING_LITERAL_PATTERN, expression, re.S):
        if re.search(r"<\s*/?\s*[A-Za-z][^>]*>|&(?:lt|gt|quot|#x27|#39);", literal):
            return True
    return False


def _has_html_escaping(expression: str) -> bool:
    return bool(
        re.search(
            r"(?:escapeHtml\w*|htmlEscape\w*|encodeForHTML\w*|Encode\s*\.\s*forHtml\w*|"
            r"StringEscapeUtils\s*\.\s*escapeHtml\w*|HtmlUtils\s*\.\s*htmlEscape\w*|"
            r"ESAPI\s*\.\s*encoder\s*\(\s*\)\s*\.\s*encodeForHTML\w*|Jsoup\s*\.\s*clean|"
            r"\.replace\s*\(\s*\"<\"\s*,\s*\"&lt;\"\s*\))",
            expression,
            re.I,
        )
    )


def _looks_like_html_value_name(expression: str) -> bool:
    return bool(
        re.search(
            r"\b(?:html|body|content|message|comment|description|title|name|query|input|user)\w*\b",
            expression,
            re.I,
        )
    )
