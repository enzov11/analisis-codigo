import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class FormatStringFinding:
    verdict: str
    start: int
    code: str
    rationale: str


IDENTIFIER_PATTERN = r"[A-Za-z_]\w*"
STRING_LITERAL_PATTERN = r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''


def analyze_format_string(code: str) -> Optional[FormatStringFinding]:
    assignments = _collect_assignments(code)
    for sink in _iter_format_sinks(code):
        expression = str(sink["format"]).strip()
        if not expression:
            continue
        classification = _classify_format(expression, code, assignments)
        if classification == "safe":
            return FormatStringFinding(
                "safe",
                int(sink["start"]),
                str(sink["code"]),
                "The formatting operation uses a fixed or locally allowlisted format string.",
            )
        if classification == "vulnerable":
            return FormatStringFinding(
                "vulnerable",
                int(sink["start"]),
                str(sink["code"]),
                "A dynamic value controls the format string instead of being passed as a formatting argument.",
            )
        return FormatStringFinding(
            "ambiguous",
            int(sink["start"]),
            str(sink["code"]),
            "The formatting operation depends on a format value whose provenance or validation cannot be resolved locally.",
        )
    return None


def _iter_format_sinks(code: str) -> List[Dict[str, object]]:
    sinks: List[Dict[str, object]] = []
    formatter_receivers = {
        match.group("name").lower()
        for match in re.finditer(
            rf"\b(?:java\s*\.\s*util\s*\.\s*)?Formatter\s+"
            rf"(?P<name>{IDENTIFIER_PATTERN})\b",
            code,
            re.I,
        )
    }
    call_pattern = re.compile(
        rf"\b(?P<callee>{IDENTIFIER_PATTERN}(?:\s*\.\s*{IDENTIFIER_PATTERN})+)"
        r"\s*\(",
        re.I,
    )
    for match in call_pattern.finditer(code):
        callee = re.sub(r"\s+", "", match.group("callee"))
        method = callee.rsplit(".", 1)[-1].lower()
        if method not in {"printf", "format"}:
            continue
        if method == "format" and not _is_recognized_format_callee(
            callee, formatter_receivers
        ):
            continue
        close = _find_call_end(code, match.end() - 1)
        if close is None:
            continue
        arguments = _split_top_level_arguments(code[match.end() : close])
        format_index = 1 if len(arguments) > 1 and _looks_like_locale(arguments[0]) else 0
        if len(arguments) <= format_index:
            continue
        sinks.append(
            {
                "start": match.start(),
                "code": code[match.start() : close + 1],
                "format": arguments[format_index],
            }
        )

    formatted_pattern = re.compile(
        rf"(?P<format>{STRING_LITERAL_PATTERN}|{IDENTIFIER_PATTERN})"
        r"\s*\.\s*formatted\s*\(",
        re.I,
    )
    for match in formatted_pattern.finditer(code):
        close = _find_call_end(code, match.end() - 1)
        if close is None:
            continue
        sinks.append(
            {
                "start": match.start(),
                "code": code[match.start() : close + 1],
                "format": match.group("format"),
            }
        )
    return sorted(sinks, key=lambda item: int(item["start"]))


def _is_recognized_format_callee(
    callee: str, formatter_receivers: Optional[set] = None
) -> bool:
    receiver = callee.rsplit(".", 1)[0].lower()
    simple_receiver = receiver.rsplit(".", 1)[-1]
    return bool(
        receiver in {"string", "messageformat", "system.out", "system.err"}
        or receiver.endswith(".messageformat")
        or simple_receiver in (formatter_receivers or set())
        or re.search(r"(?:formatter|writer|stream|out|err)$", receiver)
    )


def _looks_like_locale(expression: str) -> bool:
    expression = expression.strip()
    return bool(
        re.search(r"\bLocale\s*\.", expression, re.I)
        or re.fullmatch(r"(?:locale|outputLocale|formatLocale)", expression, re.I)
    )


def _find_call_end(code: str, open_paren: int) -> Optional[int]:
    depth = 0
    quote = ""
    escaped = False
    for index in range(open_paren, len(code)):
        char = code[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_top_level_arguments(arguments: str) -> List[str]:
    values: List[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(arguments):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            values.append(arguments[start:index].strip())
            start = index + 1
    tail = arguments[start:].strip()
    if tail:
        values.append(tail)
    return values


def _collect_assignments(code: str) -> Dict[str, List[str]]:
    assignments: Dict[str, List[str]] = {}
    pattern = re.compile(
        rf"\b(?:(?:String|CharSequence|var)\s+)?(?P<name>{IDENTIFIER_PATTERN})\s*"
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


def _classify_format(
    expression: str,
    code: str,
    assignments: Dict[str, List[str]],
    visited: Optional[set] = None,
) -> str:
    expression = expression.strip()
    visited = set() if visited is None else visited
    if _is_literal(expression) or _is_named_constant(expression):
        return "safe"
    if _escapes_format_tokens(expression):
        return "safe"
    if _uses_unresolved_format_helper(expression):
        return "ambiguous"
    if re.fullmatch(IDENTIFIER_PATTERN, expression):
        if _has_local_allowlist(expression, code):
            return "safe"
        if expression in visited:
            return "ambiguous"
        if expression not in assignments:
            return "vulnerable"
        visited.add(expression)
        states = [
            _classify_format(value, code, assignments, visited.copy())
            for value in assignments[expression]
        ]
        if states and all(state == "safe" for state in states):
            return "safe"
        if "vulnerable" in states:
            return "vulnerable"
        return "ambiguous"
    if _contains_dynamic_value(expression):
        return "vulnerable"
    return "ambiguous"


def _is_literal(expression: str) -> bool:
    return bool(re.fullmatch(rf"\s*{STRING_LITERAL_PATTERN}\s*", expression, re.S))


def _is_named_constant(expression: str) -> bool:
    return bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", expression))


def _contains_dynamic_value(expression: str) -> bool:
    without_literals = re.sub(STRING_LITERAL_PATTERN, "", expression, flags=re.S)
    return bool(re.search(IDENTIFIER_PATTERN, without_literals))


def _escapes_format_tokens(expression: str) -> bool:
    return bool(
        re.search(
            r"\.replace(?:All)?\s*\(\s*\"%\"\s*,\s*\"%%\"\s*\)",
            expression,
            re.I,
        )
    )


def _uses_unresolved_format_helper(expression: str) -> bool:
    return bool(
        re.search(
            r"\b(?:sanitizeFormat|validateFormat|safeFormat|normalizeFormat)\w*\s*\(",
            expression,
            re.I,
        )
    )


def _has_local_allowlist(name: str, code: str) -> bool:
    escaped = re.escape(name)
    collection_rejection = re.search(
        rf"!\s*(?:[A-Za-z_]\w*\.)*(?:contains|containsKey)\s*\(\s*{escaped}\s*\)"
        rf"[\s\S]{{0,180}}(?:throw\s+new|return\b)",
        code,
        re.I,
    )
    fixed_comparisons = re.findall(
        rf"(?:{escaped}\s*\.\s*equals\s*\(\s*{STRING_LITERAL_PATTERN}\s*\)|"
        rf"{STRING_LITERAL_PATTERN}\s*\.\s*equals\s*\(\s*{escaped}\s*\))",
        code,
        re.I | re.S,
    )
    rejected_otherwise = re.search(
        r"(?:else|default\s*:)[\s\S]{0,120}(?:throw\s+new|return\b)",
        code,
        re.I,
    )
    return bool(collection_rejection or (fixed_comparisons and rejected_otherwise))
