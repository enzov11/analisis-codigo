import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class SqlFinding:
    verdict: str
    start: int
    code: str
    rationale: str


SQL_LITERAL_PATTERN = r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
IDENTIFIER_PATTERN = r"[A-Za-z_]\w*"


def analyze_sql(code: str) -> Optional[SqlFinding]:
    assignments = _collect_assignments(code)

    for match in re.finditer(
        r"\.(?:execute|executeQuery|executeUpdate|addBatch)\s*\(\s*(?P<arg>[\s\S]*?)\s*\)",
        code,
        re.I,
    ):
        argument = match.group("arg").strip()
        if not argument:
            continue
        resolved = _resolve_expression(argument, assignments)
        if resolved == "dynamic":
            return SqlFinding(
                "vulnerable",
                match.start(),
                match.group(0),
                "A dynamically constructed SQL command reaches a non-parameterized execution sink.",
            )
        if resolved == "static":
            return SqlFinding(
                "safe",
                match.start(),
                match.group(0),
                "The SQL sink receives a locally resolved fixed command.",
            )

    prepared_matches = list(
        re.finditer(
            rf"(?:(?:PreparedStatement|java\.sql\.PreparedStatement)\s+)?"
            rf"(?P<statement>{IDENTIFIER_PATTERN})\s*=\s*"
            r"[^;]*?\.prepareStatement\s*\(\s*(?P<arg>[\s\S]*?)\s*\)\s*(?:;|\))",
            code,
            re.I,
        )
    )
    for match in prepared_matches:
        statement = match.group("statement")
        argument = match.group("arg").strip()
        resolved = _resolve_expression(argument, assignments)
        if resolved == "dynamic":
            return SqlFinding(
                "vulnerable",
                match.start(),
                match.group(0),
                "PreparedStatement receives a dynamically concatenated SQL command.",
            )
        if resolved == "static" and _contains_placeholder(argument, assignments):
            if re.search(
                rf"\b{re.escape(statement)}\s*\.\s*set(?:String|Int|Long|Boolean|Object|Date|BigDecimal|Bytes|Timestamp|Null)\s*\(",
                code,
                re.I,
            ):
                return SqlFinding(
                    "safe",
                    match.start(),
                    match.group(0),
                    "PreparedStatement uses a locally resolved placeholder query with bound values.",
                )
            return SqlFinding(
                "ambiguous",
                match.start(),
                match.group(0),
                "PreparedStatement uses placeholders, but matching bindings were not resolved locally.",
            )

    unresolved = re.search(
        r"\.(?:prepareStatement|createStatement|execute|executeQuery|executeUpdate|addBatch)\s*\(",
        code,
        re.I,
    )
    if unresolved:
        return SqlFinding(
            "ambiguous",
            unresolved.start(),
            unresolved.group(0),
            "A SQL-sensitive operation was found, but its local data flow is unresolved.",
        )
    return None


def _collect_assignments(code: str) -> Dict[str, List[str]]:
    assignments: Dict[str, List[str]] = {}
    pattern = re.compile(
        rf"\b(?:String\s+)?(?P<name>{IDENTIFIER_PATTERN})\s*(?P<operator>\+=|=)\s*"
        r"(?P<expression>[\s\S]*?);",
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


def _resolve_expression(
    expression: str,
    assignments: Dict[str, List[str]],
    visited: Optional[set] = None,
) -> str:
    expression = expression.strip()
    visited = set() if visited is None else visited
    if re.fullmatch(SQL_LITERAL_PATTERN, expression, re.S):
        return "static"
    if re.fullmatch(IDENTIFIER_PATTERN, expression):
        if expression in visited or expression not in assignments:
            return "unknown"
        visited.add(expression)
        states = [
            _resolve_expression(value, assignments, visited.copy())
            for value in assignments[expression]
        ]
        if "dynamic" in states:
            return "dynamic"
        if len(states) > 1 and "unknown" in states:
            return "dynamic"
        if states and all(state == "static" for state in states):
            return "static"
        return "unknown"

    without_literals = re.sub(SQL_LITERAL_PATTERN, "", expression, flags=re.S)
    identifiers = re.findall(IDENTIFIER_PATTERN, without_literals)
    if "+" in without_literals:
        if identifiers:
            states = [
                _resolve_expression(identifier, assignments, visited.copy())
                for identifier in identifiers
            ]
            return "static" if states and all(state == "static" for state in states) else "dynamic"
        return "static"
    return "unknown"


def _contains_placeholder(expression: str, assignments: Dict[str, List[str]]) -> bool:
    expression = expression.strip()
    if re.fullmatch(IDENTIFIER_PATTERN, expression) and expression in assignments:
        return any("?" in value for value in assignments[expression])
    return "?" in expression
