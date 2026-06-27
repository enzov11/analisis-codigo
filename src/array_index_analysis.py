import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class ArrayIndexFinding:
    verdict: str
    start: int
    code: str
    rationale: str


IDENTIFIER_PATTERN = r"[A-Za-z_]\w*"
STRING_LITERAL_PATTERN = r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''


def analyze_array_index(code: str) -> Optional[ArrayIndexFinding]:
    assignments = _collect_assignments(code)
    for sink in _iter_index_sinks(code):
        index_expr = str(sink["index"]).strip()
        if not index_expr:
            continue
        classification = _classify_index(
            index_expr,
            code,
            assignments,
            allows_upper_bound=bool(sink["allows_upper_bound"]),
        )
        if classification == "safe":
            return ArrayIndexFinding(
                "safe",
                int(sink["start"]),
                str(sink["code"]),
                "The index is checked, clamped, or constrained before reaching an indexed access.",
            )
        if classification == "vulnerable":
            return ArrayIndexFinding(
                "vulnerable",
                int(sink["start"]),
                str(sink["code"]),
                "A dynamic index reaches an indexed access without locally resolved bounds validation.",
            )
        if classification == "ambiguous":
            return ArrayIndexFinding(
                "ambiguous",
                int(sink["start"]),
                str(sink["code"]),
                "An indexed access depends on validation that cannot be resolved locally.",
            )
    return None


def _iter_index_sinks(code: str) -> List[Dict[str, object]]:
    sinks: List[Dict[str, object]] = []
    patterns = [
        (
            rf"\b(?P<container>{IDENTIFIER_PATTERN})\s*\[\s*(?P<index>[^\]\n;]+)\s*\]",
            False,
        ),
        (
            rf"\b(?P<container>{IDENTIFIER_PATTERN})\s*\.\s*(?:get|set|remove)\s*"
            rf"\(\s*(?P<index>[^,\)\n;]+)",
            False,
        ),
        (
            rf"\b(?P<container>{IDENTIFIER_PATTERN})\s*\.\s*add\s*"
            rf"\(\s*(?P<index>[^,\)\n;]+)\s*,",
            True,
        ),
        (r"\.\s*(?:charAt|codePointAt)\s*\(\s*(?P<index>[^,\)\n;]+)", False),
        (r"\.\s*substring\s*\(\s*(?P<index>[^,\)\n;]+)", True),
    ]
    for pattern, allows_upper_bound in patterns:
        for match in re.finditer(pattern, code, re.I):
            index = match.group("index").strip()
            container = match.groupdict().get("container", "")
            if container and container[0].isupper() and "." in match.group(0):
                continue
            if _is_declaration_or_allocation(match.group(0), container, index):
                continue
            sinks.append(
                {
                    "start": match.start(),
                    "code": match.group(0),
                    "index": index,
                    "allows_upper_bound": allows_upper_bound,
                }
            )
    return sorted(sinks, key=lambda item: int(item["start"]))


def _is_declaration_or_allocation(code_fragment: str, container: str, index: str) -> bool:
    if container in {"new", "Object", "String", "int", "long", "byte", "char", "short", "double", "float", "boolean"}:
        return True
    return bool(re.fullmatch(r"\d+", index.strip()) and "[" in code_fragment and "]" in code_fragment)


def _collect_assignments(code: str) -> Dict[str, str]:
    assignments: Dict[str, str] = {}
    pattern = re.compile(
        rf"\b(?:(?:int|Integer|long|Long|short|Short)\s+)?(?P<name>{IDENTIFIER_PATTERN})\s*=\s*(?P<expr>[\s\S]*?);",
        re.I,
    )
    for match in pattern.finditer(code):
        assignments[match.group("name")] = match.group("expr").strip()
    return assignments


def _classify_index(
    index_expr: str,
    code: str,
    assignments: Dict[str, str],
    visited: Optional[set] = None,
    allows_upper_bound: bool = False,
) -> str:
    index_expr = index_expr.strip()
    visited = set() if visited is None else visited
    if _is_constant_index(index_expr):
        return "safe"
    if _has_local_bounds_validation(index_expr, code, allows_upper_bound):
        return "safe"
    if _is_clamped_expression(index_expr):
        return "safe"
    if _uses_unresolved_validation_helper(index_expr):
        return "ambiguous"
    if re.fullmatch(IDENTIFIER_PATTERN, index_expr):
        if index_expr in visited:
            return "ambiguous"
        if index_expr in assignments:
            visited.add(index_expr)
            assigned = assignments[index_expr]
            if _is_clamped_expression(assigned):
                return "safe"
            if _uses_unresolved_validation_helper(assigned):
                return "ambiguous"
            if _has_local_bounds_validation(index_expr, code, allows_upper_bound):
                return "safe"
            return _classify_index(
                assigned,
                code,
                assignments,
                visited,
                allows_upper_bound,
            )
        return "vulnerable"
    if _contains_dynamic_value(index_expr):
        return "vulnerable"
    return "ambiguous"


def _is_constant_index(index_expr: str) -> bool:
    return bool(re.fullmatch(r"\d+", index_expr.strip()))


def _contains_dynamic_value(index_expr: str) -> bool:
    without_literals = re.sub(STRING_LITERAL_PATTERN, "", index_expr, flags=re.S)
    return bool(re.search(IDENTIFIER_PATTERN, without_literals))


def _is_clamped_expression(index_expr: str) -> bool:
    return bool(
        re.search(r"\bMath\s*\.\s*(?:min|max)\s*\(", index_expr)
        and re.search(r"\bMath\s*\.\s*(?:min|max)\s*\(", index_expr[index_expr.find("Math") + 1 :])
    )


def _uses_unresolved_validation_helper(index_expr: str) -> bool:
    return bool(
        re.search(
            r"\b(?:validateIndex|checkIndex|safeIndex|normalizeIndex|clampIndex|boundedIndex)\w*\s*\(",
            index_expr,
            re.I,
        )
    )


def _has_local_bounds_validation(
    index_expr: str,
    code: str,
    allows_upper_bound: bool = False,
) -> bool:
    if not re.fullmatch(IDENTIFIER_PATTERN, index_expr):
        return False
    idx = re.escape(index_expr)
    limit = r"(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*(?:\.\s*length|\.\s*size\s*\(\s*\))"
    exclusive_direct_check = re.search(
        rf"(?:Objects\s*\.\s*checkIndex|Preconditions\s*\.\s*check(?:Element)?Index)\s*\(\s*{idx}\s*,",
        code,
        re.I,
    )
    inclusive_direct_check = re.search(
        rf"Preconditions\s*\.\s*checkPositionIndex\s*\(\s*{idx}\s*,",
        code,
        re.I,
    )
    upper_operator = r"<=" if allows_upper_bound else r"<"
    rejection_operator = r">" if allows_upper_bound else r">="
    reversed_rejection_operator = r"<" if allows_upper_bound else r"<="
    positive_range = re.search(
        rf"(?:{idx}\s*>=\s*0|0\s*<=\s*{idx})[\s\S]{{0,180}}"
        rf"{idx}\s*{upper_operator}\s*{limit}",
        code,
        re.I,
    )
    negative_rejection = re.search(
        rf"{idx}\s*<\s*0[\s\S]{{0,180}}(?:throw\s+new|return\b)",
        code,
        re.I,
    )
    upper_rejection = re.search(
        rf"{idx}\s*{rejection_operator}\s*{limit}[\s\S]{{0,180}}"
        rf"(?:throw\s+new|return\b)",
        code,
        re.I,
    )
    reversed_upper_rejection = re.search(
        rf"{limit}\s*{reversed_rejection_operator}\s*{idx}[\s\S]{{0,180}}"
        rf"(?:throw\s+new|return\b)",
        code,
        re.I,
    )
    return bool(
        exclusive_direct_check
        or (allows_upper_bound and inclusive_direct_check)
        or positive_range
        or (negative_rejection and (upper_rejection or reversed_upper_rejection))
    )
