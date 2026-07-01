import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass(frozen=True)
class IntegerOverflowFinding:
    verdict: str
    start: int
    code: str
    rationale: str


IDENTIFIER_PATTERN = r"[A-Za-z_]\w*"
NUMERIC_TYPES = r"(?:byte|short|int|long|Byte|Short|Integer|Long)"
OPERAND_PATTERN = (
    rf"(?:\(\s*{NUMERIC_TYPES}\s*\)\s*)?"
    rf"(?:{IDENTIFIER_PATTERN}(?:\s*\.\s*(?:MAX_VALUE|MIN_VALUE))?|\d+[lL]?)"
)


def analyze_integer_overflow(code: str) -> Optional[IntegerOverflowFinding]:
    numeric_variables = _collect_numeric_variables(code)
    constant_variables = _collect_small_constant_assignments(code)

    checked = re.search(
        r"\bMath\s*\.\s*(?:addExact|subtractExact|multiplyExact|incrementExact|"
        r"decrementExact|negateExact|toIntExact)\s*\(",
        code,
        re.I,
    )
    if checked:
        return IntegerOverflowFinding(
            "safe",
            checked.start(),
            checked.group(0),
            "The arithmetic operation uses a checked Math.*Exact primitive that reports overflow.",
        )

    big_integer = re.search(
        r"\bBigInteger\b[\s\S]{0,240}\.\s*(?:add|subtract|multiply|pow)\s*\(",
        code,
        re.I,
    )
    if big_integer:
        return IntegerOverflowFinding(
            "safe",
            big_integer.start(),
            big_integer.group(0),
            "The calculation uses arbitrary-precision BigInteger arithmetic.",
        )

    operations = _iter_arithmetic_operations(code, numeric_variables)
    for operation in operations:
        variables = set(operation["variables"])
        if variables and variables.issubset(constant_variables):
            return IntegerOverflowFinding(
                "safe",
                int(operation["start"]),
                str(operation["code"]),
                "The arithmetic operands are locally assigned small constant values.",
            )
        prefix = code[max(0, int(operation["start"]) - 500) : int(operation["start"])]
        if _has_local_overflow_guard(prefix, variables):
            return IntegerOverflowFinding(
                "safe",
                int(operation["start"]),
                str(operation["code"]),
                "The arithmetic operation is preceded by a local numeric bounds check.",
            )
        if _uses_unresolved_numeric_helper(prefix, variables):
            return IntegerOverflowFinding(
                "ambiguous",
                int(operation["start"]),
                str(operation["code"]),
                "Arithmetic follows a validation helper whose overflow guarantees cannot be resolved locally.",
            )
        return IntegerOverflowFinding(
            "vulnerable",
            int(operation["start"]),
            str(operation["code"]),
            "Unchecked integer arithmetic uses a dynamic numeric value and may overflow before any later validation.",
        )

    helper = re.search(
        r"\b(?:safeAdd|checkedAdd|safeMultiply|checkedMultiply|"
        r"validateArithmetic|validateRange)\w*\s*\(",
        code,
        re.I,
    )
    if helper:
        return IntegerOverflowFinding(
            "ambiguous",
            helper.start(),
            helper.group(0),
            "A numeric helper is used, but its overflow behavior cannot be resolved locally.",
        )
    return None


def _collect_numeric_variables(code: str) -> Dict[str, str]:
    variables: Dict[str, str] = {}
    for match in re.finditer(
        rf"\b(?P<type>{NUMERIC_TYPES})\s+(?P<name>{IDENTIFIER_PATTERN})\b",
        code,
        re.I,
    ):
        variables[match.group("name")] = match.group("type").lower()
    return variables


def _collect_small_constant_assignments(code: str) -> Set[str]:
    constants: Set[str] = set()
    for match in re.finditer(
        rf"\b{NUMERIC_TYPES}\s+(?P<name>{IDENTIFIER_PATTERN})\s*=\s*"
        r"(?P<value>-?\d+[lL]?)\s*;",
        code,
        re.I,
    ):
        value = int(match.group("value").rstrip("lL"))
        if abs(value) <= 1_000_000:
            constants.add(match.group("name"))
    return constants


def _iter_arithmetic_operations(
    code: str, numeric_variables: Dict[str, str]
) -> List[Dict[str, object]]:
    operations: List[Dict[str, object]] = []
    binary = re.compile(
        rf"(?P<left>{OPERAND_PATTERN})\s*(?P<operator>[+*-])\s*"
        rf"(?P<right>{OPERAND_PATTERN})",
        re.I,
    )
    for match in binary.finditer(code):
        if _inside_control_condition(code, match.start()):
            continue
        variables = _operation_variables(match.group(0), numeric_variables)
        has_numeric_bound = bool(
            re.search(r"\b(?:Integer|Long|Short|Byte)\.(?:MAX_VALUE|MIN_VALUE)\b", match.group(0))
        )
        if not variables and not has_numeric_bound:
            continue
        if match.group("operator") == "+" and _looks_like_string_concatenation(
            code, match.start(), match.end()
        ):
            continue
        operations.append(
            {
                "start": match.start(),
                "code": match.group(0),
                "variables": sorted(variables),
            }
        )

    unary_patterns = [
        re.compile(rf"\b(?P<name>{IDENTIFIER_PATTERN})\s*(?:\+\+|--)", re.I),
        re.compile(rf"(?:\+\+|--)\s*(?P<name>{IDENTIFIER_PATTERN})\b", re.I),
        re.compile(rf"\b(?P<name>{IDENTIFIER_PATTERN})\s*(?:\+=|-=|\*=)\s*[^;\n]+", re.I),
        re.compile(
            rf"(?:\breturn\s+|=\s*|\(\s*|,\s*)-\s*(?P<name>{IDENTIFIER_PATTERN})\b",
            re.I,
        ),
    ]
    for pattern in unary_patterns:
        for match in pattern.finditer(code):
            name = match.group("name")
            if name not in numeric_variables or _inside_control_condition(code, match.start()):
                continue
            operations.append(
                {
                    "start": match.start(),
                    "code": match.group(0),
                    "variables": [name],
                }
            )
    return sorted(operations, key=lambda item: int(item["start"]))


def _operation_variables(expression: str, numeric_variables: Dict[str, str]) -> Set[str]:
    identifiers = set(re.findall(IDENTIFIER_PATTERN, expression))
    return identifiers & set(numeric_variables)


def _looks_like_string_concatenation(code: str, start: int, end: int) -> bool:
    context = code[max(0, start - 80) : min(len(code), end + 80)]
    return bool(
        re.search(r"\bString\s+\w+\s*=", context)
        or re.search(r'["\'](?:\\.|[^"\'])*["\']\s*\+', context)
        or re.search(r'\+\s*["\']', context)
    )


def _inside_control_condition(code: str, position: int) -> bool:
    candidates = list(re.finditer(r"\b(?:if|while|for)\s*\(", code[:position], re.I))
    if not candidates:
        return False
    open_paren = code.find("(", candidates[-1].start())
    close_paren = _find_matching_paren(code, open_paren)
    return close_paren is not None and position < close_paren


def _find_matching_paren(code: str, open_paren: int) -> Optional[int]:
    depth = 0
    for index in range(open_paren, len(code)):
        if code[index] == "(":
            depth += 1
        elif code[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _has_local_overflow_guard(prefix: str, variables: Set[str]) -> bool:
    if not variables:
        return False
    names = "|".join(re.escape(name) for name in sorted(variables))
    guard = re.search(
        rf"\b(?:if|while)\s*\([^)]*(?:{names})[^)]*"
        r"(?:MAX_VALUE|MIN_VALUE|Math\s*\.\s*(?:abs|sqrt)|"
        r"\b(?:max|min|limit|bound)\w*)[^)]*\)",
        prefix,
        re.I,
    )
    reverse_guard = re.search(
        rf"\b(?:if|while)\s*\([^)]*(?:MAX_VALUE|MIN_VALUE|"
        rf"\b(?:max|min|limit|bound)\w*)[^)]*(?:{names})[^)]*\)",
        prefix,
        re.I,
    )
    rejection = re.search(
        rf"\b(?:{names})\s*(?:>=|>|<=|<)\s*"
        r"(?:Integer|Long|Short|Byte)\.(?:MAX_VALUE|MIN_VALUE)"
        r"[\s\S]{0,160}(?:throw\s+new|return\b)",
        prefix,
        re.I,
    )
    return bool(guard or reverse_guard or rejection)


def _uses_unresolved_numeric_helper(prefix: str, variables: Set[str]) -> bool:
    if not variables:
        return False
    names = "|".join(re.escape(name) for name in sorted(variables))
    return bool(
        re.search(
            rf"\b(?:validateRange|validateArithmetic|checkBounds|isSafeTo"
            rf"(?:Add|Multiply|Subtract))\w*\s*\([^)]*(?:{names})[^)]*\)",
            prefix,
            re.I,
        )
    )
