import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass(frozen=True)
class ResourceExhaustionFinding:
    verdict: str
    start: int
    code: str
    rationale: str


IDENTIFIER_PATTERN = r"[A-Za-z_]\w*"
LIMIT_NAME_PATTERN = (
    r"(?:count|size|length|limit|capacity|iterations?|repetitions?|"
    r"delay|timeout|threads?|workers?|requests?|bytes?|entries|max\w*)"
)
MAX_SAFE_STATIC_BOUND = 10_000_000


def analyze_resource_exhaustion(
    code: str,
) -> Optional[ResourceExhaustionFinding]:
    constants = _collect_constant_variables(code)
    bounded = _collect_bounded_variables(code)
    fixed_limits = _collect_fixed_limit_variables(code)
    parameters = _collect_method_parameters(code)

    for sink in _resource_sinks(code):
        expression = sink["expression"]
        variables = _expression_variables(expression)
        start = int(sink["start"])

        if _is_extreme_bound(expression):
            return ResourceExhaustionFinding(
                "vulnerable",
                start,
                str(sink["code"]),
                "The resource-consuming operation uses an extreme bound that can exhaust available capacity.",
            )
        if _is_statically_bounded(expression, constants, bounded):
            return ResourceExhaustionFinding(
                "safe",
                start,
                str(sink["code"]),
                "The resource-consuming operation uses a fixed or locally capped bound.",
            )

        prefix = code[max(0, start - 900) : start]
        if variables and _has_local_upper_bound(prefix, variables, fixed_limits):
            return ResourceExhaustionFinding(
                "safe",
                start,
                str(sink["code"]),
                "The dynamic resource bound is checked against a local maximum before use.",
            )
        if variables and _uses_unresolved_limit_helper(prefix, variables):
            return ResourceExhaustionFinding(
                "ambiguous",
                start,
                str(sink["code"]),
                "A validation or quota helper is present, but its resource limit cannot be resolved locally.",
            )
        if variables and (
            variables & parameters or _looks_dynamic_resource_bound(variables)
        ):
            return ResourceExhaustionFinding(
                "vulnerable",
                start,
                str(sink["code"]),
                "A dynamic value controls resource allocation, iteration, delay, or concurrency without a local upper bound.",
            )
        if variables:
            return ResourceExhaustionFinding(
                "ambiguous",
                start,
                str(sink["code"]),
                "A variable controls resource consumption, but its provenance and maximum cannot be resolved locally.",
            )

    helper = re.search(
        r"\b(?:validate|check|cap|bound|limit|quota|sanitize)"
        r"(?:Size|Count|Limit|Capacity|Iterations|Resources?|Requests?)\w*\s*\(",
        code,
        re.I,
    )
    if helper:
        return ResourceExhaustionFinding(
            "ambiguous",
            helper.start(),
            helper.group(0),
            "A resource-limiting helper is used, but its guarantees cannot be resolved locally.",
        )
    return None


def _resource_sinks(code: str) -> List[Dict[str, object]]:
    sinks: List[Dict[str, object]] = []
    patterns = [
        re.compile(
            rf"\bnew\s+(?:byte|char|short|int|long|float|double|boolean|Object|String)"
            rf"\s*\[\s*(?P<expression>[^]\n]+)\s*\]",
            re.I,
        ),
        re.compile(
            rf"\bnew\s+(?:(?:java\s*\.\s*)?(?:util|io)\s*\.\s*)?"
            rf"(?:StringBuilder|StringBuffer|ArrayList|HashMap|HashSet|"
            rf"ByteArrayOutputStream)\s*(?:<[^>]*>)?\s*\(\s*"
            rf"(?P<expression>[^),\n]+)\s*\)",
            re.I,
        ),
        re.compile(
            rf"\bExecutors\s*\.\s*(?:newFixedThreadPool|newScheduledThreadPool|"
            rf"newWorkStealingPool)\s*\(\s*(?P<expression>[^)\n]+)\)",
            re.I,
        ),
        re.compile(
            rf"\bThread\s*\.\s*sleep\s*\(\s*(?P<expression>[^)\n]+)\)",
            re.I,
        ),
        re.compile(
            rf"\.\s*repeat\s*\(\s*(?P<expression>[^)\n]+)\)",
            re.I,
        ),
        re.compile(
            rf"\bfor\s*\([^;]*;\s*{IDENTIFIER_PATTERN}\s*(?:<|<=)\s*"
            rf"(?P<expression>{IDENTIFIER_PATTERN})\s*;[^)]*\)",
            re.I,
        ),
    ]
    for pattern in patterns:
        for match in pattern.finditer(code):
            sinks.append(
                {
                    "start": match.start(),
                    "code": match.group(0),
                    "expression": match.group("expression").strip(),
                }
            )
    return sorted(sinks, key=lambda item: int(item["start"]))


def _collect_constant_variables(code: str) -> Dict[str, int]:
    constants: Dict[str, int] = {}
    for match in re.finditer(
        rf"\b(?:byte|short|int|long|Integer|Long)\s+"
        rf"(?P<name>{IDENTIFIER_PATTERN})\s*=\s*(?P<value>\d+)[lL]?\s*;",
        code,
        re.I,
    ):
        value = int(match.group("value"))
        if value <= MAX_SAFE_STATIC_BOUND:
            constants[match.group("name")] = value
    return constants


def _collect_method_parameters(code: str) -> Set[str]:
    parameters: Set[str] = set()
    for signature in re.finditer(
        rf"\b{IDENTIFIER_PATTERN}\s*\((?P<parameters>[^)]*)\)\s*"
        r"(?:throws\s+[^{]+)?\{",
        code,
        re.I,
    ):
        for parameter in signature.group("parameters").split(","):
            match = re.search(
                rf"\b(?P<name>{IDENTIFIER_PATTERN})\s*(?:\[\s*\])?\s*$",
                parameter.strip(),
            )
            if match:
                parameters.add(match.group("name"))
    return parameters


def _collect_fixed_limit_variables(code: str) -> Set[str]:
    limits: Set[str] = set()
    for match in re.finditer(
        rf"\b(?:final\s+)?(?:byte|short|int|long|Integer|Long)\s+"
        rf"(?P<name>{IDENTIFIER_PATTERN})\s*=\s*"
        r"(?P<value>[\d_lL\s*+()-]+)\s*;",
        code,
        re.I,
    ):
        if re.search(r"\d", match.group("value")):
            limits.add(match.group("name"))
    return limits


def _collect_bounded_variables(code: str) -> Set[str]:
    bounded: Set[str] = set()
    for match in re.finditer(
        rf"\b(?P<name>{IDENTIFIER_PATTERN})\s*=\s*"
        rf"Math\s*\.\s*min\s*\(\s*(?:"
        rf"[^,]+,\s*(?:\d+[lL]?|MAX_[A-Z0-9_]+)|"
        rf"(?:\d+[lL]?|MAX_[A-Z0-9_]+)\s*,[^)]+)\s*\)\s*;",
        code,
        re.I,
    ):
        bounded.add(match.group("name"))
    return bounded


def _expression_variables(expression: str) -> Set[str]:
    ignored = {
        "Math",
        "min",
        "max",
        "Integer",
        "Long",
        "MAX_VALUE",
        "MIN_VALUE",
    }
    return set(re.findall(IDENTIFIER_PATTERN, expression)) - ignored


def _is_statically_bounded(
    expression: str, constants: Dict[str, int], bounded: Set[str]
) -> bool:
    stripped = expression.strip()
    if re.fullmatch(r"\d+[lL]?", stripped):
        return int(stripped.rstrip("lL")) <= MAX_SAFE_STATIC_BOUND
    if stripped in constants or stripped in bounded:
        return True
    return bool(
        re.search(
            r"\bMath\s*\.\s*min\s*\([^,]+,\s*"
            r"(?:\d+[lL]?|MAX_[A-Z0-9_]+)\s*\)|"
            r"\bMath\s*\.\s*min\s*\(\s*"
            r"(?:\d+[lL]?|MAX_[A-Z0-9_]+)\s*,",
            stripped,
            re.I,
        )
    )


def _is_extreme_bound(expression: str) -> bool:
    stripped = expression.strip()
    numeric = re.fullmatch(r"(\d+)[lL]?", stripped)
    return bool(
        (numeric and int(numeric.group(1)) > MAX_SAFE_STATIC_BOUND)
        or re.search(r"\b(?:Integer|Long)\s*\.\s*MAX_VALUE\b", stripped)
    )


def _has_local_upper_bound(
    prefix: str, variables: Set[str], fixed_limits: Set[str]
) -> bool:
    token_pattern = rf"(?:\d[\d_]*[lL]?|MAX_[A-Z0-9_]+|{IDENTIFIER_PATTERN})"
    for variable in variables:
        name = re.escape(variable)
        for condition in re.finditer(
            r"\bif\s*\((?P<condition>[^)]*)\)",
            prefix,
            re.I,
        ):
            expression = condition.group("condition")
            guarded = re.search(
                rf"\b{name}\b\s*(?:<=|<)\s*(?P<bound>{token_pattern})|"
                rf"(?P<reverse>{token_pattern})\s*(?:>=|>)\s*\b{name}\b",
                expression,
                re.I,
            )
            if guarded:
                bound = guarded.group("bound") or guarded.group("reverse")
                if _is_known_upper_bound(bound, fixed_limits):
                    return True

            rejected = re.search(
                rf"\b{name}\b\s*(?:>|>=)\s*(?P<bound>{token_pattern})|"
                rf"(?P<reverse>{token_pattern})\s*(?:<|<=)\s*\b{name}\b",
                expression,
                re.I,
            )
            suffix = prefix[condition.end() : condition.end() + 180]
            if rejected and re.search(r"(?:throw\s+new|return\b)", suffix, re.I):
                bound = rejected.group("bound") or rejected.group("reverse")
                if _is_known_upper_bound(bound, fixed_limits):
                    return True
    return False


def _is_known_upper_bound(bound: str, fixed_limits: Set[str]) -> bool:
    normalized = bound.rstrip("lL").replace("_", "")
    if normalized.isdigit():
        return int(normalized) > 0
    return bool(re.fullmatch(r"MAX_[A-Z0-9_]+", bound, re.I) or bound in fixed_limits)


def _uses_unresolved_limit_helper(prefix: str, variables: Set[str]) -> bool:
    names = "|".join(re.escape(name) for name in sorted(variables))
    return bool(
        re.search(
            rf"\b(?:validate|check|cap|bound|limit|quota|sanitize)\w*\s*"
            rf"\([^;]*\b(?:{names})\b[^;]*\)\s*;",
            prefix,
            re.I,
        )
    )


def _looks_dynamic_resource_bound(variables: Set[str]) -> bool:
    return any(re.fullmatch(LIMIT_NAME_PATTERN, name, re.I) for name in variables)
