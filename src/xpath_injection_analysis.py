import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass(frozen=True)
class XPathInjectionFinding:
    verdict: str
    start: int
    code: str
    rationale: str


IDENTIFIER_PATTERN = r"[A-Za-z_]\w*"


def analyze_xpath_injection(code: str) -> Optional[XPathInjectionFinding]:
    parameters = _collect_method_parameters(code)
    dynamic_names = _collect_dynamic_names(code, parameters)
    constants = _collect_string_constants(code)
    sanitized_names = _collect_sanitized_names(code)

    for sink in _xpath_sinks(code):
        expression = str(sink["expression"]).strip()
        start = int(sink["start"])
        snippet = str(sink["code"])
        variables = _expression_variables(expression)
        expanded = _expand_expression(code, expression, start)
        expanded_variables = _expression_variables(expanded)

        if _uses_xpath_variable_resolver(code, expression, constants, start):
            return XPathInjectionFinding(
                "safe",
                start,
                snippet,
                "The XPath expression is fixed and externally supplied values are bound through an XPath variable resolver.",
            )
        if _is_fixed_expression(expression, constants) and not (
            variables & dynamic_names
        ):
            return XPathInjectionFinding(
                "safe",
                start,
                snippet,
                "The XPath sink uses a fixed expression that is not controlled by external input.",
            )
        if _uses_only_sanitized_values(
            expanded, expanded_variables, dynamic_names, sanitized_names
        ):
            return XPathInjectionFinding(
                "safe",
                start,
                snippet,
                "Externally supplied values are escaped before being inserted into the XPath expression.",
            )
        if _has_local_allowlist(code, start, expanded_variables & dynamic_names):
            return XPathInjectionFinding(
                "safe",
                start,
                snippet,
                "Externally supplied XPath values are restricted by a local allowlist before expression construction.",
            )
        if _uses_unresolved_validation_helper(
            code[max(0, start - 1400) : start], expanded_variables
        ):
            return XPathInjectionFinding(
                "ambiguous",
                start,
                snippet,
                "A validation helper precedes XPath evaluation, but its guarantees cannot be resolved locally.",
            )
        if (
            _contains_external_source(expanded)
            or expanded_variables & dynamic_names
            or _looks_dynamic_xpath_name(expanded_variables)
        ):
            return XPathInjectionFinding(
                "vulnerable",
                start,
                snippet,
                "Externally controlled input influences the structure of an XPath expression.",
            )
        if variables:
            return XPathInjectionFinding(
                "ambiguous",
                start,
                snippet,
                "A variable controls the XPath expression, but its provenance cannot be resolved locally.",
            )
    return None


def _xpath_sinks(code: str) -> List[Dict[str, object]]:
    sinks: List[Dict[str, object]] = []
    patterns = [
        re.compile(
            r"\.\s*evaluate\s*\(\s*(?P<expression>(?:\"(?:\\.|[^\"\\])*\"|"
            r"'(?:\\.|[^'\\])*'|[^,])+?)\s*,",
            re.I,
        ),
        re.compile(
            r"\.\s*compile\s*\(\s*(?P<expression>[^)]+?)\s*\)",
            re.I,
        ),
    ]
    for pattern in patterns:
        for match in pattern.finditer(code):
            sinks.append(
                {
                    "start": match.start(),
                    "code": match.group(0),
                    "expression": match.group("expression"),
                }
            )
    return sorted(sinks, key=lambda item: int(item["start"]))


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


def _collect_string_constants(code: str) -> Dict[str, str]:
    constants: Dict[str, str] = {}
    for match in re.finditer(
        rf"\b(?:final\s+)?String\s+(?P<name>{IDENTIFIER_PATTERN})\s*=\s*"
        r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')\s*;",
        code,
        re.I,
    ):
        constants[match.group("name")] = match.group("value")
    return constants


def _collect_dynamic_names(code: str, parameters: Set[str]) -> Set[str]:
    names = set(parameters)
    assignments = list(
        re.finditer(
            rf"(?<![@\w\[])(?P<target>{IDENTIFIER_PATTERN})\s*=\s*"
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
            if _contains_external_source(expression) or any(
                re.search(rf"\b{re.escape(name)}\b", expression) for name in names
            ):
                names.add(target)
                changed = True
    return names


def _collect_sanitized_names(code: str) -> Set[str]:
    return {
        match.group("target")
        for match in re.finditer(
            rf"\b(?:String\s+)?(?P<target>{IDENTIFIER_PATTERN})\s*=\s*"
            r"(?:StringEscapeUtils\s*\.\s*escapeXml(?:10|11)?|"
            r"escapeXPathLiteral|encodeForXPath)\s*\(",
            code,
            re.I,
        )
    }


def _expand_expression(code: str, expression: str, sink_start: int) -> str:
    variable = re.fullmatch(IDENTIFIER_PATTERN, expression.strip())
    if not variable:
        return expression
    name = re.escape(variable.group(0))
    assignments = list(
        re.finditer(
            rf"\b{name}\s*=\s*(?P<value>[^;]+)\s*;",
            code[:sink_start],
            re.I,
        )
    )
    return assignments[-1].group("value") if assignments else expression


def _is_fixed_expression(expression: str, constants: Dict[str, str]) -> bool:
    stripped = expression.strip()
    return bool(
        re.fullmatch(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", stripped)
        or stripped in constants
    )


def _expression_variables(expression: str) -> Set[str]:
    without_literals = re.sub(
        r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        "",
        expression,
    )
    return set(re.findall(IDENTIFIER_PATTERN, without_literals))


def _uses_xpath_variable_resolver(
    code: str, expression: str, constants: Dict[str, str], sink_start: int
) -> bool:
    prefix = code[:sink_start]
    if not re.search(r"\.\s*setXPathVariableResolver\s*\(", prefix, re.I):
        return False
    expanded = constants.get(expression.strip(), expression)
    return bool(re.search(r"\$[A-Za-z_]\w*", expanded))


def _uses_only_sanitized_values(
    expression: str,
    variables: Set[str],
    dynamic_names: Set[str],
    sanitized_names: Set[str],
) -> bool:
    dynamic_in_expression = variables & dynamic_names
    return bool(
        "+" in expression
        and dynamic_in_expression
        and dynamic_in_expression <= sanitized_names
    )


def _has_local_allowlist(
    code: str, sink_start: int, variables: Set[str]
) -> bool:
    prefix = code[max(0, sink_start - 1800) : sink_start]
    candidates = set(variables)
    for variable in variables:
        alias = re.search(
            rf"\b(?:String\s+)?{re.escape(variable)}\s*=\s*"
            rf"(?P<source>{IDENTIFIER_PATTERN})\s*;",
            prefix,
            re.I,
        )
        if alias:
            candidates.add(alias.group("source"))
    for variable in candidates:
        name = re.escape(variable)
        regex_guard = re.search(
            rf"!\s*{name}\s*\.\s*matches\s*\(\s*[^)]{{1,300}}\)"
            rf"[\s\S]{{0,180}}(?:throw\s+new|return\b)",
            prefix,
            re.I,
        )
        collection_guard = re.search(
            rf"!\s*(?:(?:java\s*\.\s*util\s*\.\s*)?(?:Set|List))"
            rf"\s*\.\s*of\s*\([^)]*\)\s*\.\s*contains\s*\(\s*{name}\s*\)"
            rf"[\s\S]{{0,180}}(?:throw\s+new|return\b)",
            prefix,
            re.I,
        )
        if regex_guard or collection_guard:
            return True
    return False


def _uses_unresolved_validation_helper(prefix: str, variables: Set[str]) -> bool:
    if not variables:
        return False
    names = "|".join(re.escape(name) for name in sorted(variables))
    direct_helper = re.search(
        rf"\b(?:validate|sanitize|escape|allow|check)(?:XPath|Query|Value)"
        rf"\w*\s*\([^;]*\b(?:{names})\b[^;]*\)",
        prefix,
        re.I,
    )
    assigned_helper = re.search(
        rf"\b(?:String\s+)?(?:{names})\s*=\s*"
        r"(?:validate|sanitize|escape|allow|check)(?:XPath|Query|Value)"
        r"\w*\s*\([^;]+\)\s*;",
        prefix,
        re.I,
    )
    return bool(direct_helper or assigned_helper)


def _contains_external_source(expression: str) -> bool:
    return bool(
        re.search(
            r"\b(?:getParameter|getHeader|getQueryString|getenv|getProperty|"
            r"readLine|nextLine)\s*\(",
            expression,
            re.I,
        )
    )


def _looks_dynamic_xpath_name(variables: Set[str]) -> bool:
    return any(
        re.fullmatch(
            r"(?:xpath|query|expression|predicate|filter|username|password|"
            r"name|value|role|department|category|identifier|id)",
            name,
            re.I,
        )
        for name in variables
    )
