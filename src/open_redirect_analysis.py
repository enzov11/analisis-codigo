import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass(frozen=True)
class OpenRedirectFinding:
    verdict: str
    start: int
    code: str
    rationale: str


IDENTIFIER_PATTERN = r"[A-Za-z_]\w*"


def analyze_open_redirect(code: str) -> Optional[OpenRedirectFinding]:
    parameters = _collect_method_parameters(code)
    constants = _collect_string_constants(code)
    dynamic_names = _collect_dynamic_names(code, parameters)
    findings: List[OpenRedirectFinding] = []

    for sink in _redirect_sinks(code):
        expression = str(sink["expression"]).strip()
        start = int(sink["start"])
        snippet = str(sink["code"])

        if _is_fixed_expression(expression, constants) and not (
            set(re.findall(IDENTIFIER_PATTERN, expression)) & dynamic_names
        ):
            findings.append(
                OpenRedirectFinding(
                    "safe",
                    start,
                    snippet,
                    "The redirect uses a fixed local destination.",
                )
            )
            continue
        if _has_fixed_destination_mapping(code, start):
            findings.append(
                OpenRedirectFinding(
                    "safe",
                    start,
                    snippet,
                    "The external selector is mapped to a closed set of fixed redirect paths.",
                )
            )
            continue
        if _has_relative_path_validation(code, start):
            findings.append(
                OpenRedirectFinding(
                    "safe",
                    start,
                    snippet,
                    "The redirect is restricted to a normalized relative path and rejects absolute or protocol-relative destinations.",
                )
            )
            continue
        if _has_trusted_origin_validation(code, start):
            findings.append(
                OpenRedirectFinding(
                    "safe",
                    start,
                    snippet,
                    "The redirect URI is restricted to an explicitly trusted scheme and host.",
                )
            )
            continue
        if _has_encoded_fixed_path(code, expression):
            findings.append(
                OpenRedirectFinding(
                    "safe",
                    start,
                    snippet,
                    "Untrusted data is encoded as a path component beneath a fixed local redirect path.",
                )
            )
            continue

        variables = set(re.findall(IDENTIFIER_PATTERN, expression))
        prefix = code[max(0, start - 1200) : start]
        if _uses_unresolved_redirect_helper(prefix, variables):
            findings.append(
                OpenRedirectFinding(
                    "ambiguous",
                    start,
                    snippet,
                    "A redirect validation helper is present, but its destination restrictions cannot be resolved locally.",
                )
            )
            continue
        if (
            variables & dynamic_names
            or _contains_external_source(expression)
            or _looks_dynamic_destination(variables)
            or _has_dynamic_redirect_assignment(code, expression, dynamic_names)
        ):
            findings.append(
                OpenRedirectFinding(
                    "vulnerable",
                    start,
                    snippet,
                    "Externally controlled input reaches a redirect sink without a local destination restriction.",
                )
            )
            continue
        if variables:
            findings.append(
                OpenRedirectFinding(
                    "ambiguous",
                    start,
                    snippet,
                    "A variable controls the redirect destination, but its provenance or validation cannot be resolved locally.",
                )
            )
    priority = {"vulnerable": 0, "ambiguous": 1, "safe": 2}
    return min(findings, key=lambda finding: priority[finding.verdict], default=None)


def _redirect_sinks(code: str) -> List[Dict[str, object]]:
    sinks: List[Dict[str, object]] = []
    patterns = [
        re.compile(
            r"\.\s*sendRedirect\s*\(\s*(?P<expression>[\s\S]*?)\s*\)\s*;",
            re.I,
        ),
        re.compile(
            r"\.\s*setHeader\s*\(\s*[\"']Location[\"']\s*,\s*"
            r"(?P<expression>[^;\n]+?)\s*\)\s*;",
            re.I,
        ),
        re.compile(
            r"\bnew\s+RedirectView\s*\(\s*(?P<expression>[^;\n]+?)\s*\)",
            re.I,
        ),
        re.compile(
            r"\breturn\s+[\"']redirect:[\"']\s*\+\s*"
            r"(?P<expression>[^;\n]+)\s*;",
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
            if _contains_external_source(expression) or any(
                re.search(rf"\b{re.escape(name)}\b", expression) for name in names
            ):
                names.add(target)
                changed = True
    return names


def _is_fixed_expression(expression: str, constants: Dict[str, str]) -> bool:
    stripped = expression.strip()
    return bool(
        re.fullmatch(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", stripped)
        or stripped in constants
    )


def _contains_external_source(expression: str) -> bool:
    return bool(
        re.search(
            r"\b(?:getParameter|getHeader|getQueryString|getCookies|getenv|"
            r"getProperty|readLine|nextLine)\s*\(",
            expression,
            re.I,
        )
    )


def _looks_dynamic_destination(variables: Set[str]) -> bool:
    return any(
        re.fullmatch(
            r"(?:url|uri|target|destination|redirect|redirectUrl|next|nextUrl|"
            r"returnTo|continueTo|callback|location|path)",
            name,
            re.I,
        )
        for name in variables
    )


def _has_dynamic_redirect_assignment(
    code: str, expression: str, dynamic_names: Set[str]
) -> bool:
    variable = re.fullmatch(IDENTIFIER_PATTERN, expression.strip())
    if not variable:
        return False
    name = re.escape(variable.group(0))
    assignment = re.search(
        rf"\b{name}\s*=\s*(?P<value>[^;\n]+)\s*;",
        code,
        re.I,
    )
    if not assignment:
        return False
    value = assignment.group("value")
    return _contains_external_source(value) or any(
        re.search(rf"\b{re.escape(dynamic)}\b", value) for dynamic in dynamic_names
    )


def _uses_unresolved_redirect_helper(prefix: str, variables: Set[str]) -> bool:
    if not variables:
        return False
    names = "|".join(re.escape(name) for name in sorted(variables))
    return bool(
        re.search(
            rf"\b(?:validate|check|allow|sanitize|resolve)(?:Redirect|Url|Uri|"
            rf"Destination|ReturnPath)\w*\s*\([^;]*\b(?:{names})\b[^;]*\)\s*;",
            prefix,
            re.I,
        )
    )


def _has_relative_path_validation(code: str, sink_start: int) -> bool:
    prefix = code[max(0, sink_start - 1500) : sink_start]
    method_region = code[max(0, sink_start - 1800) : sink_start + 600]
    uri_rejection = re.search(
        r"\bif\s*\([^)]*(?:\.isAbsolute\s*\(\s*\)|\.getHost\s*\(\s*\)\s*"
        r"!=\s*null)[^)]*\)[\s\S]{0,220}(?:throw\s+new|return\b)",
        prefix,
        re.I,
    )
    protocol_relative = re.search(
        r"\bif\s*\([^)]*\.startsWith\s*\(\s*[\"']//[\"']\s*\)[^)]*\)"
        r"[\s\S]{0,180}(?:throw\s+new|return\b)",
        prefix,
        re.I,
    )
    local_path = re.search(
        r"!\s*\w+\s*\.\s*startsWith\s*\(\s*[\"']/[\"']\s*\)"
        r"[\s\S]{0,180}(?:throw\s+new|return\b)",
        prefix,
        re.I,
    )
    structural_relative_check = all(
        (
            re.search(r"\.\s*normalize\s*\(\s*\)", method_region, re.I),
            re.search(r"\.\s*isAbsolute\s*\(\s*\)", method_region, re.I),
            re.search(
                r"\.\s*(?:getHost|getRawAuthority)\s*\(\s*\)",
                method_region,
                re.I,
            ),
            re.search(
                r"\.\s*startsWith\s*\(\s*[\"']//[\"']\s*\)",
                method_region,
                re.I,
            ),
            re.search(r"\b(?:if|switch)\b", prefix, re.I),
            re.search(r"throw\s+new", method_region, re.I),
        )
    )
    return bool(
        uri_rejection
        or (protocol_relative and local_path)
        or structural_relative_check
    )


def _has_trusted_origin_validation(code: str, sink_start: int) -> bool:
    prefix = code[max(0, sink_start - 1800) : sink_start]
    method_region = code[max(0, sink_start - 2200) : sink_start + 700]
    host_guard = re.search(
        r"!\s*[\"'][A-Za-z0-9.-]+[\"']\s*\.\s*equalsIgnoreCase\s*\("
        r"[^)]*\.getHost\s*\(\s*\)\s*\)"
        r"[\s\S]{0,220}(?:throw\s+new|return\b)",
        prefix,
        re.I,
    )
    host_set = re.search(
        r"!\s*(?:(?:java\s*\.\s*util\s*\.\s*)?Set)\s*\.\s*of\s*\([^)]*\)"
        r"\s*\.\s*contains\s*\([^)]*\.getHost\s*\(\s*\)\s*\)"
        r"[\s\S]{0,220}(?:throw\s+new|return\b)",
        prefix,
        re.I,
    )
    scheme_guard = re.search(
        r"!\s*[\"']https[\"']\s*\.\s*equalsIgnoreCase\s*\("
        r"[^)]*\.getScheme\s*\(\s*\)\s*\)",
        prefix,
        re.I,
    )
    structural_origin_check = all(
        (
            re.search(r"\.\s*getScheme\s*\(\s*\)", method_region, re.I),
            re.search(r"\.\s*getHost\s*\(\s*\)", method_region, re.I),
            re.search(r"[\"']https[\"']", method_region, re.I),
            re.search(
                r"[\"'][A-Za-z0-9.-]+\.[A-Za-z]{2,}[\"']",
                method_region,
                re.I,
            ),
            re.search(r"\b(?:if|switch)\b", method_region, re.I),
            re.search(r"throw\s+new", method_region, re.I),
        )
    )
    return bool((host_guard or host_set) and scheme_guard or structural_origin_check)


def _has_fixed_destination_mapping(code: str, sink_start: int) -> bool:
    prefix = code[max(0, sink_start - 1600) : sink_start]
    switch = re.search(
        rf"\bString\s+(?P<target>{IDENTIFIER_PATTERN})\s*=\s*"
        r"switch\s*\([^)]*\)\s*\{(?P<body>[\s\S]*?)\}\s*;",
        prefix,
        re.I,
    )
    if not switch:
        return False
    fixed_cases = re.findall(
        r"case\s+[\"'][^\"']+[\"']\s*->\s*[\"']/[^\"']*[\"']",
        switch.group("body"),
        re.I,
    )
    return len(fixed_cases) >= 2 and bool(
        re.search(r"default\s*->\s*throw\s+new", switch.group("body"), re.I)
    )


def _has_encoded_fixed_path(code: str, expression: str) -> bool:
    if "URLEncoder" not in code:
        return False
    return bool(
        re.search(
            r"[\"']/[^\"']*/[\"']\s*\+\s*"
            r"(?:URLEncoder\s*\.\s*encode\s*\(|\w+)",
            expression,
            re.I,
        )
        and re.search(r"\bURLEncoder\s*\.\s*encode\s*\(", code, re.I)
    )
