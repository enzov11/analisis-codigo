import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass(frozen=True)
class UnsafeReflectionFinding:
    verdict: str
    start: int
    code: str
    rationale: str


IDENTIFIER_PATTERN = r"[A-Za-z_]\w*"


def analyze_unsafe_reflection(code: str) -> Optional[UnsafeReflectionFinding]:
    registry = _find_fixed_class_registry(code)
    if registry:
        return UnsafeReflectionFinding(
            "safe",
            registry.start(),
            registry.group(0),
            "Reflective construction selects a class from a fixed local registry of class literals.",
        )

    class_switch = _find_fixed_class_switch(code)
    if class_switch:
        return UnsafeReflectionFinding(
            "safe",
            class_switch.start(),
            class_switch.group(0),
            "Reflective construction selects a class through a closed switch of class literals.",
        )

    string_switch = _find_fixed_string_switch(code)
    if string_switch:
        return UnsafeReflectionFinding(
            "safe",
            string_switch.start(),
            string_switch.group(0),
            "The external selector is mapped through a closed switch to fixed reflective target names.",
        )

    branch_mapping = _find_fixed_branch_mapping(code)
    if branch_mapping:
        return UnsafeReflectionFinding(
            "safe",
            branch_mapping.start(),
            branch_mapping.group(0),
            "The external selector is mapped through closed local branches to fixed reflective target names.",
        )

    parameters = _collect_method_parameters(code)
    constants = _collect_string_constants(code)
    dynamic_names = _collect_dynamic_names(code, parameters)

    for sink in _reflection_sinks(code):
        expression = str(sink["expression"]).strip()
        start = int(sink["start"])
        snippet = str(sink["code"])

        if _is_fixed_expression(expression, constants):
            return UnsafeReflectionFinding(
                "safe",
                start,
                snippet,
                "The reflective target is a fixed local string rather than externally controlled input.",
            )

        prefix = code[max(0, start - 1200) : start]
        variables = set(re.findall(IDENTIFIER_PATTERN, expression))
        if _has_explicit_allowlist(code, start, variables):
            return UnsafeReflectionFinding(
                "safe",
                start,
                snippet,
                "The reflective target is restricted by a local allowlist before resolution.",
            )
        if _uses_unresolved_reflection_helper(prefix, variables):
            return UnsafeReflectionFinding(
                "ambiguous",
                start,
                snippet,
                "A validation helper precedes reflection, but its allowlist guarantees cannot be resolved locally.",
            )
        if (
            variables & dynamic_names
            or _contains_external_source(expression)
            or _looks_dynamic_reflection_target(variables)
        ):
            return UnsafeReflectionFinding(
                "vulnerable",
                start,
                snippet,
                "Externally controlled input selects a class, method, or field through reflection.",
            )
        if variables:
            return UnsafeReflectionFinding(
                "ambiguous",
                start,
                snippet,
                "A variable selects a reflective target, but its provenance cannot be resolved locally.",
            )

    helper = re.search(
        r"\b(?:validate|check|allow|resolve)(?:Class|Type|Method|Field|Plugin)\w*\s*\(",
        code,
        re.I,
    )
    if helper and re.search(
        r"\b(?:Class\s*\.\s*forName|loadClass|getDeclaredMethod|getMethod|"
        r"getDeclaredField|getField)\s*\(",
        code,
        re.I,
    ):
        return UnsafeReflectionFinding(
            "ambiguous",
            helper.start(),
            helper.group(0),
            "Reflection uses an external helper whose target restrictions cannot be resolved locally.",
        )
    return None


def _reflection_sinks(code: str) -> List[Dict[str, object]]:
    sinks: List[Dict[str, object]] = []
    patterns = [
        re.compile(
            r"\bClass\s*\.\s*forName\s*\(\s*(?P<expression>[^),]+)",
            re.I,
        ),
        re.compile(
            r"\.\s*loadClass\s*\(\s*(?P<expression>[^),]+)",
            re.I,
        ),
        re.compile(
            r"\.\s*(?:getDeclaredMethod|getMethod|getDeclaredField|getField)\s*"
            r"\(\s*(?P<expression>[^),]+)",
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
            r"\b(?:getParameter|getHeader|getQueryString|getenv|getProperty|"
            r"readLine|nextLine)\s*\(",
            expression,
            re.I,
        )
    )


def _looks_dynamic_reflection_target(variables: Set[str]) -> bool:
    return any(
        re.fullmatch(
            r"(?:class|type|plugin|handler|provider|strategy|formatter|"
            r"serializer|method|field)(?:Name|Id|Key|Alias)?",
            name,
            re.I,
        )
        for name in variables
    )


def _has_explicit_allowlist(
    code: str, sink_start: int, variables: Set[str]
) -> bool:
    prefix = code[max(0, sink_start - 1600) : sink_start]
    suffix = code[sink_start : sink_start + 500]
    for variable in variables:
        name = re.escape(variable)
        set_guard = re.search(
            rf"!\s*(?:(?:java\s*\.\s*util\s*\.\s*)?(?:Set|List))"
            rf"\s*\.\s*of\s*\([^)]*\)\s*\.\s*contains\s*"
            rf"\(\s*{name}\s*\)[\s\S]{{0,180}}(?:throw\s+new|return\b)",
            prefix,
            re.I,
        )
        if set_guard:
            return True
        for declaration in re.finditer(
            rf"\b(?:Set|List)\s*<[^>]+>\s+(?P<collection>{IDENTIFIER_PATTERN})"
            rf"\s*=\s*(?:(?:java\s*\.\s*util\s*\.\s*)?(?:Set|List))"
            rf"\s*\.\s*of\s*\([^)]*\)\s*;",
            prefix,
            re.I,
        ):
            collection = re.escape(declaration.group("collection"))
            guard = re.search(
                rf"!\s*{collection}\s*\.\s*contains\s*\(\s*{name}\s*\)"
                rf"[\s\S]{{0,180}}(?:throw\s+new|return\b)",
                prefix[declaration.end() :],
                re.I,
            )
            if guard:
                return True
            boolean_guard = re.search(
                rf"\bboolean\s+(?P<result>{IDENTIFIER_PATTERN})\s*=\s*"
                rf"{collection}\s*\.\s*contains\s*\(\s*{name}\s*\)\s*;",
                prefix[declaration.end() :],
                re.I,
            )
            if boolean_guard:
                result = re.escape(boolean_guard.group("result"))
                if re.search(
                    rf"\bif\s*\(\s*!\s*{result}\s*\)"
                    rf"[\s\S]{{0,180}}(?:throw\s+new|return\b)",
                    prefix[declaration.end() + boolean_guard.end() :],
                    re.I,
                ):
                    return True
            positive_guard = re.search(
                rf"\bif\s*\(\s*{collection}\s*\.\s*contains\s*"
                rf"\(\s*{name}\s*\)\s*\)\s*\{{",
                prefix[declaration.end() :],
                re.I,
            )
            if positive_guard and re.search(
                r"\}[\s\S]{0,120}throw\s+new",
                suffix,
                re.I,
            ):
                return True
            stream_rejection = re.search(
                rf"\bif\s*\(\s*{collection}\s*\.\s*stream\s*\(\s*\)"
                rf"\s*\.\s*noneMatch\s*\(\s*{name}\s*::\s*equals\s*\)\s*\)"
                rf"[\s\S]{{0,180}}(?:throw\s+new|return\b)",
                prefix[declaration.end() :],
                re.I,
            )
            if stream_rejection:
                return True
    return False


def _uses_unresolved_reflection_helper(prefix: str, variables: Set[str]) -> bool:
    if not variables:
        return False
    names = "|".join(re.escape(name) for name in sorted(variables))
    return bool(
        re.search(
            rf"\b(?:validate|check|allow|resolve)(?:Class|Type|Method|Field|Plugin)\w*"
            rf"\s*\([^;]*\b(?:{names})\b[^;]*\)\s*;",
            prefix,
            re.I,
        )
    )


def _find_fixed_class_registry(code: str) -> Optional[re.Match]:
    registry = re.search(
        r"\bMap\s*<\s*String\s*,\s*Class(?:\s*<[^>]*>)?\s*>\s+\w+\s*="
        r"\s*Map\s*\.\s*of(?:Entries)?\s*\([\s\S]*?\.class[\s\S]*?\)\s*;",
        code,
        re.I,
    )
    if not registry:
        return None
    if re.search(
        r"\.\s*get\s*\([^)]*\)[\s\S]{0,500}"
        r"(?:getDeclaredConstructor|getConstructor)\s*\([^)]*\)"
        r"[\s\S]{0,120}\.\s*newInstance\s*\(",
        code[registry.start() :],
        re.I,
    ):
        return registry
    return None


def _find_fixed_class_switch(code: str) -> Optional[re.Match]:
    switch = re.search(
        r"\bswitch\s*\([^)]*\)\s*\{[\s\S]*?"
        r"(?:case\s+[\"'][^\"']+[\"']\s*(?:->|:)\s*\w+\s*\.class[\s\S]*?){2,}"
        r"\}",
        code,
        re.I,
    )
    if switch and re.search(
        r"(?:getDeclaredConstructor|getConstructor)\s*\([^)]*\)"
        r"[\s\S]{0,120}\.\s*newInstance\s*\(",
        code[switch.end() :],
        re.I,
    ):
        return switch
    return None


def _find_fixed_string_switch(code: str) -> Optional[re.Match]:
    switch = re.search(
        rf"\bString\s+(?P<target>{IDENTIFIER_PATTERN})\s*=\s*"
        r"switch\s*\([^)]*\)\s*\{(?P<body>[\s\S]*?)\}\s*;",
        code,
        re.I,
    )
    if not switch:
        switch = re.search(
            rf"\b(?:final\s+)?String\s+(?P<target>{IDENTIFIER_PATTERN})\s*;"
            rf"[\s\S]{{0,120}}\b(?P=target)\s*=\s*"
            r"switch\s*\([^)]*\)\s*\{(?P<body>[\s\S]*?)\}\s*;",
            code,
            re.I,
        )
    if not switch:
        return None
    fixed_cases = re.findall(
        r"case\s+[\"'][^\"']+[\"']\s*->\s*[\"'][^\"']+[\"']",
        switch.group("body"),
        re.I,
    )
    if len(fixed_cases) < 2 or not re.search(
        r"default\s*->\s*throw\s+new",
        switch.group("body"),
        re.I,
    ):
        return None
    target = re.escape(switch.group("target"))
    if re.search(
        rf"(?:Class\s*\.\s*forName|loadClass|getDeclaredMethod|getMethod|"
        rf"getDeclaredField|getField)\s*\(\s*{target}\b",
        code[switch.end() :],
        re.I,
    ):
        return switch
    return None


def _find_fixed_branch_mapping(code: str) -> Optional[re.Match]:
    declaration = re.search(
        rf"\bString\s+(?P<target>{IDENTIFIER_PATTERN})\s*;",
        code,
        re.I,
    )
    if not declaration:
        return None
    target_name = declaration.group("target")
    target = re.escape(target_name)
    assignments = list(
        re.finditer(
            rf"\b{target}\s*=\s*[\"'][^\"']+[\"']\s*;",
            code[declaration.end() :],
            re.I,
        )
    )
    if len(assignments) < 2:
        return None
    last_assignment_end = declaration.end() + assignments[-1].end()
    mapping_region = code[declaration.start() : last_assignment_end + 240]
    if not re.search(
        r"(?:\belse\b|default\s*:)[\s\S]{0,120}throw\s+new",
        mapping_region,
        re.I,
    ):
        return None
    if re.search(
        rf"(?:Class\s*\.\s*forName|loadClass|getDeclaredMethod|getMethod|"
        rf"getDeclaredField|getField)\s*\(\s*{target}\b",
        code[last_assignment_end:],
        re.I,
    ):
        return declaration
    return None
