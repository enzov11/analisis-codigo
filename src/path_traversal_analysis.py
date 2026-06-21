import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PathTraversalFinding:
    cwe_id: str
    verdict: str
    code: str
    start: int
    rationale: str


_IDENTIFIER = r"[A-Za-z_]\w*"


def analyze_path_traversal(code: str, cwe_id: str) -> Optional[PathTraversalFinding]:
    sink = _find_path_sink(code, cwe_id)
    if not sink:
        return None

    snippet = sink.group(0)
    argument = _sink_argument(snippet)
    if _has_local_safe_path_mitigation(code, cwe_id):
        return PathTraversalFinding(
            cwe_id,
            "safe",
            snippet,
            sink.start(),
            "The path is constrained by local normalization, base-directory checks, or explicit traversal validation.",
        )
    if _is_hardcoded_path(code, argument):
        return PathTraversalFinding(
            cwe_id,
            "safe",
            snippet,
            sink.start(),
            "The file operation uses a locally hardcoded path value.",
        )
    if _has_unresolved_validation_helper(code):
        return PathTraversalFinding(
            cwe_id,
            "ambiguous",
            snippet,
            sink.start(),
            "A file path reaches a sensitive sink, but validation is delegated to a helper that is not locally resolved.",
        )
    if cwe_id == "CWE23" and _looks_like_relative_traversal_sink(snippet, argument):
        return PathTraversalFinding(
            cwe_id,
            "vulnerable",
            snippet,
            sink.start(),
            "A dynamic relative path or filename is combined with a filesystem base without a local containment check.",
        )
    if cwe_id == "CWE36" and _looks_like_absolute_traversal_sink(snippet, argument):
        return PathTraversalFinding(
            cwe_id,
            "vulnerable",
            snippet,
            sink.start(),
            "A dynamic path value is used directly as a filesystem path without rejecting absolute paths or constraining it to a safe base.",
        )

    return PathTraversalFinding(
        cwe_id,
        "ambiguous",
        snippet,
        sink.start(),
        "A filesystem sink receives a path value whose local provenance cannot be classified conclusively.",
    )


def _find_path_sink(code: str, cwe_id: str):
    patterns = []
    if cwe_id == "CWE23":
        patterns.extend(
            [
                r"new\s+File\s*\(\s*[^;\n)]*\+[^;\n)]*\)",
                r"new\s+File\s*\(\s*[^,\n)]+,\s*[^;\n)]+\)",
                r"\.\s*resolve\s*\(\s*[^;\n)]+\)",
            ]
        )
    if cwe_id == "CWE36":
        patterns.extend(
            [
                r"new\s+File\s*\(\s*[^,\n)]*\)",
                r"new\s+FileInputStream\s*\(\s*[^;\n)]+\)",
                r"new\s+FileReader\s*\(\s*[^;\n)]+\)",
                r"Paths\s*\.\s*get\s*\(\s*[^;\n)]+\)",
            ]
        )
    patterns.extend(
        [
            r"Files\s*\.\s*(?:read\w*|write\w*|newInputStream|newOutputStream|copy|delete)\s*\([^;\n]+",
        ]
    )
    for pattern in patterns:
        match = re.search(pattern, code, re.I | re.S)
        if match:
            return match
    return None


def _sink_argument(snippet: str) -> str:
    match = re.search(r"\((.*)\)", snippet, re.S)
    return match.group(1).strip() if match else snippet


def _has_local_safe_path_mitigation(code: str, cwe_id: str) -> bool:
    common_safe = [
        r"\.normalize\s*\(\s*\)",
        r"\.toRealPath\s*\(",
        r"\.startsWith\s*\(",
        r"\.getCanonicalPath\s*\(\s*\)",
        r"\.getCanonicalFile\s*\(\s*\)",
        r"(?:allowlist|allowed\w*|isAllowed\w*)",
        r"\.matches\s*\(\s*\"[^\"]+\"\s*\)",
    ]
    relative_safe = [
        r"\.contains\s*\(\s*\"(?:\.\.|\\.\\.)\"\s*\)",
        r"\.indexOf\s*\(\s*\"(?:\.\.|\\.\\.)\"\s*\)",
        r"\.replace\s*\(\s*\"(?:\.\.|\\.\\.)\"",
    ]
    absolute_safe = [
        r"\.isAbsolute\s*\(\s*\)",
        r"!?\s*Paths\s*\.\s*get\s*\([^;\n]+\)\s*\.isAbsolute\s*\(\s*\)",
    ]
    selected = common_safe + (relative_safe if cwe_id == "CWE23" else absolute_safe)
    return any(re.search(pattern, code, re.I) for pattern in selected)


def _has_unresolved_validation_helper(code: str) -> bool:
    return bool(
        re.search(
            r"\b(?:validate|sanitize|clean|check|safe|canonicalize)\w*\s*\(",
            code,
            re.I,
        )
    )


def _is_hardcoded_path(code: str, argument: str) -> bool:
    parts = [part.strip() for part in argument.split(",")]
    if parts and all(_is_literal(part) for part in parts):
        return True
    if len(parts) == 1 and re.fullmatch(_IDENTIFIER, parts[0]):
        assignment = re.search(
            rf"\b(?:String|Path|File)\s+{re.escape(parts[0])}\s*=\s*([\"'][^\"']*[\"'])\s*;",
            code,
            re.I,
        )
        return bool(assignment)
    return False


def _is_literal(value: str) -> bool:
    return bool(re.fullmatch(r"[\"'][^\"']*[\"']", value.strip()))


def _looks_like_relative_traversal_sink(snippet: str, argument: str) -> bool:
    if ".." in argument:
        return True
    if "," in argument:
        return True
    if "+" in argument:
        return True
    return bool(re.search(r"\.\s*resolve\s*\(\s*(?![\"'])", snippet, re.I))


def _looks_like_absolute_traversal_sink(snippet: str, argument: str) -> bool:
    if _is_literal(argument):
        return False
    if re.search(r"\b(?:path|input|data|user|request|parameter)\w*\b", argument, re.I):
        return True
    return bool(re.search(r"Paths\s*\.\s*get\s*\(\s*(?![\"'])", snippet, re.I))
