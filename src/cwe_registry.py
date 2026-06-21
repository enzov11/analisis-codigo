import re
from dataclasses import dataclass
from typing import Callable, Dict, List

from sql_analysis import analyze_sql
from path_traversal_analysis import analyze_path_traversal


@dataclass
class OracleAssessment:
    cwe_id: str
    verdict: str
    evidence: List[str]
    rationale: str


@dataclass(frozen=True)
class CWERegistration:
    cwe_id: str
    name: str
    description: str
    mitigation: str
    assessor: Callable[[str], OracleAssessment]
    neural_supported: bool = True
    heuristic_supported: bool = True


def _assess_patterns(
    code: str,
    cwe_id: str,
    unsafe_patterns: List[str],
    safe_patterns: List[str],
) -> OracleAssessment:
    unsafe_hits = [pattern for pattern in unsafe_patterns if re.search(pattern, code, re.I)]
    safe_hits = [pattern for pattern in safe_patterns if re.search(pattern, code, re.I)]
    if unsafe_hits and not safe_hits:
        return OracleAssessment(
            cwe_id,
            "vulnerable",
            unsafe_hits,
            "A security-sensitive operation appears to receive untrusted or concatenated data.",
        )
    if safe_hits and not unsafe_hits:
        return OracleAssessment(
            cwe_id,
            "safe",
            safe_hits,
            "A recognized validation, escaping, or fixed-argument construction is present.",
        )
    return OracleAssessment(
        cwe_id,
        "ambiguous",
        unsafe_hits + safe_hits,
        "Structural evidence alone is insufficient; manual review is required.",
    )


def assess_cwe78(code: str) -> OracleAssessment:
    unsafe_patterns = [
        r"Runtime\.getRuntime\(\)\.exec\s*\(\s*(?:\w+|[^)]*\+)",
        r"new\s+ProcessBuilder\s*\([^)]*(?:\+|user|input|argument|command)",
    ]
    safe_patterns = [
        r"(?:allowlist|allowed\w*|isAllowed\w*|validate\w*|SAFE_\w+|\.matches\s*\(|matcher\s*\([^)]*\)\.matches\s*\(|\.normalize\s*\(|InetAddress\.getByName\s*\(|IDN\.toASCII\s*\()",
        r"new\s+ProcessBuilder\s*\(\s*\"[^\"]+\"\s*(?:,\s*\"[^\"]*\"\s*)*\)",
    ]
    assessment = _assess_patterns(code, "CWE78", unsafe_patterns, safe_patterns)
    validated_process = (
        re.search(r"new\s+ProcessBuilder\s*\(", code)
        and any(re.search(pattern, code, re.I) for pattern in safe_patterns)
        and not re.search(r"Runtime\.getRuntime\(\)\.exec\s*\(", code)
    )
    if validated_process:
        return OracleAssessment(
            "CWE78",
            "safe",
            ["Validated arguments passed through ProcessBuilder without a command shell."],
            "The command uses validated arguments without dynamic shell construction.",
        )
    return assessment


def assess_cwe23(code: str) -> OracleAssessment:
    finding = analyze_path_traversal(code, "CWE23")
    if finding:
        return OracleAssessment("CWE23", finding.verdict, [finding.code], finding.rationale)
    return OracleAssessment(
        "CWE23",
        "ambiguous",
        [],
        "No conclusive relative path traversal evidence was found; manual review is required.",
    )


def assess_cwe36(code: str) -> OracleAssessment:
    finding = analyze_path_traversal(code, "CWE36")
    if finding:
        return OracleAssessment("CWE36", finding.verdict, [finding.code], finding.rationale)
    return OracleAssessment(
        "CWE36",
        "ambiguous",
        [],
        "No conclusive absolute path traversal evidence was found; manual review is required.",
    )


def assess_cwe89(code: str) -> OracleAssessment:
    finding = analyze_sql(code)
    if finding:
        return OracleAssessment("CWE89", finding.verdict, [finding.code], finding.rationale)
    return OracleAssessment(
        "CWE89",
        "ambiguous",
        [],
        "No conclusive SQL execution evidence was found; manual review is required.",
    )


def assess_cwe90(code: str) -> OracleAssessment:
    unsafe_patterns = [
        r"(?:filter|query)\w*\s*=\s*[^;\n]*\+[^;\n]*;",
        r"\.search\s*\(\s*[^,\n]+,\s*[^,\n]*\+[^,\n]*,",
        r"\.search\s*\([^;\n]*,\s*[\"'][^\"'\n]*=[^\"'\n]*[\"']\s*\+\s*",
    ]
    safe_patterns = [
        r"(?:escape\w*|encodeForLDAP\w*|LdapEncoder\w*)",
        r"(?:allowlist|whitelist|validateLdap|validateFilter)",
        r"\.search\s*\([^;\n]*[\"'][^\"']*\{0\}[^\"']*[\"']\s*,\s*new\s+Object\s*\[\s*\]",
    ]
    assessment = _assess_patterns(code, "CWE90", unsafe_patterns, safe_patterns)
    escaped_filter = re.search(
        r"(?:filter|query)\w*\s*=\s*[^;\n]*"
        r"(?:escape\w*|encodeForLDAP\w*|LdapEncoder\w*)"
        r"\s*\([^;\n]*;",
        code,
        re.I,
    )
    if escaped_filter:
        return OracleAssessment(
            "CWE90",
            "safe",
            [escaped_filter.group(0)],
            "The value inserted into the LDAP filter is explicitly escaped.",
        )
    parameterized_filter = re.search(
        r"\.search\s*\([^;\n]*[\"'][^\"']*\{0\}[^\"']*[\"']\s*,\s*new\s+Object\s*\[\s*\]",
        code,
        re.I,
    )
    if parameterized_filter:
        return OracleAssessment(
            "CWE90",
            "safe",
            [parameterized_filter.group(0)],
            "The LDAP search uses a parameterized filter expression.",
        )
    return assessment


CWE_REGISTRY: Dict[str, CWERegistration] = {
    "CWE23": CWERegistration(
        cwe_id="CWE23",
        name="Relative Path Traversal",
        description="Untrusted input controls a relative path or filename used below a filesystem base.",
        mitigation="Resolve paths against a fixed base, normalize them, and require the result to remain inside the allowed directory.",
        assessor=assess_cwe23,
    ),
    "CWE36": CWERegistration(
        cwe_id="CWE36",
        name="Absolute Path Traversal",
        description="Untrusted input controls an absolute filesystem path.",
        mitigation="Reject absolute paths from untrusted input and constrain resolved paths to an allowed base directory.",
        assessor=assess_cwe36,
    ),
    "CWE78": CWERegistration(
        cwe_id="CWE78",
        name="OS Command Injection",
        description="Untrusted input influences an operating-system command.",
        mitigation="Use fixed ProcessBuilder arguments and validate externally supplied values.",
        assessor=assess_cwe78,
    ),
    "CWE89": CWERegistration(
        cwe_id="CWE89",
        name="SQL Injection",
        description="Untrusted input influences the structure of an SQL command.",
        mitigation="Use PreparedStatement placeholders and bind every externally supplied value.",
        assessor=assess_cwe89,
    ),
    "CWE90": CWERegistration(
        cwe_id="CWE90",
        name="LDAP Injection",
        description="Untrusted input influences the structure of an LDAP filter.",
        mitigation="Escape or parameterize externally supplied LDAP filter values.",
        assessor=assess_cwe90,
    ),
}


def assess_code(code: str, cwe_id: str) -> OracleAssessment:
    registration = CWE_REGISTRY.get(cwe_id)
    if registration is None:
        raise ValueError(f"Unsupported CWE oracle: {cwe_id}")
    return registration.assessor(code)


def supported_cwe_ids() -> set:
    return set(CWE_REGISTRY)


def training_cwe_descriptions(cwe_ids=None) -> Dict[str, str]:
    selected = set(cwe_ids) if cwe_ids is not None else set(CWE_REGISTRY)
    return {
        cwe_id: registration.name
        for cwe_id, registration in CWE_REGISTRY.items()
        if registration.neural_supported and cwe_id in selected
    }
