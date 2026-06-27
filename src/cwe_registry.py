import re
from dataclasses import dataclass
from typing import Callable, Dict, List

from array_index_analysis import analyze_array_index
from http_response_splitting_analysis import analyze_http_response_splitting
from sql_analysis import analyze_sql
from path_traversal_analysis import analyze_path_traversal
from xss_analysis import analyze_xss


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


def assess_cwe80(code: str) -> OracleAssessment:
    finding = analyze_xss(code)
    if finding:
        return OracleAssessment("CWE80", finding.verdict, [finding.code], finding.rationale)
    return OracleAssessment(
        "CWE80",
        "ambiguous",
        [],
        "No conclusive cross-site scripting evidence was found; manual review is required.",
    )


def assess_cwe113(code: str) -> OracleAssessment:
    finding = analyze_http_response_splitting(code)
    if finding:
        return OracleAssessment("CWE113", finding.verdict, [finding.code], finding.rationale)
    return OracleAssessment(
        "CWE113",
        "ambiguous",
        [],
        "No conclusive HTTP response splitting evidence was found; manual review is required.",
    )


def assess_cwe129(code: str) -> OracleAssessment:
    finding = analyze_array_index(code)
    if finding:
        return OracleAssessment("CWE129", finding.verdict, [finding.code], finding.rationale)
    return OracleAssessment(
        "CWE129",
        "ambiguous",
        [],
        "No conclusive array index validation evidence was found; manual review is required.",
    )


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


def _pending_assessor(cwe_id: str) -> Callable[[str], OracleAssessment]:
    def assess_pending_cwe(code: str) -> OracleAssessment:
        return OracleAssessment(
            cwe_id,
            "ambiguous",
            [],
            "No structural oracle is implemented for this CWE yet; rely on the neural score and manual review until the category-specific heuristic is added.",
        )

    return assess_pending_cwe


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
    "CWE80": CWERegistration(
        cwe_id="CWE80",
        name="Cross-Site Scripting",
        description="Untrusted input is emitted into HTML output without context-appropriate escaping.",
        mitigation="HTML-escape untrusted values before including them in responses or templates, using a context-aware encoder.",
        assessor=assess_cwe80,
    ),
    "CWE113": CWERegistration(
        cwe_id="CWE113",
        name="HTTP Response Splitting",
        description="Untrusted input influences HTTP headers, redirects, cookies, or content-type values without CRLF protection.",
        mitigation="Reject or remove carriage returns and line feeds before writing response headers, and prefer allowlisted or encoded header values.",
        assessor=assess_cwe113,
    ),
    "CWE129": CWERegistration(
        cwe_id="CWE129",
        name="Improper Validation of Array Index",
        description="Untrusted input controls an array, list, or string index without a bounds check.",
        mitigation="Validate that the index is non-negative and below the target length or size before indexed access, or use a checked index helper.",
        assessor=assess_cwe129,
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
    "CWE134": CWERegistration(
        cwe_id="CWE134",
        name="Uncontrolled Format String",
        description="Untrusted input controls a format string or formatting operation.",
        mitigation="Use fixed format strings and pass untrusted values only as formatting arguments after validation.",
        assessor=_pending_assessor("CWE134"),
        heuristic_supported=False,
    ),
    "CWE190": CWERegistration(
        cwe_id="CWE190",
        name="Integer Overflow",
        description="Arithmetic on externally controlled numeric values may overflow before validation or allocation.",
        mitigation="Validate numeric bounds before arithmetic and use checked operations such as Math.addExact when overflow must be detected.",
        assessor=_pending_assessor("CWE190"),
        heuristic_supported=False,
    ),
    "CWE319": CWERegistration(
        cwe_id="CWE319",
        name="Cleartext Transmission of Sensitive Information",
        description="Sensitive data is transmitted over a channel that does not provide transport encryption.",
        mitigation="Use TLS-protected protocols and reject plaintext endpoints for sensitive values.",
        assessor=_pending_assessor("CWE319"),
        heuristic_supported=False,
    ),
    "CWE400": CWERegistration(
        cwe_id="CWE400",
        name="Resource Exhaustion",
        description="Untrusted input controls resource allocation, loop bounds, collection growth, or expensive processing.",
        mitigation="Apply quotas, maximum sizes, timeouts, and bounded iteration before consuming resources.",
        assessor=_pending_assessor("CWE400"),
        heuristic_supported=False,
    ),
    "CWE470": CWERegistration(
        cwe_id="CWE470",
        name="Unsafe Reflection",
        description="Untrusted input controls reflective class, method, constructor, or field resolution.",
        mitigation="Use an allowlist of permitted reflective targets and avoid resolving classes or members directly from user input.",
        assessor=_pending_assessor("CWE470"),
        heuristic_supported=False,
    ),
    "CWE601": CWERegistration(
        cwe_id="CWE601",
        name="Open Redirect",
        description="Untrusted input controls the destination of a redirect or forwarding operation.",
        mitigation="Allow only relative redirects or validate targets against a strict allowlist of trusted hosts.",
        assessor=_pending_assessor("CWE601"),
        heuristic_supported=False,
    ),
    "CWE643": CWERegistration(
        cwe_id="CWE643",
        name="XPath Injection",
        description="Untrusted input influences the structure of an XPath expression.",
        mitigation="Bind untrusted values through XPath variables or validate them against strict allowlists before expression construction.",
        assessor=_pending_assessor("CWE643"),
        heuristic_supported=False,
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
