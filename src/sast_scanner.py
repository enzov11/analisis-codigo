import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, TYPE_CHECKING

from cwe_registry import CWE_REGISTRY

if TYPE_CHECKING:
    from predictor import VulnerabilityPredictor


TOOL_NAME = "CodeScan-AI"
SARIF_VERSION = "2.1.0"


def discover_java_files(targets: Iterable[Path]) -> List[Path]:
    files: List[Path] = []
    for target in targets:
        if target.is_file() and target.suffix == ".java":
            files.append(target)
        elif target.is_dir():
            files.extend(path for path in target.rglob("*.java") if path.is_file())
        elif not target.exists():
            raise FileNotFoundError(f"Scan target not found: {target}")
    return sorted(set(files), key=lambda path: str(path))


def scan_targets(
    targets: Iterable[Path],
    predictor: Optional["VulnerabilityPredictor"] = None,
    fusion_config_path: Optional[Path] = None,
    base_dir: Optional[Path] = None,
) -> Dict[str, object]:
    selected_targets = [Path(target) for target in targets]
    if not selected_targets:
        raise ValueError("At least one scan target is required.")

    root = (base_dir or Path.cwd()).resolve()
    java_files = discover_java_files(selected_targets)
    if predictor is None:
        from predictor import VulnerabilityPredictor

        selected_predictor = VulnerabilityPredictor(fusion_config_path=fusion_config_path)
    else:
        selected_predictor = predictor

    file_results = []
    findings = []
    for java_file in java_files:
        code = java_file.read_text(encoding="utf-8")
        analysis = selected_predictor.analyze_code(code)
        file_path = _display_path(java_file, root)
        file_findings = _findings_from_analysis(file_path, analysis)
        file_results.append(
            {
                "file": file_path,
                "decision": analysis["decision"],
                "selected_cwe": analysis["selected_cwe"],
                "vulnerability_probability": analysis["vulnerability_probability"],
                "threshold": analysis["threshold"],
                "findings": file_findings,
            }
        )
        findings.extend(file_findings)

    return {
        "tool": TOOL_NAME,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "files_scanned": len(java_files),
            "findings": len(findings),
            "vulnerable": sum(1 for item in findings if item["decision"] == "vulnerable"),
            "review_required": sum(
                1 for item in findings if item["decision"] == "review_required"
            ),
        },
        "results": file_results,
        "findings": findings,
    }


def render_report(report: Dict[str, object], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report, indent=2)
    if output_format == "sarif":
        return json.dumps(to_sarif(report), indent=2)
    raise ValueError(f"Unsupported output format: {output_format}")


def write_or_print_report(report_text: str, output_path: Optional[Path]):
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_text + "\n", encoding="utf-8")
    else:
        print(report_text)


def should_fail(report: Dict[str, object], fail_on: str) -> bool:
    summary = report["summary"]
    if fail_on == "never":
        return False
    if fail_on == "review_required":
        return bool(summary["vulnerable"] or summary["review_required"])
    if fail_on == "vulnerable":
        return bool(summary["vulnerable"])
    raise ValueError(f"Unsupported fail policy: {fail_on}")


def to_sarif(report: Dict[str, object]) -> Dict[str, object]:
    findings = report["findings"]
    rules = {}
    for finding in findings:
        rule_id = finding["rule_id"]
        cwe_id = finding.get("cwe_id")
        rule_name = cwe_id or rule_id
        registry_entry = CWE_REGISTRY.get(cwe_id or "")
        description = (
            registry_entry.description
            if registry_entry
            else "CodeScan-AI security finding."
        )
        rules[rule_id] = {
            "id": rule_id,
            "name": rule_name,
            "shortDescription": {"text": description},
            "help": {"text": finding.get("suggested_fix") or description},
            "properties": {
                "tags": [value for value in ["security", cwe_id] if value],
                "precision": "medium",
            },
        }

    return {
        "version": SARIF_VERSION,
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": "https://github.com/",
                        "rules": list(rules.values()),
                    }
                },
                "results": [_sarif_result(finding) for finding in findings],
                "properties": {
                    "summary": report["summary"],
                    "generated_at": report["generated_at"],
                },
            }
        ],
    }


def _findings_from_analysis(file_path: str, analysis: Dict[str, object]) -> List[Dict[str, object]]:
    decision = analysis["decision"]
    if decision == "safe":
        return []

    evidence_key = "heuristic_evidence" if decision == "vulnerable" else "ambiguous_evidence"
    evidence_items = analysis.get(evidence_key) or []
    if not evidence_items:
        evidence_items = [
            {
                "line_number": 1,
                "code": "",
                "description": analysis["decision_reason"],
                "cwe_id": analysis["selected_cwe"],
                "suggested_fix": "",
                "confidence": analysis["vulnerability_probability"],
                "pattern_name": "hybrid_decision",
            }
        ]

    findings = []
    for evidence in evidence_items:
        cwe_id = evidence.get("cwe_id") or analysis.get("selected_cwe")
        line_number = int(evidence.get("line_number") or 1)
        severity = _severity_for(decision, cwe_id)
        rule_id = cwe_id or "CODESCAN-AI"
        findings.append(
            {
                "file": file_path,
                "line": line_number,
                "end_line": line_number,
                "column": 1,
                "rule_id": rule_id,
                "cwe_id": cwe_id,
                "decision": decision,
                "severity": severity,
                "confidence": float(evidence.get("confidence", 0.0)),
                "message": evidence.get("description") or analysis["decision_reason"],
                "code": evidence.get("code", ""),
                "suggested_fix": evidence.get("suggested_fix", ""),
                "pattern_name": evidence.get("pattern_name", "hybrid_decision"),
                "fusion_probability": analysis["vulnerability_probability"],
                "threshold": analysis["threshold"],
            }
        )
    return findings


def _sarif_result(finding: Dict[str, object]) -> Dict[str, object]:
    return {
        "ruleId": finding["rule_id"],
        "level": _sarif_level(finding["decision"], finding["severity"]),
        "message": {"text": finding["message"]},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding["file"]},
                    "region": {
                        "startLine": finding["line"],
                        "startColumn": finding["column"],
                    },
                }
            }
        ],
        "properties": {
            "cwe_id": finding.get("cwe_id"),
            "decision": finding["decision"],
            "severity": finding["severity"],
            "confidence": finding["confidence"],
            "fusion_probability": finding["fusion_probability"],
            "threshold": finding["threshold"],
            "suggested_fix": finding.get("suggested_fix", ""),
            "pattern_name": finding.get("pattern_name", ""),
        },
    }


def _sarif_level(decision: str, severity: str) -> str:
    if decision == "review_required":
        return "warning"
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _severity_for(decision: str, cwe_id: Optional[str]) -> str:
    if decision == "review_required":
        return "medium"
    high_risk = {
        "CWE78",
        "CWE80",
        "CWE89",
        "CWE90",
        "CWE113",
        "CWE319",
        "CWE470",
        "CWE601",
        "CWE643",
    }
    return "high" if cwe_id in high_risk else "medium"


def _display_path(path: Path, root: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        return resolved.as_posix()
