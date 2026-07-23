#!/usr/bin/env python3
"""Run a SpotBugs baseline over the external CWE89 holdout.

The script materializes each JSONL sample as an isolated Java class, compiles the
classes, runs SpotBugs, and maps SQL-related bug patterns back to sample IDs.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


SQL_BUG_PATTERNS = {
    "SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE",
    "SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare SpotBugs against the CWE89 large external holdout."
    )
    parser.add_argument(
        "--input",
        default="ai_benchmark/cwe89_large_holdout_samples.jsonl",
        help="Reviewed JSONL holdout samples.",
    )
    parser.add_argument(
        "--output",
        default="ai_benchmark/spotbugs_cwe89_large_holdout_summary.json",
        help="Output JSON summary.",
    )
    parser.add_argument(
        "--work-dir",
        default="",
        help="Optional directory for generated sources/classes/reports.",
    )
    parser.add_argument(
        "--spotbugs-cmd",
        default="spotbugs",
        help="SpotBugs executable or path to bin/spotbugs.",
    )
    parser.add_argument(
        "--keep-work-dir",
        action="store_true",
        help="Keep the temporary work directory after the run.",
    )
    return parser.parse_args()


def load_samples(path: Path) -> list[dict]:
    samples: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            sample = json.loads(line)
            if sample.get("cwe_id") != "CWE89":
                raise ValueError(f"Unexpected CWE at line {line_number}: {sample.get('cwe_id')}")
            samples.append(sample)
    return samples


def class_name_for(sample_id: str) -> str:
    name = re.sub(r"[^0-9A-Za-z_]", "_", sample_id)
    if not name or name[0].isdigit():
        name = f"S_{name}"
    return f"Sample_{name}"


def write_sources(samples: list[dict], source_dir: Path) -> dict[str, str]:
    class_to_sample: dict[str, str] = {}
    source_dir.mkdir(parents=True, exist_ok=True)
    for sample in samples:
        sample_id = str(sample["sample_id"])
        class_name = class_name_for(sample_id)
        class_to_sample[class_name] = sample_id
        code = str(sample.get("generated_code", "")).strip()
        source = (
            f"public final class {class_name} {{\n"
            f"{indent(code, '    ')}\n"
            "}\n"
        )
        (source_dir / f"{class_name}.java").write_text(source, encoding="utf-8")
    return class_to_sample


def indent(text: str, prefix: str) -> str:
    return "\n".join(prefix + line if line else "" for line in text.splitlines())


def run_command(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def compile_sources(source_dir: Path, classes_dir: Path) -> subprocess.CompletedProcess[str]:
    classes_dir.mkdir(parents=True, exist_ok=True)
    sources = sorted(str(path) for path in source_dir.glob("*.java"))
    return run_command(["javac", "-g", "-d", str(classes_dir), *sources], cwd=source_dir)


def run_spotbugs(
    spotbugs_cmd: str, classes_dir: Path, report_path: Path
) -> subprocess.CompletedProcess[str]:
    return run_command(
        [
            spotbugs_cmd,
            "-textui",
            "-effort:max",
            "-low",
            "-xml:withMessages",
            "-output",
            str(report_path),
            str(classes_dir),
        ],
        cwd=classes_dir.parent,
    )


def parse_spotbugs_report(report_path: Path, class_to_sample: dict[str, str]) -> dict[str, list[dict]]:
    findings_by_sample = {sample_id: [] for sample_id in class_to_sample.values()}
    if not report_path.exists():
        return findings_by_sample

    root = ET.parse(report_path).getroot()
    for bug in root.findall(".//BugInstance"):
        bug_type = bug.attrib.get("type", "")
        if bug_type not in SQL_BUG_PATTERNS:
            continue
        class_node = bug.find("Class")
        if class_node is None:
            continue
        class_name = class_node.attrib.get("classname", "").split(".")[-1]
        sample_id = class_to_sample.get(class_name)
        if not sample_id:
            continue
        source_line = bug.find("SourceLine")
        findings_by_sample[sample_id].append(
            {
                "type": bug_type,
                "priority": bug.attrib.get("priority", ""),
                "category": bug.attrib.get("category", ""),
                "line": source_line.attrib.get("start", "") if source_line is not None else "",
            }
        )
    return findings_by_sample


def compute_metrics(samples: list[dict], findings_by_sample: dict[str, list[dict]]) -> dict:
    tp = fp = tn = fn = 0
    per_sample = []
    for sample in samples:
        sample_id = str(sample["sample_id"])
        label = int(sample["label"])
        prediction = 1 if findings_by_sample.get(sample_id) else 0
        if label == 1 and prediction == 1:
            tp += 1
        elif label == 0 and prediction == 1:
            fp += 1
        elif label == 0 and prediction == 0:
            tn += 1
        else:
            fn += 1
        per_sample.append(
            {
                "sample_id": sample_id,
                "label": label,
                "prediction": prediction,
                "findings": findings_by_sample.get(sample_id, []),
            }
        )

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(samples) if samples else 0.0
    return {
        "tool": "SpotBugs",
        "cwe_id": "CWE89",
        "corpus": "cwe89_large_holdout_samples.jsonl",
        "sql_bug_patterns": sorted(SQL_BUG_PATTERNS),
        "samples": len(samples),
        "safe": sum(1 for sample in samples if int(sample["label"]) == 0),
        "vulnerable": sum(1 for sample in samples if int(sample["label"]) == 1),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "accuracy": accuracy,
            "precision_vulnerable": precision,
            "recall_vulnerable": recall,
            "f1_vulnerable": f1,
        },
        "per_sample": per_sample,
    }


def main() -> int:
    args = parse_args()
    repo_root = Path.cwd()
    input_path = (repo_root / args.input).resolve()
    output_path = (repo_root / args.output).resolve()

    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 2
    if shutil.which("javac") is None:
        print("javac is required but was not found in PATH.", file=sys.stderr)
        return 2
    if shutil.which(args.spotbugs_cmd) is None and not Path(args.spotbugs_cmd).exists():
        print(
            f"SpotBugs executable not found: {args.spotbugs_cmd}. "
            "Pass --spotbugs-cmd /path/to/spotbugs.",
            file=sys.stderr,
        )
        return 2

    samples = load_samples(input_path)
    if args.work_dir:
        work_dir = Path(args.work_dir).resolve()
        work_dir.mkdir(parents=True, exist_ok=True)
        cleanup = False
    else:
        work_dir = Path(tempfile.mkdtemp(prefix="spotbugs_cwe89_"))
        cleanup = not args.keep_work_dir

    try:
        source_dir = work_dir / "src"
        classes_dir = work_dir / "classes"
        report_path = work_dir / "spotbugs.xml"
        class_to_sample = write_sources(samples, source_dir)

        compile_result = compile_sources(source_dir, classes_dir)
        if compile_result.returncode != 0:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(
                    {
                        "tool": "SpotBugs",
                        "status": "compile_failed",
                        "work_dir": str(work_dir),
                        "stdout": compile_result.stdout,
                        "stderr": compile_result.stderr,
                    },
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            print(f"Compilation failed. Summary written to {output_path}", file=sys.stderr)
            return 1

        spotbugs_result = run_spotbugs(args.spotbugs_cmd, classes_dir, report_path)
        if spotbugs_result.returncode not in (0, 1):
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(
                    {
                        "tool": "SpotBugs",
                        "status": "spotbugs_failed",
                        "work_dir": str(work_dir),
                        "stdout": spotbugs_result.stdout,
                        "stderr": spotbugs_result.stderr,
                    },
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            print(f"SpotBugs failed. Summary written to {output_path}", file=sys.stderr)
            return 1

        findings_by_sample = parse_spotbugs_report(report_path, class_to_sample)
        summary = compute_metrics(samples, findings_by_sample)
        summary.update(
            {
                "status": "ok",
                "work_dir": str(work_dir),
                "spotbugs_stdout": spotbugs_result.stdout,
                "spotbugs_stderr": spotbugs_result.stderr,
            }
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({k: summary[k] for k in ("status", "samples", "metrics")}, indent=2))
        return 0
    finally:
        if cleanup:
            shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
