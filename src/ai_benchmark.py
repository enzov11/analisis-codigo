import argparse
import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Iterable, List

from cwe_registry import (
    OracleAssessment,
    assess_code as assess_registered_code,
    assess_cwe78,
    assess_cwe89,
    assess_cwe90,
    supported_cwe_ids,
)

SUPPORTED_CWES = supported_cwe_ids()
PROMPT_CONDITIONS = {"neutral", "secure", "risk-prone"}
INCLUDED_REVIEW_STATUS = "approved"
INCLUDED_TEST_STATUS = "passed"
REQUIRED_FIELDS = {
    "sample_id",
    "cwe_id",
    "prompt_id",
    "prompt_condition",
    "model_id",
    "generated_at",
    "generation_parameters",
    "prompt_text",
    "generated_code",
    "label",
    "label_source",
    "review_status",
    "test_status",
    "exclusion_reason",
}


class BenchmarkValidationError(ValueError):
    pass


def load_samples(path: Path) -> List[Dict[str, object]]:
    if path.suffix.lower() == ".jsonl":
        samples = []
        with open(path, "r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    samples.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise BenchmarkValidationError(
                        f"Invalid JSON on line {line_number} of {path}: {exc.msg}"
                    ) from exc
        return samples
    if path.suffix.lower() == ".csv":
        with open(path, "r", encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))
    raise BenchmarkValidationError("Benchmark samples must use .jsonl or .csv format.")


def validate_samples(samples: Iterable[Dict[str, object]]) -> Dict[str, object]:
    included = []
    excluded = []
    pending = []
    seen_ids = set()
    for index, sample in enumerate(samples, start=1):
        validate_sample(sample, index)
        sample_id = str(sample["sample_id"])
        if sample_id in seen_ids:
            raise BenchmarkValidationError(f"Duplicate sample_id: {sample_id}")
        seen_ids.add(sample_id)
        if is_included_sample(sample):
            included.append(sample)
        elif str(sample.get("exclusion_reason", "")).strip():
            excluded.append(sample)
        else:
            pending.append(sample)

    return {
        "total_samples": len(included) + len(excluded) + len(pending),
        "included_samples": len(included),
        "excluded_samples": len(excluded),
        "pending_samples": len(pending),
        "included": included,
        "excluded": excluded,
        "pending": pending,
    }


def validate_sample(sample: Dict[str, object], index: int = 1):
    missing = REQUIRED_FIELDS - set(sample)
    if missing:
        raise BenchmarkValidationError(
            f"Sample {index} is missing required fields: {sorted(missing)}"
        )

    for field in ("sample_id", "prompt_id", "model_id", "generated_at", "prompt_text"):
        if not str(sample[field]).strip():
            raise BenchmarkValidationError(f"Sample {index} has an empty {field}.")

    if str(sample["cwe_id"]) not in SUPPORTED_CWES:
        raise BenchmarkValidationError(
            f"Sample {index} has unsupported cwe_id {sample['cwe_id']}; "
            f"supported values are {sorted(SUPPORTED_CWES)}."
        )
    if str(sample["prompt_condition"]) not in PROMPT_CONDITIONS:
        raise BenchmarkValidationError(
            f"Sample {index} has invalid prompt_condition {sample['prompt_condition']}."
        )

    label = str(sample["label"]).strip()
    if is_included_sample(sample) and label not in {"0", "1"}:
        raise BenchmarkValidationError(f"Included sample {index} label must be 0 or 1.")
    if not is_included_sample(sample) and label not in {"", "0", "1"}:
        raise BenchmarkValidationError(
            f"Excluded sample {index} label must be empty, 0, or 1."
        )

    if not str(sample["generated_code"]).strip() and not str(sample["exclusion_reason"]).strip():
        raise BenchmarkValidationError(
            f"Sample {index} requires generated_code or an exclusion_reason."
        )

    if is_included_sample(sample):
        source = str(sample["label_source"]).lower()
        if "manual" not in source or not any(
            marker in source for marker in ("structural", "test", "oracle")
        ):
            raise BenchmarkValidationError(
                f"Included sample {index} must record manual and structural/test label evidence."
            )


def is_included_sample(sample: Dict[str, object]) -> bool:
    return (
        not str(sample.get("exclusion_reason", "")).strip()
        and str(sample.get("review_status", "")).strip().lower() == INCLUDED_REVIEW_STATUS
        and str(sample.get("test_status", "")).strip().lower() == INCLUDED_TEST_STATUS
    )


def assess_code(code: str, cwe_id: str) -> OracleAssessment:
    try:
        return assess_registered_code(code, cwe_id)
    except ValueError as exc:
        raise BenchmarkValidationError(str(exc)) from exc


def create_scaffold(
    manifest_path: Path,
    output_path: Path,
    model_id: str,
    generated_at: str,
    generation_parameters: Dict[str, object] = None,
):
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    conditions = manifest["conditions"]
    completions = int(manifest["completions_per_prompt"])
    records = []
    for task in manifest["tasks"]:
        for condition, condition_instruction in conditions.items():
            prompt_text = f"{task['task_prompt']}\n\n{condition_instruction}"
            for completion in range(1, completions + 1):
                records.append(
                    {
                        "sample_id": f"{task['prompt_id']}_{condition}_{completion}",
                        "cwe_id": task["cwe_id"],
                        "prompt_id": task["prompt_id"],
                        "prompt_condition": condition,
                        "model_id": model_id,
                        "generated_at": generated_at,
                        "generation_parameters": generation_parameters or {},
                        "prompt_text": prompt_text,
                        "generated_code": "",
                        "label": "",
                        "label_source": "",
                        "review_status": "pending",
                        "test_status": "pending",
                        "exclusion_reason": "",
                        "corpus_role": manifest.get("corpus_role", "unspecified"),
                    }
                )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")
    return len(records)


def prepare_review(input_path: Path, output_path: Path) -> int:
    samples = load_samples(input_path)
    reviewed = []
    for index, sample in enumerate(samples, start=1):
        validate_sample(sample, index)
        updated = dict(sample)
        if str(sample.get("generated_code", "")).strip():
            updated["oracle_assessment"] = asdict(
                assess_code(str(sample["generated_code"]), str(sample["cwe_id"]))
            )
        reviewed.append(updated)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        for sample in reviewed:
            handle.write(json.dumps(sample) + "\n")
    return len(reviewed)


def apply_confirmed_oracle_labels(input_path: Path, output_path: Path) -> Dict[str, int]:
    samples = load_samples(input_path)
    finalized = []
    counts = {"approved": 0, "excluded_ambiguous": 0, "safe": 0, "vulnerable": 0}
    for index, sample in enumerate(samples, start=1):
        validate_sample(sample, index)
        assessment = sample.get("oracle_assessment")
        if not assessment or assessment.get("verdict") not in {"safe", "vulnerable", "ambiguous"}:
            raise BenchmarkValidationError(
                f"Sample {index} requires an oracle_assessment before confirmation."
            )
        updated = dict(sample)
        manual_decision = str(sample.get("manual_review_decision", "")).strip().lower()
        if manual_decision and manual_decision not in {"safe", "vulnerable"}:
            raise BenchmarkValidationError(
                f"Sample {index} has invalid manual_review_decision {manual_decision}."
            )
        if manual_decision and not str(sample.get("manual_review_note", "")).strip():
            raise BenchmarkValidationError(
                f"Sample {index} requires manual_review_note for a manual override."
            )
        verdict = manual_decision or assessment["verdict"]
        updated["label_source"] = (
            "manual_review_override+structural_oracle_recorded"
            if manual_decision
            else "manual_review+structural_oracle_confirmed"
        )
        if verdict == "safe":
            updated.update(
                {
                    "label": 0,
                    "review_status": "approved",
                    "test_status": "passed",
                    "exclusion_reason": "",
                }
            )
            counts["approved"] += 1
            counts["safe"] += 1
        elif verdict == "vulnerable":
            updated.update(
                {
                    "label": 1,
                    "review_status": "approved",
                    "test_status": "passed",
                    "exclusion_reason": "",
                }
            )
            counts["approved"] += 1
            counts["vulnerable"] += 1
        else:
            updated.update(
                {
                    "label": "",
                    "review_status": "approved_excluded",
                    "test_status": "not_applicable",
                    "exclusion_reason": (
                        "Excluded after manual review: structural evidence remains "
                        "ambiguous for binary ground truth."
                    ),
                }
            )
            counts["excluded_ambiguous"] += 1
        finalized.append(updated)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        for sample in finalized:
            handle.write(json.dumps(sample) + "\n")
    return counts


def import_responses(scaffold_path: Path, responses_path: Path, output_path: Path) -> int:
    scaffold = load_samples(scaffold_path)
    responses = load_samples(responses_path)
    response_map = {}
    for response in responses:
        sample_id = str(response.get("sample_id", "")).strip()
        generated_code = str(response.get("generated_code", "")).strip()
        if not sample_id or not generated_code:
            raise BenchmarkValidationError(
                "Each imported response requires sample_id and generated_code."
            )
        if sample_id in response_map:
            raise BenchmarkValidationError(f"Duplicate response sample_id: {sample_id}")
        response_map[sample_id] = response

    scaffold_ids = {str(sample["sample_id"]) for sample in scaffold}
    if set(response_map) != scaffold_ids:
        missing = sorted(scaffold_ids - set(response_map))
        unexpected = sorted(set(response_map) - scaffold_ids)
        raise BenchmarkValidationError(
            f"Response IDs must match the scaffold. Missing={missing}; unexpected={unexpected}"
        )

    imported = []
    for sample in scaffold:
        response = response_map[str(sample["sample_id"])]
        updated = dict(sample)
        updated["generated_code"] = response["generated_code"]
        for optional in ("model_id", "generated_at", "generation_parameters"):
            if response.get(optional):
                updated[optional] = response[optional]
        imported.append(updated)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        for sample in imported:
            handle.write(json.dumps(sample) + "\n")
    return len(imported)


def validate_disjoint_manifests(manifest_paths: List[Path]) -> Dict[str, object]:
    prompt_owners = {}
    text_owners = {}
    for path in manifest_paths:
        with open(path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        for task in manifest["tasks"]:
            prompt_id = str(task["prompt_id"])
            text = " ".join(str(task["task_prompt"]).lower().split())
            if prompt_id in prompt_owners:
                raise BenchmarkValidationError(
                    f"Repeated prompt_id {prompt_id} in {prompt_owners[prompt_id]} and {path}."
                )
            if text in text_owners:
                raise BenchmarkValidationError(
                    f"Repeated task prompt in {text_owners[text]} and {path}."
                )
            prompt_owners[prompt_id] = str(path)
            text_owners[text] = str(path)
    return {
        "manifest_count": len(manifest_paths),
        "task_count": len(prompt_owners),
        "status": "disjoint",
    }


def main():
    parser = argparse.ArgumentParser(
        description="Prepare and validate the CodeScan-AI generated-code benchmark."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scaffold_parser = subparsers.add_parser("scaffold", help="Create annotation-ready JSONL.")
    scaffold_parser.add_argument("--manifest", required=True)
    scaffold_parser.add_argument("--output", required=True)
    scaffold_parser.add_argument("--model-id", required=True)
    scaffold_parser.add_argument("--generated-at", required=True)
    scaffold_parser.add_argument(
        "--generation-parameters-json",
        default="{}",
        help="JSON object recording exposed generation parameters or limitations.",
    )

    validate_parser = subparsers.add_parser("validate", help="Validate annotated samples.")
    validate_parser.add_argument("--input", required=True)

    import_parser = subparsers.add_parser(
        "import-responses", help="Merge collected LLM completions into a pending scaffold."
    )
    import_parser.add_argument("--scaffold", required=True)
    import_parser.add_argument("--responses", required=True)
    import_parser.add_argument("--output", required=True)

    review_parser = subparsers.add_parser(
        "prepare-review", help="Attach non-destructive oracle assessments without approving labels."
    )
    review_parser.add_argument("--input", required=True)
    review_parser.add_argument("--output", required=True)

    confirm_parser = subparsers.add_parser(
        "confirm-assessments",
        help="Apply manually confirmed oracle labels and exclude ambiguous samples.",
    )
    confirm_parser.add_argument("--input", required=True)
    confirm_parser.add_argument("--output", required=True)

    disjoint_parser = subparsers.add_parser(
        "check-manifests", help="Ensure pilot, calibration, and holdout tasks are disjoint."
    )
    disjoint_parser.add_argument("--manifests", nargs="+", required=True)

    oracle_parser = subparsers.add_parser("oracle", help="Run structural oracle on a Java file.")
    oracle_parser.add_argument("--code", required=True)
    oracle_parser.add_argument("--cwe", choices=sorted(SUPPORTED_CWES), required=True)

    args = parser.parse_args()
    if args.command == "scaffold":
        generation_parameters = json.loads(args.generation_parameters_json)
        if not isinstance(generation_parameters, dict):
            raise BenchmarkValidationError(
                "--generation-parameters-json must decode to a JSON object."
            )
        count = create_scaffold(
            Path(args.manifest),
            Path(args.output),
            args.model_id,
            args.generated_at,
            generation_parameters,
        )
        print(json.dumps({"created_samples": count, "output": args.output}, indent=2))
    elif args.command == "validate":
        summary = validate_samples(load_samples(Path(args.input)))
        print(
            json.dumps(
                {
                    key: value
                    for key, value in summary.items()
                    if key not in {"included", "excluded", "pending"}
                },
                indent=2,
            )
        )
    elif args.command == "import-responses":
        count = import_responses(
            Path(args.scaffold), Path(args.responses), Path(args.output)
        )
        print(json.dumps({"imported_samples": count, "output": args.output}, indent=2))
    elif args.command == "prepare-review":
        count = prepare_review(Path(args.input), Path(args.output))
        print(json.dumps({"prepared_samples": count, "output": args.output}, indent=2))
    elif args.command == "confirm-assessments":
        counts = apply_confirmed_oracle_labels(Path(args.input), Path(args.output))
        print(json.dumps({"output": args.output, **counts}, indent=2))
    elif args.command == "check-manifests":
        print(
            json.dumps(
                validate_disjoint_manifests([Path(path) for path in args.manifests]),
                indent=2,
            )
        )
    else:
        code = Path(args.code).read_text(encoding="utf-8")
        print(json.dumps(asdict(assess_code(code, args.cwe)), indent=2))


if __name__ == "__main__":
    main()
