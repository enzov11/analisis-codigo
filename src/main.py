import argparse
import contextlib
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv


def main():
    parser = argparse.ArgumentParser(
        description="CodeScan-AI for Java - Vulnerability Detection and Correction"
    )
    parser.add_argument(
        "mode",
        choices=["train", "predict", "scan"],
        help="Mode to run: train, predict or scan",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Java files or directories to scan recursively (for scan mode).",
    )
    parser.add_argument(
        "--code",
        type=str,
        help="Java code file to analyze (for predict mode). Can be a filename or path.",
    )
    parser.add_argument(
        "--text", type=str, help="Java code text to analyze (for predict mode)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print prediction or evaluation results as JSON.",
    )
    parser.add_argument(
        "--fusion-config",
        type=str,
        help="Frozen evidence-fusion JSON to apply in predict or scan mode.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "sarif"],
        default=None,
        help="Report format for scan mode.",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Write scan report to this path instead of stdout.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["vulnerable", "review_required", "never"],
        default=None,
        help="Condition that makes scan mode exit with status 1.",
    )
    parser.add_argument(
        "--env-file",
        type=str,
        help="Project environment file for scan mode. Defaults to .codescan.env or .env near the scan target.",
    )

    args = parser.parse_args()

    try:
        if args.mode == "train":
            from trainer import ModelTrainer

            print("Training model...")
            trainer = ModelTrainer()
            _, evaluation = trainer.train()
            print("Training completed.")
            if args.json:
                print(json.dumps(evaluation, indent=2))
            return 0
        elif args.mode == "predict":
            from predictor import VulnerabilityPredictor

            if not args.code and not args.text:
                print(
                    "Error: Either --code or --text must be provided for prediction mode."
                )
                return 1

            code = args.text if args.text else read_code_from_path(args.code)
            predictor = VulnerabilityPredictor(
                fusion_config_path=Path(args.fusion_config) if args.fusion_config else None
            )
            result = predictor.analyze_code(code)

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print_human_result(result)
            return 0
        else:
            if not args.targets:
                print("Error: At least one file or directory must be provided for scan mode.")
                return 2
            loaded_env = _load_scan_environment(args.targets, args.env_file)
            output_format = args.format or os.getenv("CODESCAN_FORMAT", "json")
            fail_on = args.fail_on or os.getenv("CODESCAN_FAIL_ON", "vulnerable")
            fusion_config_path = _resolve_scan_config_path(
                args.fusion_config,
                os.getenv("CODESCAN_FUSION_CONFIG"),
                loaded_env,
            )
            quiet_runtime = _env_flag("CODESCAN_QUIET_RUNTIME", default=True)
            if quiet_runtime:
                with _suppress_native_stderr():
                    from sast_scanner import (
                        render_report,
                        scan_targets,
                        should_fail,
                        write_or_print_report,
                    )

                    report = scan_targets(
                        [Path(target) for target in args.targets],
                        fusion_config_path=fusion_config_path,
                    )
            else:
                from sast_scanner import (
                    render_report,
                    scan_targets,
                    should_fail,
                    write_or_print_report,
                )

                report = scan_targets(
                    [Path(target) for target in args.targets],
                    fusion_config_path=fusion_config_path,
                )
            report_text = render_report(report, output_format)
            write_or_print_report(report_text, Path(args.output) if args.output else None)
            return 1 if should_fail(report, fail_on) else 0

    except Exception as exc:
        print(f"An error occurred: {exc}")
        if args.mode == "train":
            print(
                "Training failed. Check DATASET_PATH, the dataset structure, and the configured artifact paths."
            )
        return 1


def read_code_from_path(code_argument: str) -> str:
    candidate_paths = [
        Path(code_argument),
        Path(__file__).resolve().parent / "test" / code_argument,
    ]

    for candidate in candidate_paths:
        if candidate.exists():
            with open(candidate, "r", encoding="utf-8") as handle:
                return handle.read()

    searched = ", ".join(str(path) for path in candidate_paths)
    raise FileNotFoundError(
        f"File not found: {code_argument}. Searched in: {searched}"
    )


def print_human_result(result: dict):
    print("\nVulnerability Analysis Results:")
    print(f"Final Probability: {result['vulnerability_probability']:.2f}")
    print(f"Model Probability: {result['model_probability']:.2f}")
    print(f"Heuristic Probability: {result['heuristic_probability']:.2f}")
    print(f"Safety Evidence Probability: {result['safety_probability']:.2f}")
    print(f"Threshold: {result['threshold']:.2f}")
    print(f"Is Vulnerable: {'Yes' if result['is_vulnerable'] else 'No'}")
    print(f"Decision: {result['decision']}")
    print(f"Review Required: {'Yes' if result['review_required'] else 'No'}")
    print(f"Reason: {result['decision_reason']}")

    if result["probable_cwes"]:
        print("\nProbable CWE Categories:")
        for candidate in result["probable_cwes"]:
            print(
                f"{candidate['cwe_id']} ({candidate['description']}): "
                f"{candidate['confidence']:.2f} via {candidate['source']}"
            )

    if result["vulnerable_lines"]:
        print("\nPotentially Vulnerable Lines:")
        for line in result["vulnerable_lines"]:
            print(
                f"Line {line['line_number']}: {line['code']} "
                f"[{line['description']}]"
            )

    if result["suggested_fixes"]:
        print("\nSuggested Fixes:")
        for fix in result["suggested_fixes"]:
            print(f"Line {fix['line_number']}:")
            print(f"Vulnerable Code: {fix['vulnerable_code']}")
            print(f"Suggested Fix: {fix['suggested_fix']}")
            print(f"Reference: {fix['reference']}\n")


def _load_scan_environment(targets, env_file):
    selected = Path(env_file) if env_file else _find_scan_environment(targets)
    if selected and selected.exists():
        load_dotenv(selected, override=True)
        _resolve_project_relative_environment(selected.parent)
    return selected


def _find_scan_environment(targets):
    candidate_bases = []
    for raw_target in targets:
        target = Path(raw_target)
        candidate_bases.append(target.parent if target.suffix else target)

    for base in candidate_bases:
        current = base.resolve()
        for parent in [current, *current.parents]:
            for name in (".codescan.env", ".env"):
                candidate = parent / name
                if candidate.exists():
                    return candidate
            if parent == Path.cwd().resolve():
                break
    return None


def _resolve_scan_config_path(argument_value, environment_value, loaded_env):
    if argument_value:
        return Path(argument_value)
    if not environment_value:
        return None

    path = Path(environment_value)
    if path.is_absolute() or not loaded_env:
        return path
    return (loaded_env.parent / path).resolve()


def _resolve_project_relative_environment(project_dir):
    for name in (
        "MODEL_SAVE_PATH",
        "TOKENIZER_SAVE_PATH",
        "CWE_ENCODER_SAVE_PATH",
        "METADATA_SAVE_PATH",
        "EVALUATION_SAVE_PATH",
        "LOG_DIR",
    ):
        value = os.getenv(name)
        if value:
            path = Path(value)
            if not path.is_absolute():
                os.environ[name] = str((project_dir / path).resolve())


def _env_flag(name, default=False):
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@contextlib.contextmanager
def _suppress_native_stderr():
    sys.stderr.flush()
    original_fd = os.dup(2)
    try:
        with open(os.devnull, "w", encoding="utf-8") as devnull:
            os.dup2(devnull.fileno(), 2)
            yield
    finally:
        sys.stderr.flush()
        os.dup2(original_fd, 2)
        os.close(original_fd)


if __name__ == "__main__":
    sys.exit(main())
