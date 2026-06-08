import argparse
import json
import sys
from pathlib import Path

from predictor import VulnerabilityPredictor
from trainer import ModelTrainer


def main():
    parser = argparse.ArgumentParser(
        description="VulDeePecker for Java - Vulnerability Detection and Correction"
    )
    parser.add_argument(
        "mode", choices=["train", "predict"], help="Mode to run: train or predict"
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
        help="Frozen evidence-fusion JSON to apply in predict mode.",
    )

    args = parser.parse_args()

    try:
        if args.mode == "train":
            print("Training model...")
            trainer = ModelTrainer()
            _, evaluation = trainer.train()
            print("Training completed.")
            if args.json:
                print(json.dumps(evaluation, indent=2))
            return 0
        else:
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


if __name__ == "__main__":
    sys.exit(main())
