import argparse
import os
from trainer import ModelTrainer
from predictor import VulnerabilityPredictor
from config import Config


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

    args = parser.parse_args()

    try:
        if args.mode == "train":
            print("Training model...")
            trainer = ModelTrainer()
            trainer.train()
            print("Training completed.")
        elif args.mode == "predict":
            if not args.code and not args.text:
                print(
                    "Error: Either --code or --text must be provided for prediction mode"
                )
                return

            predictor = VulnerabilityPredictor()

            if args.code:
                file_path = args.code
                if not os.path.exists(file_path):
                    test_dir = os.path.join(os.path.dirname(__file__), "test")
                    possible_path = os.path.join(test_dir, args.code)
                    if os.path.exists(possible_path):
                        file_path = possible_path
                    else:
                        print(
                            f"Error: File not found - {args.code} (searched in current directory and test/)"
                        )
                        return

                try:
                    with open(file_path, "r") as f:
                        code = f.read()
                except Exception as e:
                    print(f"Error reading file: {str(e)}")
                    return
            else:
                code = args.text

            result = predictor.analyze_code(code)

            print("\nVulnerability Analysis Results:")
            print(
                f"Vulnerability Probability: {result['vulnerability_probability']:.2f}"
            )
            print(f"Is Vulnerable: {'Yes' if result['is_vulnerable'] else 'No'}")

            if result["vulnerable_lines"]:
                print("\nPotentially Vulnerable Lines:")
                for line in result["vulnerable_lines"]:
                    print(f"Line {line['line_number']}: {line['code']}")

            if result["suggested_fixes"]:
                print("\nSuggested Fixes:")
                for fix in result["suggested_fixes"]:
                    print(f"Line {fix['line_number']}:")
                    print(f"Vulnerable Code: {fix['vulnerable_code']}")
                    print(f"Suggested Fix: {fix['suggested_fix']}")
                    print(f"Reference: {fix['reference']}\n")

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        if args.mode == "train":
            print("Training failed. Check the dataset path and configuration.")


if __name__ == "__main__":
    main()
