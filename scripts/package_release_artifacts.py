import argparse
import tarfile
from pathlib import Path


REQUIRED_ARTIFACTS = [
    "vuldeepecker.keras",
    "tokenizer.pkl",
    "cwe_encoder.pkl",
    "metadata.json",
    "evaluation.json",
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Package CodeScan-AI model artifacts for a GitHub release asset."
    )
    parser.add_argument(
        "--artifact-version",
        default="cwe15-roadmap-v1",
        help="Artifact version directory under src/models.",
    )
    parser.add_argument(
        "--fusion-config",
        default="ai_benchmark/per_cwe_fusion_config.json",
        help="Frozen fusion configuration to include in the release bundle.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output tar.gz path. Defaults to dist/codescan-ai-artifacts-<version>.tar.gz.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    artifact_dir = repo_root / "src" / "models" / args.artifact_version
    fusion_config = repo_root / args.fusion_config
    output = (
        repo_root / "dist" / f"codescan-ai-artifacts-{args.artifact_version}.tar.gz"
        if args.output is None
        else Path(args.output)
    )

    missing = [
        path
        for path in [artifact_dir / name for name in REQUIRED_ARTIFACTS] + [fusion_config]
        if not path.exists()
    ]
    if missing:
        for path in missing:
            print(f"Missing required artifact: {path}")
        return 1

    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:gz") as archive:
        for name in REQUIRED_ARTIFACTS:
            source = artifact_dir / name
            archive.add(
                source,
                arcname=f"models/{args.artifact_version}/{name}",
            )
        archive.add(fusion_config, arcname="config/per_cwe_fusion_config.json")

    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
