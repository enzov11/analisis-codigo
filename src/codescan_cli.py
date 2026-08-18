import argparse
import contextlib
import os
import sys
from pathlib import Path

from dotenv import load_dotenv


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="CodeScan-AI SAST scanner for Java source files."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan", help="Analyze Java files or directories."
    )
    scan_parser.add_argument(
        "targets",
        nargs="+",
        help="Java files or directories to scan recursively.",
    )
    scan_parser.add_argument(
        "--format",
        choices=["json", "sarif"],
        default=None,
        help="Report format.",
    )
    scan_parser.add_argument(
        "--output",
        type=str,
        help="Write the report to this path instead of stdout.",
    )
    scan_parser.add_argument(
        "--fusion-config",
        type=str,
        help="Frozen evidence-fusion JSON to apply during scan.",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["vulnerable", "review_required", "never"],
        default=None,
        help="Condition that makes the command exit with status 1.",
    )
    scan_parser.add_argument(
        "--env-file",
        type=str,
        help="Project environment file. Defaults to .codescan.env or .env near the scan target.",
    )

    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
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
                        base_dir=Path.cwd(),
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
                    base_dir=Path.cwd(),
                )

            report_text = render_report(report, output_format)
            write_or_print_report(report_text, Path(args.output) if args.output else None)
            return 1 if should_fail(report, fail_on) else 0
    except Exception as exc:
        print(f"CodeScan-AI scan failed: {exc}", file=sys.stderr)
        return 2

    return 2


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
