import argparse
import json
import subprocess
import tempfile
from pathlib import Path


MODEL_ID = "OpenAI Codex CLI gpt-5.5"
GENERATION_PARAMETERS = {
    "interface": "codex exec",
    "model": "gpt-5.5",
    "sampling_parameters": "not exposed",
    "sandbox": "read-only",
    "session_mode": "ephemeral independent completion per sample",
}


def load_jsonl(path: Path):
    with open(path, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def strip_code_fence(response: str) -> str:
    response = response.strip()
    if not response.startswith("```"):
        return response
    lines = response.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def collect(prompt: str) -> str:
    with tempfile.NamedTemporaryFile(suffix=".txt") as output:
        subprocess.run(
            [
                "codex",
                "exec",
                "--ephemeral",
                "--ignore-user-config",
                "--ignore-rules",
                "--skip-git-repo-check",
                "--sandbox",
                "read-only",
                "--cd",
                "/tmp",
                "--model",
                "gpt-5.5",
                "--output-last-message",
                output.name,
                prompt,
            ],
            check=True,
        )
        output.seek(0)
        code = strip_code_fence(output.read().decode("utf-8"))
    if not code:
        raise RuntimeError("Codex returned an empty completion.")
    return code


def append_jsonl(path: Path, record: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
        handle.flush()


def main():
    parser = argparse.ArgumentParser(description="Collect auditable Codex CLI completions.")
    parser.add_argument("--scaffold", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--generated-at", required=True)
    args = parser.parse_args()

    scaffold = load_jsonl(Path(args.scaffold))
    output_path = Path(args.output)
    completed = {
        record["sample_id"]: record
        for record in load_jsonl(output_path)
    } if output_path.exists() else {}

    for position, sample in enumerate(scaffold, start=1):
        sample_id = sample["sample_id"]
        if sample_id in completed:
            print(f"[{position}/{len(scaffold)}] skipping {sample_id}", flush=True)
            continue
        print(f"[{position}/{len(scaffold)}] collecting {sample_id}", flush=True)
        append_jsonl(
            output_path,
            {
                "sample_id": sample_id,
                "generated_code": collect(sample["prompt_text"]),
                "model_id": MODEL_ID,
                "generated_at": args.generated_at,
                "generation_parameters": GENERATION_PARAMETERS,
            },
        )


if __name__ == "__main__":
    main()
