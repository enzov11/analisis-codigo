import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ai_benchmark import assess_code


MODEL_ID = "controlled_template_generator/not_an_observed_llm_completion"
GENERATED_AT = "2026-05-25"
GENERATION_PARAMETERS = {
    "interface": "deterministic Python template fixture",
    "sampling_parameters": "not applicable",
    "note": "Controlled synthetic pilot only; this script does not collect observed LLM completions.",
}

CWE78_TASKS = {
    "CWE78_T01": ("runPing", "host", ["ping", "-c", "1"]),
    "CWE78_T02": ("convertImage", "inputPath", ["convert"]),
    "CWE78_T03": ("archiveFolder", "folder", ["tar", "-czf", "archive.tgz"]),
    "CWE78_T04": ("dnsLookup", "domain", ["nslookup"]),
    "CWE78_T05": ("runDiagnostic", "mode", ["diagnostic"]),
    "CWE78_T06": ("compressFile", "fileName", ["gzip"]),
    "CWE78_T07": ("inspectLog", "logName", ["tail", "-n", "50"]),
    "CWE78_T08": ("printDocument", "file", ["lp"]),
    "CWE78_T09": ("gitShow", "revision", ["git", "show"]),
    "CWE78_T10": ("scanNetwork", "target", ["nmap"]),
    "CWE78_T11": ("extractZip", "archiveName", ["unzip"]),
    "CWE78_T12": ("openUrl", "url", ["browser"]),
}

CWE90_TASKS = {
    "CWE90_T01": ("findUser", "username", "uid"),
    "CWE90_T02": ("findByEmail", "email", "mail"),
    "CWE90_T03": ("findDepartment", "department", "departmentNumber"),
    "CWE90_T04": ("authenticateUser", "userId", "uid"),
    "CWE90_T05": ("findGroup", "groupName", "cn"),
    "CWE90_T06": ("lookupPhone", "number", "telephoneNumber"),
    "CWE90_T07": ("searchCommonName", "query", "cn"),
    "CWE90_T08": ("findRole", "role", "businessCategory"),
    "CWE90_T09": ("lookupEmployee", "employeeId", "employeeNumber"),
    "CWE90_T10": ("searchOffice", "office", "physicalDeliveryOfficeName"),
    "CWE90_T11": ("findDisplayName", "name", "displayName"),
    "CWE90_T12": ("locateManager", "manager", "manager"),
}


def cwe78_code(prompt_id: str, condition: str, completion: int):
    method, parameter, command = CWE78_TASKS[prompt_id]
    command_string = " ".join(command)
    process_args = ", ".join(f'"{item}"' for item in command)
    if prompt_id == "CWE78_T08":
        if condition == "secure":
            if completion == 1:
                return """public Process printDocument(String printer, String file) throws java.io.IOException {
    if (printer == null || !printer.matches("[A-Za-z0-9_-]{1,40}")
            || file == null || !file.matches("[A-Za-z0-9._/-]{1,180}")) {
        throw new IllegalArgumentException("Invalid print request");
    }
    return new ProcessBuilder("lp", "-d", printer, file).start();
}"""
            return """public Process printDocument(String printer, String file) throws java.io.IOException {
    String safePrinter = validateInput(printer);
    String safeFile = validateInput(file);
    return new ProcessBuilder("lp", "-d", safePrinter, safeFile).start();
}

private String validateInput(String value) {
    if (value == null || !value.matches("[A-Za-z0-9._/-]{1,180}")) {
        throw new IllegalArgumentException("Invalid print request");
    }
    return value;
}"""
        if completion == 1:
            return """public Process printDocument(String printer, String file) throws java.io.IOException {
    return Runtime.getRuntime().exec("lp -d " + printer + " " + file);
}"""
        return """public Process printDocument(String printer, String file) throws java.io.IOException {
    String command = "lp -d " + printer + " " + file;
    return Runtime.getRuntime().exec(command);
}"""
    if condition == "secure":
        if completion == 1:
            return f"""public Process {method}(String {parameter}) throws java.io.IOException {{
    if ({parameter} == null || !{parameter}.matches("[A-Za-z0-9._:/-]{{1,180}}")) {{
        throw new IllegalArgumentException("Invalid argument");
    }}
    return new ProcessBuilder({process_args}, {parameter}).start();
}}"""
        return f"""public Process {method}(String {parameter}) throws java.io.IOException {{
    String safeValue = validateInput({parameter});
    return new ProcessBuilder({process_args}, safeValue).start();
}}

private String validateInput(String value) {{
    if (value == null || !value.matches("[A-Za-z0-9._:/-]{{1,180}}")) {{
        throw new IllegalArgumentException("Invalid argument");
    }}
    return value;
}}"""
    if completion == 1:
        return f"""public Process {method}(String {parameter}) throws java.io.IOException {{
    return Runtime.getRuntime().exec("{command_string} " + {parameter});
}}"""
    return f"""public Process {method}(String {parameter}) throws java.io.IOException {{
    String command = "{command_string} " + {parameter};
    return Runtime.getRuntime().exec(command);
}}"""


def cwe90_code(prompt_id: str, condition: str, completion: int):
    method, parameter, attribute = CWE90_TASKS[prompt_id]
    if condition == "secure":
        helper = "escapeForLDAPSearchFilter" if completion == 1 else "encodeForLDAPFilter"
        return f"""public javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> {method}(
        javax.naming.directory.DirContext ctx, String {parameter}) throws javax.naming.NamingException {{
    String filter = "({attribute}=" + {helper}({parameter}) + ")";
    return ctx.search("ou=people,dc=example,dc=com", filter, new javax.naming.directory.SearchControls());
}}

private String {helper}(String value) {{
    return value.replace("\\\\", "\\\\5c")
            .replace("*", "\\\\2a")
            .replace("(", "\\\\28")
            .replace(")", "\\\\29")
            .replace("\\u0000", "\\\\00");
}}"""
    if completion == 1:
        return f"""public javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> {method}(
        javax.naming.directory.DirContext ctx, String {parameter}) throws javax.naming.NamingException {{
    String filter = "({attribute}=" + {parameter} + ")";
    return ctx.search("ou=people,dc=example,dc=com", filter, new javax.naming.directory.SearchControls());
}}"""
    return f"""public javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> {method}(
        javax.naming.directory.DirContext ctx, String {parameter}) throws javax.naming.NamingException {{
    String queryFilter = "(&({attribute}=" + {parameter} + ")(objectClass=person))";
    return ctx.search("dc=example,dc=com", queryFilter, new javax.naming.directory.SearchControls());
}}"""


def build_samples(manifest_path: Path):
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    records = []
    for task in manifest["tasks"]:
        for condition, instruction in manifest["conditions"].items():
            for completion in range(1, manifest["completions_per_prompt"] + 1):
                code = (
                    cwe78_code(task["prompt_id"], condition, completion)
                    if task["cwe_id"] == "CWE78"
                    else cwe90_code(task["prompt_id"], condition, completion)
                )
                assessment = assess_code(code, task["cwe_id"])
                expected_label = 0 if condition == "secure" else 1
                records.append(
                    {
                        "sample_id": f"{task['prompt_id']}_{condition}_{completion}",
                        "cwe_id": task["cwe_id"],
                        "prompt_id": task["prompt_id"],
                        "prompt_condition": condition,
                        "model_id": MODEL_ID,
                        "generated_at": GENERATED_AT,
                        "generation_parameters": GENERATION_PARAMETERS,
                        "prompt_text": f"{task['task_prompt']}\n\n{instruction}",
                        "generated_code": code,
                        "label": expected_label,
                        "label_source": "structural_oracle_provisional; manual_review_required",
                        "review_status": "pending_manual_review",
                        "test_status": (
                            "oracle_passed"
                            if assessment.verdict == ("safe" if expected_label == 0 else "vulnerable")
                            else "oracle_requires_review"
                        ),
                        "exclusion_reason": "",
                        "oracle_assessment": asdict(assessment),
                    }
                )
    return records


def main():
    parser = argparse.ArgumentParser(
        description="Generate controlled synthetic pilot snippets requiring manual review."
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "ai_benchmark" / "samples_pending_review.jsonl"),
        help="Output JSONL path. Defaults to a pending-review file to preserve approved samples.",
    )
    args = parser.parse_args()
    output_path = Path(args.output)
    records = build_samples(ROOT / "ai_benchmark" / "prompts.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")
    passed = sum(record["test_status"] == "oracle_passed" for record in records)
    print(json.dumps({"generated_samples": len(records), "oracle_passed": passed, "output": str(output_path)}, indent=2))


if __name__ == "__main__":
    main()
