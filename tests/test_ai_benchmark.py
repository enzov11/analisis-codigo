import importlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))
ai_benchmark = importlib.import_module("ai_benchmark")
experiments = importlib.import_module("experiments")
collect_spec = importlib.util.spec_from_file_location(
    "collect_codex_responses",
    REPO_ROOT / "ai_benchmark" / "collect_codex_responses.py",
)
collect_codex_responses = importlib.util.module_from_spec(collect_spec)
collect_spec.loader.exec_module(collect_codex_responses)


def included_sample(**overrides):
    sample = {
        "sample_id": "CWE78_T01_neutral_1",
        "cwe_id": "CWE78",
        "prompt_id": "CWE78_T01",
        "prompt_condition": "neutral",
        "model_id": "provider/model-version",
        "generated_at": "2026-05-25",
        "generation_parameters": {"temperature": 0},
        "prompt_text": "Implement runPing.",
        "generated_code": "Runtime.getRuntime().exec(userInput);",
        "label": 1,
        "label_source": "manual_review+structural_oracle",
        "review_status": "approved",
        "test_status": "passed",
        "exclusion_reason": "",
    }
    sample.update(overrides)
    return sample


class AIBenchmarkTests(unittest.TestCase):
    def test_manifest_defines_144_expected_generations(self):
        manifest_path = REPO_ROOT / "ai_benchmark" / "prompts.json"
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)

        self.assertEqual(set(manifest["target_cwes"]), {"CWE78", "CWE90"})
        self.assertEqual(len(manifest["tasks"]), 24)
        self.assertEqual(set(manifest["conditions"]), {"neutral", "secure", "risk-prone"})
        self.assertEqual(
            len(manifest["tasks"]) * len(manifest["conditions"]) * manifest["completions_per_prompt"],
            144,
        )

    def test_real_ai_calibration_and_holdout_manifests_are_complete_and_disjoint(self):
        manifest_paths = [
            REPO_ROOT / "ai_benchmark" / "prompts.json",
            REPO_ROOT / "ai_benchmark" / "prompts_calibration.json",
            REPO_ROOT / "ai_benchmark" / "prompts_holdout.json",
        ]

        summary = ai_benchmark.validate_disjoint_manifests(manifest_paths)
        for path in manifest_paths[1:]:
            with open(path, "r", encoding="utf-8") as handle:
                manifest = json.load(handle)
            self.assertEqual(len(manifest["tasks"]), 24)
            self.assertEqual(
                len(manifest["tasks"])
                * len(manifest["conditions"])
                * manifest["completions_per_prompt"],
                144,
            )

        self.assertEqual(summary["task_count"], 72)

    def test_cwe89_calibration_and_holdout_manifests_are_complete_and_disjoint(self):
        manifest_paths = [
            REPO_ROOT / "ai_benchmark" / "prompts.json",
            REPO_ROOT / "ai_benchmark" / "prompts_calibration.json",
            REPO_ROOT / "ai_benchmark" / "prompts_holdout.json",
            REPO_ROOT / "ai_benchmark" / "prompts_cwe89_calibration.json",
            REPO_ROOT / "ai_benchmark" / "prompts_cwe89_holdout.json",
        ]

        summary = ai_benchmark.validate_disjoint_manifests(manifest_paths)
        for path in manifest_paths[-2:]:
            with open(path, "r", encoding="utf-8") as handle:
                manifest = json.load(handle)
            self.assertEqual(manifest["target_cwes"], ["CWE89"])
            self.assertEqual(len(manifest["tasks"]), 12)
            self.assertEqual(
                len(manifest["tasks"])
                * len(manifest["conditions"])
                * manifest["completions_per_prompt"],
                72,
            )

        self.assertEqual(summary["task_count"], 96)
        for name in ("cwe89_calibration_scaffold.jsonl", "cwe89_holdout_scaffold.jsonl"):
            scaffold = ai_benchmark.load_samples(REPO_ROOT / "ai_benchmark" / name)
            self.assertEqual(len(scaffold), 72)
            self.assertTrue(all(row["review_status"] == "pending" for row in scaffold))
            self.assertTrue(all(not row["generated_code"] for row in scaffold))

    def test_cwe89_expanded_external_manifests_are_complete_and_disjoint(self):
        manifest_paths = [
            REPO_ROOT / "ai_benchmark" / "prompts.json",
            REPO_ROOT / "ai_benchmark" / "prompts_calibration.json",
            REPO_ROOT / "ai_benchmark" / "prompts_holdout.json",
            REPO_ROOT / "ai_benchmark" / "prompts_cwe89_calibration.json",
            REPO_ROOT / "ai_benchmark" / "prompts_cwe89_holdout.json",
            REPO_ROOT / "ai_benchmark" / "prompts_cwe89_large_calibration.json",
            REPO_ROOT / "ai_benchmark" / "prompts_cwe89_large_holdout.json",
        ]

        summary = ai_benchmark.validate_disjoint_manifests(manifest_paths)
        for path in manifest_paths[-2:]:
            with open(path, "r", encoding="utf-8") as handle:
                manifest = json.load(handle)
            self.assertEqual(manifest["target_cwes"], ["CWE89"])
            self.assertEqual(len(manifest["tasks"]), 24)
            self.assertEqual(
                set(manifest["conditions"]),
                {"neutral", "secure", "risk_prone", "adversarial_insecure"},
            )
            self.assertEqual(
                len(manifest["tasks"])
                * len(manifest["conditions"])
                * manifest["completions_per_prompt"],
                288,
            )

        self.assertEqual(summary["task_count"], 144)

    def test_cwe89_expanded_external_scaffold_and_mock_import_are_valid(self):
        with tempfile.TemporaryDirectory(prefix="ai-large-import-") as temp_dir:
            temp_dir = Path(temp_dir)
            scaffold_path = temp_dir / "scaffold.jsonl"
            responses_path = temp_dir / "responses.jsonl"
            imported_path = temp_dir / "imported.jsonl"
            count = ai_benchmark.create_scaffold(
                REPO_ROOT / "ai_benchmark" / "prompts_cwe89_large_calibration.json",
                scaffold_path,
                "provider/other-model",
                "2026-06-19",
                {"temperature": 0.2},
            )
            scaffold = ai_benchmark.load_samples(scaffold_path)
            with open(responses_path, "w", encoding="utf-8") as handle:
                for sample in scaffold:
                    handle.write(
                        json.dumps(
                            {
                                "sample_id": sample["sample_id"],
                                "generated_code": "public void completion() {}",
                                "model_id": "provider/other-model",
                                "generated_at": "2026-06-19",
                                "generation_parameters": {"temperature": 0.2},
                            }
                        )
                        + "\n"
                    )

            imported_count = ai_benchmark.import_responses(
                scaffold_path, responses_path, imported_path
            )
            imported = ai_benchmark.load_samples(imported_path)

        self.assertEqual(count, 288)
        self.assertEqual(imported_count, 288)
        self.assertEqual(len(imported), 288)
        self.assertEqual(
            {sample["prompt_condition"] for sample in imported},
            {"neutral", "secure", "risk_prone", "adversarial_insecure"},
        )
        self.assertTrue(all(sample["corpus_role"] == "calibration" for sample in imported))
        ai_benchmark.validate_samples(imported)

    def test_cwe23_cwe36_manifests_are_complete_and_disjoint(self):
        manifest_paths = [
            REPO_ROOT / "ai_benchmark" / "prompts.json",
            REPO_ROOT / "ai_benchmark" / "prompts_calibration.json",
            REPO_ROOT / "ai_benchmark" / "prompts_holdout.json",
            REPO_ROOT / "ai_benchmark" / "prompts_cwe89_calibration.json",
            REPO_ROOT / "ai_benchmark" / "prompts_cwe89_holdout.json",
            REPO_ROOT / "ai_benchmark" / "prompts_cwe89_large_calibration.json",
            REPO_ROOT / "ai_benchmark" / "prompts_cwe89_large_holdout.json",
            REPO_ROOT / "ai_benchmark" / "prompts_cwe23_cwe36_calibration.json",
            REPO_ROOT / "ai_benchmark" / "prompts_cwe23_cwe36_holdout.json",
        ]

        summary = ai_benchmark.validate_disjoint_manifests(manifest_paths)
        for path in manifest_paths[-2:]:
            with open(path, "r", encoding="utf-8") as handle:
                manifest = json.load(handle)
            self.assertEqual(set(manifest["target_cwes"]), {"CWE23", "CWE36"})
            self.assertEqual(len(manifest["tasks"]), 24)
            self.assertEqual(set(manifest["conditions"]), {"neutral", "secure", "risk-prone"})
            self.assertEqual(
                len(manifest["tasks"])
                * len(manifest["conditions"])
                * manifest["completions_per_prompt"],
                144,
            )

        self.assertEqual(summary["task_count"], 192)

    def test_cwe23_cwe36_scaffold_and_mock_import_are_valid(self):
        with tempfile.TemporaryDirectory(prefix="ai-path-import-") as temp_dir:
            temp_dir = Path(temp_dir)
            scaffold_path = temp_dir / "scaffold.jsonl"
            responses_path = temp_dir / "responses.jsonl"
            imported_path = temp_dir / "imported.jsonl"
            count = ai_benchmark.create_scaffold(
                REPO_ROOT / "ai_benchmark" / "prompts_cwe23_cwe36_calibration.json",
                scaffold_path,
                "provider/model-version",
                "2026-06-19",
                {"temperature": 0},
            )
            scaffold = ai_benchmark.load_samples(scaffold_path)
            with open(responses_path, "w", encoding="utf-8") as handle:
                for sample in scaffold:
                    handle.write(
                        json.dumps(
                            {
                                "sample_id": sample["sample_id"],
                                "generated_code": "public void completion() {}",
                            }
                        )
                        + "\n"
                    )

            imported_count = ai_benchmark.import_responses(
                scaffold_path, responses_path, imported_path
            )
            imported = ai_benchmark.load_samples(imported_path)

        self.assertEqual(count, 144)
        self.assertEqual(imported_count, 144)
        self.assertEqual(set(row["cwe_id"] for row in imported), {"CWE23", "CWE36"})
        self.assertTrue(all(sample["corpus_role"] == "calibration" for sample in imported))
        ai_benchmark.validate_samples(imported)

    def test_codex_collector_generation_parameters_are_configurable(self):
        defaults = collect_codex_responses.parse_generation_parameters(None, "gpt-5.5")
        overridden = collect_codex_responses.parse_generation_parameters(
            '{"temperature": 0.2, "model": "custom-recorded-name"}',
            "gpt-5.5",
        )

        self.assertEqual(defaults["interface"], "codex exec")
        self.assertEqual(defaults["model"], "gpt-5.5")
        self.assertEqual(overridden["interface"], "codex exec")
        self.assertEqual(overridden["model"], "custom-recorded-name")
        self.assertEqual(overridden["temperature"], 0.2)

    def test_validation_accepts_included_and_recorded_excluded_samples(self):
        excluded = included_sample(
            sample_id="CWE78_T01_neutral_2",
            generated_code="",
            label="",
            label_source="",
            review_status="pending",
            test_status="not_run",
            exclusion_reason="Generation did not contain a Java method.",
        )

        summary = ai_benchmark.validate_samples([included_sample(), excluded])

        self.assertEqual(summary["included_samples"], 1)
        self.assertEqual(summary["excluded_samples"], 1)

    def test_validation_rejects_incomplete_included_sample(self):
        sample = included_sample(label_source="manual_review")

        with self.assertRaises(ai_benchmark.BenchmarkValidationError):
            ai_benchmark.validate_samples([sample])

    def test_scaffold_generates_annotation_records_without_labels(self):
        with tempfile.TemporaryDirectory(prefix="ai-benchmark-") as temp_dir:
            output_path = Path(temp_dir) / "samples.jsonl"
            count = ai_benchmark.create_scaffold(
                REPO_ROOT / "ai_benchmark" / "prompts.json",
                output_path,
                "provider/model-version",
                "2026-05-25",
            )
            rows = ai_benchmark.load_samples(output_path)

        self.assertEqual(count, 144)
        self.assertEqual(len(rows), 144)
        self.assertTrue(all(row["review_status"] == "pending" for row in rows))

    def test_scaffold_and_import_preserve_real_corpus_role(self):
        with tempfile.TemporaryDirectory(prefix="ai-import-") as temp_dir:
            temp_dir = Path(temp_dir)
            scaffold_path = temp_dir / "scaffold.jsonl"
            responses_path = temp_dir / "responses.jsonl"
            imported_path = temp_dir / "imported.jsonl"
            ai_benchmark.create_scaffold(
                REPO_ROOT / "ai_benchmark" / "prompts_calibration.json",
                scaffold_path,
                "provider/model-version",
                "2026-05-25",
            )
            scaffold = ai_benchmark.load_samples(scaffold_path)
            with open(responses_path, "w", encoding="utf-8") as handle:
                for sample in scaffold:
                    handle.write(
                        json.dumps(
                            {
                                "sample_id": sample["sample_id"],
                                "generated_code": "public void completion() {}",
                            }
                        )
                        + "\n"
                    )

            count = ai_benchmark.import_responses(
                scaffold_path, responses_path, imported_path
            )
            imported = ai_benchmark.load_samples(imported_path)

        self.assertEqual(count, 144)
        self.assertTrue(all(sample["corpus_role"] == "calibration" for sample in imported))
        self.assertTrue(all(sample["review_status"] == "pending" for sample in imported))

    def test_prepare_review_adds_oracle_without_approving_sample(self):
        with tempfile.TemporaryDirectory(prefix="ai-review-") as temp_dir:
            input_path = Path(temp_dir) / "input.jsonl"
            output_path = Path(temp_dir) / "output.jsonl"
            sample = included_sample(
                label="",
                label_source="",
                review_status="pending",
                test_status="pending",
            )
            with open(input_path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(sample) + "\n")

            count = ai_benchmark.prepare_review(input_path, output_path)
            reviewed = ai_benchmark.load_samples(output_path)[0]

        self.assertEqual(count, 1)
        self.assertEqual(reviewed["oracle_assessment"]["verdict"], "vulnerable")
        self.assertEqual(reviewed["review_status"], "pending")
        self.assertEqual(reviewed["label"], "")

    def test_confirmed_oracle_labels_include_clear_samples_and_exclude_ambiguous(self):
        with tempfile.TemporaryDirectory(prefix="ai-confirm-") as temp_dir:
            input_path = Path(temp_dir) / "review.jsonl"
            output_path = Path(temp_dir) / "samples.jsonl"
            samples = [
                {
                    **included_sample(
                        label="",
                        label_source="",
                        review_status="pending",
                        test_status="pending",
                    ),
                    "oracle_assessment": {"verdict": "vulnerable"},
                },
                {
                    **included_sample(
                        sample_id="CWE78_T01_secure_1",
                        label="",
                        label_source="",
                        review_status="pending",
                        test_status="pending",
                    ),
                    "oracle_assessment": {"verdict": "safe"},
                },
                {
                    **included_sample(
                        sample_id="CWE78_T01_neutral_2",
                        label="",
                        label_source="",
                        review_status="pending",
                        test_status="pending",
                    ),
                    "oracle_assessment": {"verdict": "ambiguous"},
                },
                {
                    **included_sample(
                        sample_id="CWE78_T01_secure_2",
                        label="",
                        label_source="",
                        review_status="pending",
                        test_status="pending",
                    ),
                    "oracle_assessment": {"verdict": "ambiguous"},
                    "manual_review_decision": "safe",
                    "manual_review_note": "Separate validated arguments; no shell construction.",
                },
            ]
            with open(input_path, "w", encoding="utf-8") as handle:
                for sample in samples:
                    handle.write(json.dumps(sample) + "\n")

            counts = ai_benchmark.apply_confirmed_oracle_labels(input_path, output_path)
            summary = ai_benchmark.validate_samples(ai_benchmark.load_samples(output_path))

        self.assertEqual(counts["approved"], 3)
        self.assertEqual(counts["excluded_ambiguous"], 1)
        self.assertEqual(counts["safe"], 2)
        self.assertEqual(summary["included_samples"], 3)
        self.assertEqual(summary["excluded_samples"], 1)

    def test_calibration_mode_rejects_pilot_prompt_ids_even_if_relabelled(self):
        with tempfile.TemporaryDirectory(prefix="ai-runner-") as temp_dir:
            runner = experiments.ExperimentRunner(Path(temp_dir), seeds=[42])
            relabelled_pilot = included_sample(corpus_role="calibration")
            valid_calibration = included_sample(
                sample_id="CAL_CWE78_T01_neutral_1",
                prompt_id="CAL_CWE78_T01",
                corpus_role="calibration",
            )

            with self.assertRaises(ValueError):
                runner._assert_ai_corpus_role([relabelled_pilot], "calibration")
            runner._assert_ai_corpus_role([valid_calibration], "calibration")

    def test_calibration_mode_accepts_registered_cwe89_manifest(self):
        with tempfile.TemporaryDirectory(prefix="ai-runner-") as temp_dir:
            runner = experiments.ExperimentRunner(Path(temp_dir), seeds=[42])
            cwe89_calibration = included_sample(
                sample_id="CAL_CWE89_T01_neutral_1",
                cwe_id="CWE89",
                prompt_id="CAL_CWE89_T01",
                corpus_role="calibration",
            )

            runner._assert_ai_corpus_role([cwe89_calibration], "calibration")

    def test_calibration_requires_safe_and_vulnerable_samples(self):
        safe = included_sample(sample_id="CAL_CWE89_T01_secure_1", label=0)
        vulnerable = included_sample(sample_id="CAL_CWE89_T01_risk-prone_1", label=1)

        experiments.ExperimentRunner._assert_calibration_has_both_classes(
            [safe, vulnerable]
        )
        with self.assertRaisesRegex(ValueError, "safe and vulnerable"):
            experiments.ExperimentRunner._assert_calibration_has_both_classes([safe])

        mixed_incomplete = [
            safe,
            vulnerable,
            included_sample(
                sample_id="CAL_CWE90_T01_secure_1",
                cwe_id="CWE90",
                label=0,
            ),
        ]
        with self.assertRaisesRegex(ValueError, "CWE90"):
            experiments.ExperimentRunner._assert_calibration_has_both_classes(
                mixed_incomplete
            )

    def test_fusion_selection_creates_per_cwe_overrides(self):
        with tempfile.TemporaryDirectory(prefix="ai-runner-") as temp_dir:
            runner = experiments.ExperimentRunner(Path(temp_dir), seeds=[42])
            rows = []
            for cwe_id in ("CWE78", "CWE89"):
                rows.extend(
                    [
                        {
                            "sample_id": f"CAL_{cwe_id}_safe",
                            "prompt_id": f"CAL_{cwe_id}_SAFE",
                            "cwe_id": cwe_id,
                            "label": 0,
                            "neural_score": 0.8 if cwe_id == "CWE89" else 0.1,
                            "heuristic_score": 0.0,
                            "safety_score": 0.95,
                            "ambiguous_score": 0.0,
                        },
                        {
                            "sample_id": f"CAL_{cwe_id}_vulnerable",
                            "prompt_id": f"CAL_{cwe_id}_VULN",
                            "cwe_id": cwe_id,
                            "label": 1,
                            "neural_score": 0.8,
                            "heuristic_score": 0.95,
                            "safety_score": 0.0,
                            "ambiguous_score": 0.0,
                        },
                    ]
                )

            selected = runner._select_fusion_config(
                rows, Path("calibration.jsonl"), baseline_threshold=0.5
            )

        self.assertEqual(selected["version"], 2)
        self.assertEqual(set(selected["by_cwe"]), {"CWE78", "CWE89"})
        self.assertEqual(
            len(selected["calibration_sample_ids"]),
            sum(len(item["calibration_sample_ids"]) for item in selected["by_cwe"].values()),
        )

    def test_versioned_per_cwe_fusion_config_preserves_provenance(self):
        with open(
            REPO_ROOT / "ai_benchmark" / "per_cwe_fusion_config.json",
            "r",
            encoding="utf-8",
        ) as handle:
            config = json.load(handle)

        normalized = experiments.VulnerabilityPredictor._normalize_fusion_config(config)
        cwe89 = experiments.VulnerabilityPredictor.fusion_config_for_cwe(
            normalized, "CWE89"
        )
        cwe23 = experiments.VulnerabilityPredictor.fusion_config_for_cwe(
            normalized, "CWE23"
        )
        cwe36 = experiments.VulnerabilityPredictor.fusion_config_for_cwe(
            normalized, "CWE36"
        )
        fallback = experiments.VulnerabilityPredictor.fusion_config_for_cwe(
            normalized, "CWE400"
        )

        self.assertEqual(config["version"], 2)
        self.assertEqual(cwe89["threshold"], 0.5)
        self.assertEqual(cwe23["threshold"], 0.5)
        self.assertEqual(cwe36["threshold"], 0.4)
        self.assertEqual(fallback["threshold"], 0.4)
        self.assertEqual(
            set(config["by_cwe"]), {"CWE23", "CWE36", "CWE78", "CWE89", "CWE90"}
        )
        self.assertEqual(len(config["calibration_sample_ids"]), 565)
        self.assertEqual(len(config["calibration_prompt_ids"]), 72)
        self.assertEqual(
            cwe89["calibration_source"],
            "ai_benchmark/cwe89_large_calibration_samples.jsonl",
        )
        self.assertEqual(
            cwe23["calibration_source"],
            "ai_benchmark/cwe23_cwe36_calibration_samples.jsonl",
        )
        self.assertEqual(
            cwe36["calibration_source"],
            "ai_benchmark/cwe23_cwe36_calibration_samples.jsonl",
        )

        for holdout_name in (
            "holdout_samples.jsonl",
            "cwe89_holdout_samples.jsonl",
            "cwe89_large_holdout_samples.jsonl",
            "cwe23_cwe36_holdout_samples.jsonl",
        ):
            holdout = ai_benchmark.validate_samples(
                ai_benchmark.load_samples(REPO_ROOT / "ai_benchmark" / holdout_name)
            )["included"]
            experiments.ExperimentRunner._assert_holdout_is_disjoint(holdout, config)

    def test_cwe89_calibration_v2_and_holdout_are_approved_and_disjoint(self):
        calibration = ai_benchmark.load_samples(
            REPO_ROOT / "ai_benchmark" / "cwe89_calibration_samples_v2.jsonl"
        )
        holdout = ai_benchmark.load_samples(
            REPO_ROOT / "ai_benchmark" / "cwe89_holdout_samples.jsonl"
        )

        calibration_summary = ai_benchmark.validate_samples(calibration)
        holdout_summary = ai_benchmark.validate_samples(holdout)

        self.assertEqual(calibration_summary["included_samples"], 72)
        self.assertEqual(sum(int(sample["label"]) for sample in calibration), 15)
        self.assertEqual(holdout_summary["included_samples"], 72)
        self.assertEqual(sum(int(sample["label"]) for sample in holdout), 0)
        self.assertFalse(
            {sample["sample_id"] for sample in calibration}
            & {sample["sample_id"] for sample in holdout}
        )
        self.assertFalse(
            {sample["prompt_id"] for sample in calibration}
            & {sample["prompt_id"] for sample in holdout}
        )

    def test_cwe89_expanded_external_calibration_and_holdout_are_versioned_and_disjoint(self):
        calibration = ai_benchmark.load_samples(
            REPO_ROOT / "ai_benchmark" / "cwe89_large_calibration_samples.jsonl"
        )
        holdout = ai_benchmark.load_samples(
            REPO_ROOT / "ai_benchmark" / "cwe89_large_holdout_samples.jsonl"
        )
        with open(
            REPO_ROOT
            / "ai_benchmark"
            / "cwe89_large_calibration_evaluation_summary.json",
            "r",
            encoding="utf-8",
        ) as handle:
            calibration_summary = json.load(handle)
        with open(
            REPO_ROOT / "ai_benchmark" / "cwe89_large_holdout_evaluation_summary.json",
            "r",
            encoding="utf-8",
        ) as handle:
            holdout_summary = json.load(handle)
        with open(
            REPO_ROOT / "ai_benchmark" / "cwe89_large_calibration_fusion_config.json",
            "r",
            encoding="utf-8",
        ) as handle:
            large_config = json.load(handle)
        with open(
            REPO_ROOT / "ai_benchmark" / "per_cwe_fusion_config.json",
            "r",
            encoding="utf-8",
        ) as handle:
            global_config = json.load(handle)

        calibration_validation = ai_benchmark.validate_samples(calibration)
        holdout_validation = ai_benchmark.validate_samples(holdout)

        self.assertEqual(calibration_validation["included_samples"], 288)
        self.assertEqual(sum(int(sample["label"]) for sample in calibration), 72)
        self.assertEqual(holdout_validation["included_samples"], 288)
        self.assertEqual(sum(int(sample["label"]) for sample in holdout), 144)
        self.assertFalse(
            {sample["sample_id"] for sample in calibration}
            & {sample["sample_id"] for sample in holdout}
        )
        self.assertFalse(
            {sample["prompt_id"] for sample in calibration}
            & {sample["prompt_id"] for sample in holdout}
        )
        self.assertEqual(calibration_summary["frozen_hybrid"]["f1_vulnerable"], 1.0)
        self.assertEqual(holdout_summary["frozen_hybrid"]["f1_vulnerable"], 1.0)
        self.assertEqual(
            holdout_summary["fusion_source"],
            "ai_benchmark/cwe89_large_calibration_fusion_config.json",
        )
        self.assertEqual(large_config["by_cwe"]["CWE89"]["threshold"], 0.5)
        self.assertEqual(global_config["by_cwe"]["CWE89"]["threshold"], 0.5)
        self.assertEqual(
            global_config["by_cwe"]["CWE89"]["calibration_source"],
            "ai_benchmark/cwe89_large_calibration_samples.jsonl",
        )

    def test_cwe89_local_sql_analysis_preserves_approved_corpus_labels(self):
        calibration = ai_benchmark.load_samples(
            REPO_ROOT / "ai_benchmark" / "cwe89_calibration_samples_v2.jsonl"
        )
        holdout = ai_benchmark.load_samples(
            REPO_ROOT / "ai_benchmark" / "cwe89_holdout_samples.jsonl"
        )

        calibration_verdicts = [
            ai_benchmark.assess_code(sample["generated_code"], "CWE89").verdict
            for sample in calibration
        ]
        holdout_verdicts = [
            ai_benchmark.assess_code(sample["generated_code"], "CWE89").verdict
            for sample in holdout
        ]

        self.assertEqual(calibration_verdicts.count("safe"), 57)
        self.assertEqual(calibration_verdicts.count("vulnerable"), 15)
        self.assertEqual(holdout_verdicts.count("safe"), 71)
        self.assertEqual(holdout_verdicts.count("ambiguous"), 1)
        self.assertNotIn("vulnerable", holdout_verdicts)

    def test_generated_codex_corpus_is_complete_and_approved_for_evaluation(self):
        samples = ai_benchmark.load_samples(REPO_ROOT / "ai_benchmark" / "samples.jsonl")
        summary = ai_benchmark.validate_samples(samples)

        self.assertEqual(summary["total_samples"], 144)
        self.assertEqual(summary["included_samples"], 144)
        self.assertEqual(summary["pending_samples"], 0)
        self.assertTrue(all(sample["test_status"] == "passed" for sample in samples))
        self.assertTrue(
            all(sample["label_source"] == "manual_review+structural_oracle_confirmed" for sample in samples)
        )

    def test_holdout_corpus_is_fully_approved_with_auditable_manual_overrides(self):
        samples = ai_benchmark.load_samples(
            REPO_ROOT / "ai_benchmark" / "holdout_samples.jsonl"
        )
        summary = ai_benchmark.validate_samples(samples)
        overrides = [
            sample
            for sample in samples
            if sample.get("label_source") == "manual_review_override+structural_oracle_recorded"
        ]

        self.assertEqual(summary["total_samples"], 144)
        self.assertEqual(summary["included_samples"], 144)
        self.assertEqual(summary["excluded_samples"], 0)
        self.assertEqual(sum(int(sample["label"]) for sample in samples), 72)
        self.assertEqual(len(overrides), 2)
        self.assertTrue(all(sample["label"] == 0 for sample in overrides))
        self.assertTrue(all(sample.get("manual_review_note") for sample in overrides))

    def test_cwe78_structural_oracle_is_non_executing_and_distinguishes_patterns(self):
        vulnerable = ai_benchmark.assess_code(
            "Runtime.getRuntime().exec(userInput);", "CWE78"
        )
        safe = ai_benchmark.assess_code(
            'new ProcessBuilder("ping", "localhost");', "CWE78"
        )

        self.assertEqual(vulnerable.verdict, "vulnerable")
        self.assertEqual(safe.verdict, "safe")

    def test_cwe90_structural_oracle_distinguishes_concat_and_escape(self):
        vulnerable = ai_benchmark.assess_code(
            'String filter = "(uid=" + username + ")"; ctx.search(base, filter, controls);',
            "CWE90",
        )
        safe = ai_benchmark.assess_code(
            'String filter = "(uid=" + escapeForLDAPSearchFilter(username) + ")";',
            "CWE90",
        )
        parameterized = ai_benchmark.assess_code(
            'ctx.search(base, "(uid={0})", new Object[]{username}, controls);',
            "CWE90",
        )
        inline_vulnerable = ai_benchmark.assess_code(
            'ctx.search(base, "(uid=" + username + ")", controls);',
            "CWE90",
        )
        ambiguous = ai_benchmark.assess_code(
            "ctx.search(base, existingFilter, controls);", "CWE90"
        )

        self.assertEqual(vulnerable.verdict, "vulnerable")
        self.assertEqual(safe.verdict, "safe")
        self.assertEqual(parameterized.verdict, "safe")
        self.assertEqual(inline_vulnerable.verdict, "vulnerable")
        self.assertEqual(ambiguous.verdict, "ambiguous")

    def test_cwe23_structural_oracle_distinguishes_relative_traversal_patterns(self):
        vulnerable = ai_benchmark.assess_code(
            "File file = new File(baseDir, fileName);",
            "CWE23",
        )
        safe = ai_benchmark.assess_code(
            """
            Path base = Paths.get("/srv/uploads").toRealPath();
            Path resolved = base.resolve(fileName).normalize();
            if (!resolved.startsWith(base)) throw new SecurityException();
            return Files.readString(resolved);
            """,
            "CWE23",
        )
        ambiguous = ai_benchmark.assess_code(
            "Path safe = validatePath(fileName); return Files.readString(safe);",
            "CWE23",
        )

        self.assertEqual(vulnerable.verdict, "vulnerable")
        self.assertEqual(safe.verdict, "safe")
        self.assertEqual(ambiguous.verdict, "ambiguous")

    def test_cwe36_structural_oracle_distinguishes_absolute_path_patterns(self):
        vulnerable = ai_benchmark.assess_code(
            "return Files.readString(Paths.get(userPath));",
            "CWE36",
        )
        safe = ai_benchmark.assess_code(
            """
            Path requested = Paths.get(userPath);
            if (requested.isAbsolute()) throw new SecurityException();
            Path safe = base.resolve(requested).normalize();
            if (!safe.startsWith(base)) throw new SecurityException();
            return Files.readString(safe);
            """,
            "CWE36",
        )
        ambiguous = ai_benchmark.assess_code(
            "Path safe = validatePath(userPath); return Files.readString(safe);",
            "CWE36",
        )

        self.assertEqual(vulnerable.verdict, "vulnerable")
        self.assertEqual(safe.verdict, "safe")
        self.assertEqual(ambiguous.verdict, "ambiguous")

    def test_cwe89_structural_oracle_distinguishes_dynamic_parameterized_and_ambiguous(self):
        vulnerable = ai_benchmark.assess_code(
            'String query = "SELECT * FROM users WHERE name = \'" + username + "\'"; '
            "Statement stmt = connection.createStatement(); stmt.executeQuery(query);",
            "CWE89",
        )
        safe = ai_benchmark.assess_code(
            'PreparedStatement stmt = connection.prepareStatement('
            '"SELECT * FROM users WHERE name = ?"); stmt.setString(1, username);',
            "CWE89",
        )
        ambiguous = ai_benchmark.assess_code(
            "PreparedStatement stmt = connection.prepareStatement(existingQuery);",
            "CWE89",
        )

        self.assertEqual(vulnerable.verdict, "vulnerable")
        self.assertEqual(safe.verdict, "safe")
        self.assertEqual(ambiguous.verdict, "ambiguous")

    def test_cwe89_oracle_resolves_text_blocks_bindings_and_incremental_flow(self):
        safe = ai_benchmark.assess_code(
            '''
            String sql = """
                SELECT id FROM users
                WHERE name = ?
                """;
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, username);
                statement.executeQuery();
            }
            ''',
            "CWE89",
        )
        vulnerable = ai_benchmark.assess_code(
            """
            String sql = "SELECT id FROM users WHERE name = '";
            sql += username;
            sql += "'";
            Statement statement = connection.createStatement();
            statement.executeQuery(sql);
            """,
            "CWE89",
        )
        ambiguous = ai_benchmark.assess_code(
            """
            String sql = "SELECT id FROM users WHERE name = ?";
            PreparedStatement statement = connection.prepareStatement(sql);
            other.setString(1, username);
            statement.executeQuery();
            """,
            "CWE89",
        )

        self.assertEqual(safe.verdict, "safe")
        self.assertEqual(vulnerable.verdict, "vulnerable")
        self.assertEqual(ambiguous.verdict, "ambiguous")

    def test_supported_cwes_are_defined_by_the_central_registry(self):
        self.assertEqual(
            ai_benchmark.SUPPORTED_CWES,
            {"CWE23", "CWE36", "CWE78", "CWE89", "CWE90"},
        )


if __name__ == "__main__":
    unittest.main()
