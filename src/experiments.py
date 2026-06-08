import argparse
import csv
import itertools
import json
import random
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd
import tensorflow as tf
from imblearn.over_sampling import RandomOverSampler
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.layers import (
    Bidirectional,
    Concatenate,
    Dense,
    Dropout,
    Embedding,
    GlobalMaxPooling1D,
    Input,
    LSTM,
    LayerNormalization,
    MultiHeadAttention,
)
from tensorflow.keras.models import Model
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.regularizers import l2

from config import Config
from data_loader import DataLoader
from preprocessor import CodePreprocessor
from predictor import VulnerabilityPredictor
from ai_benchmark import load_samples, validate_samples


DEFAULT_SEEDS = [42, 7, 13, 21, 100]
DEFAULT_THRESHOLDS = [round(value, 1) for value in np.arange(0.1, 1.0, 0.1)]


HEURISTIC_PATTERNS = [
    (r"Runtime\.getRuntime\(\)\.exec\(", 0.95, "CWE78"),
    (r"new\s+ProcessBuilder\(", 0.75, "CWE78"),
    (r"\b\w+\.createStatement\s*\(", 0.80, "CWE89"),
    (r"SELECT\s+.+?\s+FROM\s+.+?\s+WHERE\s+.+?[\"']\s*\+", 0.92, "CWE89"),
    (
        r"(?:\b(?:filter|query)\w*\s*=\s*[^;\n]*\+[^;\n]*;|"
        r"\.search\s*\(\s*[^,\n]*\+[^,\n]*,)",
        0.90,
        "CWE90",
    ),
    (r"System\.loadLibrary\(", 0.80, "CWE114"),
    (r"\.eval\(", 0.90, "CWE95"),
    (r"POTENTIAL FLAW", 0.65, None),
]


@dataclass
class ExperimentConfig:
    experiment: str
    seed: int
    variant: str
    use_attention: bool = True
    use_auxiliary_cwe: bool = True
    use_oversampling: bool = True
    use_heuristics: bool = True
    save_model: bool = False


def main():
    parser = argparse.ArgumentParser(
        description="Run reproducible experiments for the LNCS vulnerability detection paper."
    )
    parser.add_argument(
        "--experiment",
        choices=["all", "e1", "e2", "e3", "e4", "e5", "e6", "e7"],
        default="all",
        help="Experiment group to run.",
    )
    parser.add_argument(
        "--seeds",
        nargs="+",
        type=int,
        default=DEFAULT_SEEDS,
        help="Random seeds for repeated neural experiments.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(Config.SRC_DIR / "models" / "experiments"),
        help="Directory where experiment JSON and CSV results will be written.",
    )
    parser.add_argument(
        "--external-csv",
        help="Optional CSV for E5 with columns: code,label and optional cwe_id.",
    )
    parser.add_argument(
        "--ai-benchmark",
        help="Annotated CodeScan-AI JSONL/CSV corpus for pilot, calibration, or holdout evaluation.",
    )
    parser.add_argument(
        "--ai-mode",
        choices=["pilot", "calibration", "holdout"],
        default="pilot",
        help="Role of --ai-benchmark. Calibration selects fusion settings; holdout applies frozen settings.",
    )
    parser.add_argument(
        "--fusion-config",
        help="Fusion JSON produced by --ai-mode calibration; required for holdout.",
    )
    parser.add_argument(
        "--save-model",
        action="store_true",
        help="Persist trained Keras models for neural experiment runs.",
    )
    args = parser.parse_args()

    runner = ExperimentRunner(
        output_dir=Path(args.output_dir),
        seeds=args.seeds,
        save_model=args.save_model,
    )
    runner.run(
        args.experiment,
        external_csv=args.external_csv,
        ai_benchmark=args.ai_benchmark,
        ai_mode=args.ai_mode,
        fusion_config=args.fusion_config,
    )


class ExperimentRunner:
    def __init__(self, output_dir: Path, seeds: Iterable[int], save_model: bool = False):
        self.config = Config()
        self.output_dir = output_dir
        self.seeds = list(seeds)
        self.save_model = save_model
        self.data_loader = DataLoader()
        self.preprocessor = CodePreprocessor()

    def run(
        self,
        experiment: str,
        external_csv: Optional[str] = None,
        ai_benchmark: Optional[str] = None,
        ai_mode: str = "pilot",
        fusion_config: Optional[str] = None,
    ):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if experiment == "e5" and ai_benchmark:
            self.run_ai_generated_benchmark(
                Path(ai_benchmark),
                mode=ai_mode,
                fusion_config_path=Path(fusion_config) if fusion_config else None,
            )
            return

        df, _ = self.data_loader.load_dataset()

        if experiment in {"all", "e1"}:
            self.run_repeated_baseline(df)
        if experiment in {"all", "e2"}:
            self.run_ablation_study(df)
        if experiment in {"all", "e3"}:
            self.run_baselines(df)
        if experiment in {"all", "e4"}:
            self.run_cwe_generalization(df)
        if experiment in {"all", "e5"}:
            if ai_benchmark:
                self.run_ai_generated_benchmark(
                    Path(ai_benchmark),
                    mode=ai_mode,
                    fusion_config_path=Path(fusion_config) if fusion_config else None,
                )
            else:
                self.run_external_dataset(df, external_csv)
        if experiment in {"all", "e6"}:
            self.run_localization(df)
        if experiment in {"all", "e7"}:
            self.run_threshold_analysis(df)

    def run_repeated_baseline(self, df: pd.DataFrame):
        records = []
        for seed in self.seeds:
            cfg = ExperimentConfig(
                experiment="e1_repeated_juliet",
                seed=seed,
                variant="full_model",
                save_model=self.save_model,
            )
            records.append(self._run_neural_experiment(df, cfg))
        self._write_summary("e1_repeated_juliet", records)

    def run_ablation_study(self, df: pd.DataFrame):
        variants = [
            ExperimentConfig("e2_ablation", 42, "full_model", save_model=self.save_model),
            ExperimentConfig(
                "e2_ablation",
                42,
                "no_attention",
                use_attention=False,
                save_model=self.save_model,
            ),
            ExperimentConfig(
                "e2_ablation",
                42,
                "no_auxiliary_cwe",
                use_auxiliary_cwe=False,
                save_model=self.save_model,
            ),
            ExperimentConfig(
                "e2_ablation",
                42,
                "no_oversampling",
                use_oversampling=False,
                save_model=self.save_model,
            ),
            ExperimentConfig(
                "e2_ablation",
                42,
                "model_only_no_heuristics",
                use_heuristics=False,
                save_model=self.save_model,
            ),
        ]
        records = [self._run_neural_experiment(df, cfg) for cfg in variants]
        records.append(self._run_heuristic_only(df, "e2_ablation", 42))
        self._write_summary("e2_ablation", records)

    def run_baselines(self, df: pd.DataFrame):
        train_df, test_df = self._split(df, seed=42)
        records = [
            self._run_tfidf_baseline(
                "logistic_regression_tfidf",
                LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42),
                train_df,
                test_df,
            ),
            self._run_tfidf_baseline(
                "random_forest_tfidf",
                RandomForestClassifier(
                    n_estimators=200,
                    class_weight="balanced",
                    random_state=42,
                    n_jobs=-1,
                ),
                train_df,
                test_df,
            ),
            self._run_tfidf_baseline(
                "linear_svm_tfidf",
                LinearSVC(class_weight="balanced", random_state=42),
                train_df,
                test_df,
            ),
            self._run_neural_experiment(
                df,
                ExperimentConfig(
                    "e3_baselines",
                    42,
                    "blstm_no_attention",
                    use_attention=False,
                    save_model=self.save_model,
                ),
            ),
        ]
        self._write_summary("e3_baselines", records)

    def run_cwe_generalization(self, df: pd.DataFrame):
        records = []
        cwe_ids = sorted(df["cwe_id"].unique())
        for train_cwe in cwe_ids:
            for test_cwe in cwe_ids:
                if train_cwe == test_cwe:
                    continue
                train_df = df[df["cwe_id"] == train_cwe].reset_index(drop=True)
                test_df = df[df["cwe_id"] == test_cwe].reset_index(drop=True)
                if train_df["label"].nunique() < 2 or test_df["label"].nunique() < 2:
                    continue
                records.append(
                    self._run_neural_train_test(
                        train_df,
                        test_df,
                        ExperimentConfig(
                            "e4_cwe_generalization",
                            42,
                            f"train_{train_cwe}_test_{test_cwe}",
                            use_auxiliary_cwe=False,
                            save_model=self.save_model,
                        ),
                    )
                )
        self._write_summary("e4_cwe_generalization", records)

    def run_external_dataset(self, df: pd.DataFrame, external_csv: Optional[str]):
        if not external_csv:
            self._write_json(
                self.output_dir / "e5_external_dataset" / "manifest.json",
                {
                    "status": "skipped",
                    "reason": "Provide --external-csv with columns code,label and optional cwe_id.",
                    "recommended_sources": ["SARD/Juliet holdout", "Java CVE corpus", "Big-Vul/Draper as non-Java transfer references"],
                },
            )
            return

        external_df = pd.read_csv(external_csv)
        required = {"code", "label"}
        missing = required - set(external_df.columns)
        if missing:
            raise ValueError(f"External CSV missing required columns: {sorted(missing)}")
        if "cwe_id" not in external_df:
            external_df["cwe_id"] = "external"

        train_df, _ = self._split(df, seed=42)
        record = self._run_neural_train_test(
            train_df,
            external_df.reset_index(drop=True),
            ExperimentConfig("e5_external_dataset", 42, "juliet_train_external_test"),
        )
        self._write_summary("e5_external_dataset", [record])

    def run_ai_generated_benchmark(
        self,
        benchmark_path: Path,
        mode: str = "pilot",
        fusion_config_path: Optional[Path] = None,
    ):
        validation = validate_samples(load_samples(benchmark_path))
        included = validation["included"]
        target_dir = self.output_dir / f"e5_ai_{mode}"
        if not included:
            raise ValueError("The AI benchmark contains no included, validated samples.")
        if mode in {"calibration", "holdout"}:
            self._assert_ai_corpus_role(included, mode)
        if mode == "holdout" and not fusion_config_path:
            raise ValueError("AI holdout evaluation requires --fusion-config from calibration.")

        predictor = VulnerabilityPredictor(
            fusion_config_path=fusion_config_path if mode == "holdout" else None
        )
        if mode == "holdout":
            self._assert_holdout_is_disjoint(included, predictor.fusion_config)
        baseline_threshold = float(
            predictor.metadata.get("prediction_threshold", self.config.PREDICTION_THRESHOLD)
        )
        raw_predictions = self._collect_ai_predictions(predictor, included)
        if mode == "calibration":
            fusion_config = self._select_fusion_config(
                raw_predictions, benchmark_path, baseline_threshold
            )
            self._write_json(target_dir / "fusion_config.json", fusion_config)
        else:
            fusion_config = predictor.fusion_config

        threshold = (
            baseline_threshold
            if fusion_config.get("threshold") is None
            else float(fusion_config["threshold"])
        )
        predictions = []
        for row in raw_predictions:
            hybrid_score = VulnerabilityPredictor.fuse_scores(
                row["neural_score"],
                row["heuristic_score"],
                row["safety_score"],
                row["ambiguous_score"],
                fusion_config,
            )
            contextual_max_score = max(row["neural_score"], row["heuristic_score"])
            predictions.append(
                {
                    **row,
                    "contextual_max_score": contextual_max_score,
                    "hybrid_score": hybrid_score,
                    "neural_prediction": int(row["neural_score"] >= baseline_threshold),
                    "heuristic_prediction": int(row["heuristic_score"] >= baseline_threshold),
                    "contextual_max_prediction": int(contextual_max_score >= baseline_threshold),
                    "hybrid_prediction": int(hybrid_score >= threshold),
                }
            )

        overall = self._benchmark_variant_metrics(
            predictions, threshold, baseline_threshold
        )
        by_cwe = self._grouped_benchmark_metrics(
            predictions, "cwe_id", threshold, baseline_threshold
        )
        by_condition = self._grouped_benchmark_metrics(
            predictions, "prompt_condition", threshold, baseline_threshold
        )
        errors = [
            row for row in predictions if row["label"] != row["hybrid_prediction"]
        ]
        manifest = {
            "experiment": f"e5_ai_{mode}",
            "evaluation_type": {
                "pilot": "controlled_synthetic_pilot_diagnostic",
                "calibration": "real_ai_development_calibration",
                "holdout": "real_ai_frozen_holdout_evaluation",
            }[mode],
            "training_source": "Juliet persisted artifacts",
            "benchmark_source": str(benchmark_path),
            "threshold": threshold,
            "baseline_threshold": baseline_threshold,
            "fusion_config": fusion_config,
            "total_annotated_samples": validation["total_samples"],
            "included_samples": validation["included_samples"],
            "excluded_samples": validation["excluded_samples"],
            "model_id_values": sorted({str(row["model_id"]) for row in predictions}),
            "target_cwes": sorted({str(row["cwe_id"]) for row in predictions}),
            "note": {
                "pilot": "Controlled template-produced snippets are diagnostic only and are not evidence of observed LLM completions.",
                "calibration": "Real LLM completions in this development corpus may select fusion settings, but never train the Juliet model.",
                "holdout": "Real LLM completions are evaluated once using frozen fusion settings selected without these samples.",
            }[mode],
        }
        self._write_json(target_dir / "manifest.json", manifest)
        self._write_json(
            target_dir / "metrics.json",
            {
                "prevalence": self._benchmark_prevalence(predictions),
                "overall": overall,
                "by_cwe": by_cwe,
                "by_prompt_condition": by_condition,
            },
        )
        self._write_csv(target_dir / "predictions.csv", predictions)
        self._write_csv(target_dir / "errors_for_review.csv", errors)

    @staticmethod
    def _collect_ai_predictions(predictor, included):
        rows = []
        for sample in included:
            result = predictor.predict(str(sample["generated_code"]))
            rows.append(
                {
                    "sample_id": sample["sample_id"],
                    "cwe_id": sample["cwe_id"],
                    "prompt_id": sample["prompt_id"],
                    "prompt_condition": sample["prompt_condition"],
                    "model_id": sample["model_id"],
                    "label": int(sample["label"]),
                    "neural_score": result["neural_probability"],
                    "heuristic_score": result["heuristic_probability"],
                    "safety_score": result["safety_probability"],
                    "ambiguous_score": result["ambiguous_probability"],
                    "heuristic_evidence": json.dumps(result["heuristic_evidence"]),
                    "safety_evidence": json.dumps(result["safety_evidence"]),
                    "ambiguous_evidence": json.dumps(result["ambiguous_evidence"]),
                    "decision_reason": result["decision_reason"],
                }
            )
        return rows

    def _select_fusion_config(self, rows, benchmark_path, baseline_threshold):
        y_true = np.array([row["label"] for row in rows])
        candidates = []
        for model_weight, heuristic_weight, safety_discount, ambiguous_weight, threshold in itertools.product(
            [0.75, 1.0],
            [0.55, 0.75, 1.0],
            [0.20, 0.35, 0.50],
            [0.0, 0.15],
            [0.4, 0.5, 0.6],
        ):
            config = {
                "version": 1,
                "selection_source": "ai_calibration_set",
                "threshold": threshold,
                "model_weight": model_weight,
                "heuristic_weight": heuristic_weight,
                "safety_discount": safety_discount,
                "ambiguous_weight": ambiguous_weight,
            }
            scores = np.array(
                [
                    VulnerabilityPredictor.fuse_scores(
                        row["neural_score"],
                        row["heuristic_score"],
                        row["safety_score"],
                        row["ambiguous_score"],
                        config,
                    )
                    for row in rows
                ]
            )
            metrics = binary_metrics(y_true, scores, threshold)
            candidates.append((config, metrics))
        selected, metrics = max(
            candidates,
            key=lambda item: (
                item[1]["f1_vulnerable"],
                item[1]["precision_vulnerable"],
                item[1]["recall_vulnerable"],
                -item[1]["false_positives"],
            ),
        )
        selected.update(
            {
                "objective": "maximize_f1_vulnerable_then_precision_then_recall",
                "calibration_benchmark": str(benchmark_path),
                "calibration_sample_ids": sorted(str(row["sample_id"]) for row in rows),
                "calibration_prompt_ids": sorted({str(row["prompt_id"]) for row in rows}),
                "baseline_neural_threshold": baseline_threshold,
                "calibration_metrics": metrics,
                "informative_operating_points": self._operating_points(rows, selected),
            }
        )
        return selected

    @staticmethod
    def _operating_points(rows, fusion_config):
        y_true = np.array([row["label"] for row in rows])
        score_sets = []
        for threshold in DEFAULT_THRESHOLDS:
            scores = np.array(
                [
                    VulnerabilityPredictor.fuse_scores(
                        row["neural_score"],
                        row["heuristic_score"],
                        row["safety_score"],
                        row["ambiguous_score"],
                        fusion_config,
                    )
                    for row in rows
                ]
            )
            score_sets.append({"threshold": threshold, **binary_metrics(y_true, scores, threshold)})
        recall_point = max(
            score_sets,
            key=lambda item: (item["recall_vulnerable"], item["precision_vulnerable"]),
        )
        precision_point = max(
            score_sets,
            key=lambda item: (item["precision_vulnerable"], item["recall_vulnerable"]),
        )
        return {
            "recall_oriented_fusion_reference": recall_point,
            "precision_oriented_fusion_reference": precision_point,
        }

    def _assert_ai_corpus_role(self, included, expected_role):
        invalid = [
            str(sample["sample_id"])
            for sample in included
            if str(sample.get("corpus_role", "")).strip().lower() != expected_role
        ]
        if invalid:
            raise ValueError(
                f"AI {expected_role} mode requires corpus_role={expected_role} for every "
                f"included sample; invalid sample IDs: {invalid[:5]}"
            )
        manifest_path = (
            self.config.BASE_DIR / "ai_benchmark" / f"prompts_{expected_role}.json"
        )
        with open(manifest_path, "r", encoding="utf-8") as handle:
            expected_prompts = {
                str(task["prompt_id"]) for task in json.load(handle)["tasks"]
            }
        unexpected_prompts = sorted(
            {
                str(sample["prompt_id"])
                for sample in included
                if str(sample["prompt_id"]) not in expected_prompts
            }
        )
        if unexpected_prompts:
            raise ValueError(
                f"AI {expected_role} samples must originate from {manifest_path}; "
                f"unexpected prompt IDs: {unexpected_prompts[:5]}"
            )

    @staticmethod
    def _assert_holdout_is_disjoint(included, fusion_config):
        if fusion_config.get("selection_source") != "ai_calibration_set":
            raise ValueError(
                "AI holdout requires a fusion configuration selected from an AI calibration set."
            )
        calibration_samples = set(fusion_config.get("calibration_sample_ids", []))
        calibration_prompts = set(fusion_config.get("calibration_prompt_ids", []))
        sample_overlap = calibration_samples.intersection(
            str(sample["sample_id"]) for sample in included
        )
        prompt_overlap = calibration_prompts.intersection(
            str(sample["prompt_id"]) for sample in included
        )
        if sample_overlap or prompt_overlap:
            raise ValueError(
                "AI holdout overlaps calibration samples or prompts; use a disjoint holdout corpus."
            )

    def _benchmark_variant_metrics(
        self,
        rows: List[Dict[str, object]],
        hybrid_threshold: float,
        baseline_threshold: float,
    ):
        y_true = np.array([row["label"] for row in rows])
        metrics = {}
        for variant, score_field, threshold in (
            ("neural_only", "neural_score", baseline_threshold),
            ("heuristic_only", "heuristic_score", baseline_threshold),
            ("contextual_max_score", "contextual_max_score", baseline_threshold),
            ("recalibrated_hybrid", "hybrid_score", hybrid_threshold),
            ("hybrid", "hybrid_score", hybrid_threshold),
        ):
            scores = np.array([row[score_field] for row in rows])
            result = binary_metrics(y_true, scores, threshold)
            result["threshold"] = threshold
            result["roc_auc"] = safe_roc_auc(y_true, scores)
            metrics[variant] = result
        return metrics

    def _grouped_benchmark_metrics(
        self,
        rows: List[Dict[str, object]],
        group_field: str,
        hybrid_threshold: float,
        baseline_threshold: float,
    ):
        groups = {}
        for group_value in sorted({str(row[group_field]) for row in rows}):
            group_rows = [row for row in rows if str(row[group_field]) == group_value]
            groups[group_value] = {
                **self._benchmark_prevalence(group_rows),
                "metrics": self._benchmark_variant_metrics(
                    group_rows, hybrid_threshold, baseline_threshold
                ),
            }
        return groups

    @staticmethod
    def _benchmark_prevalence(rows: List[Dict[str, object]]):
        vulnerable = sum(int(row["label"]) for row in rows)
        total = len(rows)
        return {
            "num_samples": total,
            "safe_samples": total - vulnerable,
            "vulnerable_samples": vulnerable,
            "vulnerability_rate": safe_divide(vulnerable, total),
        }

    def run_localization(self, df: pd.DataFrame):
        records = []
        vulnerable_df = df[df["label"] == 1].reset_index(drop=True)
        for _, row in vulnerable_df.iterrows():
            expected_lines = extract_expected_vulnerable_lines(row["code"])
            predicted_lines = [match["line_number"] for match in scan_heuristics(row["code"])]
            if not expected_lines:
                continue
            records.append(
                {
                    "sample_name": row.get("sample_name", ""),
                    "cwe_id": row.get("cwe_id", ""),
                    "expected_lines": expected_lines,
                    "predicted_lines": predicted_lines,
                    "top1_hit": int(bool(predicted_lines) and predicted_lines[0] in expected_lines),
                    "top3_hit": int(any(line in expected_lines for line in predicted_lines[:3])),
                    "line_recall": safe_divide(
                        len(set(expected_lines).intersection(predicted_lines)),
                        len(set(expected_lines)),
                    ),
                    "num_marked_lines": len(predicted_lines),
                }
            )

        summary = {
            "experiment": "e6_localization",
            "num_evaluable_samples": len(records),
            "top1_line_accuracy": mean_metric(records, "top1_hit"),
            "top3_line_accuracy": mean_metric(records, "top3_hit"),
            "mean_line_recall": mean_metric(records, "line_recall"),
            "mean_marked_lines": mean_metric(records, "num_marked_lines"),
        }
        target_dir = self.output_dir / "e6_localization"
        self._write_json(target_dir / "summary.json", summary)
        self._write_csv(target_dir / "localization_records.csv", records)

    def run_threshold_analysis(self, df: pd.DataFrame):
        train_df, test_df = self._split(df, seed=42)
        raw = self._fit_predict_neural(
            train_df,
            test_df,
            ExperimentConfig(
                "e7_threshold_analysis",
                42,
                "full_model_threshold_scan",
                save_model=self.save_model,
            ),
        )
        y_true = raw["y_test"]
        scores = raw["scores"]
        records = []
        for threshold in DEFAULT_THRESHOLDS:
            metrics = binary_metrics(y_true, scores, threshold)
            metrics["threshold"] = threshold
            records.append(metrics)

        fpr, tpr, roc_thresholds = roc_curve(y_true, scores)
        precision, recall, pr_thresholds = precision_recall_curve(y_true, scores)
        target_dir = self.output_dir / "e7_threshold_analysis"
        self._write_csv(target_dir / "threshold_metrics.csv", records)
        self._write_json(
            target_dir / "curves.json",
            {
                "roc_curve": {
                    "fpr": fpr.tolist(),
                    "tpr": tpr.tolist(),
                    "thresholds": roc_thresholds.tolist(),
                },
                "precision_recall_curve": {
                    "precision": precision.tolist(),
                    "recall": recall.tolist(),
                    "thresholds": pr_thresholds.tolist(),
                },
            },
        )

    def _run_neural_experiment(self, df: pd.DataFrame, cfg: ExperimentConfig):
        train_df, test_df = self._split(df, seed=cfg.seed)
        return self._run_neural_train_test(train_df, test_df, cfg)

    def _run_neural_train_test(
        self,
        train_df: pd.DataFrame,
        test_df: pd.DataFrame,
        cfg: ExperimentConfig,
    ):
        started = time.perf_counter()
        raw = self._fit_predict_neural(train_df, test_df, cfg)
        training_seconds = time.perf_counter() - started

        scores = raw["scores"]
        if cfg.use_heuristics:
            heuristic_scores = np.array([heuristic_probability(code) for code in test_df["code"]])
            scores = np.maximum(scores, heuristic_scores)

        record = binary_metrics(raw["y_test"], scores, self.config.PREDICTION_THRESHOLD)
        record.update(
            {
                "experiment": cfg.experiment,
                "variant": cfg.variant,
                "seed": cfg.seed,
                "roc_auc": safe_roc_auc(raw["y_test"], scores),
                "training_seconds": training_seconds,
                "mean_inference_ms": raw["mean_inference_ms"],
                "config": asdict(cfg),
            }
        )
        if raw["cwe_report"] is not None:
            record["cwe_classification_report"] = raw["cwe_report"]

        run_dir = self.output_dir / cfg.experiment / cfg.variant / str(cfg.seed)
        self._write_json(run_dir / "metrics.json", record)
        return record

    def _fit_predict_neural(
        self,
        train_df: pd.DataFrame,
        test_df: pd.DataFrame,
        cfg: ExperimentConfig,
    ):
        set_seed(cfg.seed)
        preprocessor = CodePreprocessor()
        X_train, y_train, _ = preprocessor.prepare_dataset(train_df, fit_tokenizer=True)
        X_test, y_test, _ = preprocessor.prepare_dataset(test_df, fit_tokenizer=False)

        cwe_encoder = LabelEncoder()
        all_cwes = pd.concat([train_df["cwe_id"], test_df["cwe_id"]]).astype(str)
        cwe_encoder.fit(all_cwes)
        cwe_train = cwe_encoder.transform(train_df["cwe_id"].astype(str))
        cwe_test = cwe_encoder.transform(test_df["cwe_id"].astype(str))
        num_cwes = len(cwe_encoder.classes_)
        use_aux = cfg.use_auxiliary_cwe and num_cwes > 1

        X_train, y_train, cwe_train = balance_if_needed(
            X_train,
            y_train,
            cwe_train,
            cfg.use_oversampling,
            cfg.seed,
            self.config.MAX_CODE_LENGTH,
            use_aux,
        )
        X_test = np.array(X_test).reshape(-1, self.config.MAX_CODE_LENGTH)
        y_test = np.array(y_test)
        cwe_test = np.array(cwe_test)

        model = build_sequence_model(
            config=self.config,
            vocab_size=len(preprocessor.tokenizer.word_index) + 1,
            num_cwe_types=num_cwes,
            use_attention=cfg.use_attention,
            use_auxiliary_cwe=use_aux,
        )
        callbacks = [EarlyStopping(patience=5, restore_best_weights=True)]

        if use_aux:
            model.fit(
                x=X_train,
                y={"main": y_train, "cwe_type": cwe_train},
                validation_data=(X_test, {"main": y_test, "cwe_type": cwe_test}),
                batch_size=self.config.BATCH_SIZE,
                epochs=self.config.EPOCHS,
                callbacks=callbacks,
                verbose=self.config.TRAINING_VERBOSE,
            )
        else:
            model.fit(
                X_train,
                y_train,
                validation_data=(X_test, y_test),
                batch_size=self.config.BATCH_SIZE,
                epochs=self.config.EPOCHS,
                callbacks=callbacks,
                verbose=self.config.TRAINING_VERBOSE,
            )

        inference_started = time.perf_counter()
        predictions = model.predict(X_test, verbose=0)
        inference_seconds = time.perf_counter() - inference_started
        if isinstance(predictions, list):
            scores = predictions[0].reshape(-1)
            cwe_predictions = predictions[1]
        else:
            scores = predictions.reshape(-1)
            cwe_predictions = None

        cwe_report = None
        if cwe_predictions is not None:
            cwe_labels = np.argmax(cwe_predictions, axis=1)
            cwe_report = classification_report(
                cwe_test,
                cwe_labels,
                output_dict=True,
                zero_division=0,
            )

        if cfg.save_model:
            model_dir = self.output_dir / cfg.experiment / cfg.variant / str(cfg.seed)
            model_dir.mkdir(parents=True, exist_ok=True)
            model.save(model_dir / "model.keras")

        return {
            "y_test": y_test,
            "scores": scores,
            "cwe_report": cwe_report,
            "mean_inference_ms": safe_divide(inference_seconds * 1000, len(X_test)),
        }

    def _run_tfidf_baseline(self, name: str, estimator, train_df, test_df):
        started = time.perf_counter()
        preprocessor = CodePreprocessor()
        pipeline = Pipeline(
            [
                (
                    "tfidf",
                    TfidfVectorizer(
                        preprocessor=preprocessor.preprocess_code,
                        lowercase=False,
                    ),
                ),
                ("classifier", estimator),
            ]
        )
        pipeline.fit(train_df["code"], train_df["label"].astype(int))
        training_seconds = time.perf_counter() - started

        inference_started = time.perf_counter()
        predictions = pipeline.predict(test_df["code"])
        inference_seconds = time.perf_counter() - inference_started
        scores = estimator_scores(pipeline, test_df["code"], predictions)

        record = binary_metrics(
            test_df["label"].astype(int).to_numpy(),
            scores,
            0.5,
            y_pred=predictions,
        )
        record.update(
            {
                "experiment": "e3_baselines",
                "variant": name,
                "seed": 42,
                "roc_auc": safe_roc_auc(test_df["label"].astype(int).to_numpy(), scores),
                "training_seconds": training_seconds,
                "mean_inference_ms": safe_divide(inference_seconds * 1000, len(test_df)),
            }
        )
        run_dir = self.output_dir / "e3_baselines" / name / "42"
        self._write_json(run_dir / "metrics.json", record)
        return record

    def _run_heuristic_only(self, df: pd.DataFrame, experiment: str, seed: int):
        _, test_df = self._split(df, seed=seed)
        y_true = test_df["label"].astype(int).to_numpy()
        scores = np.array([heuristic_probability(code) for code in test_df["code"]])
        record = binary_metrics(y_true, scores, self.config.PREDICTION_THRESHOLD)
        record.update(
            {
                "experiment": experiment,
                "variant": "heuristics_only",
                "seed": seed,
                "roc_auc": safe_roc_auc(y_true, scores),
                "training_seconds": 0.0,
                "mean_inference_ms": None,
            }
        )
        run_dir = self.output_dir / experiment / "heuristics_only" / str(seed)
        self._write_json(run_dir / "metrics.json", record)
        return record

    def _split(self, df: pd.DataFrame, seed: int):
        original_seed = self.config.RANDOM_SEED
        original_loader_seed = self.data_loader.config.RANDOM_SEED
        self.config.RANDOM_SEED = seed
        self.data_loader.config.RANDOM_SEED = seed
        try:
            return self.data_loader.split_dataset(df)
        finally:
            self.config.RANDOM_SEED = original_seed
            self.data_loader.config.RANDOM_SEED = original_loader_seed

    def _write_summary(self, experiment: str, records: List[Dict[str, object]]):
        target_dir = self.output_dir / experiment
        self._write_json(target_dir / "summary.json", aggregate_records(records))
        self._write_csv(target_dir / "runs.csv", flatten_records(records))

    @staticmethod
    def _write_json(path: Path, payload: Dict[str, object]):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    @staticmethod
    def _write_csv(path: Path, rows: List[Dict[str, object]]):
        path.parent.mkdir(parents=True, exist_ok=True)
        if not rows:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("")
            return
        fieldnames = sorted({key for row in rows for key in row.keys()})
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)


def build_sequence_model(
    config: Config,
    vocab_size: int,
    num_cwe_types: int,
    use_attention: bool,
    use_auxiliary_cwe: bool,
) -> Model:
    inputs = Input(shape=(config.MAX_CODE_LENGTH,))
    embedding = Embedding(
        input_dim=vocab_size,
        output_dim=config.EMBEDDING_DIM,
        input_length=config.MAX_CODE_LENGTH,
        mask_zero=False,
        embeddings_regularizer=l2(0.01),
    )(inputs)
    blstm1 = Bidirectional(
        LSTM(config.LSTM_UNITS, return_sequences=True, kernel_regularizer=l2(0.01))
    )(embedding)
    blstm1 = LayerNormalization()(blstm1)
    blstm2 = Bidirectional(
        LSTM(config.LSTM_UNITS // 2, return_sequences=True, kernel_regularizer=l2(0.01))
    )(blstm1)
    blstm2 = LayerNormalization()(blstm2)

    if use_attention:
        query = Dense(64)(blstm2)
        key = Dense(64)(blstm2)
        value = Dense(64)(blstm2)
        attention_output = MultiHeadAttention(num_heads=4, key_dim=16, value_dim=16)(
            query, key, value
        )
        features = Concatenate()([blstm2, attention_output])
        features = LayerNormalization()(features)
    else:
        features = blstm2

    pooled = GlobalMaxPooling1D()(features)
    dense1 = Dense(config.DENSE_UNITS, activation="relu")(pooled)
    dense1 = Dropout(config.DROPOUT_RATE)(dense1)
    dense2 = Dense(config.DENSE_UNITS // 2, activation="relu")(dense1)
    dense2 = Dropout(config.DROPOUT_RATE)(dense2)
    main_output = Dense(1, activation="sigmoid", name="main")(dense2)

    if use_auxiliary_cwe:
        cwe_output = Dense(num_cwe_types, activation="softmax", name="cwe_type")(pooled)
        model = Model(inputs=inputs, outputs=[main_output, cwe_output])
        model.compile(
            optimizer=Adam(learning_rate=config.LEARNING_RATE),
            loss={"main": "binary_crossentropy", "cwe_type": "sparse_categorical_crossentropy"},
            metrics={"main": ["accuracy"], "cwe_type": ["accuracy"]},
            loss_weights={"main": 0.8, "cwe_type": 0.2},
        )
    else:
        model = Model(inputs=inputs, outputs=main_output)
        model.compile(
            optimizer=Adam(learning_rate=config.LEARNING_RATE),
            loss="binary_crossentropy",
            metrics=["accuracy"],
        )
    return model


def balance_if_needed(X_train, y_train, cwe_train, enabled, seed, max_length, use_aux):
    X_train = np.array(X_train)
    y_train = np.array(y_train)
    cwe_train = np.array(cwe_train)
    if not enabled:
        return X_train.reshape(-1, max_length), y_train, cwe_train

    if use_aux:
        groups = np.array([f"{label}_{cwe}" for label, cwe in zip(y_train, cwe_train)])
        indices = np.arange(len(X_train))
        ros = RandomOverSampler(random_state=seed)
        resampled_indices, _ = ros.fit_resample(indices.reshape(-1, 1), groups)
        resampled_indices = resampled_indices.flatten()
        return (
            X_train[resampled_indices].reshape(-1, max_length),
            y_train[resampled_indices],
            cwe_train[resampled_indices],
        )

    ros = RandomOverSampler(random_state=seed)
    X_resampled, y_resampled = ros.fit_resample(X_train.reshape(X_train.shape[0], -1), y_train)
    return X_resampled.reshape(-1, max_length), y_resampled, cwe_train


def binary_metrics(y_true, scores, threshold, y_pred=None):
    y_true = np.array(y_true).astype(int)
    scores = np.array(scores)
    if y_pred is None:
        y_pred = (scores >= threshold).astype(int)
    else:
        y_pred = np.array(y_pred).astype(int)
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    confusion = confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_vulnerable": float(report.get("1", {}).get("precision", 0.0)),
        "recall_vulnerable": float(report.get("1", {}).get("recall", 0.0)),
        "f1_vulnerable": float(report.get("1", {}).get("f1-score", 0.0)),
        "false_positives": int(confusion[0][1]) if len(confusion) == 2 else None,
        "false_negatives": int(confusion[1][0]) if len(confusion) == 2 else None,
        "confusion_matrix": confusion,
    }


def estimator_scores(pipeline: Pipeline, X, predictions):
    classifier = pipeline.named_steps["classifier"]
    if hasattr(classifier, "predict_proba"):
        return pipeline.predict_proba(X)[:, 1]
    if hasattr(classifier, "decision_function"):
        raw_scores = pipeline.decision_function(X)
        min_score = np.min(raw_scores)
        max_score = np.max(raw_scores)
        if max_score == min_score:
            return np.zeros_like(raw_scores, dtype=float)
        return (raw_scores - min_score) / (max_score - min_score)
    return np.array(predictions, dtype=float)


def scan_heuristics(code: str):
    matches = []
    for pattern, confidence, cwe_id in HEURISTIC_PATTERNS:
        for match in re.finditer(pattern, code, re.IGNORECASE | re.DOTALL):
            matches.append(
                {
                    "line_number": code[: match.start()].count("\n") + 1,
                    "confidence": confidence,
                    "cwe_id": cwe_id,
                    "matched_text": match.group(0),
                }
            )
    return sorted(matches, key=lambda item: item["confidence"], reverse=True)


def heuristic_probability(code: str):
    matches = scan_heuristics(code)
    if not matches:
        return 0.0
    return max(match["confidence"] for match in matches)


def extract_expected_vulnerable_lines(code: str):
    lines = code.splitlines()
    expected = []
    for index, line in enumerate(lines, start=1):
        if "POTENTIAL FLAW" not in line:
            continue
        expected.append(index)
        for candidate_index in range(index + 1, min(index + 5, len(lines) + 1)):
            candidate = lines[candidate_index - 1].strip()
            if candidate and not candidate.startswith("*") and not candidate.startswith("//"):
                expected.append(candidate_index)
                break
    return sorted(set(expected))


def set_seed(seed: int):
    random.seed(seed)
    np.random.seed(seed)
    tf.random.set_seed(seed)


def safe_roc_auc(y_true, scores):
    if len(np.unique(y_true)) < 2:
        return None
    try:
        return float(roc_auc_score(y_true, scores))
    except ValueError:
        return None


def safe_divide(numerator, denominator):
    return float(numerator / denominator) if denominator else 0.0


def mean_metric(records: List[Dict[str, object]], key: str):
    values = [record[key] for record in records if record.get(key) is not None]
    return float(np.mean(values)) if values else None


def aggregate_records(records: List[Dict[str, object]]):
    if not records:
        return {"num_runs": 0}
    metrics = [
        "accuracy",
        "precision_vulnerable",
        "recall_vulnerable",
        "f1_vulnerable",
        "roc_auc",
        "false_positives",
        "false_negatives",
        "training_seconds",
        "mean_inference_ms",
    ]
    summary = {"num_runs": len(records), "runs": flatten_records(records)}
    for metric in metrics:
        values = [record[metric] for record in records if record.get(metric) is not None]
        if values:
            summary[f"{metric}_mean"] = float(np.mean(values))
            summary[f"{metric}_std"] = float(np.std(values))
    return summary


def flatten_records(records: List[Dict[str, object]]):
    flattened = []
    for record in records:
        row = {}
        for key, value in record.items():
            if isinstance(value, (dict, list)):
                row[key] = json.dumps(value)
            else:
                row[key] = value
        flattened.append(row)
    return flattened


if __name__ == "__main__":
    main()
