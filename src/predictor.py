import json
import pickle
import re
from typing import Dict, List

import numpy as np
from tensorflow.keras.models import load_model

from config import Config
from preprocessor import CodePreprocessor


class VulnerabilityPredictor:
    def __init__(self):
        self.config = Config()
        self.preprocessor = CodePreprocessor()
        self.model = None
        self.cwe_encoder = None
        self.metadata = {}
        self.load_artifacts()

        self.dangerous_patterns = [
            {
                "name": "runtime_exec",
                "pattern": r"Runtime\.getRuntime\(\)\.exec\(",
                "cwe_id": "CWE78",
                "confidence": 0.95,
                "description": "Dynamic command execution via Runtime.exec",
                "suggested_fix": "Use ProcessBuilder with a fixed command array and validated arguments.",
            },
            {
                "name": "process_builder",
                "pattern": r"new\s+ProcessBuilder\(",
                "cwe_id": "CWE78",
                "confidence": 0.75,
                "description": "ProcessBuilder usage requires input validation to avoid command injection.",
                "suggested_fix": "Build commands from trusted constants and validate all user-controlled values.",
            },
            {
                "name": "create_statement",
                "pattern": r"\b\w+\.createStatement\s*\(",
                "cwe_id": "CWE89",
                "confidence": 0.8,
                "description": "Statement creation detected; this often precedes non-parameterized SQL execution.",
                "suggested_fix": "Prefer PreparedStatement with parameterized queries.",
            },
            {
                "name": "dynamic_sql",
                "pattern": r"SELECT\s+.+?\s+FROM\s+.+?\s+WHERE\s+.+?[\"']\s*\+",
                "cwe_id": "CWE89",
                "confidence": 0.92,
                "description": "SQL query appears to concatenate user-controlled data.",
                "suggested_fix": "Replace string concatenation with parameter placeholders.",
            },
            {
                "name": "unsafe_load_library",
                "pattern": r"System\.loadLibrary\(",
                "cwe_id": "CWE114",
                "confidence": 0.8,
                "description": "Dynamic library loading can be dangerous when influenced by untrusted input.",
                "suggested_fix": "Restrict library names to a trusted allowlist.",
            },
            {
                "name": "unsafe_eval",
                "pattern": r"\.eval\(",
                "cwe_id": "CWE95",
                "confidence": 0.9,
                "description": "Dynamic evaluation detected.",
                "suggested_fix": "Avoid eval-like execution on untrusted content.",
            },
            {
                "name": "flaw_comment",
                "pattern": r"POTENTIAL FLAW",
                "cwe_id": None,
                "confidence": 0.65,
                "description": "Juliet marker indicates a potentially vulnerable path.",
                "suggested_fix": "Review the marked code path and compare it with the secure variant in the testcase.",
            },
        ]

    def load_artifacts(self):
        artifact_paths = self.config.get_artifact_paths()
        self.config.validate_prediction_artifacts()

        self.model = load_model(artifact_paths["model"])
        self.preprocessor.load_tokenizer(artifact_paths["tokenizer"])

        metadata_path = artifact_paths["metadata"]
        with open(metadata_path, "r", encoding="utf-8") as handle:
            self.metadata = json.load(handle)

        cwe_encoder_path = artifact_paths["cwe_encoder"]
        if cwe_encoder_path.exists():
            with open(cwe_encoder_path, "rb") as handle:
                self.cwe_encoder = pickle.load(handle)

    def predict(self, code: str) -> Dict[str, object]:
        processed_code = self.preprocessor.preprocess_code(code)
        sequence = self.preprocessor.text_to_sequence([processed_code])
        prediction = self.model.predict(sequence, verbose=0)

        if isinstance(prediction, list):
            main_output = prediction[0]
            cwe_output = prediction[1]
        else:
            main_output = prediction
            cwe_output = None

        model_probability = float(np.squeeze(main_output))
        cwe_candidates = self._decode_cwe_predictions(cwe_output)

        heuristic_matches = self._scan_patterns(code)
        heuristic_probability = (
            max(match["confidence"] for match in heuristic_matches)
            if heuristic_matches
            else 0.0
        )

        final_probability = max(model_probability, heuristic_probability)
        return {
            "model_probability": model_probability,
            "heuristic_probability": heuristic_probability,
            "final_probability": final_probability,
            "processed_code": processed_code,
            "cwe_candidates": cwe_candidates,
            "heuristic_matches": heuristic_matches,
        }

    def analyze_code(self, code: str) -> dict:
        prediction = self.predict(code)
        threshold = float(
            self.metadata.get("prediction_threshold", self.config.PREDICTION_THRESHOLD)
        )
        vulnerabilities = self._build_vulnerable_lines(prediction["heuristic_matches"])
        suggested_fixes = self._build_suggested_fixes(prediction["heuristic_matches"])
        probable_cwes = self._merge_cwe_candidates(
            prediction["cwe_candidates"], prediction["heuristic_matches"]
        )

        result = {
            "vulnerability_probability": prediction["final_probability"],
            "model_probability": prediction["model_probability"],
            "heuristic_probability": prediction["heuristic_probability"],
            "is_vulnerable": prediction["final_probability"] >= threshold,
            "threshold": threshold,
            "vulnerable_lines": vulnerabilities,
            "suggested_fixes": suggested_fixes,
            "processed_code": prediction["processed_code"],
            "detected_patterns": vulnerabilities,
            "heuristic_matches": prediction["heuristic_matches"],
            "probable_cwes": probable_cwes,
        }
        return result

    def _scan_patterns(self, code: str) -> List[Dict[str, object]]:
        matches: List[Dict[str, object]] = []
        for pattern_info in self.dangerous_patterns:
            if (
                pattern_info["name"] == "create_statement"
                and "PreparedStatement" in code
                and "createStatement(" not in code
            ):
                continue
            for match in re.finditer(pattern_info["pattern"], code, re.IGNORECASE):
                line_number = code[: match.start()].count("\n") + 1
                matches.append(
                    {
                        "pattern_name": pattern_info["name"],
                        "pattern": pattern_info["pattern"],
                        "line_number": line_number,
                        "code": match.group(0),
                        "confidence": pattern_info["confidence"],
                        "description": pattern_info["description"],
                        "cwe_id": pattern_info["cwe_id"],
                        "suggested_fix": pattern_info["suggested_fix"],
                        "source": "heuristic",
                    }
                )
        return matches

    def _decode_cwe_predictions(self, cwe_output) -> List[Dict[str, object]]:
        if cwe_output is None or self.cwe_encoder is None:
            return []

        probabilities = np.squeeze(cwe_output)
        if probabilities.ndim == 0:
            probabilities = np.array([float(probabilities)])

        top_indices = np.argsort(probabilities)[::-1][:3]
        candidates = []
        for index in top_indices:
            confidence = float(probabilities[index])
            if confidence <= 0:
                continue
            cwe_id = self.cwe_encoder.inverse_transform([index])[0]
            candidates.append(
                {
                    "cwe_id": cwe_id,
                    "confidence": confidence,
                    "description": self.config.TARGET_CWES.get(cwe_id, "Unknown CWE"),
                    "source": "model",
                }
            )
        return candidates

    def _build_vulnerable_lines(self, heuristic_matches: List[Dict[str, object]]):
        return [
            {
                "line_number": match["line_number"],
                "code": match["code"],
                "severity": match["confidence"],
                "cwe_id": match["cwe_id"],
                "description": match["description"],
                "source": match["source"],
            }
            for match in heuristic_matches
        ]

    def _build_suggested_fixes(self, heuristic_matches: List[Dict[str, object]]):
        fixes = []
        seen_keys = set()
        for match in heuristic_matches:
            key = (match["line_number"], match["cwe_id"], match["suggested_fix"])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            fixes.append(
                {
                    "line_number": match["line_number"],
                    "vulnerable_code": match["code"],
                    "suggested_fix": match["suggested_fix"],
                    "reference": match["cwe_id"] or "Heuristic review",
                    "source": match["source"],
                }
            )
        return fixes

    def _merge_cwe_candidates(
        self,
        model_candidates: List[Dict[str, object]],
        heuristic_matches: List[Dict[str, object]],
    ):
        merged: Dict[str, Dict[str, object]] = {}

        for candidate in model_candidates:
            merged[candidate["cwe_id"]] = candidate.copy()

        for match in heuristic_matches:
            cwe_id = match["cwe_id"]
            if not cwe_id:
                continue
            existing = merged.get(cwe_id)
            heuristic_candidate = {
                "cwe_id": cwe_id,
                "confidence": match["confidence"],
                "description": self.config.TARGET_CWES.get(cwe_id, "Unknown CWE"),
                "source": "heuristic",
            }
            if existing is None or heuristic_candidate["confidence"] > existing["confidence"]:
                merged[cwe_id] = heuristic_candidate

        return sorted(merged.values(), key=lambda item: item["confidence"], reverse=True)
