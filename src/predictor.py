import json
import pickle
import re
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
from tensorflow.keras.models import load_model

from array_index_analysis import analyze_array_index
from cleartext_transmission_analysis import analyze_cleartext_transmission
from format_string_analysis import analyze_format_string
from integer_overflow_analysis import analyze_integer_overflow
from config import Config
from cwe_registry import CWE_REGISTRY
from http_response_splitting_analysis import analyze_http_response_splitting
from path_traversal_analysis import analyze_path_traversal
from preprocessor import CodePreprocessor
from sql_analysis import analyze_sql
from xss_analysis import analyze_xss


class VulnerabilityPredictor:
    DEFAULT_FUSION_CONFIG = {
        "version": 1,
        "selection_source": "built_in_contextual_fusion",
        "threshold": None,
        "model_weight": 1.0,
        "heuristic_weight": 1.0,
        "safety_discount": 0.35,
        "ambiguous_weight": 0.15,
    }
    FUSION_FIELDS = {
        "threshold",
        "model_weight",
        "heuristic_weight",
        "safety_discount",
        "ambiguous_weight",
    }

    def __init__(
        self,
        fusion_config_path: Optional[Path] = None,
        fusion_config: Optional[Dict[str, object]] = None,
    ):
        self.config = Config()
        self.preprocessor = CodePreprocessor()
        self.model = None
        self.cwe_encoder = None
        self.metadata = {}
        self.load_artifacts()
        self.fusion_config = self._load_fusion_config(fusion_config_path, fusion_config)

        self.dangerous_patterns = [
            {
                "name": "flaw_comment",
                "pattern": r"POTENTIAL FLAW",
                "cwe_id": None,
                "confidence": 0.65,
                "description": "Juliet marker indicates a potentially vulnerable path.",
                "suggested_fix": "Review the marked code path and compare it with the secure variant in the testcase.",
            },
        ]

    def _load_fusion_config(
        self,
        fusion_config_path: Optional[Path],
        fusion_config: Optional[Dict[str, object]],
    ) -> Dict[str, object]:
        selected: Dict[str, object] = {}
        if fusion_config_path:
            with open(fusion_config_path, "r", encoding="utf-8") as handle:
                selected.update(json.load(handle))
        if fusion_config:
            selected.update(fusion_config)
        return self._normalize_fusion_config(selected or self.DEFAULT_FUSION_CONFIG)

    @classmethod
    def _normalize_fusion_config(cls, config: Dict[str, object]) -> Dict[str, object]:
        if not isinstance(config, dict):
            raise ValueError("Fusion configuration must be a JSON object.")
        version = int(config.get("version", 1))
        if version == 1:
            selected = dict(cls.DEFAULT_FUSION_CONFIG)
            selected.update(config)
            cls._validate_fusion_parameters(selected, "global fusion configuration")
            return selected
        if version != 2:
            raise ValueError(f"Unsupported fusion configuration version: {version}")

        default_override = config.get("default", {})
        by_cwe_override = config.get("by_cwe", {})
        if not isinstance(default_override, dict):
            raise ValueError("Fusion configuration default must be a JSON object.")
        if not isinstance(by_cwe_override, dict):
            raise ValueError("Fusion configuration by_cwe must be a JSON object.")
        default = dict(cls.DEFAULT_FUSION_CONFIG)
        default.update(default_override)
        cls._validate_fusion_parameters(default, "default fusion configuration")
        by_cwe = {}
        for cwe_id, override in by_cwe_override.items():
            if cwe_id not in CWE_REGISTRY:
                raise ValueError(f"Fusion configuration contains unknown CWE: {cwe_id}")
            if not isinstance(override, dict):
                raise ValueError(f"Fusion override for {cwe_id} must be a JSON object.")
            effective = dict(default)
            effective.update(override)
            cls._validate_fusion_parameters(effective, f"fusion override for {cwe_id}")
            by_cwe[cwe_id] = dict(override)

        selected = dict(config)
        selected["version"] = 2
        selected["default"] = default
        selected["by_cwe"] = by_cwe
        return selected

    @classmethod
    def _validate_fusion_parameters(cls, config: Dict[str, object], label: str):
        missing = cls.FUSION_FIELDS - set(config)
        if missing:
            raise ValueError(f"{label} is missing fields: {sorted(missing)}")
        for field in cls.FUSION_FIELDS:
            value = config[field]
            if field == "threshold" and value is None:
                continue
            try:
                numeric = float(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{label} has a non-numeric {field}.") from exc
            if numeric < 0:
                raise ValueError(f"{label} requires non-negative {field}.")

    def resolve_fusion_config(self, cwe_id: Optional[str] = None) -> Dict[str, object]:
        return self.fusion_config_for_cwe(self.fusion_config, cwe_id)

    @staticmethod
    def fusion_config_for_cwe(
        fusion_config: Dict[str, object], cwe_id: Optional[str] = None
    ) -> Dict[str, object]:
        if int(fusion_config.get("version", 1)) == 1:
            return fusion_config
        selected = dict(fusion_config["default"])
        if cwe_id:
            selected.update(fusion_config["by_cwe"].get(cwe_id, {}))
        selected["version"] = 2
        return selected

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

        evidence = self._scan_evidence(code)
        heuristic_matches = evidence["vulnerable"]
        safety_evidence = evidence["safety"]
        ambiguous_evidence = evidence["ambiguous"]
        heuristic_probability = (
            max(match["confidence"] for match in heuristic_matches)
            if heuristic_matches
            else 0.0
        )
        safety_probability = (
            max(match["confidence"] for match in safety_evidence)
            if safety_evidence
            else 0.0
        )
        ambiguous_probability = (
            max(match["confidence"] for match in ambiguous_evidence)
            if ambiguous_evidence
            else 0.0
        )
        cwe_evaluations = []
        if int(self.fusion_config.get("version", 1)) == 2:
            relevant_cwes = self._relevant_cwes(evidence, cwe_candidates)
            cwe_evaluations = [
                self.evaluate_cwe(
                    cwe_id,
                    model_probability,
                    heuristic_matches,
                    safety_evidence,
                    ambiguous_evidence,
                )
                for cwe_id in relevant_cwes
            ]
            selected_evaluation = max(
                cwe_evaluations,
                key=lambda item: (item["is_vulnerable"], item["margin"]),
            )
            final_probability = selected_evaluation["fusion_probability"]
            threshold = selected_evaluation["threshold"]
            review_required = bool(
                not any(item["is_vulnerable"] for item in cwe_evaluations)
                and any(item["review_required"] for item in cwe_evaluations)
            )
            decision = (
                "vulnerable"
                if any(item["is_vulnerable"] for item in cwe_evaluations)
                else ("review_required" if review_required else "safe")
            )
            effective_fusion_config = selected_evaluation["fusion_config"]
            selected_cwe = selected_evaluation["cwe_id"]
        else:
            final_probability = self.fuse_scores(
                model_probability,
                heuristic_probability,
                safety_probability,
                ambiguous_probability,
                self.fusion_config,
            )
            threshold = self._decision_threshold()
            review_required = bool(
                ambiguous_evidence
                and not heuristic_matches
                and final_probability < threshold
            )
            decision = (
                "vulnerable"
                if final_probability >= threshold
                else ("review_required" if review_required else "safe")
            )
            effective_fusion_config = self.fusion_config
            selected_cwe = self._selected_cwe_from_evidence(
                heuristic_matches, cwe_candidates
            )
        return {
            "neural_probability": model_probability,
            "model_probability": model_probability,
            "heuristic_probability": heuristic_probability,
            "safety_probability": safety_probability,
            "ambiguous_probability": ambiguous_probability,
            "fusion_probability": final_probability,
            "final_probability": final_probability,
            "processed_code": processed_code,
            "cwe_candidates": cwe_candidates,
            "heuristic_evidence": heuristic_matches,
            "safety_evidence": safety_evidence,
            "ambiguous_evidence": ambiguous_evidence,
            "heuristic_matches": heuristic_matches,
            "review_required": review_required,
            "decision": decision,
            "decision_reason": self._decision_reason(
                heuristic_matches, safety_evidence, ambiguous_evidence
            ),
            "fusion_config": self.fusion_config,
            "effective_fusion_config": effective_fusion_config,
            "cwe_evaluations": cwe_evaluations,
            "selected_cwe": selected_cwe,
            "threshold": threshold,
        }

    def analyze_code(self, code: str) -> dict:
        prediction = self.predict(code)
        threshold = prediction["threshold"]
        vulnerabilities = self._build_vulnerable_lines(prediction["heuristic_matches"])
        suggested_fixes = self._build_suggested_fixes(prediction["heuristic_matches"])
        probable_cwes = self._merge_cwe_candidates(
            prediction["cwe_candidates"], prediction["heuristic_matches"]
        )

        result = {
            "vulnerability_probability": prediction["final_probability"],
            "neural_probability": prediction["neural_probability"],
            "model_probability": prediction["model_probability"],
            "heuristic_probability": prediction["heuristic_probability"],
            "safety_probability": prediction["safety_probability"],
            "fusion_probability": prediction["fusion_probability"],
            "is_vulnerable": prediction["final_probability"] >= threshold,
            "decision": prediction["decision"],
            "review_required": prediction["review_required"],
            "decision_reason": prediction["decision_reason"],
            "threshold": threshold,
            "vulnerable_lines": vulnerabilities,
            "suggested_fixes": suggested_fixes,
            "processed_code": prediction["processed_code"],
            "detected_patterns": vulnerabilities,
            "heuristic_evidence": prediction["heuristic_evidence"],
            "safety_evidence": prediction["safety_evidence"],
            "ambiguous_evidence": prediction["ambiguous_evidence"],
            "heuristic_matches": prediction["heuristic_matches"],
            "probable_cwes": probable_cwes,
            "cwe_evaluations": prediction["cwe_evaluations"],
            "selected_cwe": prediction["selected_cwe"],
            "effective_fusion_config": prediction["effective_fusion_config"],
        }
        return result

    def evaluate_cwe(
        self,
        cwe_id: str,
        neural_probability: float,
        heuristic_matches: List[Dict[str, object]],
        safety_evidence: List[Dict[str, object]],
        ambiguous_evidence: List[Dict[str, object]],
    ) -> Dict[str, object]:
        config = self.resolve_fusion_config(cwe_id)
        vulnerable = self._evidence_for_cwe(heuristic_matches, cwe_id)
        safety = self._evidence_for_cwe(safety_evidence, cwe_id)
        ambiguous = self._evidence_for_cwe(ambiguous_evidence, cwe_id)
        heuristic_probability = self._max_confidence(vulnerable)
        safety_probability = self._max_confidence(safety)
        ambiguous_probability = self._max_confidence(ambiguous)
        score = self.fuse_scores(
            neural_probability,
            heuristic_probability,
            safety_probability,
            ambiguous_probability,
            config,
        )
        threshold = self._decision_threshold(config)
        return {
            "cwe_id": cwe_id,
            "neural_probability": neural_probability,
            "heuristic_probability": heuristic_probability,
            "safety_probability": safety_probability,
            "ambiguous_probability": ambiguous_probability,
            "fusion_probability": score,
            "threshold": threshold,
            "margin": score - threshold,
            "is_vulnerable": score >= threshold,
            "review_required": bool(ambiguous and not vulnerable and score < threshold),
            "fusion_config": config,
        }

    @staticmethod
    def _evidence_for_cwe(evidence: List[Dict[str, object]], cwe_id: str):
        return [item for item in evidence if item.get("cwe_id") == cwe_id]

    @staticmethod
    def _max_confidence(evidence: List[Dict[str, object]]) -> float:
        return max((float(item["confidence"]) for item in evidence), default=0.0)

    @staticmethod
    def _relevant_cwes(evidence, cwe_candidates):
        evidence_cwes = {
            str(item["cwe_id"])
            for items in evidence.values()
            for item in items
            if item.get("cwe_id")
        }
        if evidence_cwes:
            return sorted(evidence_cwes)
        if cwe_candidates:
            return [str(cwe_candidates[0]["cwe_id"])]
        return [sorted(CWE_REGISTRY)[0]]

    @staticmethod
    def _selected_cwe_from_evidence(heuristic_matches, cwe_candidates):
        evidence_with_cwe = [
            item for item in heuristic_matches if item.get("cwe_id") is not None
        ]
        if evidence_with_cwe:
            selected = max(
                evidence_with_cwe,
                key=lambda item: float(item.get("confidence", 0.0)),
            )
            return selected["cwe_id"]
        return cwe_candidates[0]["cwe_id"] if cwe_candidates else None

    @staticmethod
    def fuse_scores(
        neural_probability: float,
        heuristic_probability: float,
        safety_probability: float,
        ambiguous_probability: float,
        config: Dict[str, object],
    ) -> float:
        score = (
            float(config["model_weight"]) * neural_probability
            + float(config["heuristic_weight"]) * heuristic_probability
            + float(config["ambiguous_weight"]) * ambiguous_probability
            - float(config["safety_discount"]) * safety_probability
        )
        return float(np.clip(score, 0.0, 1.0))

    def _decision_threshold(self, fusion_config: Optional[Dict[str, object]] = None) -> float:
        selected = fusion_config or self.resolve_fusion_config()
        threshold = selected.get("threshold")
        if threshold is None:
            threshold = self.metadata.get(
                "prediction_threshold", self.config.PREDICTION_THRESHOLD
            )
        return float(threshold)

    @staticmethod
    def _decision_reason(
        heuristic_matches: List[Dict[str, object]],
        safety_evidence: List[Dict[str, object]],
        ambiguous_evidence: List[Dict[str, object]],
    ) -> str:
        if heuristic_matches:
            return "Strong vulnerability-oriented heuristic evidence was detected."
        if safety_evidence:
            return "Recognized validation or escaping evidence reduces heuristic risk."
        if ambiguous_evidence:
            return "A security-sensitive sink was detected without conclusive data-flow evidence."
        return "The decision is based on the neural probability only."

    def _scan_evidence(self, code: str) -> Dict[str, List[Dict[str, object]]]:
        evidence = {"vulnerable": [], "safety": [], "ambiguous": []}
        self._scan_command_evidence(code, evidence)
        self._scan_path_traversal_evidence(code, evidence)
        self._scan_xss_evidence(code, evidence)
        self._scan_http_response_splitting_evidence(code, evidence)
        self._scan_array_index_evidence(code, evidence)
        self._scan_format_string_evidence(code, evidence)
        self._scan_integer_overflow_evidence(code, evidence)
        self._scan_cleartext_transmission_evidence(code, evidence)
        self._scan_sql_evidence(code, evidence)
        self._scan_ldap_evidence(code, evidence)
        evidence["vulnerable"].extend(self._scan_generic_patterns(code))
        return evidence

    def _scan_generic_patterns(self, code: str) -> List[Dict[str, object]]:
        matches: List[Dict[str, object]] = []
        for pattern_info in self.dangerous_patterns:
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
                        "evidence_type": "vulnerable",
                    }
                )
        return matches

    def _scan_command_evidence(
        self, code: str, evidence: Dict[str, List[Dict[str, object]]]
    ):
        validation = re.search(
            r"(?:validate\w*\s*\(|\.matches\s*\(|allowlist|allowed\w*|isAllowed\w*\s*\(|InetAddress\.getByName\s*\(|IDN\.toASCII\s*\()",
            code,
            re.I,
        )
        for match in re.finditer(
            r"Runtime\.getRuntime\(\)\.exec\s*\(\s*([^;\n]*)\)", code, re.I
        ):
            argument = match.group(1)
            assignment_is_dynamic = re.search(
                rf"\b{re.escape(argument.strip())}\s*=\s*[^;\n]*\+[^;\n]*;",
                code,
                re.I,
            )
            variable_argument = re.fullmatch(r"\s*[A-Za-z_]\w*\s*", argument)
            kind = (
                "vulnerable"
                if "+" in argument
                or assignment_is_dynamic
                or (variable_argument and not validation)
                else "ambiguous"
            )
            confidence = 0.95 if kind == "vulnerable" else 0.4
            evidence[kind].append(
                self._evidence_match(
                    code,
                    match,
                    "runtime_exec_dynamic" if kind == "vulnerable" else "runtime_exec_review",
                    "CWE78",
                    confidence,
                    "Dynamic command execution appears to receive concatenated input."
                    if kind == "vulnerable"
                    else "Runtime.exec requires review because its argument flow is unresolved.",
                    "Use ProcessBuilder with fixed arguments and validate user-controlled values.",
                    kind,
                )
            )

        for match in re.finditer(r"new\s+ProcessBuilder\s*\((.*?)\)", code, re.I | re.S):
            arguments = match.group(1)
            shell = re.match(
                r"\s*[\"'](?:(?:/bin/)?sh|bash|cmd(?:\.exe)?)[\"']\s*,\s*[\"'](?:-c|/c)[\"']",
                arguments,
                re.I,
            )
            variable_argument = re.search(
                r"(?:^|,)\s*(?![\"'])([A-Za-z_]\w*)\s*(?:,|$)", arguments
            )
            dynamic = "+" in arguments or bool(variable_argument)
            if validation and not shell:
                evidence["safety"].append(
                    self._evidence_match(
                        code,
                        match,
                        "validated_process_builder",
                        "CWE78",
                        0.9,
                        "ProcessBuilder arguments are accompanied by recognized validation.",
                        "",
                        "safety",
                    )
                )
            elif shell or dynamic:
                evidence["vulnerable"].append(
                    self._evidence_match(
                        code,
                        match,
                        "unsafe_process_builder",
                        "CWE78",
                        0.9,
                        "ProcessBuilder appears to receive dynamic or shell-evaluated input.",
                        "Use fixed command arguments and validate values with an allowlist.",
                        "vulnerable",
                    )
                )
            else:
                evidence["ambiguous"].append(
                    self._evidence_match(
                        code,
                        match,
                        "process_builder_review",
                        "CWE78",
                        0.35,
                        "ProcessBuilder use requires confirmation of argument provenance.",
                        "Validate user-controlled values before constructing the process.",
                        "ambiguous",
                    )
                )

    def _scan_sql_evidence(
        self, code: str, evidence: Dict[str, List[Dict[str, object]]]
    ):
        registration = CWE_REGISTRY["CWE89"]
        finding = analyze_sql(code)
        if not finding:
            return
        kind = "safety" if finding.verdict == "safe" else finding.verdict
        confidence = {"vulnerable": 0.95, "safety": 0.95, "ambiguous": 0.4}[kind]
        pattern_name = {
            "vulnerable": "dynamic_sql_execution",
            "safety": "locally_resolved_safe_sql",
            "ambiguous": "sql_data_flow_review",
        }[kind]
        match = re.compile(re.escape(finding.code), re.S).search(code, finding.start)
        evidence[kind].append(
            self._evidence_match(
                code,
                match,
                pattern_name,
                "CWE89",
                confidence,
                finding.rationale,
                registration.mitigation if kind != "safety" else "",
                kind,
            )
        )

    def _scan_xss_evidence(
        self, code: str, evidence: Dict[str, List[Dict[str, object]]]
    ):
        registration = CWE_REGISTRY["CWE80"]
        finding = analyze_xss(code)
        if not finding:
            return
        kind = "safety" if finding.verdict == "safe" else finding.verdict
        confidence = {"vulnerable": 0.9, "safety": 0.9, "ambiguous": 0.4}[kind]
        pattern_name = {
            "vulnerable": "unescaped_html_output",
            "safety": "escaped_html_output",
            "ambiguous": "html_output_review",
        }[kind]
        match = re.compile(re.escape(finding.code), re.S).search(code, finding.start)
        evidence[kind].append(
            self._evidence_match(
                code,
                match,
                pattern_name,
                "CWE80",
                confidence,
                finding.rationale,
                registration.mitigation if kind != "safety" else "",
                kind,
            )
        )

    def _scan_http_response_splitting_evidence(
        self, code: str, evidence: Dict[str, List[Dict[str, object]]]
    ):
        registration = CWE_REGISTRY["CWE113"]
        finding = analyze_http_response_splitting(code)
        if not finding:
            return
        kind = "safety" if finding.verdict == "safe" else finding.verdict
        confidence = {"vulnerable": 0.9, "safety": 0.9, "ambiguous": 0.4}[kind]
        pattern_name = {
            "vulnerable": "dynamic_http_header_value",
            "safety": "safe_http_header_value",
            "ambiguous": "http_header_review",
        }[kind]
        match = re.compile(re.escape(finding.code), re.S).search(code, finding.start)
        evidence[kind].append(
            self._evidence_match(
                code,
                match,
                pattern_name,
                "CWE113",
                confidence,
                finding.rationale,
                registration.mitigation if kind != "safety" else "",
                kind,
            )
        )

    def _scan_array_index_evidence(
        self, code: str, evidence: Dict[str, List[Dict[str, object]]]
    ):
        registration = CWE_REGISTRY["CWE129"]
        finding = analyze_array_index(code)
        if not finding:
            return
        kind = "safety" if finding.verdict == "safe" else finding.verdict
        confidence = {"vulnerable": 0.9, "safety": 0.9, "ambiguous": 0.4}[kind]
        pattern_name = {
            "vulnerable": "unchecked_dynamic_index",
            "safety": "checked_array_index",
            "ambiguous": "array_index_review",
        }[kind]
        match = re.compile(re.escape(finding.code), re.S).search(code, finding.start)
        evidence[kind].append(
            self._evidence_match(
                code,
                match,
                pattern_name,
                "CWE129",
                confidence,
                finding.rationale,
                registration.mitigation if kind != "safety" else "",
                kind,
            )
        )

    def _scan_format_string_evidence(
        self, code: str, evidence: Dict[str, List[Dict[str, object]]]
    ):
        registration = CWE_REGISTRY["CWE134"]
        finding = analyze_format_string(code)
        if not finding:
            return
        kind = "safety" if finding.verdict == "safe" else finding.verdict
        confidence = {"vulnerable": 0.9, "safety": 0.9, "ambiguous": 0.4}[kind]
        pattern_name = {
            "vulnerable": "uncontrolled_format_string",
            "safety": "fixed_format_string",
            "ambiguous": "format_string_review",
        }[kind]
        match = re.compile(re.escape(finding.code), re.S).search(code, finding.start)
        evidence[kind].append(
            self._evidence_match(
                code,
                match,
                pattern_name,
                "CWE134",
                confidence,
                finding.rationale,
                registration.mitigation if kind != "safety" else "",
                kind,
            )
        )

    def _scan_integer_overflow_evidence(
        self, code: str, evidence: Dict[str, List[Dict[str, object]]]
    ):
        registration = CWE_REGISTRY["CWE190"]
        finding = analyze_integer_overflow(code)
        if not finding:
            return
        kind = "safety" if finding.verdict == "safe" else finding.verdict
        confidence = {"vulnerable": 0.9, "safety": 0.9, "ambiguous": 0.4}[kind]
        pattern_name = {
            "vulnerable": "unchecked_integer_arithmetic",
            "safety": "checked_integer_arithmetic",
            "ambiguous": "integer_overflow_review",
        }[kind]
        match = re.compile(re.escape(finding.code), re.S).search(code, finding.start)
        evidence[kind].append(
            self._evidence_match(
                code,
                match,
                pattern_name,
                "CWE190",
                confidence,
                finding.rationale,
                registration.mitigation if kind != "safety" else "",
                kind,
            )
        )

    def _scan_cleartext_transmission_evidence(
        self, code: str, evidence: Dict[str, List[Dict[str, object]]]
    ):
        registration = CWE_REGISTRY["CWE319"]
        finding = analyze_cleartext_transmission(code)
        if not finding:
            return
        kind = "safety" if finding.verdict == "safe" else finding.verdict
        confidence = {"vulnerable": 0.9, "safety": 0.9, "ambiguous": 0.4}[kind]
        pattern_name = {
            "vulnerable": "cleartext_sensitive_transmission",
            "safety": "tls_sensitive_transmission",
            "ambiguous": "transport_security_review",
        }[kind]
        match = re.compile(re.escape(finding.code), re.S).search(code, finding.start)
        evidence[kind].append(
            self._evidence_match(
                code,
                match,
                pattern_name,
                "CWE319",
                confidence,
                finding.rationale,
                registration.mitigation if kind != "safety" else "",
                kind,
            )
        )

    def _scan_path_traversal_evidence(
        self, code: str, evidence: Dict[str, List[Dict[str, object]]]
    ):
        for cwe_id in ("CWE23", "CWE36"):
            registration = CWE_REGISTRY[cwe_id]
            finding = analyze_path_traversal(code, cwe_id)
            if not finding:
                continue
            kind = "safety" if finding.verdict == "safe" else finding.verdict
            confidence = {"vulnerable": 0.9, "safety": 0.9, "ambiguous": 0.4}[kind]
            pattern_name = {
                "CWE23": {
                    "vulnerable": "relative_path_traversal",
                    "safety": "safe_relative_path_resolution",
                    "ambiguous": "relative_path_review",
                },
                "CWE36": {
                    "vulnerable": "absolute_path_traversal",
                    "safety": "safe_absolute_path_rejection",
                    "ambiguous": "absolute_path_review",
                },
            }[cwe_id][kind]
            match = re.compile(re.escape(finding.code), re.S).search(
                code, finding.start
            )
            evidence[kind].append(
                self._evidence_match(
                    code,
                    match,
                    pattern_name,
                    cwe_id,
                    confidence,
                    finding.rationale,
                    registration.mitigation if kind != "safety" else "",
                    kind,
                )
            )

    def _scan_ldap_evidence(
        self, code: str, evidence: Dict[str, List[Dict[str, object]]]
    ):
        if not re.search(r"\.search\s*\(", code, re.I):
            return
        ldap_patterns = [
            r"\b(?:filter|query)\w*\s*=\s*[^;\n]*\+[^;\n]*;",
            r"\.search\s*\(\s*[^,\n]+,\s*[^,\n]*\+[^,\n]*,",
            r"\.search\s*\([^;\n]*,\s*[\"'][^\"'\n]*=[^\"'\n]*[\"']\s*\+\s*",
        ]
        escape_pattern = r"(?:escape\w*|encodeForLDAP\w*|LdapEncoder\w*)\s*\("
        validation_pattern = r"(?:validateLdap\w*|validateFilter\w*|allowlist|allowed\w*)"
        for match in re.finditer(
            r"\.search\s*\([^;\n]*[\"'][^\"']*\{0\}[^\"']*[\"']\s*,\s*new\s+Object\s*\[\s*\]",
            code,
            re.I,
        ):
            evidence["safety"].append(
                self._evidence_match(
                    code,
                    match,
                    "parameterized_ldap_filter",
                    "CWE90",
                    0.95,
                    "LDAP search uses a parameterized filter expression.",
                    "",
                    "safety",
                )
            )
        for pattern in ldap_patterns:
            for match in re.finditer(pattern, code, re.I):
                if re.search(escape_pattern, match.group(0), re.I) or re.search(
                    validation_pattern, code, re.I
                ):
                    evidence["safety"].append(
                        self._evidence_match(
                            code,
                            match,
                            "escaped_ldap_filter",
                            "CWE90",
                            0.9,
                            "The value inserted into the LDAP filter is escaped or validated.",
                            "",
                            "safety",
                        )
                    )
                else:
                    evidence["vulnerable"].append(
                        self._evidence_match(
                            code,
                            match,
                            "dynamic_ldap_filter",
                            "CWE90",
                            0.9,
                            "LDAP filter appears to concatenate unescaped input.",
                            "Escape LDAP filter values before constructing the query.",
                            "vulnerable",
                        )
                    )
        if (
            re.search(r"\.search\s*\(", code, re.I)
            and not evidence["vulnerable"]
            and not evidence["safety"]
        ):
            match = re.search(r"\.search\s*\(", code, re.I)
            evidence["ambiguous"].append(
                self._evidence_match(
                    code,
                    match,
                    "ldap_filter_review",
                    "CWE90",
                    0.35,
                    "LDAP search detected without locally resolvable filter construction.",
                    "Ensure externally supplied filter values are escaped.",
                    "ambiguous",
                )
            )

    @staticmethod
    def _evidence_match(
        code: str,
        match,
        name: str,
        cwe_id: str,
        confidence: float,
        description: str,
        suggested_fix: str,
        evidence_type: str,
    ) -> Dict[str, object]:
        return {
            "pattern_name": name,
            "pattern": match.re.pattern,
            "line_number": code[: match.start()].count("\n") + 1,
            "code": match.group(0),
            "confidence": confidence,
            "description": description,
            "cwe_id": cwe_id,
            "suggested_fix": suggested_fix,
            "source": "heuristic",
            "evidence_type": evidence_type,
        }

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
