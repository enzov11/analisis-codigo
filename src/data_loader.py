import os
import re
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from config import Config


class DataLoader:
    METHOD_PATTERN = re.compile(
        r"(?P<signature>(?:public|private|protected)\s+[\w<>\[\]]+\s+"
        r"(?P<name>\w+)\s*\([^)]*\)\s*(?:throws [^{]+)?\{)",
        re.MULTILINE,
    )

    def __init__(self):
        self.config = Config()

    def load_dataset(self) -> Tuple[pd.DataFrame, Dict[str, str]]:
        dataset_root = self.config.require_dataset_path()
        data: List[Dict[str, object]] = []
        cwe_descriptions = self.config.TARGET_CWES
        file_patterns = self.config.get_file_patterns()

        for root, _, files in os.walk(dataset_root):
            root_path = Path(root)
            if "CWE" not in root:
                continue

            cwe_id = root_path.name.split("_")[0]
            if cwe_id not in cwe_descriptions:
                continue

            for file_name in files:
                if not re.match(file_patterns["java_files"], file_name):
                    continue

                file_path = root_path / file_name
                with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                    code = handle.read()

                samples = self._extract_samples(file_path, code, cwe_id, cwe_descriptions)
                data.extend(samples)

        df = pd.DataFrame(data)
        if df.empty:
            raise ValueError(
                "No training samples were extracted from the dataset. "
                "Check DATASET_PATH and the selected TARGET_CWES."
            )
        return df, cwe_descriptions

    def split_dataset(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        splitter = GroupShuffleSplit(
            n_splits=1,
            train_size=self.config.TRAIN_TEST_SPLIT,
            random_state=self.config.RANDOM_SEED,
        )
        groups = df["sample_group"]
        train_idx, test_idx = next(splitter.split(df, df["label"], groups))

        train_df = df.iloc[train_idx].reset_index(drop=True)
        test_df = df.iloc[test_idx].reset_index(drop=True)
        return train_df, test_df

    def summarize_dataset(self, df: pd.DataFrame) -> Dict[str, object]:
        return {
            "num_samples": int(len(df)),
            "num_files": int(df["file_path"].nunique()),
            "num_groups": int(df["sample_group"].nunique()),
            "label_distribution": {
                str(key): int(value) for key, value in df["label"].value_counts().items()
            },
            "cwe_distribution": {
                key: int(value) for key, value in df["cwe_id"].value_counts().items()
            },
            "sample_kind_distribution": {
                key: int(value)
                for key, value in df["sample_kind"].value_counts().items()
            },
            "avg_code_length_chars": float(df["code"].str.len().mean()),
        }

    def _extract_samples(
        self,
        file_path: Path,
        code: str,
        cwe_id: str,
        cwe_descriptions: Dict[str, str],
    ) -> List[Dict[str, object]]:
        methods = self._extract_methods(code)
        family_id = self._build_family_id(file_path.name)
        file_label = self._label_from_filename(file_path.name)

        if not methods:
            fallback_label = 0 if file_label is None else file_label
            return [
                self._build_sample(
                    file_path=file_path,
                    code=code,
                    label=fallback_label,
                    cwe_id=cwe_id,
                    cwe_description=cwe_descriptions[cwe_id],
                    sample_kind="file",
                    sample_name=file_path.stem,
                    family_id=family_id,
                )
            ]

        samples: List[Dict[str, object]] = []
        for method in methods:
            label = self._label_from_method(method["name"])
            if label is None:
                label = self._label_from_method_body(method["code"])
            if label is None:
                label = file_label
            if label is None:
                continue

            samples.append(
                self._build_sample(
                    file_path=file_path,
                    code=method["code"],
                    label=label,
                    cwe_id=cwe_id,
                    cwe_description=cwe_descriptions[cwe_id],
                    sample_kind="method",
                    sample_name=method["name"],
                    family_id=family_id,
                )
            )

        if samples:
            return samples

        fallback_label = 0 if file_label is None else file_label
        return [
            self._build_sample(
                file_path=file_path,
                code=code,
                label=fallback_label,
                cwe_id=cwe_id,
                cwe_description=cwe_descriptions[cwe_id],
                sample_kind="file",
                sample_name=file_path.stem,
                family_id=family_id,
            )
        ]

    def _build_sample(
        self,
        file_path: Path,
        code: str,
        label: int,
        cwe_id: str,
        cwe_description: str,
        sample_kind: str,
        sample_name: str,
        family_id: str,
    ) -> Dict[str, object]:
        return {
            "file_path": str(file_path),
            "code": code,
            "label": int(label),
            "cwe_id": cwe_id,
            "cwe_description": cwe_description,
            "sample_kind": sample_kind,
            "sample_name": sample_name,
            "sample_group": family_id,
        }

    def _extract_methods(self, code: str) -> List[Dict[str, str]]:
        methods: List[Dict[str, str]] = []
        for match in self.METHOD_PATTERN.finditer(code):
            start = match.start()
            body_start = match.end() - 1
            end = self._find_matching_brace(code, body_start)
            if end is None:
                continue
            methods.append(
                {
                    "name": match.group("name"),
                    "code": code[start : end + 1],
                }
            )
        return methods

    @staticmethod
    def _find_matching_brace(code: str, opening_brace_index: int):
        depth = 0
        for index in range(opening_brace_index, len(code)):
            char = code[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
        return None

    def _label_from_filename(self, file_name: str):
        patterns = self.config.get_file_patterns()
        if re.search(patterns["bad_pattern"], file_name):
            return 1
        if re.search(patterns["good_pattern"], file_name):
            return 0
        return None

    @staticmethod
    def _label_from_method(method_name: str):
        lowered = method_name.lower()
        if lowered == "bad" or lowered.endswith("_bad") or "badsink" in lowered:
            return 1
        if lowered.startswith("good") or "goodg2b" in lowered or "goodb2g" in lowered:
            return 0
        return None

    @staticmethod
    def _label_from_method_body(method_code: str):
        if "/* POTENTIAL FLAW:" in method_code and "/* FIX:" not in method_code:
            return 1
        if "/* FIX:" in method_code and "/* POTENTIAL FLAW:" not in method_code:
            return 0
        if "FIX:" in method_code and "POTENTIAL FLAW" not in method_code:
            return 0
        return None

    @staticmethod
    def _build_family_id(file_name: str) -> str:
        stem = Path(file_name).stem
        family = re.sub(r"_(?:\d+[a-z]?|goodG2B\d*|goodB2G\d*|goodG2B|goodB2G|good|bad)$", "", stem)
        return family
