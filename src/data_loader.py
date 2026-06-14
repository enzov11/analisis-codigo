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
            cwe_id = self._resolve_cwe_id(root_path, dataset_root)
            if cwe_id is None:
                continue
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
        missing_cwes = sorted(set(cwe_descriptions) - set(df["cwe_id"].unique()))
        if missing_cwes and self.config.REQUIRE_ALL_TARGET_CWES:
            raise ValueError(
                "The dataset does not contain samples for every official target CWE. "
                f"Missing: {missing_cwes}. Add the required Juliet/SARD cases or set "
                "REQUIRE_ALL_TARGET_CWES=False only for an explicitly partial experiment."
            )
        return df, cwe_descriptions

    def split_dataset(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        train_df, validation_df, test_df = self.split_train_validation_test(df)
        development_df = pd.concat([train_df, validation_df], ignore_index=True)
        return development_df, test_df

    def split_train_validation_test(
        self, df: pd.DataFrame
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        self._validate_split_fractions()
        train_parts = []
        validation_parts = []
        test_parts = []

        for offset, (_, cwe_df) in enumerate(sorted(df.groupby("cwe_id"))):
            train_part, remainder = self._group_split(
                cwe_df,
                train_size=self.config.TRAIN_SPLIT,
                random_state=self.config.RANDOM_SEED + offset,
            )
            validation_share = self.config.VALIDATION_SPLIT / (
                self.config.VALIDATION_SPLIT + self.config.TEST_SPLIT
            )
            validation_part, test_part = self._group_split(
                remainder,
                train_size=validation_share,
                random_state=self.config.RANDOM_SEED + 1000 + offset,
            )
            train_parts.append(train_part)
            validation_parts.append(validation_part)
            test_parts.append(test_part)

        return (
            pd.concat(train_parts, ignore_index=True).sample(
                frac=1, random_state=self.config.RANDOM_SEED
            ).reset_index(drop=True),
            pd.concat(validation_parts, ignore_index=True).sample(
                frac=1, random_state=self.config.RANDOM_SEED
            ).reset_index(drop=True),
            pd.concat(test_parts, ignore_index=True).sample(
                frac=1, random_state=self.config.RANDOM_SEED
            ).reset_index(drop=True),
        )

    def split_train_validation(
        self, df: pd.DataFrame
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        self._validate_split_fractions()
        train_parts = []
        validation_parts = []
        train_share = self.config.TRAIN_SPLIT / (
            self.config.TRAIN_SPLIT + self.config.VALIDATION_SPLIT
        )
        for offset, (_, cwe_df) in enumerate(sorted(df.groupby("cwe_id"))):
            train_part, validation_part = self._group_split(
                cwe_df,
                train_size=train_share,
                random_state=self.config.RANDOM_SEED + offset,
            )
            train_parts.append(train_part)
            validation_parts.append(validation_part)
        return (
            pd.concat(train_parts, ignore_index=True).sample(
                frac=1, random_state=self.config.RANDOM_SEED
            ).reset_index(drop=True),
            pd.concat(validation_parts, ignore_index=True).sample(
                frac=1, random_state=self.config.RANDOM_SEED
            ).reset_index(drop=True),
        )

    @staticmethod
    def _group_split(df: pd.DataFrame, train_size: float, random_state: int):
        if df["sample_group"].nunique() < 2:
            raise ValueError(
                f"At least two sample groups are required to split {df['cwe_id'].iloc[0]}."
            )
        splitter = GroupShuffleSplit(
            n_splits=64,
            train_size=train_size,
            random_state=random_state,
        )
        candidates = splitter.split(df, df["label"], groups=df["sample_group"])
        train_idx, test_idx = min(
            candidates,
            key=lambda indices: DataLoader._split_score(
                df, indices[0], indices[1], train_size
            ),
        )
        return (
            df.iloc[train_idx].reset_index(drop=True),
            df.iloc[test_idx].reset_index(drop=True),
        )

    @staticmethod
    def _split_score(df, train_idx, test_idx, target_train_size):
        labels = sorted(df["label"].unique())
        full_distribution = df["label"].value_counts(normalize=True)
        train_distribution = df.iloc[train_idx]["label"].value_counts(normalize=True)
        test_distribution = df.iloc[test_idx]["label"].value_counts(normalize=True)
        size_error = abs((len(train_idx) / len(df)) - target_train_size)
        label_error = sum(
            abs(train_distribution.get(label, 0.0) - full_distribution.get(label, 0.0))
            + abs(test_distribution.get(label, 0.0) - full_distribution.get(label, 0.0))
            for label in labels
        )
        return size_error + label_error

    def _validate_split_fractions(self):
        fractions = (
            self.config.TRAIN_SPLIT,
            self.config.VALIDATION_SPLIT,
            self.config.TEST_SPLIT,
        )
        if any(value <= 0 or value >= 1 for value in fractions):
            raise ValueError("TRAIN_SPLIT, VALIDATION_SPLIT, and TEST_SPLIT must be between 0 and 1.")
        if abs(sum(fractions) - 1.0) > 1e-9:
            raise ValueError("TRAIN_SPLIT, VALIDATION_SPLIT, and TEST_SPLIT must sum to 1.0.")

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

    @staticmethod
    def _resolve_cwe_id(root_path: Path, dataset_root: Path):
        dataset_root = dataset_root.resolve()
        current = root_path.resolve()
        while True:
            match = re.match(r"^(CWE\d+)(?:_|$)", current.name)
            if match:
                return match.group(1)
            if current == dataset_root or current.parent == current:
                return None
            current = current.parent

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
