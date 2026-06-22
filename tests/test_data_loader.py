import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import sys

import pandas as pd


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from data_loader import DataLoader


JAVA_TEMPLATE = """
public class Example {{
    public void {method_name}() {{
        {marker}
        String value = "test";
    }}
}}
"""


class DataLoaderDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="juliet-loader-")
        self.dataset_root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_case(self, relative_path, method_name, marker):
        path = self.dataset_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            JAVA_TEMPLATE.format(method_name=method_name, marker=marker),
            encoding="utf-8",
        )

    def _loader(self, target_cwes, require_all=True):
        loader = DataLoader()
        loader.config = SimpleNamespace(
            TARGET_CWES={cwe_id: cwe_id for cwe_id in target_cwes},
            REQUIRE_ALL_TARGET_CWES=require_all,
            TRAIN_SPLIT=0.7,
            VALIDATION_SPLIT=0.15,
            TEST_SPLIT=0.15,
            RANDOM_SEED=42,
            require_dataset_path=lambda: self.dataset_root,
            get_file_patterns=lambda: {
                "java_files": r"CWE\d+_.*\.java$",
                "bad_pattern": r"(?:_|^)bad(?:[_0-9]|$)",
                "good_pattern": r"(?:_|^)good(?:[_A-Z0-9]|$)",
            },
        )
        return loader

    def test_loads_direct_and_nested_cwe_directories(self):
        self._write_case(
            "CWE78_OS_Command_Injection/CWE78_example_01.java",
            "bad",
            "/* POTENTIAL FLAW: unsafe command */",
        )
        self._write_case(
            "CWE89_SQL_Injection/s01/CWE89_example_01.java",
            "good",
            "/* FIX: parameterized query */",
        )

        dataset, _ = self._loader(["CWE78", "CWE89"]).load_dataset()

        self.assertEqual(set(dataset["cwe_id"]), {"CWE78", "CWE89"})
        self.assertEqual(set(dataset["label"]), {0, 1})

    def test_excludes_unselected_cwe_directories(self):
        self._write_case(
            "CWE78_OS_Command_Injection/CWE78_example_01.java",
            "bad",
            "/* POTENTIAL FLAW: unsafe command */",
        )
        self._write_case(
            "CWE90_LDAP_Injection/CWE90_example_01.java",
            "bad",
            "/* POTENTIAL FLAW: unsafe filter */",
        )

        dataset, _ = self._loader(["CWE78"]).load_dataset()

        self.assertEqual(set(dataset["cwe_id"]), {"CWE78"})

    def test_requires_every_selected_cwe_when_configured(self):
        self._write_case(
            "CWE78_OS_Command_Injection/CWE78_example_01.java",
            "bad",
            "/* POTENTIAL FLAW: unsafe command */",
        )

        with self.assertRaisesRegex(ValueError, r"Missing: \['CWE89'\]"):
            self._loader(["CWE78", "CWE89"], require_all=True).load_dataset()

    def test_allows_explicitly_partial_dataset(self):
        self._write_case(
            "CWE78_OS_Command_Injection/CWE78_example_01.java",
            "bad",
            "/* POTENTIAL FLAW: unsafe command */",
        )

        dataset, descriptions = self._loader(
            ["CWE78", "CWE89"], require_all=False
        ).load_dataset()

        self.assertEqual(set(dataset["cwe_id"]), {"CWE78"})
        self.assertEqual(set(descriptions), {"CWE78", "CWE89"})

    def test_three_way_split_is_per_cwe_and_has_no_group_overlap(self):
        rows = []
        for cwe_id in ("CWE23", "CWE36", "CWE78", "CWE80", "CWE89", "CWE90"):
            for group_index in range(20):
                for label in (0, 1):
                    rows.append(
                        {
                            "cwe_id": cwe_id,
                            "label": label,
                            "sample_group": f"{cwe_id}_family_{group_index}",
                        }
                    )
        dataset = pd.DataFrame(rows)

        train, validation, test = self._loader(
            ["CWE23", "CWE36", "CWE78", "CWE80", "CWE89", "CWE90"]
        ).split_train_validation_test(dataset)

        group_sets = [set(part["sample_group"]) for part in (train, validation, test)]
        self.assertFalse(group_sets[0] & group_sets[1])
        self.assertFalse(group_sets[0] & group_sets[2])
        self.assertFalse(group_sets[1] & group_sets[2])
        for part in (train, validation, test):
            self.assertEqual(
                set(part["cwe_id"]),
                {"CWE23", "CWE36", "CWE78", "CWE80", "CWE89", "CWE90"},
            )
            self.assertEqual(set(part["label"]), {0, 1})

    def test_three_way_split_requires_fractions_summing_to_one(self):
        loader = self._loader(["CWE78"])
        loader.config.TRAIN_SPLIT = 0.8
        dataset = pd.DataFrame(
            [
                {"cwe_id": "CWE78", "label": 0, "sample_group": "a"},
                {"cwe_id": "CWE78", "label": 1, "sample_group": "b"},
            ]
        )

        with self.assertRaisesRegex(ValueError, "must sum to 1.0"):
            loader.split_train_validation_test(dataset)
