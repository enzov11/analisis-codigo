import os
import re
from typing import List, Dict, Tuple
import pandas as pd
from tqdm import tqdm
from config import Config


class DataLoader:
    def __init__(self):
        self.config = Config()

    def load_dataset(self) -> Tuple[pd.DataFrame, Dict[str, str]]:
        """Carga el dataset Juliet específicamente"""
        data = []
        cwe_descriptions = self.config.TARGET_CWES
        file_patterns = self.config.get_file_patterns()

        for root, dirs, files in os.walk(self.config.DATASET_PATH):
            if "CWE" not in root:
                continue

            cwe_id = os.path.basename(root).split("_")[0]
            if cwe_id not in cwe_descriptions:
                continue

            for file in files:
                if re.match(file_patterns["java_files"], file):
                    file_path = os.path.join(root, file)
                    label = 1 if re.search(file_patterns["bad_pattern"], file) else 0

                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        code = f.read()

                    data.append(
                        {
                            "file_path": file_path,
                            "code": code,
                            "label": label,
                            "cwe_id": cwe_id,
                            "cwe_description": cwe_descriptions[cwe_id],
                        }
                    )

        return pd.DataFrame(data), cwe_descriptions

    def split_dataset(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Split dataset into train and test sets"""
        # Mezclar los datos primero
        df = df.sample(frac=1, random_state=self.config.RANDOM_SEED).reset_index(
            drop=True
        )

        # Calcular el punto de división
        split_idx = int(len(df) * self.config.TRAIN_TEST_SPLIT)

        train_df = df.iloc[:split_idx]
        test_df = df.iloc[split_idx:]

        return train_df, test_df
