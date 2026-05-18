import pickle
import re
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import Tokenizer

from config import Config


class CodePreprocessor:
    def __init__(self):
        self.config = Config()
        self.tokenizer = None
        self.special_tokens = {
            "<EXEC>": 1,
            "<PROCESS_BUILDER>": 2,
            "<SQL_EXEC>": 3,
            "<DYNAMIC_SQL>": 4,
            "<UNSAFE_LOAD>": 5,
            "<FLAW>": 6,
            "<SAFE>": 7,
        }

    def preprocess_code(self, code: str) -> str:
        code = re.sub(
            r"/\*.*?POTENTIAL FLAW.*?\*/|//\s*POTENTIAL FLAW.*",
            "<FLAW>",
            code,
            flags=re.DOTALL,
        )
        code = re.sub(
            r"/\*.*?FIX.*?\*/|//\s*FIX.*",
            "<SAFE>",
            code,
            flags=re.DOTALL,
        )

        code = re.sub(r"Runtime\.getRuntime\(\)\.exec\(", "<EXEC> ", code)
        code = re.sub(r"new\s+ProcessBuilder\(", "<PROCESS_BUILDER> ", code)
        code = re.sub(r"\b\w+\.createStatement\s*\(", "<SQL_EXEC> ", code)
        code = re.sub(r"\b(?:stmt|statement)\.(?:execute|executeQuery|executeUpdate)\s*\(", "<SQL_EXEC> ", code)
        code = re.sub(
            r"SELECT\s+.+?\s+FROM\s+.+?\s+WHERE\s+.+?[\"']\s*\+",
            "<DYNAMIC_SQL> ",
            code,
            flags=re.IGNORECASE | re.DOTALL,
        )
        code = re.sub(r"System\.loadLibrary\(", "<UNSAFE_LOAD> ", code)

        code = re.sub(r'"(.*?)"', lambda match: f"STR_LIT_{len(match.group(1))}", code)
        code = re.sub(r"\bString\b\s+\w+", "VAR_STRING", code)
        code = re.sub(r"\bint\b\s+\w+", "VAR_INT", code)
        code = re.sub(r"package\s+.*?;", "", code)
        code = re.sub(r"import\s+.*?;", "", code)

        return " ".join(code.split())

    def create_tokenizer(self, texts: List[str]):
        self.tokenizer = Tokenizer(
            num_words=self.config.MAX_TOKENS,
            oov_token=self.config.TOKENIZER_OOV_TOKEN,
            filters="",
            lower=False,
            split=" ",
            char_level=False,
        )
        self.tokenizer.fit_on_texts(texts)

        for token, idx in self.special_tokens.items():
            self.tokenizer.word_index[token] = idx
            self.tokenizer.index_word[idx] = token

    def save_tokenizer(self, path=None):
        target_path = path or self.config.get_artifact_paths()["tokenizer"]
        if self.tokenizer is None:
            raise ValueError("Tokenizer has not been created yet.")
        with open(target_path, "wb") as handle:
            pickle.dump(self.tokenizer, handle)

    def load_tokenizer(self, path=None):
        target_path = path or self.config.get_artifact_paths()["tokenizer"]
        with open(target_path, "rb") as handle:
            self.tokenizer = pickle.load(handle)
        return self.tokenizer

    def text_to_sequence(self, texts: List[str]) -> np.ndarray:
        if self.tokenizer is None:
            raise ValueError("Tokenizer is not loaded. Train the model or load artifacts.")
        sequences = self.tokenizer.texts_to_sequences(texts)
        return pad_sequences(
            sequences,
            maxlen=self.config.MAX_CODE_LENGTH,
            padding="post",
            truncating="post",
            value=0,
        )

    def prepare_dataset(self, df: pd.DataFrame, fit_tokenizer: bool = False) -> Tuple[np.ndarray, np.ndarray, Dict[str, int]]:
        processed_df = df.copy()
        processed_df["processed_code"] = processed_df["code"].apply(self.preprocess_code)

        if fit_tokenizer or self.tokenizer is None:
            self.create_tokenizer(processed_df["processed_code"].tolist())

        X = self.text_to_sequence(processed_df["processed_code"].tolist())
        y = processed_df["label"].astype(int).to_numpy()
        cwe_types = processed_df["cwe_id"].value_counts().to_dict()
        return X, y, cwe_types
