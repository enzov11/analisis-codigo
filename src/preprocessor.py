from typing import List, Tuple, Dict
import re
import numpy as np
import pandas as pd
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.preprocessing import LabelEncoder
from config import Config


class CodePreprocessor:
    def __init__(self):
        self.config = Config()
        self.tokenizer = None
        self.label_encoder = LabelEncoder()
        self.special_tokens = {
            "<EXEC>": 1,
            "<PROCESS_BUILDER>": 2,
            "<SQL_INJECTION>": 3,
            "<COMMAND_INJECTION>": 4,
            "<FLAW>": 5,
            "<SAFE>": 6,
        }

    def preprocess_code(self, code: str) -> str:
        """
        Enhanced code preprocessing that preserves security-relevant patterns
        """
        # Keep important comments
        code = re.sub(r"/\*.*?POTENTIAL FLAW.*?\*/", "<FLAW>", code, flags=re.DOTALL)
        code = re.sub(r"/\*.*?FIX.*?\*/", "<SAFE>", code, flags=re.DOTALL)

        # Replace dangerous patterns with special tokens
        code = re.sub(r"Runtime\.getRuntime\(\)\.exec\(", "<EXEC> ", code)
        code = re.sub(r"new ProcessBuilder\(", "<PROCESS_BUILDER> ", code)
        code = re.sub(
            r"stmt\.execute\(|<SELECT>.+?\+.+",
            "<SQL_INJECTION> ",
            code,
            flags=re.DOTALL,
        )
        code = re.sub(r"System\.loadLibrary\(", "<COMMAND_INJECTION> ", code)

        # Preserve string literals (often contain important patterns)
        code = re.sub(r'"(.*?)"', lambda m: f"STR_LIT_{len(m.group(1))}", code)

        # Standardize variable names but preserve types
        code = re.sub(r"\bString\b\s+\w+", "VAR_STRING", code)
        code = re.sub(r"\bint\b\s+\w+", "VAR_INT", code)

        # Remove package/import but keep class/method structure
        code = re.sub(r"package\s+.*?;", "", code)
        code = re.sub(r"import\s+.*?;", "", code)

        return " ".join(code.split())

    def create_tokenizer(self, texts: List[str]):
        """Custom tokenizer with security-aware vocabulary"""
        self.tokenizer = Tokenizer(
            num_words=self.config.MAX_TOKENS,
            oov_token="<OOV>",
            filters="",  # Don't filter special chars
            lower=False,  # Case sensitive
            split=" ",
            char_level=False,
        )

        # Fit on texts
        self.tokenizer.fit_on_texts(texts)

        # Add special tokens
        for token, idx in self.special_tokens.items():
            self.tokenizer.word_index[token] = idx

        # Ensure special tokens are at the beginning
        self.tokenizer.word_index = {
            k: v
            for k, v in sorted(
                self.tokenizer.word_index.items(),
                key=lambda item: (
                    item[1]
                    if item[0] not in self.special_tokens
                    else self.special_tokens[item[0]]
                ),
            )
        }

    def text_to_sequence(self, texts: List[str]) -> np.ndarray:
        """Convert code to sequences with special handling"""
        sequences = self.tokenizer.texts_to_sequences(texts)
        return pad_sequences(
            sequences,
            maxlen=self.config.MAX_CODE_LENGTH,
            padding="post",
            truncating="post",
            value=0,
        )

    def encode_labels(self, labels: List[int]) -> np.ndarray:
        return self.label_encoder.fit_transform(labels)

    def prepare_dataset(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, Dict]:
        """Enhanced dataset preparation with metadata"""
        # Preprocess code
        df["processed_code"] = df["code"].apply(self.preprocess_code)

        # Create tokenizer
        if not self.tokenizer:
            self.create_tokenizer(df["processed_code"].tolist())

        # Convert to sequences
        X = self.text_to_sequence(df["processed_code"].tolist())
        y = self.encode_labels(df["label"].tolist())

        # Get CWE types for weighted loss
        cwe_types = df["cwe_id"].value_counts().to_dict()

        return X, y, cwe_types
