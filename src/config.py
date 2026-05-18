import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()


class Config:
    BASE_DIR = Path(__file__).resolve().parent.parent
    SRC_DIR = BASE_DIR / "src"

    DATASET_PATH = os.getenv("DATASET_PATH")

    MODEL_SAVE_PATH = os.getenv(
        "MODEL_SAVE_PATH", str(SRC_DIR / "models" / "vuldeepecker.keras")
    )
    TOKENIZER_SAVE_PATH = os.getenv(
        "TOKENIZER_SAVE_PATH", str(SRC_DIR / "models" / "tokenizer.pkl")
    )
    CWE_ENCODER_SAVE_PATH = os.getenv(
        "CWE_ENCODER_SAVE_PATH", str(SRC_DIR / "models" / "cwe_encoder.pkl")
    )
    METADATA_SAVE_PATH = os.getenv(
        "METADATA_SAVE_PATH", str(SRC_DIR / "models" / "metadata.json")
    )
    EVALUATION_SAVE_PATH = os.getenv(
        "EVALUATION_SAVE_PATH", str(SRC_DIR / "models" / "evaluation.json")
    )
    LOG_DIR = os.getenv("LOG_DIR", str(SRC_DIR / "logs" / "training"))

    TARGET_CWES = {
        "CWE78": "OS Command Injection",
        "CWE79": "Cross-site Scripting",
        "CWE89": "SQL Injection",
        "CWE119": "Buffer Overflow",
        "CWE125": "Out-of-bounds Read",
        "CWE20": "Improper Input Validation",
        "CWE352": "Cross-Site Request Forgery",
        "CWE434": "Unrestricted Upload",
        "CWE502": "Deserialization of Untrusted Data",
        "CWE80": "XSS",
        "CWE90": "LDAP Injection",
    }

    MAX_CODE_LENGTH = int(os.getenv("MAX_CODE_LENGTH", "500"))
    MAX_TOKENS = int(os.getenv("MAX_TOKENS", "20000"))
    TOKENIZER_OOV_TOKEN = os.getenv("TOKENIZER_OOV_TOKEN", "<OOV>")

    EMBEDDING_DIM = int(os.getenv("EMBEDDING_DIM", "256"))
    LSTM_UNITS = int(os.getenv("LSTM_UNITS", "128"))
    DENSE_UNITS = int(os.getenv("DENSE_UNITS", "64"))
    DROPOUT_RATE = float(os.getenv("DROPOUT_RATE", "0.3"))
    LEARNING_RATE = float(os.getenv("LEARNING_RATE", "0.001"))

    BATCH_SIZE = int(os.getenv("BATCH_SIZE", "32"))
    EPOCHS = int(os.getenv("EPOCHS", "15"))
    TRAIN_TEST_SPLIT = float(os.getenv("TRAIN_TEST_SPLIT", "0.8"))
    RANDOM_SEED = int(os.getenv("RANDOM_SEED", "42"))
    BALANCE_DATASET = os.getenv("BALANCE_DATASET", "True").lower() in (
        "true",
        "1",
        "t",
    )
    PREDICTION_THRESHOLD = float(os.getenv("PREDICTION_THRESHOLD", "0.5"))
    TRAINING_VERBOSE = int(os.getenv("TRAINING_VERBOSE", "1"))

    @classmethod
    def resolve_path(cls, path_value: str) -> Path:
        path = Path(path_value)
        if path.is_absolute():
            return path
        return cls.BASE_DIR / path

    @classmethod
    def require_dataset_path(cls) -> Path:
        if not cls.DATASET_PATH:
            raise ValueError("DATASET_PATH must be set in .env file for training mode.")

        dataset_path = cls.resolve_path(cls.DATASET_PATH)
        if not dataset_path.exists():
            raise FileNotFoundError(
                f"Dataset path not found: {dataset_path}. Update DATASET_PATH in .env."
            )
        return dataset_path

    @classmethod
    def get_artifact_paths(cls) -> dict:
        return {
            "model": cls.resolve_path(cls.MODEL_SAVE_PATH),
            "tokenizer": cls.resolve_path(cls.TOKENIZER_SAVE_PATH),
            "cwe_encoder": cls.resolve_path(cls.CWE_ENCODER_SAVE_PATH),
            "metadata": cls.resolve_path(cls.METADATA_SAVE_PATH),
            "evaluation": cls.resolve_path(cls.EVALUATION_SAVE_PATH),
            "log_dir": cls.resolve_path(cls.LOG_DIR),
        }

    @staticmethod
    def get_file_patterns():
        return {
            "java_files": r"CWE\d+_.*\.java$",
            "bad_pattern": r"(?:_|^)bad(?:[_0-9]|$)",
            "good_pattern": r"(?:_|^)good(?:[_A-Z0-9]|$)",
        }

    @classmethod
    def ensure_dirs(cls):
        artifact_paths = cls.get_artifact_paths()
        for key, path in artifact_paths.items():
            target = path if key == "log_dir" else path.parent
            os.makedirs(target, exist_ok=True)

    @classmethod
    def validate_prediction_artifacts(cls):
        artifact_paths = cls.get_artifact_paths()
        missing = [
            str(path)
            for key, path in artifact_paths.items()
            if key in {"model", "tokenizer", "metadata"} and not path.exists()
        ]
        if missing:
            raise FileNotFoundError(
                "Missing prediction artifacts: "
                + ", ".join(missing)
                + ". Train the model first or update the artifact paths in .env."
            )
