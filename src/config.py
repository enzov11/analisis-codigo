import os
from pathlib import Path

from dotenv import load_dotenv

from cwe_registry import supported_cwe_ids, training_cwe_descriptions


load_dotenv()


def _selected_training_cwes():
    raw = os.getenv("TARGET_CWE_IDS", ",".join(sorted(supported_cwe_ids())))
    selected = [value.strip() for value in raw.split(",") if value.strip()]
    unknown = sorted(set(selected) - supported_cwe_ids())
    if unknown:
        raise ValueError(f"TARGET_CWE_IDS contains unregistered CWE values: {unknown}")
    return selected


def _optional_positive_int(name: str):
    raw = os.getenv(name, "").strip()
    if not raw:
        return None
    value = int(raw)
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer when set.")
    return value


class Config:
    BASE_DIR = Path(__file__).resolve().parent.parent
    SRC_DIR = BASE_DIR / "src"

    DATASET_PATH = os.getenv("DATASET_PATH")
    ARTIFACT_VERSION = os.getenv("ARTIFACT_VERSION", "").strip()
    DEFAULT_ARTIFACT_DIR = (
        SRC_DIR / "models" / ARTIFACT_VERSION
        if ARTIFACT_VERSION
        else SRC_DIR / "models"
    )

    MODEL_SAVE_PATH = os.getenv(
        "MODEL_SAVE_PATH", str(DEFAULT_ARTIFACT_DIR / "vuldeepecker.keras")
    )
    TOKENIZER_SAVE_PATH = os.getenv(
        "TOKENIZER_SAVE_PATH", str(DEFAULT_ARTIFACT_DIR / "tokenizer.pkl")
    )
    CWE_ENCODER_SAVE_PATH = os.getenv(
        "CWE_ENCODER_SAVE_PATH", str(DEFAULT_ARTIFACT_DIR / "cwe_encoder.pkl")
    )
    METADATA_SAVE_PATH = os.getenv(
        "METADATA_SAVE_PATH", str(DEFAULT_ARTIFACT_DIR / "metadata.json")
    )
    EVALUATION_SAVE_PATH = os.getenv(
        "EVALUATION_SAVE_PATH", str(DEFAULT_ARTIFACT_DIR / "evaluation.json")
    )
    LOG_DIR = os.getenv("LOG_DIR", str(SRC_DIR / "logs" / "training"))

    TARGET_CWE_IDS = _selected_training_cwes()
    TARGET_CWES = training_cwe_descriptions(TARGET_CWE_IDS)

    MAX_CODE_LENGTH = int(os.getenv("MAX_CODE_LENGTH", "500"))
    MAX_TOKENS = int(os.getenv("MAX_TOKENS", "20000"))
    TOKENIZER_OOV_TOKEN = os.getenv("TOKENIZER_OOV_TOKEN", "<OOV>")

    EMBEDDING_DIM = int(os.getenv("EMBEDDING_DIM", "256"))
    LSTM_UNITS = int(os.getenv("LSTM_UNITS", "128"))
    DENSE_UNITS = int(os.getenv("DENSE_UNITS", "64"))
    DROPOUT_RATE = float(os.getenv("DROPOUT_RATE", "0.3"))
    LEARNING_RATE = float(os.getenv("LEARNING_RATE", "0.001"))

    TRAINING_PROFILE = os.getenv("TRAINING_PROFILE", "final").strip().lower()
    if TRAINING_PROFILE not in {"final", "smoke"}:
        raise ValueError("TRAINING_PROFILE must be either 'final' or 'smoke'.")
    BATCH_SIZE = int(os.getenv("BATCH_SIZE", "32"))
    CONFIGURED_EPOCHS = int(os.getenv("EPOCHS", "15"))
    EPOCHS = min(CONFIGURED_EPOCHS, 2) if TRAINING_PROFILE == "smoke" else CONFIGURED_EPOCHS
    TRAIN_SPLIT = float(os.getenv("TRAIN_SPLIT", "0.7"))
    VALIDATION_SPLIT = float(os.getenv("VALIDATION_SPLIT", "0.15"))
    TEST_SPLIT = float(os.getenv("TEST_SPLIT", "0.15"))
    RANDOM_SEED = int(os.getenv("RANDOM_SEED", "42"))
    BALANCE_DATASET = os.getenv("BALANCE_DATASET", "True").lower() in (
        "true",
        "1",
        "t",
    )
    MAX_OVERSAMPLE_MULTIPLIER = float(os.getenv("MAX_OVERSAMPLE_MULTIPLIER", "2.0"))
    REQUIRE_ALL_TARGET_CWES = os.getenv("REQUIRE_ALL_TARGET_CWES", "True").lower() in (
        "true",
        "1",
        "t",
    )
    PREDICTION_THRESHOLD = float(os.getenv("PREDICTION_THRESHOLD", "0.5"))
    TRAINING_VERBOSE = int(os.getenv("TRAINING_VERBOSE", "1"))
    MAX_SAMPLES_PER_CWE = _optional_positive_int("MAX_SAMPLES_PER_CWE")
    EARLY_STOPPING_PATIENCE = int(os.getenv("EARLY_STOPPING_PATIENCE", "3"))
    EARLY_STOPPING_MIN_DELTA = float(os.getenv("EARLY_STOPPING_MIN_DELTA", "0.001"))
    EARLY_STOPPING_MONITOR = os.getenv(
        "EARLY_STOPPING_MONITOR", "val_main_loss"
    ).strip()
    EARLY_STOPPING_MODE = os.getenv("EARLY_STOPPING_MODE", "min").strip()
    CHECKPOINT_MONITOR = os.getenv("CHECKPOINT_MONITOR", "val_main_loss").strip()
    CHECKPOINT_MODE = os.getenv("CHECKPOINT_MODE", "min").strip()
    TENSORBOARD_HISTOGRAM_FREQ = int(os.getenv("TENSORBOARD_HISTOGRAM_FREQ", "0"))

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
