import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # Configuración del dataset (obligatorio en .env)
    DATASET_PATH = os.getenv("DATASET_PATH")
    if not DATASET_PATH:
        raise ValueError("DATASET_PATH must be set in .env file")

    # Configuración de rutas (con valores por defecto relativos al proyecto)
    MODEL_SAVE_PATH = os.getenv(
        "MODEL_SAVE_PATH", os.path.join("models", "vuldeepecker.keras")
    )
    TOKENIZER_SAVE_PATH = os.getenv(
        "TOKENIZER_SAVE_PATH", os.path.join("models", "tokenizer.pkl")
    )
    LOG_DIR = os.getenv("LOG_DIR", os.path.join("logs", "training"))

    # Filtro de CWEs relevantes
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

    # Configuración de preprocesamiento
    MAX_CODE_LENGTH = int(
        os.getenv("MAX_CODE_LENGTH", "500")
    )  # Longitud máxima de código
    MAX_TOKENS = int(os.getenv("MAX_TOKENS", "20000"))  # Tamaño de vocabulario
    TOKENIZER_OOV_TOKEN = os.getenv("TOKENIZER_OOV_TOKEN", "<OOV>")

    # Configuración del modelo
    EMBEDDING_DIM = int(os.getenv("EMBEDDING_DIM", "256"))
    LSTM_UNITS = int(os.getenv("LSTM_UNITS", "128"))
    DENSE_UNITS = int(os.getenv("DENSE_UNITS", "64"))
    DROPOUT_RATE = float(os.getenv("DROPOUT_RATE", "0.3"))
    LEARNING_RATE = float(os.getenv("LEARNING_RATE", "0.001"))

    # Configuración de entrenamiento
    BATCH_SIZE = int(os.getenv("BATCH_SIZE", "32"))
    EPOCHS = int(os.getenv("EPOCHS", "15"))
    TRAIN_TEST_SPLIT = float(os.getenv("TRAIN_TEST_SPLIT", "0.8"))
    RANDOM_SEED = int(os.getenv("RANDOM_SEED", "42"))
    BALANCE_DATASET = os.getenv("BALANCE_DATASET", "True").lower() in ("true", "1", "t")

    @staticmethod
    def get_file_patterns():
        """Patrones para identificar archivos de testcases en Juliet"""
        return {
            "java_files": r"CWE\d+_.*\.java$",
            "bad_pattern": r"bad([0-9]*)\.java$",
            "good_pattern": r"good([0-9]*)\.java$",
        }

    @staticmethod
    def ensure_dirs():
        """Crea los directorios necesarios si no existen"""
        os.makedirs(os.path.dirname(Config.MODEL_SAVE_PATH), exist_ok=True)
        os.makedirs(os.path.dirname(Config.TOKENIZER_SAVE_PATH), exist_ok=True)
        os.makedirs(Config.LOG_DIR, exist_ok=True)
