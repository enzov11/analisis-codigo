import importlib
import json
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.layers import Dense, Embedding, GlobalAveragePooling1D, Input
from tensorflow.keras.models import Model


REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"


def reload_modules():
    sys.path.insert(0, str(SRC_DIR))
    config_module = importlib.import_module("config")
    preprocessor_module = importlib.import_module("preprocessor")
    predictor_module = importlib.import_module("predictor")
    importlib.reload(config_module)
    importlib.reload(preprocessor_module)
    importlib.reload(predictor_module)
    return config_module, preprocessor_module, predictor_module


def create_test_artifacts(base_dir: Path):
    model_path = base_dir / "model.keras"
    tokenizer_path = base_dir / "tokenizer.pkl"
    encoder_path = base_dir / "cwe_encoder.pkl"
    metadata_path = base_dir / "metadata.json"

    os.environ["MODEL_SAVE_PATH"] = str(model_path)
    os.environ["TOKENIZER_SAVE_PATH"] = str(tokenizer_path)
    os.environ["CWE_ENCODER_SAVE_PATH"] = str(encoder_path)
    os.environ["METADATA_SAVE_PATH"] = str(metadata_path)
    os.environ["EVALUATION_SAVE_PATH"] = str(base_dir / "evaluation.json")
    os.environ["LOG_DIR"] = str(base_dir / "logs")
    os.environ["PREDICTION_THRESHOLD"] = "0.5"

    config_module, preprocessor_module, _ = reload_modules()
    preprocessor = preprocessor_module.CodePreprocessor()
    sample_texts = [
        preprocessor.preprocess_code("Runtime.getRuntime().exec(userInput);"),
        preprocessor.preprocess_code('String q = "SELECT * FROM users WHERE id = " + userInput;'),
        preprocessor.preprocess_code("PreparedStatement stmt = connection.prepareStatement(query);"),
    ]
    preprocessor.create_tokenizer(sample_texts)
    preprocessor.save_tokenizer(model_path.parent / "tokenizer.pkl")

    encoder = LabelEncoder()
    encoder.fit(["CWE78", "CWE89"])
    with open(encoder_path, "wb") as handle:
        pickle.dump(encoder, handle)

    inputs = Input(shape=(config_module.Config.MAX_CODE_LENGTH,))
    x = Embedding(input_dim=128, output_dim=8)(inputs)
    x = GlobalAveragePooling1D()(x)
    main_output = Dense(1, activation="sigmoid", name="main")(x)
    cwe_output = Dense(2, activation="softmax", name="cwe_type")(x)
    model = Model(inputs=inputs, outputs=[main_output, cwe_output])
    model.compile(
        optimizer="adam",
        loss={"main": "binary_crossentropy", "cwe_type": "sparse_categorical_crossentropy"},
    )

    main_weights = model.get_layer("main").get_weights()
    main_weights[0] = np.zeros_like(main_weights[0])
    main_weights[1] = np.array([-10.0], dtype=np.float32)
    model.get_layer("main").set_weights(main_weights)

    cwe_weights = model.get_layer("cwe_type").get_weights()
    cwe_weights[0] = np.zeros_like(cwe_weights[0])
    cwe_weights[1] = np.array([0.0, 2.0], dtype=np.float32)
    model.get_layer("cwe_type").set_weights(cwe_weights)
    model.save(model_path)

    metadata = {
        "prediction_threshold": 0.5,
        "cwe_classes": ["CWE78", "CWE89"],
        "num_cwe_types": 2,
    }
    with open(metadata_path, "w", encoding="utf-8") as handle:
        json.dump(metadata, handle)

    return {
        "model_path": model_path,
        "tokenizer_path": tokenizer_path,
        "encoder_path": encoder_path,
        "metadata_path": metadata_path,
    }


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="tesis-tests-"))
        self.original_env = os.environ.copy()
        self.artifacts = create_test_artifacts(self.temp_dir)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.original_env)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_predictor_marks_vulnerable_example(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor()
        code = (SRC_DIR / "test" / "test_vulnerable.java").read_text(encoding="utf-8")

        result = predictor.analyze_code(code)

        self.assertTrue(result["is_vulnerable"])
        self.assertGreaterEqual(result["vulnerability_probability"], 0.88)
        self.assertTrue(any(item["cwe_id"] == "CWE89" for item in result["probable_cwes"]))
        self.assertTrue(result["suggested_fixes"])

    def test_predictor_handles_safe_example_without_exception(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor()
        code = (SRC_DIR / "test" / "test_safe.java").read_text(encoding="utf-8")

        result = predictor.analyze_code(code)

        self.assertFalse(result["is_vulnerable"])
        self.assertEqual(result["suggested_fixes"], [])
        self.assertEqual(result["vulnerable_lines"], [])

    def test_preprocessor_tokenizer_roundtrip(self):
        _, preprocessor_module, _ = reload_modules()
        preprocessor = preprocessor_module.CodePreprocessor()
        preprocessor.create_tokenizer(["<EXEC> foo", "<SAFE> bar"])
        preprocessor.save_tokenizer(self.temp_dir / "roundtrip.pkl")

        restored = preprocessor_module.CodePreprocessor()
        restored.load_tokenizer(self.temp_dir / "roundtrip.pkl")

        original = preprocessor.text_to_sequence(["<EXEC> foo"]).tolist()
        loaded = restored.text_to_sequence(["<EXEC> foo"]).tolist()
        self.assertEqual(original, loaded)

    def test_cli_json_output(self):
        command = [
            str(REPO_ROOT / "venv" / "bin" / "python"),
            "src/main.py",
            "predict",
            "--code",
            "src/test/test_vulnerable.java",
            "--json",
        ]
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, msg=completed.stderr)
        data = json.loads(completed.stdout)
        self.assertTrue(data["is_vulnerable"])
        self.assertIn("probable_cwes", data)

    def test_missing_artifacts_raise_clear_error(self):
        os.remove(self.artifacts["tokenizer_path"])
        _, _, predictor_module = reload_modules()

        with self.assertRaises(FileNotFoundError) as context:
            predictor_module.VulnerabilityPredictor()

        self.assertIn("Missing prediction artifacts", str(context.exception))


if __name__ == "__main__":
    unittest.main()
