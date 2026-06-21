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

    def test_predictor_identifies_dynamic_ldap_filter_heuristic(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor()
        code = 'String filter = "(uid=" + username + ")"; ctx.search("ou=users", filter, controls);'

        result = predictor.analyze_code(code)

        self.assertTrue(result["is_vulnerable"])
        self.assertTrue(any(item["cwe_id"] == "CWE90" for item in result["probable_cwes"]))
        self.assertTrue(
            any(match["pattern_name"] == "dynamic_ldap_filter" for match in result["heuristic_matches"])
        )

    def test_predictor_suppresses_escaped_ldap_filter_false_positive(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor()
        code = (
            'String filter = "(uid=" + escapeForLDAPSearchFilter(username) + ")"; '
            'ctx.search("ou=users", filter, controls);'
        )

        result = predictor.analyze_code(code)

        self.assertFalse(result["is_vulnerable"])
        self.assertTrue(result["safety_evidence"])
        self.assertFalse(result["heuristic_evidence"])

    def test_predictor_distinguishes_dynamic_parameterized_and_ambiguous_sql(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor()
        vulnerable = (
            'String query = "SELECT * FROM users WHERE name = \'" + username + "\'"; '
            "Statement stmt = connection.createStatement(); stmt.executeQuery(query);"
        )
        safe = (
            'PreparedStatement stmt = connection.prepareStatement('
            '"SELECT * FROM users WHERE name = ?"); stmt.setString(1, username);'
        )
        ambiguous = "Statement stmt = connection.createStatement(); stmt.executeQuery(existingQuery);"

        vulnerable_result = predictor.analyze_code(vulnerable)
        safe_result = predictor.analyze_code(safe)
        ambiguous_result = predictor.analyze_code(ambiguous)

        self.assertTrue(vulnerable_result["is_vulnerable"])
        self.assertTrue(
            any(item["cwe_id"] == "CWE89" for item in vulnerable_result["probable_cwes"])
        )
        self.assertFalse(
            any(item["cwe_id"] == "CWE90" for item in vulnerable_result["probable_cwes"])
        )
        self.assertFalse(safe_result["is_vulnerable"])
        self.assertTrue(safe_result["safety_evidence"])
        self.assertTrue(ambiguous_result["review_required"])

    def test_predictor_resolves_sql_text_blocks_and_matching_bindings(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor()
        safe = '''
        String sql = """
            SELECT id, name
            FROM users
            WHERE name = ?
            """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, username);
            statement.executeQuery();
        }
        '''
        wrong_binding = '''
        String sql = "SELECT id FROM users WHERE name = ?";
        PreparedStatement statement = connection.prepareStatement(sql);
        otherStatement.setString(1, username);
        statement.executeQuery();
        '''

        safe_result = predictor.analyze_code(safe)
        wrong_binding_result = predictor.analyze_code(wrong_binding)

        self.assertFalse(safe_result["is_vulnerable"])
        self.assertTrue(safe_result["safety_evidence"])
        self.assertTrue(wrong_binding_result["review_required"])
        self.assertFalse(wrong_binding_result["safety_evidence"])

    def test_predictor_resolves_sql_auxiliary_variables_and_incremental_concat(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor()
        safe = """
        String base = "SELECT id FROM users";
        String sql = base;
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
        """
        vulnerable = """
        String base = "SELECT id FROM users WHERE name = '";
        String sql = base;
        sql += username;
        sql += "'";
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
        """

        safe_result = predictor.analyze_code(safe)
        vulnerable_result = predictor.analyze_code(vulnerable)

        self.assertFalse(safe_result["is_vulnerable"])
        self.assertTrue(safe_result["safety_evidence"])
        self.assertTrue(vulnerable_result["is_vulnerable"])
        self.assertTrue(vulnerable_result["heuristic_evidence"])

    def test_predictor_recognizes_parameterized_ldap_and_inline_injection(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor()

        safe_result = predictor.analyze_code(
            'ctx.search(base, "(uid={0})", new Object[]{username}, controls);'
        )
        unsafe_result = predictor.analyze_code(
            'ctx.search(base, "(uid=" + username + ")", controls);'
        )

        self.assertFalse(safe_result["is_vulnerable"])
        self.assertTrue(safe_result["safety_evidence"])
        self.assertTrue(unsafe_result["is_vulnerable"])
        self.assertTrue(unsafe_result["heuristic_evidence"])

    def test_predictor_identifies_relative_and_absolute_path_traversal(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor()
        relative = "File file = new File(baseDir, fileName); return new FileInputStream(file);"
        absolute = "return Files.readString(Paths.get(userPath));"
        safe = """
        Path requested = Paths.get(userPath);
        if (requested.isAbsolute()) throw new SecurityException();
        Path resolved = base.resolve(requested).normalize();
        if (!resolved.startsWith(base)) throw new SecurityException();
        return Files.readString(resolved);
        """
        ambiguous = "Path safe = validatePath(userPath); return Files.readString(safe);"

        relative_result = predictor.analyze_code(relative)
        absolute_result = predictor.analyze_code(absolute)
        safe_result = predictor.analyze_code(safe)
        ambiguous_result = predictor.analyze_code(ambiguous)

        self.assertTrue(relative_result["is_vulnerable"])
        self.assertTrue(
            any(item["cwe_id"] == "CWE23" for item in relative_result["probable_cwes"])
        )
        self.assertFalse(
            any(item["cwe_id"] == "CWE36" for item in relative_result["heuristic_evidence"])
        )
        self.assertTrue(absolute_result["is_vulnerable"])
        self.assertEqual(absolute_result["selected_cwe"], "CWE36")
        self.assertTrue(safe_result["safety_evidence"])
        self.assertFalse(safe_result["is_vulnerable"])
        self.assertTrue(ambiguous_result["review_required"])

    def test_path_traversal_safety_does_not_suppress_other_cwe_evidence(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor(
            fusion_config={
                "version": 2,
                "default": {
                    "threshold": 0.4,
                    "model_weight": 0.75,
                    "heuristic_weight": 0.55,
                    "safety_discount": 0.2,
                    "ambiguous_weight": 0.0,
                },
            }
        )
        code = """
        Path requested = Paths.get(userPath);
        if (requested.isAbsolute()) throw new SecurityException();
        Path resolved = base.resolve(requested).normalize();
        if (!resolved.startsWith(base)) throw new SecurityException();
        Runtime.getRuntime().exec(command);
        """

        result = predictor.analyze_code(code)
        evaluations = {item["cwe_id"]: item for item in result["cwe_evaluations"]}

        self.assertTrue(result["is_vulnerable"])
        self.assertEqual(result["selected_cwe"], "CWE78")
        self.assertTrue(evaluations["CWE78"]["is_vulnerable"])
        self.assertFalse(evaluations["CWE23"]["is_vulnerable"])
        self.assertFalse(evaluations["CWE36"]["is_vulnerable"])

    def test_predictor_distinguishes_validated_and_dynamic_process_builder(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor()
        safe = """
        public Process ping(String host) throws Exception {
            if (!host.matches("[A-Za-z0-9.-]+")) throw new IllegalArgumentException();
            return new ProcessBuilder("ping", "-c", "1", host).start();
        }
        """
        safe_composed_argument = """
        public Process mount(String shareName) throws Exception {
            if (!shareName.matches("[A-Za-z0-9_-]+")) throw new IllegalArgumentException();
            return new ProcessBuilder("mount", "//server/" + shareName, "/mnt/share").start();
        }
        """
        vulnerable = 'return new ProcessBuilder("sh", "-c", "ping " + host).start();'
        direct_input = 'return new ProcessBuilder("ping", host).start();'

        safe_result = predictor.analyze_code(safe)
        safe_composed_result = predictor.analyze_code(safe_composed_argument)
        vulnerable_result = predictor.analyze_code(vulnerable)
        direct_result = predictor.analyze_code(direct_input)

        self.assertFalse(safe_result["is_vulnerable"])
        self.assertTrue(safe_result["safety_evidence"])
        self.assertFalse(safe_composed_result["is_vulnerable"])
        self.assertTrue(safe_composed_result["safety_evidence"])
        self.assertTrue(vulnerable_result["is_vulnerable"])
        self.assertTrue(vulnerable_result["heuristic_evidence"])
        self.assertTrue(direct_result["is_vulnerable"])

    def test_predictor_marks_unvalidated_runtime_input_as_strong_evidence(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor()

        result = predictor.analyze_code("return Runtime.getRuntime().exec(userInput);")

        self.assertTrue(result["is_vulnerable"])
        self.assertTrue(result["heuristic_evidence"])

    def test_predictor_marks_unresolved_sensitive_sink_for_review(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor()

        result = predictor.analyze_code('return new ProcessBuilder("date").start();')

        self.assertFalse(result["is_vulnerable"])
        self.assertTrue(result["review_required"])
        self.assertEqual(result["decision"], "review_required")

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

    def test_cli_accepts_frozen_fusion_config(self):
        fusion_path = self.temp_dir / "fusion.json"
        with open(fusion_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "selection_source": "ai_calibration_set",
                    "threshold": 0.4,
                    "model_weight": 1.0,
                    "heuristic_weight": 1.0,
                    "safety_discount": 0.35,
                    "ambiguous_weight": 0.15,
                },
                handle,
            )
        command = [
            str(REPO_ROOT / "venv" / "bin" / "python"),
            "src/main.py",
            "predict",
            "--text",
            "return Runtime.getRuntime().exec(userInput);",
            "--fusion-config",
            str(fusion_path),
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
        self.assertEqual(data["threshold"], 0.4)
        self.assertTrue(data["is_vulnerable"])

    def test_predictor_normalizes_v1_and_resolves_v2_cwe_overrides(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor(
            fusion_config={
                "version": 2,
                "selection_source": "ai_calibration_set",
                "default": {
                    "threshold": 0.4,
                    "model_weight": 0.75,
                    "heuristic_weight": 0.55,
                    "safety_discount": 0.2,
                    "ambiguous_weight": 0.0,
                },
                "by_cwe": {"CWE89": {"threshold": 0.7}},
            }
        )

        self.assertEqual(predictor.resolve_fusion_config("CWE78")["threshold"], 0.4)
        self.assertEqual(predictor.resolve_fusion_config("CWE89")["threshold"], 0.7)

        legacy = predictor_module.VulnerabilityPredictor._normalize_fusion_config(
            {"version": 1, "threshold": 0.6}
        )
        self.assertEqual(legacy["threshold"], 0.6)
        self.assertEqual(legacy["model_weight"], 1.0)

    def test_predictor_rejects_unknown_cwe_fusion_override(self):
        _, _, predictor_module = reload_modules()

        with self.assertRaisesRegex(ValueError, "unknown CWE"):
            predictor_module.VulnerabilityPredictor(
                fusion_config={
                    "version": 2,
                    "default": {
                        "threshold": 0.5,
                        "model_weight": 1.0,
                        "heuristic_weight": 1.0,
                        "safety_discount": 0.35,
                        "ambiguous_weight": 0.15,
                    },
                    "by_cwe": {"CWE999": {"threshold": 0.7}},
                }
            )

    def test_per_cwe_fusion_keeps_other_vulnerability_despite_sql_safety(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor(
            fusion_config={
                "version": 2,
                "selection_source": "ai_calibration_set",
                "default": {
                    "threshold": 0.4,
                    "model_weight": 0.75,
                    "heuristic_weight": 0.55,
                    "safety_discount": 0.2,
                    "ambiguous_weight": 0.0,
                },
                "by_cwe": {"CWE89": {"threshold": 0.7}},
            }
        )
        code = """
        Runtime.getRuntime().exec(userInput);
        PreparedStatement stmt = connection.prepareStatement(
            "SELECT * FROM users WHERE name = ?");
        stmt.setString(1, username);
        """

        result = predictor.analyze_code(code)
        evaluations = {item["cwe_id"]: item for item in result["cwe_evaluations"]}

        self.assertTrue(result["is_vulnerable"])
        self.assertEqual(result["selected_cwe"], "CWE78")
        self.assertTrue(evaluations["CWE78"]["is_vulnerable"])
        self.assertFalse(evaluations["CWE89"]["is_vulnerable"])
        self.assertEqual(evaluations["CWE89"]["threshold"], 0.7)

    def test_per_cwe_fusion_uses_top_neural_candidate_without_evidence(self):
        _, _, predictor_module = reload_modules()
        predictor = predictor_module.VulnerabilityPredictor(
            fusion_config={
                "version": 2,
                "default": {
                    "threshold": 0.4,
                    "model_weight": 0.75,
                    "heuristic_weight": 0.55,
                    "safety_discount": 0.2,
                    "ambiguous_weight": 0.0,
                },
                "by_cwe": {"CWE89": {"threshold": 0.7}},
            }
        )

        result = predictor.analyze_code("public void noop() {}")

        self.assertEqual(result["selected_cwe"], "CWE89")
        self.assertEqual(len(result["cwe_evaluations"]), 1)
        self.assertEqual(result["effective_fusion_config"]["threshold"], 0.7)

    def test_missing_artifacts_raise_clear_error(self):
        os.remove(self.artifacts["tokenizer_path"])
        _, _, predictor_module = reload_modules()

        with self.assertRaises(FileNotFoundError) as context:
            predictor_module.VulnerabilityPredictor()

        self.assertIn("Missing prediction artifacts", str(context.exception))

    def test_limited_oversampling_caps_each_group_multiplier(self):
        trainer_module = importlib.import_module("trainer")
        trainer = trainer_module.ModelTrainer()
        trainer.config.MAX_OVERSAMPLE_MULTIPLIER = 2.0
        trainer.config.RANDOM_SEED = 42
        groups = np.array(["small"] * 2 + ["medium"] * 4 + ["large"] * 10)

        selected = trainer._limited_oversample_indices(groups)
        selected_counts = {
            group: int(np.sum(groups[selected] == group)) for group in set(groups)
        }

        self.assertEqual(selected_counts, {"small": 4, "medium": 8, "large": 10})


if __name__ == "__main__":
    unittest.main()
