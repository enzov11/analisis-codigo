import numpy as np
from tensorflow.keras.models import load_model
from preprocessor import CodePreprocessor
from config import Config
import re


class VulnerabilityPredictor:
    def __init__(self):
        self.config = Config()
        self.preprocessor = CodePreprocessor()
        self.model = None
        self.load_model()

        # Enhanced security patterns
        self.dangerous_patterns = {
            r"Runtime\.getRuntime\(\)\.exec\(": 0.95,
            r"new ProcessBuilder\(": 0.9,
            r"stmt\.execute\(": 0.85,
            r"SELECT\s.+?\sFROM\s.+?\sWHERE\s.+?\+\s": 0.9,
            r"System\.loadLibrary\(": 0.8,
            r"Unsafe\.getUnsafe\(": 0.85,
            r"POTENTIAL FLAW": 0.7,
            r"\.eval\(": 0.9,
            r"\.setCatalog\(": 0.75,
        }

    def load_model(self):
        """Load model and necessary artifacts"""
        self.model = load_model(self.config.MODEL_SAVE_PATH)

        # Initialize tokenizer with dummy data
        dummy_data = ["<EXEC> VAR_STRING", "<SQL_INJECTION> VAR_STRING"]
        self.preprocessor.create_tokenizer(dummy_data)

    def predict(self, code: str) -> float:
        """Enhanced prediction with pattern matching"""
        # Preprocess code
        processed_code = self.preprocessor.preprocess_code(code)

        # Convert to sequence
        sequence = self.preprocessor.text_to_sequence([processed_code])

        # Model prediction
        prediction = self.model.predict(sequence)
        base_prob = float(prediction[0][0])

        # Pattern-based boosting
        max_pattern_prob = 0.0
        for pattern, min_prob in self.dangerous_patterns.items():
            if re.search(pattern, code, re.IGNORECASE):
                max_pattern_prob = max(max_pattern_prob, min_prob)

        # Combine predictions
        final_prob = max(base_prob, max_pattern_prob)
        return final_prob

    def analyze_code(self, code: str) -> dict:
        """Comprehensive code analysis with proper dictionary initialization"""
        # Inicializar el diccionario con todas las claves posibles
        result = {
            "vulnerability_probability": 0.0,
            "is_vulnerable": False,
            "vulnerable_lines": [],
            "suggested_fixes": [],
            "processed_code": "",
            "detected_patterns": [],
        }

        try:
            # Calcular probabilidad de vulnerabilidad
            prob = self.predict(code)
            result["vulnerability_probability"] = prob
            result["is_vulnerable"] = prob > 0.5

            # Detección de patrones vulnerables
            vulnerabilities = []
            for pattern, severity in self.dangerous_patterns.items():
                matches = re.finditer(pattern, code, re.IGNORECASE)
                for match in matches:
                    line_start = code[: match.start()].count("\n") + 1
                    vulnerabilities.append(
                        {
                            "pattern": pattern,
                            "line_number": line_start,
                            "code": match.group(0),
                            "severity": severity,
                        }
                    )

            result["vulnerable_lines"] = vulnerabilities
            result["detected_patterns"] = vulnerabilities  # Para compatibilidad

            # Sugerencias de fixes
            suggested_fixes = []
            if "Runtime.getRuntime().exec(" in code:
                suggested_fixes.append(
                    {
                        "line_number": next(
                            (
                                v["line_number"]
                                for v in vulnerabilities
                                if "Runtime.getRuntime().exec(" in v["code"]
                            )
                        ),
                        "vulnerable_code": "Runtime.getRuntime().exec(...)",
                        "suggested_fix": "Use ProcessBuilder with command array",
                        "reference": "CWE-78",
                    }
                )

            if any(p in code for p in ["stmt.execute(", "SELECT"]):
                suggested_fixes.append(
                    {
                        "line_number": next(
                            (
                                v["line_number"]
                                for v in vulnerabilities
                                if any(
                                    p in v["code"] for p in ["stmt.execute(", "SELECT"]
                                )
                            )
                        ),
                        "vulnerable_code": "SQL query concatenation",
                        "suggested_fix": "Use PreparedStatement with parameterized queries",
                        "reference": "CWE-89",
                    }
                )

            result["suggested_fixes"] = suggested_fixes
            result["processed_code"] = self.preprocessor.preprocess_code(code)

        except Exception as e:
            print(f"Error during analysis: {str(e)}")

        return result
