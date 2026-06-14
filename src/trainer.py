import json
import pickle
from collections import Counter

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint, TensorBoard

from config import Config
from data_loader import DataLoader
from model import VulDeePeckerModel
from preprocessor import CodePreprocessor


class ModelTrainer:
    def __init__(self):
        self.config = Config()
        self.data_loader = DataLoader()
        self.preprocessor = CodePreprocessor()
        self.cwe_encoder = LabelEncoder()

    def train(self):
        self.config.ensure_dirs()
        artifact_paths = self.config.get_artifact_paths()

        print("Loading and preprocessing dataset...")
        df, _ = self.data_loader.load_dataset()
        dataset_summary = self.data_loader.summarize_dataset(df)
        train_df, validation_df, test_df = self.data_loader.split_train_validation_test(df)

        print(f"Dataset summary: {json.dumps(dataset_summary, indent=2)}")

        X_train, y_train, _ = self.preprocessor.prepare_dataset(train_df, fit_tokenizer=True)
        X_validation, y_validation, _ = self.preprocessor.prepare_dataset(
            validation_df, fit_tokenizer=False
        )
        X_test, y_test, _ = self.preprocessor.prepare_dataset(test_df, fit_tokenizer=False)

        all_cwe_types = pd.concat(
            [train_df["cwe_id"], validation_df["cwe_id"], test_df["cwe_id"]]
        )
        self.cwe_encoder.fit(all_cwe_types)

        cwe_types_train = self.cwe_encoder.transform(train_df["cwe_id"])
        cwe_types_validation = self.cwe_encoder.transform(validation_df["cwe_id"])
        cwe_types_test = self.cwe_encoder.transform(test_df["cwe_id"])

        print(f"Class distribution before balancing: {Counter(y_train)}")
        print(f"CWE type distribution before balancing: {Counter(train_df['cwe_id'])}")

        vocab_size = len(self.preprocessor.tokenizer.word_index) + 1
        num_cwe_types = len(self.cwe_encoder.classes_)
        model = VulDeePeckerModel(vocab_size, num_cwe_types)
        model.summary()

        monitor_metric = "val_main_accuracy" if num_cwe_types > 1 else "val_accuracy"
        callbacks = [
            ModelCheckpoint(
                artifact_paths["model"],
                monitor=monitor_metric,
                save_best_only=True,
                mode="max",
            ),
            TensorBoard(log_dir=artifact_paths["log_dir"], histogram_freq=1),
            EarlyStopping(patience=5, restore_best_weights=True),
        ]

        X_train, y_train, cwe_types_train = self._balance_dataset(
            X_train, y_train, cwe_types_train, num_cwe_types
        )
        X_validation = np.array(X_validation).reshape(-1, self.config.MAX_CODE_LENGTH)
        y_validation = np.array(y_validation)
        cwe_types_validation = np.array(cwe_types_validation)
        X_test = np.array(X_test).reshape(-1, self.config.MAX_CODE_LENGTH)
        y_test = np.array(y_test)
        cwe_types_test = np.array(cwe_types_test)

        print("Training model...")
        if num_cwe_types > 1:
            history = model.model.fit(
                x=X_train,
                y={"main": y_train, "cwe_type": cwe_types_train},
                validation_data=(
                    X_validation,
                    {"main": y_validation, "cwe_type": cwe_types_validation},
                ),
                batch_size=self.config.BATCH_SIZE,
                epochs=self.config.EPOCHS,
                callbacks=callbacks,
                verbose=self.config.TRAINING_VERBOSE,
            )
        else:
            history = model.model.fit(
                X_train,
                y_train,
                validation_data=(X_validation, y_validation),
                batch_size=self.config.BATCH_SIZE,
                epochs=self.config.EPOCHS,
                callbacks=callbacks,
                verbose=self.config.TRAINING_VERBOSE,
            )

        self.preprocessor.save_tokenizer(artifact_paths["tokenizer"])
        with open(artifact_paths["cwe_encoder"], "wb") as handle:
            pickle.dump(self.cwe_encoder, handle)

        evaluation = self.evaluate(model.model, X_test, y_test, cwe_types_test, test_df)
        metadata = {
            "artifact_version": self.config.ARTIFACT_VERSION or "unversioned",
            "max_code_length": self.config.MAX_CODE_LENGTH,
            "max_tokens": self.config.MAX_TOKENS,
            "prediction_threshold": self.config.PREDICTION_THRESHOLD,
            "num_cwe_types": num_cwe_types,
            "cwe_classes": self.cwe_encoder.classes_.tolist(),
            "dataset_summary": dataset_summary,
            "train_samples": int(len(train_df)),
            "validation_samples": int(len(validation_df)),
            "test_samples": int(len(test_df)),
            "split_summaries": {
                "train": self.data_loader.summarize_dataset(train_df),
                "validation": self.data_loader.summarize_dataset(validation_df),
                "test": self.data_loader.summarize_dataset(test_df),
            },
            "balance_dataset": self.config.BALANCE_DATASET,
            "max_oversample_multiplier": self.config.MAX_OVERSAMPLE_MULTIPLIER,
        }

        with open(artifact_paths["metadata"], "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2)
        with open(artifact_paths["evaluation"], "w", encoding="utf-8") as handle:
            json.dump(evaluation, handle, indent=2)

        print(f"Model saved to {artifact_paths['model']}")
        print(f"Tokenizer saved to {artifact_paths['tokenizer']}")
        print(f"CWE encoder saved to {artifact_paths['cwe_encoder']}")
        print(f"Evaluation summary saved to {artifact_paths['evaluation']}")
        return history, evaluation

    def evaluate(self, trained_model, X_test, y_test, cwe_types_test, test_df):
        raw_predictions = trained_model.predict(X_test, verbose=0)
        if isinstance(raw_predictions, list):
            main_predictions = raw_predictions[0].reshape(-1)
            cwe_predictions = raw_predictions[1]
        else:
            main_predictions = raw_predictions.reshape(-1)
            cwe_predictions = None

        predicted_labels = (main_predictions >= self.config.PREDICTION_THRESHOLD).astype(int)
        report = classification_report(
            y_test,
            predicted_labels,
            output_dict=True,
            zero_division=0,
        )
        confusion = confusion_matrix(y_test, predicted_labels).tolist()

        evaluation = {
            "threshold": self.config.PREDICTION_THRESHOLD,
            "roc_auc": self._safe_roc_auc(y_test, main_predictions),
            "classification_report": report,
            "confusion_matrix": confusion,
            "per_cwe_positive_rate": self._per_cwe_positive_rate(test_df, predicted_labels),
            "per_cwe_metrics": self._per_cwe_metrics(
                test_df, predicted_labels, main_predictions
            ),
        }

        if cwe_predictions is not None:
            cwe_predicted_labels = np.argmax(cwe_predictions, axis=1)
            cwe_report = classification_report(
                cwe_types_test,
                cwe_predicted_labels,
                output_dict=True,
                zero_division=0,
            )
            evaluation["cwe_classification_report"] = cwe_report

        return evaluation

    def _balance_dataset(self, X_train, y_train, cwe_types_train, num_cwe_types):
        X_train = np.array(X_train)
        y_train = np.array(y_train)
        cwe_types_train = np.array(cwe_types_train)

        if not self.config.BALANCE_DATASET:
            return (
                X_train.reshape(-1, self.config.MAX_CODE_LENGTH),
                y_train,
                cwe_types_train,
            )

        groups = (
            np.array([f"{label}_{cwe}" for label, cwe in zip(y_train, cwe_types_train)])
            if num_cwe_types > 1
            else y_train.astype(str)
        )
        resampled_indices = self._limited_oversample_indices(groups)
        X_train = X_train[resampled_indices]
        y_train = y_train[resampled_indices]
        cwe_types_train = cwe_types_train[resampled_indices]

        print(f"Class distribution after balancing: {Counter(y_train)}")
        print(f"CWE type distribution after balancing: {Counter(cwe_types_train)}")
        return X_train.reshape(-1, self.config.MAX_CODE_LENGTH), y_train, cwe_types_train

    def _limited_oversample_indices(self, groups):
        rng = np.random.default_rng(self.config.RANDOM_SEED)
        counts = Counter(groups)
        largest_group = max(counts.values())
        selected = []
        for group in sorted(counts, key=str):
            indices = np.flatnonzero(groups == group)
            target = min(
                largest_group,
                int(np.ceil(len(indices) * self.config.MAX_OVERSAMPLE_MULTIPLIER)),
            )
            selected.extend(indices.tolist())
            if target > len(indices):
                selected.extend(
                    rng.choice(indices, size=target - len(indices), replace=True).tolist()
                )
        rng.shuffle(selected)
        return np.array(selected, dtype=int)

    @staticmethod
    def _safe_roc_auc(y_true, y_scores):
        try:
            return float(roc_auc_score(y_true, y_scores))
        except ValueError:
            return None

    def _per_cwe_positive_rate(self, test_df, predicted_labels):
        df = test_df.copy()
        df["predicted_label"] = predicted_labels
        grouped = df.groupby("cwe_id")["predicted_label"].mean()
        return {cwe_id: float(rate) for cwe_id, rate in grouped.items()}

    def _per_cwe_metrics(self, test_df, predicted_labels, scores):
        metrics = {}
        for cwe_id, indices in test_df.groupby("cwe_id").groups.items():
            positions = np.array(list(indices), dtype=int)
            y_true = test_df.iloc[positions]["label"].astype(int).to_numpy()
            y_pred = predicted_labels[positions]
            report = classification_report(
                y_true,
                y_pred,
                output_dict=True,
                zero_division=0,
            )
            metrics[cwe_id] = {
                "num_samples": int(len(positions)),
                "roc_auc": self._safe_roc_auc(y_true, scores[positions]),
                "confusion_matrix": confusion_matrix(
                    y_true, y_pred, labels=[0, 1]
                ).tolist(),
                "classification_report": report,
            }
        return metrics
