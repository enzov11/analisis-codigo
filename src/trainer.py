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
        original_dataset_summary = self.data_loader.summarize_dataset(df)
        df = self._limit_samples_per_cwe(df)
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

        callbacks = self._build_callbacks(artifact_paths)

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

        training_run = self._training_run_summary(history)
        evaluation = self.evaluate(model.model, X_test, y_test, cwe_types_test, test_df)
        metadata = {
            "artifact_version": self.config.ARTIFACT_VERSION or "unversioned",
            "training_profile": self.config.TRAINING_PROFILE,
            "max_code_length": self.config.MAX_CODE_LENGTH,
            "max_tokens": self.config.MAX_TOKENS,
            "max_samples_per_cwe": self.config.MAX_SAMPLES_PER_CWE,
            "prediction_threshold": self.config.PREDICTION_THRESHOLD,
            "num_cwe_types": num_cwe_types,
            "cwe_classes": self.cwe_encoder.classes_.tolist(),
            "original_dataset_summary": original_dataset_summary,
            "dataset_summary": dataset_summary,
            "train_samples": int(len(train_df)),
            "validation_samples": int(len(validation_df)),
            "test_samples": int(len(test_df)),
            "epochs_trained": training_run["epochs_trained"],
            "best_epoch": training_run["best_epoch"],
            "best_monitor": training_run["best_monitor"],
            "best_monitor_value": training_run["best_monitor_value"],
            "training_run": training_run,
            "callback_config": {
                "early_stopping_monitor": self.config.EARLY_STOPPING_MONITOR,
                "early_stopping_mode": self.config.EARLY_STOPPING_MODE,
                "early_stopping_patience": self.config.EARLY_STOPPING_PATIENCE,
                "early_stopping_min_delta": self.config.EARLY_STOPPING_MIN_DELTA,
                "checkpoint_monitor": self.config.CHECKPOINT_MONITOR,
                "checkpoint_mode": self.config.CHECKPOINT_MODE,
                "tensorboard_histogram_freq": self.config.TENSORBOARD_HISTOGRAM_FREQ,
            },
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

    def _build_callbacks(self, artifact_paths):
        return [
            ModelCheckpoint(
                artifact_paths["model"],
                monitor=self.config.CHECKPOINT_MONITOR,
                save_best_only=True,
                mode=self.config.CHECKPOINT_MODE,
            ),
            TensorBoard(
                log_dir=artifact_paths["log_dir"],
                histogram_freq=self.config.TENSORBOARD_HISTOGRAM_FREQ,
            ),
            EarlyStopping(
                monitor=self.config.EARLY_STOPPING_MONITOR,
                mode=self.config.EARLY_STOPPING_MODE,
                patience=self.config.EARLY_STOPPING_PATIENCE,
                min_delta=self.config.EARLY_STOPPING_MIN_DELTA,
                restore_best_weights=True,
            ),
        ]

    def _limit_samples_per_cwe(self, df):
        max_samples = self.config.MAX_SAMPLES_PER_CWE
        if not max_samples:
            return df

        sampled = []
        rng = self.config.RANDOM_SEED
        for _, cwe_df in df.groupby("cwe_id", sort=True):
            if len(cwe_df) <= max_samples:
                sampled.append(cwe_df)
                continue
            sampled.append(self._stratified_sample_cwe(cwe_df, max_samples, rng))
        limited = pd.concat(sampled).sample(frac=1, random_state=rng).reset_index(drop=True)
        print(
            "Applied MAX_SAMPLES_PER_CWE="
            f"{max_samples}; dataset reduced from {len(df)} to {len(limited)} samples."
        )
        return limited

    @staticmethod
    def _stratified_sample_cwe(cwe_df, max_samples, random_state):
        label_groups = list(cwe_df.groupby("label", sort=True))
        if len(label_groups) == 1:
            return cwe_df.sample(n=max_samples, random_state=random_state)

        total = len(cwe_df)
        allocations = {}
        remainders = []
        for label, label_df in label_groups:
            exact = max_samples * len(label_df) / total
            count = min(len(label_df), max(1, int(np.floor(exact))))
            allocations[label] = count
            remainders.append((exact - np.floor(exact), label, len(label_df)))

        while sum(allocations.values()) < max_samples:
            candidates = [
                item for item in sorted(remainders, reverse=True)
                if allocations[item[1]] < item[2]
            ]
            if not candidates:
                break
            _, label, _ = candidates[0]
            allocations[label] += 1

        while sum(allocations.values()) > max_samples:
            label = max(allocations, key=allocations.get)
            if allocations[label] <= 1:
                break
            allocations[label] -= 1

        sampled = [
            label_df.sample(n=allocations[label], random_state=random_state)
            for label, label_df in label_groups
        ]
        return pd.concat(sampled)

    def _training_run_summary(self, history):
        epochs_trained = len(history.epoch)
        monitor = self.config.EARLY_STOPPING_MONITOR
        values = history.history.get(monitor, [])
        best_epoch = None
        best_value = None
        if values:
            if self.config.EARLY_STOPPING_MODE == "max":
                best_index = int(np.argmax(values))
            else:
                best_index = int(np.argmin(values))
            best_epoch = best_index + 1
            best_value = float(values[best_index])
        return {
            "epochs_requested": self.config.EPOCHS,
            "epochs_trained": epochs_trained,
            "best_epoch": best_epoch,
            "best_monitor": monitor,
            "best_monitor_value": best_value,
        }

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
