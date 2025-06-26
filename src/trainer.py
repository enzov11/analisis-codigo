import os
import numpy as np
import pandas as pd
from tensorflow.keras.callbacks import ModelCheckpoint, TensorBoard, EarlyStopping
from imblearn.over_sampling import RandomOverSampler
from sklearn.preprocessing import LabelEncoder
from collections import Counter
from data_loader import DataLoader
from preprocessor import CodePreprocessor
from model import VulDeePeckerModel
from config import Config


class ModelTrainer:
    def __init__(self):
        self.config = Config()
        self.data_loader = DataLoader()
        self.preprocessor = CodePreprocessor()
        self.cwe_encoder = LabelEncoder()

    def train(self):
        """Enhanced training process with proper type handling"""
        print("Loading and preprocessing dataset...")
        df, cwe_descriptions = self.data_loader.load_dataset()
        train_df, test_df = self.data_loader.split_dataset(df)

        # Prepare datasets
        X_train, y_train, cwe_counts = self.preprocessor.prepare_dataset(train_df)
        X_test, y_test, _ = self.preprocessor.prepare_dataset(test_df)

        # Encode CWE types as integers
        all_cwe_types = pd.concat([train_df["cwe_id"], test_df["cwe_id"]])
        self.cwe_encoder.fit(all_cwe_types)

        cwe_types_train = self.cwe_encoder.transform(train_df["cwe_id"])
        cwe_types_test = self.cwe_encoder.transform(test_df["cwe_id"])

        print(f"Class distribution before balancing: {Counter(y_train)}")
        print(f"CWE types distribution: {Counter(train_df['cwe_id'])}")

        # Initialize model
        vocab_size = len(self.preprocessor.tokenizer.word_index) + 1
        num_cwe_types = len(self.cwe_encoder.classes_)
        model = VulDeePeckerModel(vocab_size, num_cwe_types)
        model.summary()

        # Callbacks
        callbacks = [
            ModelCheckpoint(
                self.config.MODEL_SAVE_PATH,
                monitor="val_main_accuracy",
                save_best_only=True,
                mode="max",
            ),
            TensorBoard(log_dir=self.config.LOG_DIR, histogram_freq=1),
            EarlyStopping(patience=5, restore_best_weights=True),
        ]

        print("Training model...")
        if num_cwe_types > 1:
            if self.config.BALANCE_DATASET:
                # Combine all data
                indices = np.arange(len(X_train))

                # We need to balance based on both y_train and cwe_types
                # Create unique groups for balancing
                groups = np.array(
                    [f"{y}_{cwe}" for y, cwe in zip(y_train, cwe_types_train)]
                )

                ros = RandomOverSampler(random_state=self.config.RANDOM_SEED)
                resampled_indices, _ = ros.fit_resample(indices.reshape(-1, 1), groups)
                resampled_indices = resampled_indices.flatten()

                X_train = X_train[resampled_indices]
                y_train = y_train[resampled_indices]
                cwe_types_train = cwe_types_train[resampled_indices]

                print(f"Class distribution after balancing: {Counter(y_train)}")
                print(
                    f"CWE types distribution after balancing: {Counter(cwe_types_train)}"
                )

            # Convert to numpy arrays if they aren't already
            X_train = np.array(X_train)
            y_train = np.array(y_train)
            cwe_types_train = np.array(cwe_types_train)

            X_train = np.array(X_train).reshape(-1, self.config.MAX_CODE_LENGTH)
            X_test = np.array(X_test).reshape(-1, self.config.MAX_CODE_LENGTH)

            history = model.model.fit(
                x=X_train,
                y={"main": y_train, "cwe_type": cwe_types_train},
                validation_data=(X_test, {"main": y_test, "cwe_type": cwe_types_test}),
                batch_size=self.config.BATCH_SIZE,
                epochs=self.config.EPOCHS,
                callbacks=callbacks,
                verbose=1,
            )
        else:
            if self.config.BALANCE_DATASET:
                ros = RandomOverSampler(random_state=self.config.RANDOM_SEED)
                X_train, y_train = ros.fit_resample(
                    X_train.reshape(X_train.shape[0], -1), y_train
                )
                X_train = X_train.reshape(-1, self.config.MAX_CODE_LENGTH)

                print(f"Class distribution after balancing: {Counter(y_train)}")

            history = model.model.fit(
                X_train,
                y_train,
                validation_data=(X_test, y_test),
                batch_size=self.config.BATCH_SIZE,
                epochs=self.config.EPOCHS,
                callbacks=callbacks,
                verbose=1,
            )

        print(f"Model saved to {self.config.MODEL_SAVE_PATH}")
        return history
