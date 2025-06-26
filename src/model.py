from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Input,
    Embedding,
    Bidirectional,
    LSTM,
    Dense,
    Dropout,
    GlobalMaxPooling1D,
    Concatenate,
    LayerNormalization,
    MultiHeadAttention,
    Reshape,
)
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.regularizers import l2
from config import Config


class VulDeePeckerModel:
    def __init__(self, vocab_size: int, num_cwe_types: int = 1):
        self.config = Config()
        self.vocab_size = vocab_size
        self.num_cwe_types = num_cwe_types
        self.model = self.build_model()

    def build_model(self) -> Model:
        """Enhanced model architecture with fixed attention mechanism"""
        # Input layer
        inputs = Input(shape=(self.config.MAX_CODE_LENGTH,))

        # Enhanced embedding with positional encoding
        embedding = Embedding(
            input_dim=self.vocab_size,
            output_dim=self.config.EMBEDDING_DIM,
            input_length=self.config.MAX_CODE_LENGTH,
            mask_zero=False,  # Changed to False to avoid mask warnings
            embeddings_regularizer=l2(0.01),
        )(inputs)

        # Bidirectional LSTM layers
        blstm1 = Bidirectional(
            LSTM(
                self.config.LSTM_UNITS,
                return_sequences=True,
                kernel_regularizer=l2(0.01),
            )
        )(embedding)
        blstm1 = LayerNormalization()(blstm1)

        blstm2 = Bidirectional(
            LSTM(
                self.config.LSTM_UNITS // 2,
                return_sequences=True,
                kernel_regularizer=l2(0.01),
            )
        )(blstm1)
        blstm2 = LayerNormalization()(blstm2)

        # Fixed attention mechanism
        query = Dense(64)(blstm2)
        key = Dense(64)(blstm2)
        value = Dense(64)(blstm2)

        attention_output = MultiHeadAttention(num_heads=4, key_dim=16, value_dim=16)(
            query, key, value
        )

        # Skip connection
        attention_output = Concatenate()([blstm2, attention_output])
        attention_output = LayerNormalization()(attention_output)

        # Global pooling
        pooled = GlobalMaxPooling1D()(attention_output)

        # CWE-type auxiliary output
        if self.num_cwe_types > 1:
            cwe_output = Dense(
                self.num_cwe_types, activation="softmax", name="cwe_type"
            )(pooled)

        # Main vulnerability detection
        dense1 = Dense(self.config.DENSE_UNITS, activation="relu")(pooled)
        dense1 = Dropout(self.config.DROPOUT_RATE)(dense1)

        dense2 = Dense(self.config.DENSE_UNITS // 2, activation="relu")(dense1)
        dense2 = Dropout(self.config.DROPOUT_RATE)(dense2)

        main_output = Dense(1, activation="sigmoid", name="main")(dense2)

        # Compile model
        if self.num_cwe_types > 1:
            model = Model(inputs=inputs, outputs=[main_output, cwe_output])
            model.compile(
                optimizer=Adam(learning_rate=self.config.LEARNING_RATE),
                loss={
                    "main": "binary_crossentropy",
                    "cwe_type": "sparse_categorical_crossentropy",
                },
                metrics={"main": ["accuracy"], "cwe_type": ["accuracy"]},
                loss_weights={"main": 0.8, "cwe_type": 0.2},
            )
        else:
            model = Model(inputs=inputs, outputs=main_output)
            model.compile(
                optimizer=Adam(learning_rate=self.config.LEARNING_RATE),
                loss="binary_crossentropy",
                metrics=["accuracy"],
            )

        return model

    def summary(self):
        return self.model.summary()
