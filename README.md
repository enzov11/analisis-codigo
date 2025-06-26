# VulDeePecker for Java - Vulnerability Detection

Sistema de detección de vulnerabilidades en código Java basado en deep learning.

## Requisitos
- Python 3.8+
- TensorFlow 2.x
- imbalanced-learn
- scikit-learn
- pandas

## Instalación
git clone https://github.com/tu-usuario/tu-repo.git
cd tu-repo
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows
pip install -r requirements.txt

Configuración

    Copia el archivo .env.example a .env

    Edita .env con tus rutas locales:
    ini

    DATASET_PATH=/ruta/a/tu/dataset

## Entrenamiento
bash

python src/main.py train

Uso para detección
bash

# Analizar archivo
python src/main.py predict --code test/test_file.java

# Analizar texto directo
python src/main.py predict --text "Statement stmt = conn.createStatement();"

Estructura del proyecto
text

├── src/
│   ├── config.py
│   ├── data_loader.py
│   ├── model.py
│   ├── predictor.py
│   ├── preprocessor.py
│   └── trainer.py
├── test/               # Archivos de prueba
├── models/             # Modelos entrenados
├── logs/               # Logs de entrenamiento
└── data/               # Dataset (no incluido)

