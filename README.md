# Vulnerability Detection

Sistema de detección de vulnerabilidades en código Java basado en deep learning.

## Requisitos
- Python 3.8+
- TensorFlow 2.x
- imbalanced-learn
- scikit-learn
- pandas

## Instalación

- Crear entorno virtual: python -m venv venv
- Activar entorno virtual: source venv/bin/activate
- Instalar dependencias: pip install -r requirements.txt

## Configuración

Copiar el archivo .env.example a .env y editar con rutas locales para el dataset
DATASET_PATH=/ruta/a/tu/dataset

## Entrenamiento
```
python src/main.py train
```

## Analizar archivo
```
python src/main.py predict --code test/test_file.java
```
## Analizar texto directo
```
python src/main.py predict --text "Statement stmt = conn.createStatement();"
```
