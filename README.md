# Vulnerability Detection

Sistema de detección de vulnerabilidades CWE en código Java basado en deep learning y heurísticas explicables.

## Qué hace el proyecto

- Entrena un modelo para clasificar fragmentos de código Java como vulnerables o seguros.
- Usa el dataset Juliet como fuente principal de entrenamiento.
- Persiste el pipeline completo de inferencia: modelo, tokenizer, encoder de CWE y metadata.
- Analiza código desde archivo o texto directo y devuelve:
  - probabilidad del modelo,
  - probabilidad heurística,
  - decisión final,
  - CWE probables,
  - líneas sospechosas,
  - sugerencias de corrección.

## Requisitos

- Python 3.8+
- TensorFlow 2.x
- imbalanced-learn
- scikit-learn
- pandas

## Instalación

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuración

Copiar `.env.example` a `.env`.

`DATASET_PATH` solo es obligatorio para `train`.

Artefactos por defecto:

- Modelo: `src/models/vuldeepecker.keras`
- Tokenizer: `src/models/tokenizer.pkl`
- Encoder de CWE: `src/models/cwe_encoder.pkl`
- Metadata: `src/models/metadata.json`
- Evaluación: `src/models/evaluation.json`

## Entrenamiento

```bash
python src/main.py train
```

Para obtener el resumen de evaluación en JSON:

```bash
python src/main.py train --json
```

Durante el entrenamiento el sistema:

- extrae muestras por método cuando es posible para reducir ruido en Juliet,
- realiza un split por grupos para reducir leakage entre variantes relacionadas,
- guarda métricas de validación persistentes.

## Predicción

Analizar un archivo:

```bash
python src/main.py predict --code src/test/test_vulnerable.java
```

Analizar texto directo:

```bash
python src/main.py predict --text "Statement stmt = conn.createStatement();"
```

Salida JSON:

```bash
python src/main.py predict --code src/test/test_vulnerable.java --json
```

## Pruebas

```bash
python -m unittest discover -s tests -v
```

## Notas

- `predict` requiere que existan el modelo, tokenizer y metadata guardados.
- Si faltan artefactos, la CLI devuelve un error explícito indicando qué archivo no está disponible.
- Las heurísticas siguen activas, pero ahora se reportan por separado del score del modelo para mantener trazabilidad.
