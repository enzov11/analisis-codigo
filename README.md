# CodeScan-AI

CodeScan-AI es un sistema de deteccion de vulnerabilidades CWE en codigo Java. Combina un modelo neuronal entrenado con Juliet/SARD y una capa heuristica explicable para analizar fragmentos de codigo, reportar evidencia de riesgo y sugerir correcciones.

El repositorio contiene el codigo, el protocolo experimental y los corpus necesarios para replicar los experimentos principales.

## Que Hace

- Entrena un modelo para clasificar fragmentos Java como seguros o vulnerables.
- Usa Juliet como fuente principal de entrenamiento.
- Extrae muestras principalmente a nivel de metodo.
- Reduce leakage usando un split por grupos de familias Juliet.
- Persiste modelo, tokenizer, encoder CWE, metadata y resumen de evaluacion.
- Analiza codigo desde archivo o texto directo.
- Devuelve probabilidad neuronal, evidencia heuristica, decision final, CWE probables, lineas sospechosas y sugerencias de correccion.
- Permite aplicar una configuracion de fusion congelada para reproducir la evaluacion de codigo generado por IA.
- Define las CWE oficiales y sus oraculos no destructivos en un registro central extensible.

Las categorias oficiales actuales son `CWE78`, `CWE89` y `CWE90`. Los artefactos
persistidos actuales corresponden al modelo entrenado con las tres categorias.

## Estructura Del Proyecto

```text
src/
  main.py              CLI para entrenar y predecir
  trainer.py           entrenamiento principal sobre Juliet
  predictor.py         inferencia neuronal + heuristicas explicables
  cwe_registry.py      registro oficial y oraculos estructurales CWE
  experiments.py       runner de experimentos del articulo
  ai_benchmark.py      utilidades para corpus de codigo generado por IA
  data_loader.py       carga y etiquetado de muestras Juliet
  preprocessor.py      tokenizacion y normalizacion de codigo Java
  model.py             arquitectura BLSTM con attention
  test/                ejemplos Java simples

ai_benchmark/
  README.md            protocolo del benchmark IA
  prompts*.json        manifiestos de piloto, calibracion y holdout
  *_samples*.jsonl     corpus anotados y aprobados
  *_summary.json       resumenes versionables de resultados

tests/
  test_system.py       pruebas de CLI, predictor y heuristicas
  test_ai_benchmark.py pruebas del benchmark IA
```

Los modelos entrenados y salidas experimentales generadas en `src/models/` no se versionan. Se regeneran con los comandos de entrenamiento y experimentacion.

El procedimiento uniforme para incorporar nuevas categorias esta documentado en
[`docs/AGREGAR_CWE.md`](docs/AGREGAR_CWE.md). El estado actual, la hoja de ruta de
15 categorias y el inventario auditado de Juliet estan en
[`docs/ESTADO_CWE.md`](docs/ESTADO_CWE.md). Las decisiones de arquitectura, el historial
de evolucion por etapas y el trabajo futuro se explican en
[`docs/ARQUITECTURA_Y_EVOLUCION.md`](docs/ARQUITECTURA_Y_EVOLUCION.md).

## Requisitos

- Python 3.8 o superior.
- Dependencias listadas en `requirements.txt`.
- Dataset Juliet/SARD Java disponible localmente para entrenar desde cero.

## Instalacion Desde Cero

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Editar `.env` y configurar `DATASET_PATH` con la ruta local al dataset Juliet:

```env
DATASET_PATH=/ruta/al/dataset/Juliet
```

`DATASET_PATH` solo es obligatorio para entrenamiento y experimentos que recargan Juliet. Para predecir se necesitan artefactos ya entrenados en `src/models/`.

## Configuracion Principal

Los valores por defecto estan en `.env.example`:

```env
MODEL_SAVE_PATH=src/models/vuldeepecker.keras
TOKENIZER_SAVE_PATH=src/models/tokenizer.pkl
CWE_ENCODER_SAVE_PATH=src/models/cwe_encoder.pkl
METADATA_SAVE_PATH=src/models/metadata.json
EVALUATION_SAVE_PATH=src/models/evaluation.json

MAX_CODE_LENGTH=500
MAX_TOKENS=20000
EMBEDDING_DIM=256
LSTM_UNITS=128
BATCH_SIZE=32
EPOCHS=15
TRAIN_SPLIT=0.7
VALIDATION_SPLIT=0.15
TEST_SPLIT=0.15
RANDOM_SEED=42
BALANCE_DATASET=True
MAX_OVERSAMPLE_MULTIPLIER=2.0
PREDICTION_THRESHOLD=0.5
```

Para crear artefactos nuevos sin sobrescribir modelos anteriores, definir una version y no reemplazar manualmente los paths:

```env
ARTIFACT_VERSION=cwe78-cwe89-cwe90-v1
TARGET_CWE_IDS=CWE78,CWE89,CWE90
REQUIRE_ALL_TARGET_CWES=True
```

Con `REQUIRE_ALL_TARGET_CWES=True`, el entrenamiento falla si el dataset no contiene alguna categoria oficial.

## Entrenar El Modelo Principal

```bash
python src/main.py train
```

Para imprimir el resumen de evaluacion:

```bash
python src/main.py train --json
```

La version de tres categorias requiere casos Java para `CWE78`, `CWE89` y `CWE90`. El Juliet local auditado contiene las tres categorias, incluida CWE89 dentro de subdirectorios `s01` a `s04`.

Para reproducir estrictamente el modelo original del articulo antes de ampliar el dataset:

```env
TARGET_CWE_IDS=CWE78,CWE90
ARTIFACT_VERSION=paper-cwe78-cwe90-v1
```

El entrenamiento realiza:

1. Carga de archivos Java de Juliet.
2. Extraccion de metodos cuando es posible.
3. Etiquetado seguro/vulnerable y asignacion CWE.
4. Split por CWE y grupos en entrenamiento, validacion y prueba para reducir leakage.
5. Tokenizacion y padding.
6. Oversampling opcional con multiplicador maximo por combinacion CWE-etiqueta.
7. Entrenamiento BLSTM con attention y salida auxiliar CWE.
8. Persistencia de artefactos en `src/models/`.

Artefactos esperados:

```text
src/models/vuldeepecker.keras
src/models/tokenizer.pkl
src/models/cwe_encoder.pkl
src/models/metadata.json
src/models/evaluation.json
```

## Analizar Codigo

Analizar un archivo:

```bash
python src/main.py predict --code src/test/test_vulnerable.java
```

Analizar texto directo:

```bash
python src/main.py predict --text 'Runtime.getRuntime().exec("ping " + userInput);'
```

Obtener salida JSON:

```bash
python src/main.py predict --code src/test/test_vulnerable.java --json
```

Aplicar la configuracion de fusion congelada usada en el experimento IA:

```bash
python src/main.py predict --code src/test/test_vulnerable.java --json \
  --fusion-config ai_benchmark/calibration_fusion_config.json
```

La salida incluye:

- `neural_probability`
- `heuristic_evidence`
- `safety_evidence`
- `ambiguous_evidence`
- `fusion_probability`
- `decision`
- `review_required`
- CWE probables
- lineas sospechosas
- sugerencias de correccion

## Pruebas

```bash
python -m unittest discover -s tests -v
```

Las pruebas cubren:

- inferencia CLI;
- carga de artefactos;
- heuristicas y oraculos CWE78, CWE89 y CWE90;
- casos seguros, vulnerables y ambiguos;
- validacion de corpus IA;
- overrides manuales auditables;
- separacion entre piloto, calibracion y holdout.

## Experimentos Del Articulo

Todos los experimentos escriben salidas en `src/models/experiments/`, que es un directorio generado e ignorado por Git.

### E1: Estabilidad Con Seeds

```bash
python src/experiments.py --experiment e1 --seeds 42 7 13 21 100
```

Evalua estabilidad del modelo repitiendo entrenamiento con varias semillas. Esto permite reportar promedio y variacion, no solo una corrida favorable.

Para guardar los resultados de la version de tres CWE por separado:

```bash
python src/experiments.py --experiment e1 --seeds 42 7 13 21 100 \
  --output-dir src/models/experiments/cwe78-cwe89-cwe90-v1
```

### E2: Ablation Study

```bash
python src/experiments.py --experiment e2
```

Compara el modelo completo contra variantes sin attention, sin salida auxiliar CWE, sin oversampling, sin heuristicas y solo heuristicas.

### E3: Baselines Clasicos

```bash
python src/experiments.py --experiment e3
```

Evalua Logistic Regression, Random Forest y Linear SVM con TF-IDF, ademas de una variante BLSTM sin attention.

### E5: Codigo Generado Por IA

Piloto sintetico:

```bash
python src/experiments.py --experiment e5 --ai-mode pilot \
  --ai-benchmark ai_benchmark/samples.jsonl
```

Calibracion:

```bash
python src/experiments.py --experiment e5 --ai-mode calibration \
  --ai-benchmark ai_benchmark/calibration_samples.jsonl
```

Holdout congelado:

```bash
python src/experiments.py --experiment e5 --ai-mode holdout \
  --ai-benchmark ai_benchmark/holdout_samples.jsonl \
  --fusion-config ai_benchmark/calibration_fusion_config.json
```

La calibracion selecciona la fusion sin reentrenar el modelo Juliet. El holdout debe evaluarse con la configuracion congelada.

Los manifiestos, configuraciones congeladas, comandos de reproduccion y resultados de
cada etapa se documentan en [`ai_benchmark/README.md`](ai_benchmark/README.md).

### Otros Experimentos

```bash
python src/experiments.py --experiment e4
python src/experiments.py --experiment e6
python src/experiments.py --experiment e7
```

- `e4`: generalizacion entre CWE.
- `e6`: localizacion de lineas sospechosas.
- `e7`: analisis de umbrales entre `0.1` y `0.9`.

## Evolucion Y Resultados

| Etapa | Alcance | Documentacion |
|---|---|---|
| 1 | Evaluador inicial y primer protocolo externo | [Arquitectura y evolucion](docs/ARQUITECTURA_Y_EVOLUCION.md#etapa-1-evaluador-inicial-para-cwe78-y-cwe90); [Benchmark](ai_benchmark/README.md#etapa-1-cwe78-y-cwe90) |
| 2 | Ampliacion del evaluador y del protocolo externo | [Arquitectura y evolucion](docs/ARQUITECTURA_Y_EVOLUCION.md#etapa-2-ampliacion-a-cwe89); [Benchmark](ai_benchmark/README.md#etapa-2-cwe89) |

Cada etapa conserva sus metricas, cambios, hallazgos y limitaciones. El estado vigente
de soporte y la hoja de ruta se mantienen en
[`docs/ESTADO_CWE.md`](docs/ESTADO_CWE.md).

## Reproducir Evaluaciones Externas

El flujo general para crear, revisar, validar y evaluar nuevos corpus esta documentado
en [`ai_benchmark/README.md`](ai_benchmark/README.md). Ese documento conserva tambien
los artefactos y comandos exactos de cada etapa historica.
