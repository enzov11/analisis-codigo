# Protocolo De Evaluacion De Codigo Generado Por IA

Esta carpeta contiene el protocolo externo usado para evaluar CodeScan-AI sobre codigo Java producido en una sesion registrada con un asistente de IA. El benchmark esta separado del entrenamiento con Juliet: los snippets IA se usan para diagnostico, calibracion y evaluacion externa, pero no para reentrenar el modelo neuronal.

## Resumen Del Protocolo

- CWE objetivo: `CWE78` y `CWE90`.
- Condiciones de prompt: `neutral`, `secure` y `risk-prone`.
- Tamano por corpus: `12` tareas por CWE, `3` condiciones y `2` completions por condicion, para `144` snippets.
- Ground truth: revision manual mas oraculo estructural no destructivo.
- Exclusion: muestras incompletas, no evaluables o ambiguas quedan registradas con `exclusion_reason`.
- Separacion: la calibracion selecciona la fusion; el holdout evalua una vez la configuracion congelada.

## Archivos Principales

- `prompts.json`: manifiesto del piloto sintetico.
- `samples.jsonl`: piloto sintetico aprobado; documenta el fallo inicial de falsos positivos.
- `evaluation_summary.json`: resumen versionable del piloto con la fusion legacy.
- `prompts_calibration.json`: tareas del conjunto de calibracion.
- `calibration_samples.jsonl`: corpus de calibracion aprobado; `133` incluidas y `11` excluidas.
- `calibration_evaluation_summary.json`: metricas versionables de calibracion.
- `calibration_fusion_config.json`: configuracion congelada de fusion.
- `prompts_holdout.json`: tareas disjuntas del holdout.
- `holdout_samples.jsonl`: corpus holdout aprobado; `144` incluidas, `72` seguras y `72` vulnerables.
- `holdout_evaluation_summary.json`: metricas versionables del holdout congelado.
- `generate_codex_samples.py`: generador de fixtures sinteticos; no debe usarse como evidencia de completions reales.

Archivos como `*_scaffold.jsonl`, `*_pending.jsonl`, `*_for_review.jsonl` y `*_responses_raw.jsonl` conservan trazabilidad del proceso de recoleccion y revision.

## Flujo Para Crear Un Nuevo Corpus

Validar que los manifiestos no compartan tareas:

```bash
python src/ai_benchmark.py check-manifests \
  --manifests ai_benchmark/prompts.json \
              ai_benchmark/prompts_calibration.json \
              ai_benchmark/prompts_holdout.json
```

Crear un scaffold pendiente:

```bash
python src/ai_benchmark.py scaffold \
  --manifest ai_benchmark/prompts_calibration.json \
  --output ai_benchmark/calibration_scaffold.jsonl \
  --model-id "provider/model-version" \
  --generated-at "YYYY-MM-DD" \
  --generation-parameters-json '{"temperature": 0}'
```

Recolectar una respuesta por `sample_id` y guardarla en JSONL con, al menos:

```json
{"sample_id": "CAL_CWE78_T01_neutral_1", "generated_code": "public ..."}
```

Importar respuestas:

```bash
python src/ai_benchmark.py import-responses \
  --scaffold ai_benchmark/calibration_scaffold.jsonl \
  --responses ai_benchmark/calibration_responses_raw.jsonl \
  --output ai_benchmark/calibration_samples_pending.jsonl
```

Preparar archivo de revision con oraculo estructural:

```bash
python src/ai_benchmark.py prepare-review \
  --input ai_benchmark/calibration_samples_pending.jsonl \
  --output ai_benchmark/calibration_samples_for_review.jsonl
```

El oraculo no ejecuta comandos ni se conecta a LDAP. Solo inspecciona patrones estructurales:

- `CWE78`: construccion dinamica de comandos, shell explicito, `Runtime.exec`, `ProcessBuilder` con o sin validacion.
- `CWE90`: concatenacion directa en filtros LDAP, escaping reconocido y filtros parametrizados.

Aplicar labels confirmados por revision manual:

```bash
python src/ai_benchmark.py confirm-assessments \
  --input ai_benchmark/calibration_samples_for_review.jsonl \
  --output ai_benchmark/calibration_samples.jsonl
```

Si una muestra queda ambigua, se conserva como exclusion. Si la revision manual resuelve un caso ambiguo, debe quedar documentado con `manual_review_decision` y `manual_review_note`.

## Validar Corpus Aprobados

```bash
python src/ai_benchmark.py validate --input ai_benchmark/calibration_samples.jsonl
python src/ai_benchmark.py validate --input ai_benchmark/holdout_samples.jsonl
```

Resultados esperados actuales:

```text
calibration_samples.jsonl: total 144, incluidas 133, excluidas 11, pendientes 0
holdout_samples.jsonl:     total 144, incluidas 144, excluidas 0,  pendientes 0
```

## Reproducir La Evaluacion Del Articulo

El modelo entrenado con Juliet debe existir en `src/models/`. Si no existe, entrenar primero desde la raiz:

```bash
python src/main.py train --json
```

Ejecutar piloto sintetico:

```bash
python src/experiments.py --experiment e5 --ai-mode pilot \
  --ai-benchmark ai_benchmark/samples.jsonl
```

Ejecutar calibracion:

```bash
python src/experiments.py --experiment e5 --ai-mode calibration \
  --ai-benchmark ai_benchmark/calibration_samples.jsonl
```

Ejecutar holdout con fusion congelada:

```bash
python src/experiments.py --experiment e5 --ai-mode holdout \
  --ai-benchmark ai_benchmark/holdout_samples.jsonl \
  --fusion-config ai_benchmark/calibration_fusion_config.json
```

Las salidas generadas por el runner se escriben en:

```text
src/models/experiments/e5_ai_pilot/
src/models/experiments/e5_ai_calibration/
src/models/experiments/e5_ai_holdout/
```

Estas carpetas son artefactos generados y no se versionan. Los resumenes versionables del articulo estan en:

```text
ai_benchmark/evaluation_summary.json
ai_benchmark/calibration_evaluation_summary.json
ai_benchmark/holdout_evaluation_summary.json
```

## Resultados Registrados

### Piloto Sintetico

- `144` snippets generados por plantillas.
- No representa completions reales observadas.
- Diagnostico inicial: el neural-only no detecto vulnerabilidades externas y la fusion legacy produjo `48` falsos positivos sobre la condicion segura.

### Calibracion

- `144` completions recolectadas.
- `133` incluidas.
- `11` excluidas por ambiguedad.
- F1 del hibrido recalibrado: `1.000`.
- Uso: seleccion de fusion y threshold, sin reentrenar Juliet.

### Holdout

- `144` muestras incluidas.
- `72` seguras y `72` vulnerables.
- Dos casos `CWE78` ambiguos fueron resueltos manualmente como seguros y documentados.
- F1 neural-only: `0.000`.
- F1 hibrido congelado: `1.000`.
- Matriz del hibrido congelado: `[[72, 0], [0, 72]]`.

## Interpretacion

Los resultados muestran que el modelo neuronal entrenado solo con Juliet no transfirio por si mismo al corpus IA controlado. La mejora provino de heuristicas contextuales y fusion calibrada que distinguen sinks vulnerables de usos seguros con validacion, escaping o argumentos separados.

La evaluacion esta limitada a:

- una sesion/modelo registrado;
- prompts controlados;
- dos CWE (`CWE78` y `CWE90`);
- fragmentos Java aislados, no repositorios completos.

Por eso, los resultados no deben interpretarse como rendimiento general en codigo generado por IA sin restricciones.
