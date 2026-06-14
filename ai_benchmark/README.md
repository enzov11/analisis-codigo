# Protocolo De Evaluacion De Codigo Generado Por IA

Esta carpeta contiene el protocolo externo usado para evaluar CodeScan-AI sobre codigo
Java generado por IA. Los corpus se mantienen separados del entrenamiento con Juliet:
se usan para diagnostico, calibracion y evaluacion externa, pero no para reentrenar el
modelo neuronal.

El protocolo general permanece estable. Los corpus, comandos y resultados particulares
se registran posteriormente dentro de la etapa de integracion correspondiente.

## Principios Del Protocolo

- Usar tareas de calibracion y holdout disjuntas.
- Recolectar condiciones `neutral`, `secure` y `risk-prone`.
- Conservar modelo declarado, fecha, prompts, respuestas y decisiones de revision.
- Establecer ground truth mediante revision manual y oraculos estructurales no
  destructivos.
- Registrar como excluidas las muestras incompletas, no evaluables o ambiguas.
- Seleccionar reglas, pesos y umbrales exclusivamente con calibracion.
- Congelar la configuracion antes de evaluar el holdout una sola vez.
- No incorporar muestras del benchmark externo al entrenamiento Juliet.

## Tipos De Artefactos

Por cada etapa pueden existir:

- `prompts*.json`: manifiestos de tareas disjuntas.
- `*_scaffold.jsonl`: registros preparados para recolectar respuestas.
- `*_responses_raw.jsonl`: respuestas originales.
- `*_pending.jsonl` y `*_for_review.jsonl`: estados intermedios auditables.
- `*_samples.jsonl`: corpus revisados y aprobados.
- `*_fusion_config.json`: configuraciones seleccionadas en calibracion y congeladas.
- `*_evaluation_summary.json`: resultados versionables.

`collect_codex_responses.py` permite recolectar respuestas de forma reanudable.
`generate_codex_samples.py` produce fixtures sinteticos y no debe presentarse como
evidencia de completions reales.

## Flujo Para Crear Un Nuevo Corpus

Validar que los manifiestos no compartan tareas:

```bash
python src/ai_benchmark.py check-manifests \
  --manifests ai_benchmark/<prompts_calibracion>.json \
              ai_benchmark/<prompts_holdout>.json
```

Crear un scaffold pendiente:

```bash
python src/ai_benchmark.py scaffold \
  --manifest ai_benchmark/<prompts_calibracion>.json \
  --output ai_benchmark/<calibracion_scaffold>.jsonl \
  --model-id "provider/model-version" \
  --generated-at "YYYY-MM-DD" \
  --generation-parameters-json '{"temperature": 0}'
```

Recolectar una respuesta por `sample_id` y guardarla con, al menos:

```json
{"sample_id": "CAL_CWE_ID_T01_neutral_1", "generated_code": "public ..."}
```

Importar respuestas y preparar la revision:

```bash
python src/ai_benchmark.py import-responses \
  --scaffold ai_benchmark/<calibracion_scaffold>.jsonl \
  --responses ai_benchmark/<calibracion_respuestas>.jsonl \
  --output ai_benchmark/<calibracion_pendiente>.jsonl

python src/ai_benchmark.py prepare-review \
  --input ai_benchmark/<calibracion_pendiente>.jsonl \
  --output ai_benchmark/<calibracion_revision>.jsonl
```

Los oraculos inspeccionan patrones estructurales sin ejecutar comandos, consultas,
conexiones ni payloads. Si una muestra queda ambigua, se conserva como exclusion. Si la
revision manual resuelve el caso, debe registrar `manual_review_decision` y
`manual_review_note`.

Confirmar evaluaciones y validar el corpus aprobado:

```bash
python src/ai_benchmark.py confirm-assessments \
  --input ai_benchmark/<calibracion_revision>.jsonl \
  --output ai_benchmark/<calibracion_muestras>.jsonl

python src/ai_benchmark.py validate \
  --input ai_benchmark/<calibracion_muestras>.jsonl
```

Ejecutar calibracion y holdout:

```bash
python src/experiments.py --experiment e5 --ai-mode calibration \
  --ai-benchmark ai_benchmark/<calibracion_muestras>.jsonl

python src/experiments.py --experiment e5 --ai-mode holdout \
  --ai-benchmark ai_benchmark/<holdout_muestras>.jsonl \
  --fusion-config ai_benchmark/<fusion_congelada>.json
```

## Evolucion Del Benchmark Por Etapas

### Etapa 1: CWE78 Y CWE90

Esta etapa establecio el protocolo inicial, diagnostico la fusion legacy y produjo la
primera calibracion y el primer holdout observado.

#### Artefactos Y Reproduccion

- Piloto: `prompts.json`, `samples.jsonl`, `evaluation_summary.json`.
- Calibracion: `prompts_calibration.json`, `calibration_samples.jsonl`,
  `calibration_evaluation_summary.json`, `calibration_fusion_config.json`.
- Holdout: `prompts_holdout.json`, `holdout_samples.jsonl`,
  `holdout_evaluation_summary.json`.

```bash
python src/experiments.py --experiment e5 --ai-mode pilot \
  --ai-benchmark ai_benchmark/samples.jsonl

python src/experiments.py --experiment e5 --ai-mode calibration \
  --ai-benchmark ai_benchmark/calibration_samples.jsonl

python src/experiments.py --experiment e5 --ai-mode holdout \
  --ai-benchmark ai_benchmark/holdout_samples.jsonl \
  --fusion-config ai_benchmark/calibration_fusion_config.json
```

#### Resultados

- Piloto sintetico: `144` snippets; F1 neural `0,000`; la fusion legacy produjo
  `48` falsos positivos sobre la condicion segura.
- Calibracion observada: `144` recolectadas, `133` incluidas y `11` ambiguas
  excluidas; F1 hibrido recalibrado `1,000`.
- Holdout congelado: `144` incluidas, `72` seguras y `72` vulnerables; F1 neural
  `0,000`; F1 hibrido `1,000`; matriz hibrida `[[72, 0], [0, 72]]`.

Dos casos ambiguos del holdout fueron confirmados manualmente como seguros y quedaron
documentados. Los resultados corresponden a prompts controlados y una sesion registrada.

### Etapa 2: CWE89

Esta etapa amplio el protocolo a SQL injection e incorporo validaciones que impiden
seleccionar una fusion con una calibracion que no contiene ambas clases.

#### Artefactos Y Reproduccion

- Manifiestos: `prompts_cwe89_calibration.json`,
  `prompts_cwe89_calibration_adversarial.json`, `prompts_cwe89_holdout.json`.
- Calibracion: `cwe89_calibration_samples.jsonl`,
  `cwe89_calibration_samples_v2.jsonl`,
  `cwe89_calibration_collection_summary.json`,
  `cwe89_calibration_v2_evaluation_summary.json`,
  `cwe89_calibration_fusion_config.json`.
- Holdout: `cwe89_holdout_samples.jsonl`,
  `cwe89_holdout_evaluation_summary.json`.

```bash
python src/experiments.py --experiment e5 --ai-mode calibration \
  --ai-benchmark ai_benchmark/cwe89_calibration_samples_v2.jsonl

python src/experiments.py --experiment e5 --ai-mode holdout \
  --ai-benchmark ai_benchmark/cwe89_holdout_samples.jsonl \
  --fusion-config ai_benchmark/cwe89_calibration_fusion_config.json
```

#### Resultados

La primera recoleccion produjo `72` muestras seguras. Se conservo como diagnostico, no
como calibracion valida: neural produjo `72` falsos positivos, la fusion vigente `27` y
las heuristicas `0`.

La calibracion v2 contiene `57` muestras seguras y `15` vulnerables. El neural obtuvo
F1 vulnerable `0,3448`, las heuristicas `0,9655` y el hibrido congelado `0,8571`.

El holdout congelado contiene `72` muestras seguras: neural produjo `71` falsos
positivos, heuristicas `0` e hibrido `5`. La ausencia de muestras vulnerables impide
estimar recall, F1 vulnerable y ROC-AUC.

## Convencion Para Futuras Etapas

Cada ampliacion debe agregar una subseccion cronologica que identifique sus categorias,
artefactos, comandos de reproduccion, resultados y limitaciones. Los resultados de
etapas anteriores se conservan sin reemplazarlos.

Las decisiones arquitectonicas y el analisis conjunto de cada etapa se documentan en
[`../docs/ARQUITECTURA_Y_EVOLUCION.md`](../docs/ARQUITECTURA_Y_EVOLUCION.md).
