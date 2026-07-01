# Protocolo De Evaluacion De Codigo Generado Por IA

Esta carpeta contiene el protocolo externo usado para evaluar CodeScan-AI sobre codigo
Java generado por IA. Los corpus se mantienen separados del entrenamiento con Juliet:
se usan para diagnostico, calibracion y evaluacion externa, pero no para reentrenar el
modelo neuronal.

El protocolo general permanece estable. Los corpus, comandos y resultados particulares
se registran posteriormente dentro de la etapa de integracion correspondiente.

## Principios Del Protocolo

- Usar tareas de calibracion y holdout disjuntas.
- Recolectar condiciones controladas como `neutral`, `secure`, `risk-prone` o
  variantes explicitas de riesgo/adversariales cuando la etapa lo requiera.
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

Las configuraciones de fusion version 1 aplican parametros globales. Las de version 2
definen un bloque `default` y overrides en `by_cwe`. Una categoria sin override hereda
el bloque `default`.

`collect_codex_responses.py` permite recolectar respuestas de forma reanudable.
Para sesiones Codex CLI se puede parametrizar el modelo, el identificador auditable y
los parametros registrados. Para otros proveedores, se debe guardar un JSONL de
respuestas crudas e importarlo con `import-responses`.
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

## Recoleccion Para Validacion Externa Ampliada

Para una nueva validacion externa de CWE89 se prepararon dos manifiestos disjuntos:

- `prompts_cwe89_large_calibration.json`
- `prompts_cwe89_large_holdout.json`

Cada corpus contiene `24` tareas, `4` condiciones y `3` respuestas por condicion:
`288` muestras esperadas para calibracion y `288` para holdout. Las condiciones son
`neutral`, `secure`, `risk_prone` y `adversarial_insecure`. El holdout ampliado no
debe abrirse hasta congelar una configuracion seleccionada exclusivamente con la
calibracion ampliada.

Crear scaffolds:

```bash
python src/ai_benchmark.py scaffold \
  --manifest ai_benchmark/prompts_cwe89_large_calibration.json \
  --output ai_benchmark/cwe89_large_calibration_scaffold.jsonl \
  --model-id "provider/model-version" \
  --generated-at "YYYY-MM-DD" \
  --generation-parameters-json '{"temperature": 0}'

python src/ai_benchmark.py scaffold \
  --manifest ai_benchmark/prompts_cwe89_large_holdout.json \
  --output ai_benchmark/cwe89_large_holdout_scaffold.jsonl \
  --model-id "provider/model-version" \
  --generated-at "YYYY-MM-DD" \
  --generation-parameters-json '{"temperature": 0}'
```

Si la recoleccion se hace con Codex CLI:

```bash
python ai_benchmark/collect_codex_responses.py \
  --scaffold ai_benchmark/cwe89_large_calibration_scaffold.jsonl \
  --output ai_benchmark/cwe89_large_calibration_responses_raw.jsonl \
  --generated-at "YYYY-MM-DD" \
  --codex-model "gpt-5.5" \
  --model-id "OpenAI Codex CLI gpt-5.5"
```

Para otro proveedor o una sesion manual, procesar cada registro del scaffold de forma
independiente con este prompt operativo:

```text
Vas a generar respuestas Java para un benchmark de seguridad.

Reglas obligatorias:
1. Lee un registro JSONL a la vez.
2. Usa exactamente el campo "prompt_text" como solicitud al modelo.
3. Devuelve unicamente codigo Java, sin Markdown, sin explicacion y sin texto adicional.
4. La respuesta debe ser un unico metodo Java autocontenido cuando sea posible.
5. No uses contexto de respuestas anteriores.
6. No corrijas ni suavices la intencion del prompt: responde a la solicitud tal como esta escrita.
7. No ejecutes herramientas, no inspecciones repositorios y no agregues dependencias externas salvo que el prompt las pida.
8. Guarda la salida cruda asociada al mismo "sample_id".
9. Registra el modelo, fecha, proveedor/sesion y parametros usados.

Formato de salida JSONL requerido:
{"sample_id":"...","generated_code":"...","model_id":"<proveedor/modelo/version>","generated_at":"YYYY-MM-DD","generation_parameters":{...}}

Ahora procesa los registros del scaffold uno por uno.
```

Luego importar, revisar y validar:

```bash
python src/ai_benchmark.py import-responses \
  --scaffold ai_benchmark/cwe89_large_calibration_scaffold.jsonl \
  --responses ai_benchmark/cwe89_large_calibration_responses_raw.jsonl \
  --output ai_benchmark/cwe89_large_calibration_pending.jsonl

python src/ai_benchmark.py prepare-review \
  --input ai_benchmark/cwe89_large_calibration_pending.jsonl \
  --output ai_benchmark/cwe89_large_calibration_review.jsonl

python src/ai_benchmark.py confirm-assessments \
  --input ai_benchmark/cwe89_large_calibration_review.jsonl \
  --output ai_benchmark/cwe89_large_calibration_samples.jsonl

python src/ai_benchmark.py validate \
  --input ai_benchmark/cwe89_large_calibration_samples.jsonl
```

Repetir el mismo flujo para el holdout solo despues de seleccionar y congelar la nueva
configuracion desde calibracion.

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
- Validacion externa ampliada con otra sesion/modelo:
  `prompts_cwe89_large_calibration.json`,
  `prompts_cwe89_large_holdout.json`, `cwe89_large_calibration_samples.jsonl`,
  `cwe89_large_holdout_samples.jsonl`,
  `cwe89_large_calibration_evaluation_summary.json`,
  `cwe89_large_calibration_fusion_config.json` y
  `cwe89_large_holdout_evaluation_summary.json`.
- Fusion combinada: `per_cwe_fusion_config.json`; conserva el fallback historico y
  aplica a CWE89 la configuracion de validacion externa ampliada con umbral `0,5`.

```bash
python src/experiments.py --experiment e5 --ai-mode calibration \
  --ai-benchmark ai_benchmark/cwe89_calibration_samples_v2.jsonl

python src/experiments.py --experiment e5 --ai-mode holdout \
  --ai-benchmark ai_benchmark/cwe89_holdout_samples.jsonl \
  --fusion-config ai_benchmark/cwe89_calibration_fusion_config.json

python src/experiments.py --experiment e5 --ai-mode calibration \
  --ai-benchmark ai_benchmark/cwe89_large_calibration_samples.jsonl

python src/experiments.py --experiment e5 --ai-mode holdout \
  --ai-benchmark ai_benchmark/cwe89_large_holdout_samples.jsonl \
  --fusion-config ai_benchmark/cwe89_large_calibration_fusion_config.json
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

Despues de abrir ese holdout se implemento la fusion configurable por CWE. El primer
override CWE89 uso el punto de calibracion con umbral `0,7`, `0` falsos positivos, `1`
falso negativo y F1 vulnerable `0,9655`. Los holdouts existentes se conservan solo como
regresion de compatibilidad y no se publican nuevas metricas a partir de ellos.

Tambien se unifico la resolucion SQL local usada por el predictor y el oraculo. Esta
reconoce variables auxiliares, concatenacion incremental, text blocks y bindings del
`PreparedStatement` correspondiente. La comprobacion de regresion conserva los labels
aprobados; no constituye una nueva evaluacion del holdout.

La validacion externa ampliada posterior uso `288` muestras de calibracion y `288` de
holdout disjunto recolectadas con otra sesion/modelo. La calibracion ampliada contuvo
`216` muestras seguras y `72` vulnerables; el holdout ampliado quedo equilibrado con
`144` seguras y `144` vulnerables. En ambos corpus, el componente neuronal mantuvo
falsos positivos masivos (`216` en calibracion y `144` en holdout), mientras que las
heuristicas y el hibrido congelado obtuvieron F1 vulnerable `1,000`, sin falsos
positivos ni falsos negativos. La configuracion de validacion externa ampliada
selecciono para CWE89 umbral `0,5` con los mismos pesos base de fusion y fue promovida
como override oficial en `per_cwe_fusion_config.json`.

Ejemplo de aplicacion durante prediccion:

```bash
python src/main.py predict --code src/test/test_vulnerable.java --json \
  --fusion-config ai_benchmark/per_cwe_fusion_config.json
```

### Etapa 3: CWE23 Y CWE36

Esta etapa evalua traversal de rutas relativo y absoluto con corpus externos separados
para calibracion y holdout congelado. Los resultados historicos se conservan asociados a
esta etapa y no reemplazan las etapas anteriores.

#### Artefactos

- Manifiestos: `prompts_cwe23_cwe36_calibration.json`,
  `prompts_cwe23_cwe36_holdout.json`.
- Calibracion: `cwe23_cwe36_calibration_samples.jsonl`,
  `cwe23_cwe36_calibration_evaluation_summary.json`,
  `cwe23_cwe36_calibration_fusion_config.json`.
- Holdout: `cwe23_cwe36_holdout_samples.jsonl`,
  `cwe23_cwe36_holdout_evaluation_summary.json`.
- Fusion combinada: `per_cwe_fusion_config.json`; conserva los overrides previos y agrega
  los overrides de CWE23 y CWE36.

```bash
python src/ai_benchmark.py scaffold \
  --manifest ai_benchmark/prompts_cwe23_cwe36_calibration.json \
  --output ai_benchmark/cwe23_cwe36_calibration_scaffold.jsonl \
  --model-id "provider/model-version" \
  --generated-at "YYYY-MM-DD" \
  --generation-parameters-json '{"temperature": 0}'

python src/ai_benchmark.py scaffold \
  --manifest ai_benchmark/prompts_cwe23_cwe36_holdout.json \
  --output ai_benchmark/cwe23_cwe36_holdout_scaffold.jsonl \
  --model-id "provider/model-version" \
  --generated-at "YYYY-MM-DD" \
  --generation-parameters-json '{"temperature": 0}'
```

Evaluacion congelada:

```bash
python src/experiments.py --experiment e5 --ai-mode calibration \
  --ai-benchmark ai_benchmark/cwe23_cwe36_calibration_samples.jsonl

python src/experiments.py --experiment e5 --ai-mode holdout \
  --ai-benchmark ai_benchmark/cwe23_cwe36_holdout_samples.jsonl \
  --fusion-config ai_benchmark/cwe23_cwe36_calibration_fusion_config.json
```

La calibracion selecciono umbral `0,5` para CWE23 y `0,4` para CWE36. En holdout, el
modelo neuronal obtuvo F1 vulnerable `0,8` con `48` falsos positivos; las heuristicas y
el hibrido congelado obtuvieron F1 vulnerable `1,0`, sin falsos positivos ni falsos
negativos. Cada corpus incluyo `144` muestras, balanceadas por categoria: `72` CWE23 y
`72` CWE36.

### Etapa 4: CWE80

Esta etapa incorpora el benchmark externo para cross-site scripting en salida HTML. La
calibracion cuenta con respuestas aprobadas y configuracion seleccionada; el holdout
congelado ya fue ejecutado con esa configuracion.

#### Artefactos Preparados

- Manifiestos: `prompts_cwe80_calibration.json`, `prompts_cwe80_holdout.json`.
- Calibracion: `cwe80_calibration_samples.jsonl`,
  `cwe80_calibration_evaluation_summary.json`,
  `cwe80_calibration_fusion_config.json`.
- Holdout: `cwe80_holdout_samples.jsonl`,
  `cwe80_holdout_evaluation_summary.json`.

```bash
python src/ai_benchmark.py scaffold \
  --manifest ai_benchmark/prompts_cwe80_calibration.json \
  --output ai_benchmark/cwe80_calibration_scaffold.jsonl \
  --model-id "provider/model-version" \
  --generated-at "YYYY-MM-DD" \
  --generation-parameters-json '{"temperature": 0}'

python src/ai_benchmark.py scaffold \
  --manifest ai_benchmark/prompts_cwe80_holdout.json \
  --output ai_benchmark/cwe80_holdout_scaffold.jsonl \
  --model-id "provider/model-version" \
  --generated-at "YYYY-MM-DD" \
  --generation-parameters-json '{"temperature": 0}'

python src/experiments.py --experiment e5 --ai-mode calibration \
  --ai-benchmark ai_benchmark/cwe80_calibration_samples.jsonl

python src/experiments.py --experiment e5 --ai-mode holdout \
  --ai-benchmark ai_benchmark/cwe80_holdout_samples.jsonl \
  --fusion-config ai_benchmark/cwe80_calibration_fusion_config.json
```

La calibracion contiene `72` muestras aprobadas: `48` seguras y `24` vulnerables. El
modelo neuronal externo obtuvo F1 vulnerable `0,0645`, con `36` falsos positivos y `22`
falsos negativos. Las heuristicas y la fusion calibrada obtuvieron F1 vulnerable `1,0`,
sin falsos positivos ni falsos negativos. La configuracion seleccionada usa umbral `0,4`
para CWE80.

El holdout congelado tambien contiene `72` muestras aprobadas: `48` seguras y `24`
vulnerables. El modelo neuronal obtuvo F1 vulnerable `0,0`, con `36` falsos positivos y
`24` falsos negativos. Las heuristicas y el hibrido congelado obtuvieron F1 vulnerable
`1,0`, sin falsos positivos ni falsos negativos.

### Etapa 5: CWE113

Esta etapa prepara el benchmark externo para HTTP Response Splitting. Ya existen
calibracion aprobada y holdout congelado ejecutado. No se actualiza la fusion global por
CWE porque la configuracion calibrada no supero a la heuristica en holdout; la etapa se
cierra con esa limitacion documentada.

#### Artefactos Preparados

- Manifiestos: `prompts_cwe113_calibration.json`, `prompts_cwe113_holdout.json`.
- Scaffolds: `cwe113_calibration_scaffold.jsonl`, `cwe113_holdout_scaffold.jsonl`.
- Calibracion: `cwe113_calibration_samples.jsonl`,
  `cwe113_calibration_evaluation_summary.json`,
  `cwe113_calibration_fusion_config.json`.
- Holdout: `cwe113_holdout_samples.jsonl`,
  `cwe113_holdout_evaluation_summary.json`.

```bash
python src/ai_benchmark.py scaffold \
  --manifest ai_benchmark/prompts_cwe113_calibration.json \
  --output ai_benchmark/cwe113_calibration_scaffold.jsonl \
  --model-id "provider/model-version" \
  --generated-at "YYYY-MM-DD" \
  --generation-parameters-json '{"temperature": 0}'

python src/ai_benchmark.py scaffold \
  --manifest ai_benchmark/prompts_cwe113_holdout.json \
  --output ai_benchmark/cwe113_holdout_scaffold.jsonl \
  --model-id "provider/model-version" \
  --generated-at "YYYY-MM-DD" \
  --generation-parameters-json '{"temperature": 0}'
```

```bash
python src/experiments.py --experiment e5 --ai-mode calibration \
  --ai-benchmark ai_benchmark/cwe113_calibration_samples.jsonl

python src/experiments.py --experiment e5 --ai-mode holdout \
  --ai-benchmark ai_benchmark/cwe113_holdout_samples.jsonl \
  --fusion-config ai_benchmark/cwe113_calibration_fusion_config.json
```

La calibracion contiene `72` muestras aprobadas: `12` seguras y `60` vulnerables. El
modelo neuronal obtuvo F1 vulnerable `0,9091`, con `12` falsos positivos y `0` falsos
negativos. Las heuristicas y la fusion calibrada obtuvieron F1 vulnerable `1,0`, sin
falsos positivos ni falsos negativos. La configuracion seleccionada usa umbral `0,5`
para CWE113.

El holdout congelado contiene `72` muestras aprobadas: `18` seguras y `54` vulnerables.
El modelo neuronal obtuvo F1 vulnerable `0,8571`, con `18` falsos positivos y `0` falsos
negativos. Las heuristicas obtuvieron F1 vulnerable `1,0`, sin falsos positivos ni
falsos negativos. El hibrido congelado obtuvo F1 vulnerable `0,8710`, con `16` falsos
positivos y `0` falsos negativos. Por esto, CWE113 queda cerrada sin override global
activo; una regla de fusion mas conservadora queda como mejora futura.

### Etapa 6: CWE129

Esta etapa evalua la validacion impropia de indices. CWE129 ya fue incluida en el
baseline neuronal comun `cwe15-roadmap-v1` y completo su calibracion externa desde el
scaffold JSONL y su holdout congelado. El override validado fue incorporado a
`per_cwe_fusion_config.json`.

En Juliet, el baseline comun obtuvo para CWE129 ROC-AUC `0,999627` y F1 vulnerable
`0,9768` sobre `2.796` muestras de test. Estos numeros solo documentan el rendimiento en
Juliet; la decision de fusion debe salir del corpus de calibracion externo.

#### Artefactos Preparados

- Manifiestos: `prompts_cwe129_calibration.json`, `prompts_cwe129_holdout.json`.
- Scaffolds: `cwe129_calibration_scaffold.jsonl`, `cwe129_holdout_scaffold.jsonl`.
- Corpus aprobado: `cwe129_calibration_samples.jsonl`, con `72` muestras (`24` seguras
  y `48` vulnerables).
- Configuracion congelada: `cwe129_calibration_fusion_config.json`.
- Holdout aprobado: `cwe129_holdout_samples.jsonl`, con `72` muestras (`48` seguras y
  `24` vulnerables).
- Metricas: `cwe129_calibration_evaluation_summary.json` y
  `cwe129_holdout_evaluation_summary.json`.

La red sola obtuvo F1 vulnerable `0,800` y `24` falsos positivos. La heuristica y la
fusion calibrada alcanzaron F1 vulnerable `1,000`, sin falsos positivos ni falsos
negativos. La configuracion seleccionada usa umbral `0,4`, pesos `0,75` y `0,55`,
descuento seguro `0,20` y peso ambiguo `0,0`.

En holdout, la red sola obtuvo F1 vulnerable `0,500` y `48` falsos positivos. La
heuristica y la fusion congelada mantuvieron F1 vulnerable `1,000`, sin falsos
positivos ni falsos negativos. Las respuestas neutral y secure fueron seguras, mientras
las risk-prone fueron vulnerables. La etapa queda cerrada, con la limitacion de que el
corpus externo es controlado y las dos completions de cada condicion fueron identicas.

### Etapa 7: CWE134

Esta etapa incorpora cadenas de formato no controladas. CWE134 ya forma parte del
baseline neuronal comun `cwe15-roadmap-v1`; no requiere un nuevo entrenamiento.

El oraculo distingue entre un formato dinamico que controla `printf`, `String.format`,
`Formatter.format`, `MessageFormat.format` o `String.formatted`, y el uso seguro de un
formato literal con valores externos como argumentos. Las asignaciones locales a
literales y allowlists explicitas se reconocen como seguras; helpers de sanitizacion no
resolubles quedan ambiguos.

En Juliet, el baseline comun obtuvo ROC-AUC `0,999626` y F1 vulnerable `0,9767` sobre
`762` muestras de test, con `9` falsos positivos y `0` falsos negativos. Estas metricas
no sustituyen la evaluacion externa.

#### Artefactos Preparados

- Manifiestos: `prompts_cwe134_calibration.json`, `prompts_cwe134_holdout.json`.
- Scaffolds: `cwe134_calibration_scaffold.jsonl`, `cwe134_holdout_scaffold.jsonl`.
- Cada corpus contiene `12` tareas, `3` condiciones y `2` completions: `72` muestras
  potenciales.
- Corpus aprobado: `cwe134_calibration_samples.jsonl`, con `24` muestras seguras y `48`
  vulnerables.
- Configuracion congelada: `cwe134_calibration_fusion_config.json`.
- Holdout aprobado: `cwe134_holdout_samples.jsonl`, con `24` muestras seguras y `48`
  vulnerables.
- Metricas: `cwe134_calibration_evaluation_summary.json` y
  `cwe134_holdout_evaluation_summary.json`.

La red sola obtuvo F1 vulnerable `0,800` y `24` falsos positivos. La heuristica y la
fusion calibrada alcanzaron F1 vulnerable `1,000`, sin falsos positivos ni falsos
negativos. La configuracion seleccionada usa umbral `0,4`, pesos `0,75` y `0,55`,
descuento seguro `0,20` y peso ambiguo `0,0`.

En holdout, la red sola mantuvo F1 vulnerable `0,800` y `24` falsos positivos. La
heuristica y la fusion congelada mantuvieron F1 vulnerable `1,000`, sin falsos
positivos ni falsos negativos. El override CWE134 fue incorporado a
`per_cwe_fusion_config.json`.

La etapa queda cerrada. Como limitacion, las respuestas neutral y risk-prone fueron
identicas, al igual que las dos completions de cada condicion, por lo que el corpus no
representa variacion independiente entre generaciones.

### Etapa 8: CWE190

Esta etapa incorpora desbordamiento de enteros. CWE190 ya forma parte del baseline
neuronal comun `cwe15-roadmap-v1`; no requiere un nuevo entrenamiento.

El oraculo clasifica como vulnerable la aritmetica directa sobre parametros numericos
mediante suma, resta, multiplicacion, incremento o decremento. Reconoce como segura la
familia `Math.*Exact`, `BigInteger`, constantes pequenas y guardas locales contra
limites numericos. Los helpers externos de validacion quedan ambiguos.

En Juliet, el baseline comun obtuvo ROC-AUC `0,999730` y F1 vulnerable `0,9807` sobre
`2.793` muestras de test, con `21` falsos positivos y `6` falsos negativos. Estas
metricas no sustituyen la evaluacion externa.

#### Artefactos Preparados

- Manifiestos: `prompts_cwe190_calibration.json`, `prompts_cwe190_holdout.json`.
- Scaffolds: `cwe190_calibration_scaffold.jsonl`, `cwe190_holdout_scaffold.jsonl`.
- Cada corpus contiene `12` tareas, `3` condiciones y `2` completions: `72` muestras
  potenciales.
- Corpus aprobado: `cwe190_calibration_samples.jsonl`, con `24` muestras seguras y `48`
  vulnerables.
- Configuracion congelada: `cwe190_calibration_fusion_config.json`.
- Holdout aprobado: `cwe190_holdout_samples.jsonl`, con `24` muestras seguras y `48`
  vulnerables.
- Metricas: `cwe190_calibration_evaluation_summary.json` y
  `cwe190_holdout_evaluation_summary.json`.

La red sola obtuvo F1 vulnerable `0,800` y `24` falsos positivos. La heuristica y la
fusion calibrada alcanzaron F1 vulnerable `1,000`, sin falsos positivos ni falsos
negativos. La configuracion seleccionada usa umbral `0,4`, pesos `0,75` y `0,55`,
descuento seguro `0,20` y peso ambiguo `0,0`.

En holdout, la red sola mantuvo F1 vulnerable `0,800` y `24` falsos positivos. La
heuristica y la fusion congelada mantuvieron F1 vulnerable `1,000`, sin falsos
positivos ni falsos negativos. El override CWE190 fue incorporado a
`per_cwe_fusion_config.json`.

La etapa queda cerrada. Como limitacion, las respuestas neutral y risk-prone fueron
identicas, al igual que las dos completions de cada condicion, por lo que el corpus no
representa variacion independiente entre generaciones.

### Etapa 9: CWE319

Esta etapa incorpora transmision en texto claro de informacion sensible. CWE319 ya
forma parte del baseline neuronal comun `cwe15-roadmap-v1`; no requiere un nuevo
entrenamiento.

El oraculo exige dos elementos antes de emitir evidencia: una variable sensible y un
sink de red. Distingue HTTP, FTP, Telnet y `Socket` plano de HTTPS, `SSLSocket` y APIs
TLS. Los endpoints dinamicos sin validacion local quedan ambiguos; una URL aislada sin
flujo sensible no se considera evidencia.

En Juliet, el baseline comun obtuvo ROC-AUC `0,999208` y F1 vulnerable `0,9725` sobre
`507` muestras de test, con `5` falsos positivos y `2` falsos negativos. Estas metricas
no sustituyen la evaluacion externa.

#### Artefactos Preparados

- Manifiestos: `prompts_cwe319_calibration.json`, `prompts_cwe319_holdout.json`.
- Scaffolds: `cwe319_calibration_scaffold.jsonl`, `cwe319_holdout_scaffold.jsonl`.
- Cada corpus contiene `12` tareas, `3` condiciones y `2` completions: `72` muestras
  potenciales.
- Corpus aprobado: `cwe319_calibration_samples.jsonl`, con `48` muestras seguras y `24`
  vulnerables.
- Configuracion congelada: `cwe319_calibration_fusion_config.json`.
- Holdout aprobado: `cwe319_holdout_samples.jsonl`, con `48` muestras seguras y `24`
  vulnerables.
- Metricas: `cwe319_calibration_evaluation_summary.json` y
  `cwe319_holdout_evaluation_summary.json`.

La red sola clasifico las `72` muestras como seguras: obtuvo F1 vulnerable `0,000` y
`24` falsos negativos. La heuristica y la fusion calibrada alcanzaron F1 vulnerable
`1,000`, sin falsos positivos ni falsos negativos. La configuracion seleccionada usa
umbral `0,4`, pesos `0,75` y `0,55`, descuento seguro `0,20` y peso ambiguo `0,0`.

En el holdout congelado, la red volvio a clasificar las `72` muestras como seguras:
obtuvo F1 vulnerable `0,000` y `24` falsos negativos. La heuristica y la fusion
mantuvieron F1 vulnerable `1,000`, sin falsos positivos ni falsos negativos. El
override CWE319 validado se incorporo a `per_cwe_fusion_config.json`.

La etapa queda cerrada. Como limitacion, las dos completions de cada combinacion de
tarea y condicion fueron identicas, por lo que el corpus contiene `33` implementaciones
distintas entre sus `72` muestras.

## Convencion Para Futuras Etapas

Cada ampliacion debe agregar una subseccion cronologica que identifique sus categorias,
artefactos, comandos de reproduccion, resultados y limitaciones. Los resultados de
etapas anteriores se conservan sin reemplazarlos.

Las decisiones arquitectonicas y el analisis conjunto de cada etapa se documentan en
[`../docs/ARQUITECTURA_Y_EVOLUCION.md`](../docs/ARQUITECTURA_Y_EVOLUCION.md).
