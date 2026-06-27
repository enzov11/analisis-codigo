# Arquitectura, Decisiones Y Evolucion

Este documento explica las decisiones tecnicas principales de CodeScan-AI, el motivo
del enfoque hibrido y la evolucion del proyecto a medida que se incorporan nuevas
categorias. El cuerpo principal describe la arquitectura vigente de forma general. El
historial posterior conserva, por etapa de integracion, los cambios, resultados,
hallazgos y asuntos pendientes.

Los resultados experimentales citados provienen de artefactos persistidos y resumenes
versionados. Las explicaciones sobre sus causas se presentan como hipotesis cuando no
existe evidencia suficiente para establecer causalidad.

## Objetivo Del Sistema

CodeScan-AI evalua fragmentos Java generados por IA para detectar vulnerabilidades
mapeadas a CWE. El sistema no busca reemplazar una revision de seguridad completa ni
un analisis interprocedural de repositorios. Su objetivo actual es combinar una
estimacion neuronal con evidencia estructural explicable para:

- clasificar fragmentos como seguros, vulnerables o sujetos a revision;
- proponer categorias CWE probables;
- localizar lineas sospechosas;
- reconocer mitigaciones conocidas;
- sugerir correcciones concretas.

## Componente Neuronal

### Datos Y Unidad De Analisis

El entrenamiento usa Juliet/SARD porque ofrece casos Java etiquetados, variantes
seguras y vulnerables, categorias CWE conocidas y condiciones experimentales
reproducibles. Los archivos se convierten principalmente en muestras a nivel de
metodo. Esta granularidad reduce ruido respecto al archivo completo y se aproxima a
la unidad que suele revisar una persona cuando recibe un fragmento generado por IA.

Juliet es un benchmark sintetico. Por ello, un resultado alto dentro de Juliet no
demuestra por si solo que el modelo generalice a codigo producido por asistentes,
repositorios reales o estilos de programacion diferentes.

### Preprocesamiento Especializado

El codigo se transforma en secuencias de tokens de longitud fija. El preprocesador:

- normaliza declaraciones simples y literales;
- elimina paquetes e imports;
- conserva tokens especiales para operaciones sensibles y marcadores Juliet;
- limita el vocabulario y representa tokens desconocidos de forma consistente.

Esta normalizacion reduce dispersion del vocabulario y ayuda al modelo a aprender
regularidades relacionadas con vulnerabilidades. Como contrapartida, puede eliminar
detalles que distinguen una mitigacion segura de un uso vulnerable, especialmente
cuando la diferencia depende del flujo de datos o de varias sentencias.

### Arquitectura Elegida

La arquitectura actual usa embeddings, dos capas BLSTM bidireccionales, normalizacion,
atencion multi-cabeza, una conexion de representaciones, pooling global y capas densas.
Produce:

- una salida binaria que estima la probabilidad de vulnerabilidad;
- una salida auxiliar que clasifica el tipo de CWE cuando existen varias categorias.

Se eligio una BLSTM porque el significado de un token de seguridad puede depender del
contexto anterior y posterior dentro del metodo. La atencion permite que el modelo
asigne diferente relevancia a posiciones de la secuencia. La salida auxiliar CWE busca
que la representacion compartida aprenda tanto la decision segura/vulnerable como
diferencias entre familias de debilidades.

Esta solucion es compatible con el volumen de datos y la infraestructura disponibles,
y conserva continuidad con trabajos neuronales de deteccion de vulnerabilidades
basados en secuencias. Actualmente se analizan metodos completos; la extraccion mediante
*code gadgets* y *program slicing* permanece como trabajo futuro.

### Limitaciones Neuronales

El componente neuronal tiene varias limitaciones que deben conservarse al interpretar
sus probabilidades:

- aprende correlaciones del dominio de entrenamiento, incluidas regularidades propias
  de Juliet;
- no explica por si solo que linea o mitigacion determino la decision;
- no realiza un analisis de flujo de datos completo;
- su probabilidad puede no estar calibrada al aplicarse a otro dominio;
- puede reaccionar a un sink sensible sin comprender completamente su contexto.

## Componente Heuristico

La capa heuristica inspecciona patrones estructurales sin ejecutar comandos, consultas,
conexiones ni payloads. Las categorias oficiales, mitigaciones y oraculos se mantienen
en un registro central. Para cada CWE se busca distinguir tres tipos de evidencia:

- **Vulnerable:** existe una construccion de riesgo suficientemente clara.
- **Segura:** se reconoce una mitigacion concreta.
- **Ambigua:** existe un sink sensible, pero el flujo local no permite confirmar si es
  seguro o vulnerable.

Las heuristicas permiten asociar evidencia con una linea, una CWE, una explicacion y
una correccion sugerida. Tambien sirven como oraculos estructurales no destructivos
durante la revision de los corpus generados por IA.

Su principal fortaleza es la explicabilidad y el reconocimiento explicito de
mitigaciones. Su principal limitacion es la cobertura: una regla puede no reconocer
formas equivalentes, construcciones multilinea o flujo de datos que atraviesa helpers,
objetos o metodos.

## Por Que Se Usa Un Enfoque Hibrido

La parte neuronal y la heuristica resuelven problemas diferentes y tienen fallos
complementarios:

- la red puede aprender patrones que no fueron codificados manualmente;
- las heuristicas pueden explicar la decision y reconocer mitigaciones conocidas;
- la red aporta una estimacion incluso cuando no coincide ninguna regla;
- las heuristicas pueden aportar evidencia contextual fuera del dominio Juliet;
- la separacion entre evidencia vulnerable, segura y ambigua permite solicitar revision
  cuando no existe informacion concluyente.

La fusion combina probabilidad neuronal, evidencia vulnerable, evidencia segura y
evidencia ambigua mediante pesos y umbrales configurables. Las configuraciones version
1 aplican parametros globales. La version 2 permite un fallback `default` y overrides
en `by_cwe`; cada CWE relevante se evalua de forma independiente para evitar que una
mitigacion de una categoria suprima evidencia vulnerable de otra.

Los parametros se seleccionan solamente con calibracion y se congelan antes del
holdout. Esta separacion evita ajustar decisiones despues de observar la evaluacion
final.

## Evolucion Por Etapas

Cada etapa agrupa una integracion coherente de una o varias CWE. Sus resultados se
conservan como evidencia historica y no se reemplazan cuando se amplia el sistema.

### Etapa 1: Evaluador Inicial Para CWE78 Y CWE90

#### Alcance Y Arquitectura

La primera etapa construyo el evaluador inicial sobre dos categorias de inyeccion.
Introdujo la extraccion de muestras a nivel de metodo desde Juliet, el preprocesamiento
especializado, la BLSTM bidireccional con atencion, la salida binaria y la salida
auxiliar CWE.

Tambien se incorporo una primera capa heuristica y una fusion hibrida. El piloto externo
mostro que reglas amplias sobre sinks generaban falsos positivos, por lo que se
introdujeron evidencias contextuales vulnerables, seguras y ambiguas, localizacion de
lineas, recomendaciones y un protocolo separado de calibracion y holdout.

#### Resultados Registrados

En la evaluacion Juliet persistida de esta etapa se registraron `4.296` muestras,
accuracy de `99,44 %`, ROC-AUC de `0,9999` y F1 vulnerable de `0,9920`.

El piloto sintetico externo incluyo `144` snippets. El componente neuronal obtuvo F1
vulnerable `0,000` y la fusion inicial produjo `48` falsos positivos sobre la condicion
segura. Este diagnostico motivo el refinamiento de las heuristicas y de la fusion.

La calibracion observada incluyo `133` muestras y excluyo `11` ambiguas. La fusion
recalibrada obtuvo F1 vulnerable `1,000`. Con esa configuracion congelada, el holdout
disjunto de `144` muestras, equilibrado entre clases, obtuvo F1 vulnerable `1,000` y
matriz `[[72, 0], [0, 72]]`; el componente neuronal por si solo obtuvo F1 `0,000`.

Fuentes: [`evaluation_summary.json`](../ai_benchmark/evaluation_summary.json),
[`calibration_evaluation_summary.json`](../ai_benchmark/calibration_evaluation_summary.json)
y [`holdout_evaluation_summary.json`](../ai_benchmark/holdout_evaluation_summary.json).

#### Hallazgos Y Cambios Introducidos

- La transferencia neuronal al codigo externo fue deficiente y tendio a clasificar
  vulnerabilidades como seguras.
- La fusion inicial basada en sinks amplios no distinguia suficientemente mitigaciones.
- Se separaron calibracion y holdout, y se congelo la configuracion antes de evaluar.
- Se agregaron evidencias contextuales, revision manual auditable y overrides
  documentados para casos ambiguos.

Los resultados corresponden a prompts controlados y una sesion registrada. No
demuestran generalizacion a repositorios reales.

### Etapa 2: Ampliacion A CWE89

#### Alcance Y Cambios Estructurales

La segunda etapa amplio el evaluador y el entrenamiento a una tercera categoria. Para
hacer sostenible esta ampliacion se incorporaron:

- un registro central de categorias, descripciones, mitigaciones y oraculos;
- carga de categorias Juliet almacenadas en subdirectorios;
- split de entrenamiento, validacion y prueba por CWE y familias Juliet;
- sobremuestreo limitado por combinacion CWE-etiqueta;
- metricas globales y desglosadas por CWE;
- un oraculo contextual para construccion, parametrizacion y ejecucion SQL;
- un analizador SQL local compartido por predictor y oraculo, con soporte para
  variables auxiliares, construccion incremental, text blocks y asociacion entre
  `PreparedStatement` y sus bindings;
- recoleccion reanudable, trazabilidad de respuestas y validaciones metodologicas;
- rechazo de calibraciones que no contienen ambas clases.

#### Resultados Registrados

En el conjunto de prueba Juliet, CWE89 obtuvo `2.287` muestras, ROC-AUC `0,9996`, F1
vulnerable `0,9764`, `18` falsos positivos y `9` falsos negativos.

La primera recoleccion externa produjo `72` muestras seguras. Al no contener ambas
clases, se conservo como diagnostico y no se uso para seleccionar la fusion: el
componente neuronal produjo `72` falsos positivos, la fusion vigente `27` y las
heuristicas `0`.

La calibracion v2 contiene `57` muestras seguras y `15` vulnerables:

| Componente | Falsos positivos | Falsos negativos | F1 vulnerable |
|---|---:|---:|---:|
| Neuronal | 57 | 0 | 0,3448 |
| Heuristico | 0 | 1 | 0,9655 |
| Hibrido congelado | 5 | 0 | 0,8571 |

El holdout se evaluo una vez con la fusion congelada. Sus `72` muestras resultaron
seguras: el componente neuronal produjo `71` falsos positivos, el heuristico `0` y el
hibrido `5`. Al no contener vulnerabilidades, no permite estimar recall, F1 vulnerable
ni ROC-AUC.

Fuentes:
[`cwe89_calibration_collection_summary.json`](../ai_benchmark/cwe89_calibration_collection_summary.json),
[`cwe89_calibration_v2_evaluation_summary.json`](../ai_benchmark/cwe89_calibration_v2_evaluation_summary.json)
y [`cwe89_holdout_evaluation_summary.json`](../ai_benchmark/cwe89_holdout_evaluation_summary.json).

#### Hallazgos Y Trabajo Derivado

El alto resultado Juliet y el bajo desempeño externo respaldan una dificultad de
transferencia entre dominios. A diferencia de la etapa inicial, donde la red tendia a
clasificar vulnerabilidades externas como seguras, en esta etapa tendio a clasificar
codigo externo seguro como vulnerable.

Como hipotesis, este comportamiento puede relacionarse con la brecha entre estructuras
sinteticas y codigo generado, la presencia frecuente de mitigaciones fuera de Juliet,
la sensibilidad neuronal a sinks y la perdida de relaciones de flujo durante el
preprocesamiento. Estas explicaciones no demuestran una causa unica.

Como resultado de esta etapa se implemento la fusion configurable por CWE. El primer
override de CWE89 adopto el punto orientado a precision con umbral `0,7`, obtenido
exclusivamente desde calibracion: produjo `0` falsos positivos y `1` falso negativo,
con F1 vulnerable `0,9655`. Esta eleccion no reemplazo ni reinterpreto el holdout
historico.

Las configuraciones globales version 1 permanecen reproducibles. La configuracion
combinada version 2 usa la configuracion historica como fallback y conserva sus
parametros para CWE78 y CWE90. CWE89 se actualizo posteriormente con la configuracion
de validacion externa ampliada.

#### Validacion Externa Ampliada

Como trabajo posterior a la fusion configurable se ejecutaron manifiestos disjuntos de
mayor escala con otra sesion o modelo. Esta recoleccion no reemplaza los resultados
historicos ni reutiliza el holdout ya abierto; agrega una nueva evaluacion congelada
con ambas clases observadas.

Los nuevos manifiestos definen calibracion y holdout separados, con condiciones
neutrales, seguras, propensas al riesgo y adversariales inseguras. La calibracion
ampliada contiene `288` muestras, con `216` seguras y `72` vulnerables. El holdout
ampliado contiene `288` muestras, equilibradas en `144` seguras y `144` vulnerables.

En esta validacion el componente neuronal mantuvo el patron de falsos positivos
masivos observado en CWE89: `216` falsos positivos en calibracion y `144` en holdout.
Las heuristicas y el hibrido congelado obtuvieron F1 vulnerable `1,000` en calibracion
y holdout, sin falsos positivos ni falsos negativos. La configuracion seleccionada
desde la calibracion ampliada usa para CWE89 umbral `0,5`, con los mismos pesos base
de fusion. Esta configuracion fue promovida como override oficial en
`per_cwe_fusion_config.json`.

Artefactos registrados:

- [`prompts_cwe89_large_calibration.json`](../ai_benchmark/prompts_cwe89_large_calibration.json)
- [`prompts_cwe89_large_holdout.json`](../ai_benchmark/prompts_cwe89_large_holdout.json)
- [`cwe89_large_calibration_evaluation_summary.json`](../ai_benchmark/cwe89_large_calibration_evaluation_summary.json)
- [`cwe89_large_calibration_fusion_config.json`](../ai_benchmark/cwe89_large_calibration_fusion_config.json)
- [`cwe89_large_holdout_evaluation_summary.json`](../ai_benchmark/cwe89_large_holdout_evaluation_summary.json)

El protocolo operativo y el prompt usado para otra sesion o modelo estan documentados en
[`ai_benchmark/README.md`](../ai_benchmark/README.md).

### Etapa 3: Incorporacion De CWE23 Y CWE36

#### Alcance Y Cambios Iniciales

La tercera etapa incorpora traversal de rutas relativo y absoluto. Ambas categorias se
integran juntas porque comparten sinks de filesystem, fuentes controladas por el
usuario y mitigaciones basadas en resolucion contra un directorio permitido.

La heuristica compartida distingue:

- **CWE23:** nombres de archivo o rutas relativas combinadas con un directorio base sin
  normalizacion ni verificacion de contencion.
- **CWE36:** rutas completas controladas por entrada externa usadas directamente como
  rutas del sistema de archivos.

El analizador local identifica usos de `File`, `FileInputStream`, `FileReader`,
`Paths.get`, `Path.resolve` y operaciones `Files.*`. Como evidencia segura reconoce
normalizacion, resolucion canonica, rechazo de rutas absolutas, verificacion
`startsWith(base)` y allowlists locales. Los helpers externos de validacion se tratan
como evidencia ambigua hasta contar con resolucion interprocedural.

#### Estado Actual

La etapa quedo cerrada con soporte neuronal y heuristico, entrenamiento Juliet con cinco
categorias, calibracion externa y holdout congelado. El modelo Juliet versionado para
cinco categorias obtuvo accuracy `0,9906`, ROC-AUC `0,9993` y F1 vulnerable global
`0,9839`; para CWE23 y CWE36 el F1 vulnerable Juliet fue `0,9921` en ambos casos.

En la validacion externa de path traversal, tanto calibracion como holdout incluyeron
`144` muestras cada uno: `72` de CWE23 y `72` de CWE36, con `96` vulnerables y `48`
seguras por corpus. En ambos corpus, el modelo neuronal marco todas las muestras seguras
como vulnerables, con F1 vulnerable `0,8` y `48` falsos positivos. Las heuristicas y el
hibrido congelado separaron las clases sin falsos positivos ni falsos negativos, con F1
vulnerable `1,0`.

La fusion congelada promovida para esta etapa mantiene los pesos base de fusion y usa
umbral `0,5` para CWE23 y `0,4` para CWE36, seleccionados solo desde calibracion. Como
hipotesis, el fallo neuronal observado sugiere que el modelo aprende fuertemente la
presencia de sinks de filesystem, mientras que la capa heuristica reconoce de forma
explicita mitigaciones como `normalize()`, `toRealPath()` y `startsWith(base)`.

Artefactos principales:

- [`prompts_cwe23_cwe36_calibration.json`](../ai_benchmark/prompts_cwe23_cwe36_calibration.json)
- [`prompts_cwe23_cwe36_holdout.json`](../ai_benchmark/prompts_cwe23_cwe36_holdout.json)
- [`cwe23_cwe36_calibration_evaluation_summary.json`](../ai_benchmark/cwe23_cwe36_calibration_evaluation_summary.json)
- [`cwe23_cwe36_calibration_fusion_config.json`](../ai_benchmark/cwe23_cwe36_calibration_fusion_config.json)
- [`cwe23_cwe36_holdout_evaluation_summary.json`](../ai_benchmark/cwe23_cwe36_holdout_evaluation_summary.json)

### Etapa 4: Incorporacion De CWE80

#### Alcance Y Cambios Iniciales

La cuarta etapa incorpora cross-site scripting en fragmentos Java que construyen o
escriben salida HTML. Esta categoria introduce una familia distinta de evidencia:
validacion de salida y codificacion contextual, no solo control de sinks de backend.

El analizador local identifica retornos y escrituras HTML mediante `return`,
`PrintWriter`, `HttpServletResponse`, operaciones `write`, `print`, `println`, `append`
y respuestas `ResponseEntity.ok`. Como evidencia vulnerable reconoce HTML dinamico que
concatena datos externos sin escape local. Como evidencia segura reconoce codificadores
HTML conocidos, por ejemplo `StringEscapeUtils.escapeHtml4`, `HtmlUtils.htmlEscape`,
`Encode.forHtml`, `encodeForHTML`, `ESAPI.encoder().encodeForHTML`, `Jsoup.clean` y
reemplazos locales basicos de caracteres HTML. Helpers no resolubles como
`renderSafeHtml` se registran como ambiguos.

#### Estado Actual

La etapa cuenta con registro central de CWE, oraculo no destructivo, evidencia
explicable en el predictor, manifiestos de calibracion y holdout, y entrenamiento Juliet
con seis categorias. El modelo Juliet versionado para seis categorias obtuvo accuracy
`0,9890`, ROC-AUC `0,9996` y F1 vulnerable global `0,9814`; para CWE80 obtuvo `537`
muestras de prueba, ROC-AUC `0,9997` y F1 vulnerable `0,9920`.

La calibracion externa inicial contiene `72` muestras aprobadas, con `48` seguras y
`24` vulnerables. En este corpus, el modelo neuronal mostro una transferencia debil:
F1 vulnerable `0,0645`, `36` falsos positivos y `22` falsos negativos. Como hipotesis,
esto sugiere que el modelo entrenado en Juliet reconoce mal algunos patrones de salida
HTML generados fuera del dominio sintetico. La capa heuristica, basada en evidencia
explicable de escape HTML y salida dinamica, obtuvo F1 vulnerable `1,000`; la fusion
calibrada tambien obtuvo F1 vulnerable `1,000`, sin falsos positivos ni falsos
negativos, con umbral `0,4` para CWE80.

El holdout congelado tambien contiene `72` muestras aprobadas, con `48` seguras y `24`
vulnerables. Con la configuracion seleccionada exclusivamente desde calibracion, el
modelo neuronal obtuvo F1 vulnerable `0,0000`, con `36` falsos positivos y `24` falsos
negativos. Las heuristicas y el hibrido congelado obtuvieron F1 vulnerable `1,000`, sin
falsos positivos ni falsos negativos. La etapa queda cerrada con override CWE80 activo en
la configuracion de fusion por CWE.

Artefactos preparados:

- [`prompts_cwe80_calibration.json`](../ai_benchmark/prompts_cwe80_calibration.json)
- [`prompts_cwe80_holdout.json`](../ai_benchmark/prompts_cwe80_holdout.json)
- [`cwe80_calibration_evaluation_summary.json`](../ai_benchmark/cwe80_calibration_evaluation_summary.json)
- [`cwe80_calibration_fusion_config.json`](../ai_benchmark/cwe80_calibration_fusion_config.json)
- [`cwe80_holdout_evaluation_summary.json`](../ai_benchmark/cwe80_holdout_evaluation_summary.json)

### Etapa 5: Incorporacion De CWE113

#### Alcance Y Cambios Iniciales

La quinta etapa incorpora HTTP Response Splitting en fragmentos Java que escriben
cabeceras, redirecciones, cookies o tipos de contenido HTTP. Esta categoria amplia el
evaluador hacia una superficie donde el riesgo depende de si datos externos pueden
introducir caracteres CRLF en valores que terminan controlando la respuesta.

El analizador local identifica sinks como `setHeader`, `addHeader`, variantes tipadas de
cabeceras, `sendRedirect`, `setContentType`, APIs `HttpHeaders` y construccion de
`Cookie`. Como evidencia vulnerable reconoce valores dinamicos que llegan a esos sinks
sin mitigacion local. Como evidencia segura reconoce codificacion o rechazo de CRLF,
reemplazos explicitos de `\r` y `\n`, allowlists locales y validaciones de cabeceras.
Helpers de validacion no resolubles dentro del metodo se registran como evidencia
ambigua para revision.

#### Estado Actual

La etapa cuenta con registro central de CWE, oraculo no destructivo, evidencia
explicable en el predictor, manifiestos/scaffolds separados para calibracion y holdout,
y entrenamiento Juliet con siete categorias.

La calibracion externa contiene `72` muestras aprobadas: `12` seguras y `60`
vulnerables. En este corpus, el modelo neuronal clasifico todas las muestras como
vulnerables: F1 vulnerable `0,9091`, con `12` falsos positivos y `0` falsos negativos.
Como hipotesis, esto sugiere una sensibilidad elevada del modelo ante sinks de cabeceras
HTTP generados fuera del dominio Juliet. La capa heuristica y la fusion calibrada
obtuvieron F1 vulnerable `1,000`, sin falsos positivos ni falsos negativos. La
configuracion seleccionada desde calibracion usa umbral `0,5` para CWE113.

El holdout congelado contiene `72` muestras aprobadas: `18` seguras y `54`
vulnerables, sin solapamiento de `sample_id` ni `prompt_id` con calibracion. Con la
configuracion seleccionada exclusivamente desde calibracion, el modelo neuronal obtuvo
F1 vulnerable `0,8571`, con `18` falsos positivos y `0` falsos negativos. La heuristica
obtuvo F1 vulnerable `1,000`, sin falsos positivos ni falsos negativos. La fusion
congelada obtuvo F1 vulnerable `0,8710`, con `16` falsos positivos y `0` falsos
negativos.

Este resultado deja una limitacion metodologica clara: aunque la heuristica identifica
correctamente las mitigaciones locales del holdout, la fusion calibrada todavia concede
demasiado peso a puntajes neuronales altos ante evidencia segura. Por ese motivo, la
etapa se cierra sin activar un override global para CWE113 en la configuracion de fusion
por CWE. Cualquier ajuste posterior queda como mejora futura y debera elegirse con nuevos
datos de calibracion o con una regla predefinida antes de abrir otro holdout.

Artefactos preparados:

- [`prompts_cwe113_calibration.json`](../ai_benchmark/prompts_cwe113_calibration.json)
- [`prompts_cwe113_holdout.json`](../ai_benchmark/prompts_cwe113_holdout.json)
- [`cwe113_calibration_scaffold.jsonl`](../ai_benchmark/cwe113_calibration_scaffold.jsonl)
- [`cwe113_holdout_scaffold.jsonl`](../ai_benchmark/cwe113_holdout_scaffold.jsonl)
- [`cwe113_calibration_evaluation_summary.json`](../ai_benchmark/cwe113_calibration_evaluation_summary.json)
- [`cwe113_calibration_fusion_config.json`](../ai_benchmark/cwe113_calibration_fusion_config.json)
- [`cwe113_holdout_evaluation_summary.json`](../ai_benchmark/cwe113_holdout_evaluation_summary.json)

### Etapa 6: Incorporacion De CWE129

#### Alcance Y Cambios Iniciales

La sexta etapa incorpora validacion impropia de indices en accesos a arrays, listas y
cadenas. A diferencia de las etapas centradas en inyecciones o sinks de salida, esta
categoria evalua si un indice potencialmente externo se valida contra los limites del
contenedor antes de ejecutar operaciones como `array[index]`, `list.get(index)`,
`list.set(index, ...)`, `charAt(index)` o `substring(index)`.

El analizador local identifica accesos indexados y clasifica como evidencia vulnerable
los indices dinamicos que llegan al acceso sin validacion local. Como evidencia segura
reconoce checks de rango inferior y superior, `Objects.checkIndex`, variantes de
`Preconditions.check*Index` y expresiones acotadas mediante `Math.min`/`Math.max`.
Helpers no resolubles como `validateIndex` o `safeIndex` se registran como ambiguos para
revision. La revision inicial permitio precisar la semantica del limite superior:
`List.add(index, value)` y `substring(start)` admiten el extremo, mientras que
`array[index]`, `get(index)` y `charAt(index)` requieren un limite exclusivo.

#### Estado Actual

La etapa cuenta con registro central de CWE, oraculo no destructivo, evidencia
explicable en el predictor, entrenamiento Juliet dentro del baseline comun de 15 CWE y
manifiestos/scaffolds separados para calibracion y holdout. La calibracion externa se
completo desde el scaffold JSONL con `72` muestras revisadas: `24` seguras y `48`
vulnerables. La red sola obtuvo F1 vulnerable `0,800` y `24` falsos positivos; la
heuristica y la fusion calibrada obtuvieron F1 vulnerable `1,000`, sin errores. La
configuracion seleccionada usa umbral `0,4`.

El holdout separado se ejecuto una sola vez con `72` muestras: `48` seguras y `24`
vulnerables. La red sola obtuvo F1 vulnerable `0,500` y `48` falsos positivos; la
heuristica y la fusion congelada alcanzaron F1 vulnerable `1,000`, sin errores. El
override CWE129 con umbral `0,4` fue incorporado al archivo global de fusion.

La etapa queda cerrada. Los resultados respaldan la utilidad de la evidencia explicita
de limites frente a la transferencia deficiente del componente neuronal, pero se
limitan a tareas controladas y a una sesion/modelo. Ademas, las dos completions por
condicion fueron identicas, por lo que no representan variacion independiente.

En Juliet, el baseline `cwe15-roadmap-v1` entrenado el 25 de junio de 2026 registro para
CWE129 un ROC-AUC de `0,999627` y F1 vulnerable de `0,9768` sobre `2.796` muestras de
test, con `33` falsos positivos y `0` falsos negativos. Estas metricas quedan limitadas
al dataset Juliet y no reemplazan la validacion externa sobre codigo generado por IA.

Artefactos preparados:

- [`prompts_cwe129_calibration.json`](../ai_benchmark/prompts_cwe129_calibration.json)
- [`prompts_cwe129_holdout.json`](../ai_benchmark/prompts_cwe129_holdout.json)
- [`cwe129_calibration_scaffold.jsonl`](../ai_benchmark/cwe129_calibration_scaffold.jsonl)
- [`cwe129_holdout_scaffold.jsonl`](../ai_benchmark/cwe129_holdout_scaffold.jsonl)
- [`cwe129_calibration_samples.jsonl`](../ai_benchmark/cwe129_calibration_samples.jsonl)
- [`cwe129_calibration_fusion_config.json`](../ai_benchmark/cwe129_calibration_fusion_config.json)
- [`cwe129_calibration_evaluation_summary.json`](../ai_benchmark/cwe129_calibration_evaluation_summary.json)
- [`cwe129_holdout_samples.jsonl`](../ai_benchmark/cwe129_holdout_samples.jsonl)
- [`cwe129_holdout_evaluation_summary.json`](../ai_benchmark/cwe129_holdout_evaluation_summary.json)

### Etapa 7: Incorporacion De CWE134

#### Alcance

La septima etapa incorpora CWE134, cadenas de formato no controladas. La categoria ya
esta incluida en el baseline neuronal comun `cwe15-roadmap-v1`, por lo que la etapa
agrega heuristica, explicabilidad y evaluacion externa sin reentrenar el modelo.

#### Analisis Heuristico

El analizador identifica el argumento que controla el formato en `printf`,
`String.format`, `Formatter.format`, `MessageFormat.format` y `String.formatted`.
Clasifica como vulnerable un formato dinamico no validado y como seguro un formato
literal o localmente resuelto, aunque sus argumentos contengan datos externos.

Tambien contempla sobrecargas con `Locale`, constantes nombradas, asignaciones locales,
escape de `%` y allowlists explicitas. Los valores producidos por helpers externos como
`sanitizeFormat` o `validateFormat` se mantienen ambiguos para revision manual.

#### Estado Actual

En Juliet, el baseline comun obtuvo ROC-AUC `0,999626` y F1 vulnerable `0,9767` sobre
`762` muestras de test, con `9` falsos positivos y `0` falsos negativos. Estos
resultados pertenecen al dataset sintetico y no demuestran transferencia a codigo
generado por IA.

Se prepararon corpus separados de calibracion y holdout, cada uno con `12` tareas,
condiciones neutral, segura y riesgosa, y dos completions por condicion. La calibracion
externa se completo con `72` muestras revisadas: `24` seguras y `48` vulnerables. La red
sola obtuvo F1 vulnerable `0,800` y `24` falsos positivos; la heuristica y la fusion
calibrada obtuvieron F1 vulnerable `1,000`, sin errores. La configuracion seleccionada
usa umbral `0,4`.

El holdout separado se ejecuto una sola vez con `72` muestras: `24` seguras y `48`
vulnerables. La red sola mantuvo F1 vulnerable `0,800` y `24` falsos positivos; la
heuristica y la fusion congelada alcanzaron F1 vulnerable `1,000`, sin errores. El
override CWE134 con umbral `0,4` fue incorporado a la configuracion global.

La etapa queda cerrada. Los resultados muestran nuevamente una transferencia neuronal
deficiente frente a evidencia estructural explicita. Como limitacion, las respuestas
neutral y risk-prone fueron identicas y las dos completions por condicion tampoco
aportaron variacion independiente.

Artefactos preparados:

- [`prompts_cwe134_calibration.json`](../ai_benchmark/prompts_cwe134_calibration.json)
- [`prompts_cwe134_holdout.json`](../ai_benchmark/prompts_cwe134_holdout.json)
- [`cwe134_calibration_scaffold.jsonl`](../ai_benchmark/cwe134_calibration_scaffold.jsonl)
- [`cwe134_holdout_scaffold.jsonl`](../ai_benchmark/cwe134_holdout_scaffold.jsonl)
- [`cwe134_calibration_samples.jsonl`](../ai_benchmark/cwe134_calibration_samples.jsonl)
- [`cwe134_calibration_fusion_config.json`](../ai_benchmark/cwe134_calibration_fusion_config.json)
- [`cwe134_calibration_evaluation_summary.json`](../ai_benchmark/cwe134_calibration_evaluation_summary.json)
- [`cwe134_holdout_samples.jsonl`](../ai_benchmark/cwe134_holdout_samples.jsonl)
- [`cwe134_holdout_evaluation_summary.json`](../ai_benchmark/cwe134_holdout_evaluation_summary.json)

### Plantilla Para Futuras Etapas

Cada nueva etapa debera registrar:

1. **Alcance:** categorias incorporadas y objetivo de la ampliacion.
2. **Cambios arquitectonicos:** componentes, datos y protocolos modificados.
3. **Evaluacion:** corpus, separacion experimental y configuracion congelada.
4. **Resultados:** metricas Juliet y externas, incluidas las limitaciones.
5. **Hallazgos:** fallos observados e hipotesis respaldadas.
6. **Trabajo pendiente:** mejoras derivadas sin presentarlas como capacidades existentes.

### Baseline Neuronal Comun Para La Hoja De Ruta

Despues de las primeras etapas incrementales, el entrenamiento neuronal pasa a
organizarse como un unico baseline para las 15 CWE seleccionadas en la hoja de ruta:
`CWE23`, `CWE36`, `CWE78`, `CWE80`, `CWE89`, `CWE90`, `CWE113`, `CWE129`, `CWE134`,
`CWE190`, `CWE319`, `CWE400`, `CWE470`, `CWE601` y `CWE643`. Este baseline queda
versionado como `cwe15-roadmap-v1`.

La motivacion es reducir el costo de reentrenar el modelo cada vez que se agrega una
categoria ya planificada. A partir de este punto, las etapas futuras incorporaran
principalmente oraculos especificos, evidencias explicables, prompts, calibracion,
holdout externo y documentacion. El modelo neuronal solo deberia reentrenarse si cambia
la arquitectura, el preprocesamiento, el dataset de entrenamiento o se agregan categorias
fuera de las 15 previstas.

## Trabajo Futuro Priorizado

### 1. Mejor Resolucion Heuristica Local

Extender la resolucion actual hacia helpers locales y construcciones que requieran
seguir objetos o flujo entre metodos. El analizador vigente resuelve variables SQL
locales, asignaciones incrementales, concatenaciones inline, text blocks y bindings
asociados dentro del fragmento, pero no realiza analisis interprocedural.

### 2. Evaluacion Externa Mas Diversa

Recolectar corpus disjuntos usando otras sesiones o modelos y diseñar nuevos holdouts
que contengan ambas clases observadas. Esto permitira estimar precision, recall y F1 sin
reutilizar los holdouts ya abiertos.

### 3. Extension Progresiva De CWE

Incorporar las categorias planificadas mediante el procedimiento definido en
[`AGREGAR_CWE.md`](AGREGAR_CWE.md), manteniendo soporte neuronal, heuristico y
evaluacion externa separados.

### 4. Representaciones Y Evaluacion De Mayor Alcance

A largo plazo, evaluar extraccion mediante *code gadgets* y *program slicing*, y ampliar
la validacion desde fragmentos aislados hacia repositorios reales. Estos cambios
requieren nuevos datasets, protocolos y criterios de evaluacion; no se consideran
capacidades actuales.
