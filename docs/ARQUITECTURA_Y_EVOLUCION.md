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

La fusion actual combina probabilidad neuronal, evidencia vulnerable, evidencia segura
y evidencia ambigua mediante pesos y un umbral configurables globalmente. Los
parametros se seleccionan solamente con un corpus de calibracion y se congelan antes
del holdout. Esta separacion evita ajustar decisiones despues de observar la evaluacion
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

La etapa motivo priorizar una fusion configurable por CWE y mejorar la resolucion
heuristica de flujo local, construcciones multilinea y mitigaciones relacionadas.

### Plantilla Para Futuras Etapas

Cada nueva etapa debera registrar:

1. **Alcance:** categorias incorporadas y objetivo de la ampliacion.
2. **Cambios arquitectonicos:** componentes, datos y protocolos modificados.
3. **Evaluacion:** corpus, separacion experimental y configuracion congelada.
4. **Resultados:** metricas Juliet y externas, incluidas las limitaciones.
5. **Hallazgos:** fallos observados e hipotesis respaldadas.
6. **Trabajo pendiente:** mejoras derivadas sin presentarlas como capacidades existentes.

## Trabajo Futuro Priorizado

### 1. Fusion Configurable Por CWE

El siguiente paso priorizado es permitir pesos y umbrales diferentes por CWE. Esta
funcionalidad todavia no esta implementada ni validada. La seleccion futura debera
realizarse exclusivamente con calibracion y mantener los holdouts existentes sin nuevos
ajustes.

### 2. Mejor Resolucion Heuristica Local

Ampliar el reconocimiento de variables locales, asignaciones y construcciones
multilinea, mitigaciones asociadas, concatenaciones inline y flujo hacia sinks.

### 3. Evaluacion Externa Mas Diversa

Recolectar corpus disjuntos usando otras sesiones o modelos y diseñar nuevos holdouts
que contengan ambas clases observadas. Esto permitira estimar precision, recall y F1 sin
reutilizar los holdouts ya abiertos.

### 4. Extension Progresiva De CWE

Incorporar las categorias planificadas mediante el procedimiento definido en
[`AGREGAR_CWE.md`](AGREGAR_CWE.md), manteniendo soporte neuronal, heuristico y
evaluacion externa separados.

### 5. Representaciones Y Evaluacion De Mayor Alcance

A largo plazo, evaluar extraccion mediante *code gadgets* y *program slicing*, y ampliar
la validacion desde fragmentos aislados hacia repositorios reales. Estos cambios
requieren nuevos datasets, protocolos y criterios de evaluacion; no se consideran
capacidades actuales.
