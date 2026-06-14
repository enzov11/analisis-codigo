# Proceso Estandar Para Agregar Una CWE

Este documento define el proceso obligatorio para ampliar CodeScan-AI de forma uniforme. Las CWE oficiales se registran en `src/cwe_registry.py`; una categoria no se considera integrada solamente por aparecer en una regla o en un prompt.

El estado actual, los conteos auditados de Juliet y la hoja de ruta seleccionada se
mantienen en [`ESTADO_CWE.md`](ESTADO_CWE.md).

## Estados De Soporte

Cada CWE registrada declara dos capacidades independientes:

- `neural_supported`: existen datos de entrenamiento adecuados y la categoria puede entrar al encoder CWE.
- `heuristic_supported`: existe un oraculo contextual no destructivo con resultados `safe`, `vulnerable` y `ambiguous`.

Una CWE solo se presenta como completamente soportada cuando ambas capacidades fueron implementadas, probadas y evaluadas.

## Lista De Verificacion Por CWE

1. **Definir alcance:** documentar fuente, sink, mitigacion, casos ambiguos y categorias vecinas que no deben confundirse.
2. **Confirmar datos:** verificar que Juliet/SARD contenga ejemplos Java seguros y vulnerables, con suficientes familias independientes.
3. **Registrar categoria:** agregar una entrada completa en `CWE_REGISTRY`; no crear listas paralelas.
4. **Implementar oraculo:** inspeccionar estructura sin ejecutar comandos, consultas, conexiones ni payloads.
5. **Integrar predictor:** producir evidencia vulnerable, de seguridad o ambigua con linea, razon y correccion sugerida.
6. **Agregar pruebas:** cubrir al menos un caso vulnerable, uno seguro, uno ambiguo, confusiones con CWE vecinas y regresiones existentes.
7. **Preparar entrenamiento:** comprobar distribucion por CWE y ejecutar split por grupos con semillas `42`, `7`, `13`, `21` y `100`.
8. **Crear benchmark IA:** definir 12 tareas de calibracion y 12 de holdout, disjuntas, con tres condiciones y dos completions.
9. **Revisar y congelar:** usar revision manual y oraculo estructural; calibrar solamente con calibracion y ejecutar holdout una vez.
10. **Versionar resultados:** conservar modelos, configuraciones y resumenes anteriores; publicar metricas globales y por CWE aunque sean bajas.
11. **Actualizar la evolucion:** agregar la categoria a una nueva etapa o a la etapa de integracion correspondiente en [`ARQUITECTURA_Y_EVOLUCION.md`](ARQUITECTURA_Y_EVOLUCION.md), sin reemplazar resultados historicos.

## Criterios De Aceptacion

- La CWE aparece una sola vez en el registro central.
- La CWE se agrega a `TARGET_CWE_IDS` solamente cuando sus datos de entrenamiento estan disponibles.
- El dataset contiene la categoria; el entrenamiento falla claramente si falta.
- Los tests seguros, vulnerables, ambiguos y de no confusion pasan.
- No existe solapamiento entre tareas de calibracion y holdout.
- Ninguna muestra IA entra al entrenamiento Juliet.
- La configuracion se congela antes del holdout.
- Los resultados distinguen soporte neuronal, heuristico e hibrido.
- El historial registra alcance, cambios, evaluacion, resultados, hallazgos y trabajo pendiente de la etapa.

## Plantilla De Benchmark

Por cada nueva CWE:

```text
12 tareas de calibracion x 3 condiciones x 2 completions = 72 muestras
12 tareas de holdout     x 3 condiciones x 2 completions = 72 muestras
```

Las condiciones son `neutral`, `secure` y `risk-prone`. Los casos ambiguos deben excluirse o resolverse mediante una decision manual documentada.

## Hoja De Ruta Hacia 15 CWE

La hoja de ruta se selecciona segun relevancia, volumen, diversidad de familias y
viabilidad de heuristicas explicables. Consultar [`ESTADO_CWE.md`](ESTADO_CWE.md) para
la lista vigente de 15 categorias y el inventario completo del Juliet auditado.
