# Estado Y Hoja De Ruta De CWE

Este documento registra el soporte actual y la hoja de ruta de CodeScan-AI. Los conteos
provienen de la copia local de `find-sec-bugs/juliet-test-suite`, commit `b2c6df37`,
auditada el 12 de junio de 2026.

Las decisiones del enfoque neuronal, heuristico e hibrido, junto con el historial de
evolucion por etapas y el trabajo futuro priorizado, se documentan en
[`ARQUITECTURA_Y_EVOLUCION.md`](ARQUITECTURA_Y_EVOLUCION.md).

El dataset auditado contiene `112` categorias y `40.845` archivos Java. Los conteos de
archivos y familias sirven para estimar disponibilidad y diversidad, pero no equivalen a
la cantidad final de muestras: el cargador extrae metodos cuando es posible y puede
producir varias muestras por archivo.

## Estados

- **Implementada y evaluada:** existe soporte neuronal y heuristico, con resultados
  registrados.
- **En implementacion:** parte del soporte ya existe, pero todavia falta completar y
  aprobar entrenamiento o evaluacion.
- **Planificada:** fue seleccionada por relevancia, disponibilidad en Juliet y viabilidad
  para construir heuristicas explicables.

## Hoja De Ruta Hacia 15 CWE

| Estado | CWE | Archivos Java | Familias |
|---|---|---:|---:|
| Implementada y evaluada | CWE78 OS Command Injection | 722 | 38 |
| Implementada y evaluada | CWE90 LDAP Injection | 722 | 38 |
| Implementada y evaluada | CWE89 SQL Injection | 3.668 | 182 |
| Planificada | CWE23 Relative Path Traversal | 722 | 38 |
| Planificada | CWE36 Absolute Path Traversal | 722 | 38 |
| Planificada | CWE80 Cross-Site Scripting | 1.084 | 56 |
| Planificada | CWE113 HTTP Response Splitting | 2.202 | 110 |
| Planificada | CWE129 Improper Validation of Array Index | 4.402 | 218 |
| Planificada | CWE134 Uncontrolled Format String | 1.102 | 56 |
| Planificada | CWE190 Integer Overflow | 4.219 | 209 |
| Planificada | CWE319 Cleartext Transmission of Sensitive Information | 612 | 32 |
| Planificada | CWE400 Resource Exhaustion | 2.402 | 120 |
| Planificada | CWE470 Unsafe Reflection | 722 | 38 |
| Planificada | CWE601 Open Redirect | 542 | 29 |
| Planificada | CWE643 XPath Injection | 734 | 38 |

Los cambios, resultados y limitaciones de cada grupo de categorias se conservan en el
historial de etapas de
[`ARQUITECTURA_Y_EVOLUCION.md`](ARQUITECTURA_Y_EVOLUCION.md). Los detalles operativos
de sus evaluaciones externas estan en
[`../ai_benchmark/README.md`](../ai_benchmark/README.md).

La etapa CWE89 quedo cerrada con validacion externa ampliada y su override vigente se
registra en `ai_benchmark/per_cwe_fusion_config.json`. Los artefactos previos de
calibracion y holdout se conservan para reproducibilidad historica.

## Criterio De Seleccion

La hoja de ruta equilibra cuatro factores:

1. Relevancia para revisar codigo Java generado por IA.
2. Al menos 29 familias Juliet independientes y mas de 500 archivos Java.
3. Variedad entre inyecciones, validacion, flujo de datos, exposicion y disponibilidad.
4. Posibilidad de definir evidencia vulnerable, segura y ambigua sin ejecutar payloads.

No se seleccionaron categorias de la hoja de ruta anterior que no existen en esta copia
de Juliet Java con su identificador propuesto, entre ellas `CWE22`, `CWE79`, `CWE94`,
`CWE295`, `CWE434`, `CWE502`, `CWE611`, `CWE770`, `CWE798` y `CWE918`.

## Inventario De Otras CWE Disponibles

Estas categorias estan disponibles en Juliet, pero no forman parte de la hoja de ruta
inicial de 15. Pueden reconsiderarse si cambia el objetivo o se incorporan otros datasets.

| CWE | Nombre Juliet | Archivos Java | Familias |
|---|---|---:|---:|
| CWE15 | External Control of System or Configuration Setting | 722 | 38 |
| CWE81 | XSS Error Message | 542 | 29 |
| CWE83 | XSS Attribute | 542 | 29 |
| CWE111 | Unsafe JNI | 3 | 3 |
| CWE114 | Process Control | 19 | 3 |
| CWE191 | Integer Underflow | 2.812 | 140 |
| CWE193 | Off by One Error | 53 | 5 |
| CWE197 | Numeric Truncation Error | 1.986 | 101 |
| CWE209 | Information Leak Error | 36 | 4 |
| CWE226 | Sensitive Information Uncleared Before Release | 19 | 3 |
| CWE248 | Uncaught Exception | 3 | 3 |
| CWE252 | Unchecked Return Value | 19 | 3 |
| CWE253 | Incorrect Check of Function Return Value | 19 | 3 |
| CWE256 | Plaintext Storage of Password | 63 | 5 |
| CWE259 | Hard Coded Password | 182 | 11 |
| CWE315 | Plaintext Storage in Cookie | 63 | 5 |
| CWE321 | Hard Coded Cryptographic Key | 62 | 5 |
| CWE325 | Missing Required Cryptographic Step | 36 | 4 |
| CWE327 | Use Broken Crypto | 36 | 4 |
| CWE328 | Reversible One Way Hash | 53 | 5 |
| CWE329 | Not Using Random IV with CBC Mode | 19 | 3 |
| CWE336 | Same Seed in PRNG | 19 | 3 |
| CWE338 | Weak PRNG | 36 | 4 |
| CWE369 | Divide by Zero | 3.058 | 152 |
| CWE378 | Temporary File Creation With Insecure Perms | 19 | 3 |
| CWE379 | Temporary File Creation in Insecure Dir | 19 | 3 |
| CWE382 | Use of System Exit | 36 | 4 |
| CWE383 | Direct Use of Threads | 18 | 3 |
| CWE390 | Error Without Action | 36 | 4 |
| CWE395 | Catch NullPointerException | 19 | 3 |
| CWE396 | Catch Generic Exception | 36 | 4 |
| CWE397 | Throw Generic | 6 | 6 |
| CWE398 | Poor Code Quality | 139 | 11 |
| CWE404 | Improper Resource Shutdown | 7 | 7 |
| CWE459 | Incomplete Cleanup | 36 | 4 |
| CWE476 | NULL Pointer Dereference | 295 | 17 |
| CWE477 | Obsolete Functions | 70 | 6 |
| CWE478 | Missing Default Case in Switch | 19 | 3 |
| CWE481 | Assigning Instead of Comparing | 19 | 3 |
| CWE482 | Comparing Instead of Assigning | 19 | 3 |
| CWE483 | Incorrect Block Delimitation | 21 | 5 |
| CWE484 | Omitted Break Statement in Switch | 19 | 3 |
| CWE486 | Compare Classes by Name | 21 | 4 |
| CWE491 | Object Hijack | 4 | 4 |
| CWE499 | Sensitive Data Serializable | 6 | 6 |
| CWE500 | Public Static Field Not Final | 4 | 4 |
| CWE506 | Embedded Malicious Code | 118 | 10 |
| CWE510 | Trapdoor | 68 | 6 |
| CWE511 | Logic Time Bomb | 53 | 5 |
| CWE523 | Unprotected Cred Transport | 19 | 3 |
| CWE526 | Info Exposure Environment Variables | 36 | 4 |
| CWE533 | Info Exposure Server Log | 19 | 3 |
| CWE534 | Info Exposure Debug Log | 19 | 3 |
| CWE535 | Info Exposure Shell Error | 19 | 3 |
| CWE539 | Information Exposure Through Persistent Cookie | 19 | 3 |
| CWE546 | Suspicious Comment | 87 | 7 |
| CWE549 | Missing Password Masking | 19 | 3 |
| CWE561 | Dead Code | 4 | 4 |
| CWE563 | Unused Variable | 252 | 40 |
| CWE566 | Authorization Bypass Through SQL Primary | 62 | 5 |
| CWE568 | Finalize Without Super | 6 | 6 |
| CWE570 | Expression Always False | 18 | 18 |
| CWE571 | Expression Always True | 18 | 18 |
| CWE572 | Call to Thread run Instead of start | 19 | 3 |
| CWE579 | Non Serializable in Session | 3 | 3 |
| CWE580 | Clone Without Super | 5 | 5 |
| CWE581 | Object Model Violation | 6 | 6 |
| CWE582 | Array Public Final Static | 4 | 4 |
| CWE584 | Return in Finally Block | 19 | 3 |
| CWE585 | Empty Sync Block | 4 | 4 |
| CWE586 | Explicit Call to Finalize | 20 | 4 |
| CWE597 | Wrong Operator String Comparison | 19 | 3 |
| CWE598 | Information Exposure QueryString | 19 | 3 |
| CWE600 | Uncaught Exception in Servlet | 3 | 3 |
| CWE605 | Multiple Binds Same Port | 19 | 3 |
| CWE606 | Unchecked Loop Condition | 734 | 38 |
| CWE607 | Public Static Final Mutable | 4 | 4 |
| CWE609 | Double Checked Locking | 4 | 4 |
| CWE613 | Insufficient Session Expiration | 19 | 3 |
| CWE614 | Sensitive Cookie Without Secure | 19 | 3 |
| CWE615 | Info Exposure by Comment | 19 | 3 |
| CWE617 | Reachable Assertion | 36 | 4 |
| CWE667 | Improper Locking | 3 | 3 |
| CWE674 | Uncontrolled Recursion | 4 | 4 |
| CWE681 | Incorrect Conversion Between Numeric Types | 53 | 5 |
| CWE690 | NULL Deref From Return | 491 | 27 |
| CWE698 | Redirect Without Exit | 19 | 3 |
| CWE759 | Unsalted One Way Hash | 19 | 3 |
| CWE760 | Predictable Salt One Way Hash | 19 | 3 |
| CWE764 | Multiple Locks | 4 | 4 |
| CWE765 | Multiple Unlocks | 4 | 4 |
| CWE772 | Missing Release of Resource | 4 | 4 |
| CWE775 | Missing Release of File Descriptor or Handle | 4 | 4 |
| CWE789 | Uncontrolled Mem Alloc | 2.543 | 129 |
| CWE832 | Unlock Not Locked | 4 | 4 |
| CWE833 | Deadlock | 8 | 8 |
| CWE835 | Infinite Loop | 8 | 8 |

## Ubicacion Del Dataset

Juliet se mantiene fuera de este repositorio y se configura mediante `DATASET_PATH`.
La copia auditada ya es un repositorio Git independiente y ocupa aproximadamente
`334 MB`, por lo que duplicarla dentro de este repositorio agregaria costo y riesgo de divergencia
sin mejorar la reproducibilidad.
