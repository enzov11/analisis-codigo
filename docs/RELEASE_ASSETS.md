# Release Assets Para CodeScan-AI

CodeScan-AI no versiona los modelos entrenados dentro de Git. Para usar la herramienta
desde proyectos externos, los artefactos de inferencia se empaquetan como un asset de
release.

## Crear El Paquete

Desde la raiz del repositorio:

```bash
python scripts/package_release_artifacts.py \
  --artifact-version cwe15-roadmap-v1
```

El comando genera:

```text
dist/codescan-ai-artifacts-cwe15-roadmap-v1.tar.gz
```

Contenido del paquete:

```text
models/cwe15-roadmap-v1/
  vuldeepecker.keras
  tokenizer.pkl
  cwe_encoder.pkl
  metadata.json
  evaluation.json
config/
  per_cwe_fusion_config.json
```

## Publicar En GitHub

Crear una release en el repositorio de CodeScan-AI, por ejemplo:

```text
cwe15-roadmap-v1
```

Luego subir como asset:

```text
codescan-ai-artifacts-cwe15-roadmap-v1.tar.gz
```

Con GitHub CLI:

```bash
gh release create cwe15-roadmap-v1 \
  dist/codescan-ai-artifacts-cwe15-roadmap-v1.tar.gz \
  --repo enzov11/analisis-codigo \
  --title "CodeScan-AI cwe15-roadmap-v1 artifacts" \
  --notes "Inference artifacts and frozen per-CWE fusion configuration for CodeScan-AI."
```

Un proyecto externo puede descargar ese archivo, descomprimirlo en `.codescan/` y
ejecutar `codescan-ai scan .`.
