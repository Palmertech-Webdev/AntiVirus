# Signature Bundle

This folder contains external scan-engine content that can ship separately from the core agent binaries.

The default bundle format is `default-signatures.tsv` with one rule per line:

`scope|code|message|tacticId|techniqueId|score|pattern1;pattern2;pattern3`

Supported scopes:

- `any`
- `text`
- `ascii`
- `script`
- `pe`
- `zip`
- `ole`
- `lnk`
- `office`

How it is used:

- The scan engine first applies its built-in heuristics.
- It then loads `signatures\default-signatures.tsv` from the installed release layout, or from `ANTIVIRUS_SIGNATURE_BUNDLE_PATH` if that environment variable is set.
- Missing signature content is non-fatal; the engine falls back to compiled heuristics.

This gives the updater a clean path to ship new detection content without replacing the whole agent binary.