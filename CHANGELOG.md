# Change Log

## 2026-09-07 - AURUM-V Recovery Specification byte freeze

The recovery specification was transitioned from design state to immutable normative source.

- Specification identifier: `AURUMV_RECOVERY_SPECIFICATION`
- Version label: `SEMANTICALLY_FINAL`
- Frozen filename: `spec/AURUMV_RECOVERY_SPECIFICATION_FROZEN.txt`
- Exact byte count: `7814`
- SHA-256: `d422b30ec51a95fd515c7e1a069cd223b0a8fce2313366921b1816b5678241f1`
- Freeze timestamp (UTC): `2026-09-07T10:39:19Z`
- Serialization: UTF-8 without BOM; LF line endings; no trailing spaces/tabs; one final LF.

### Downstream artifacts

The following artifacts are derived from, and subordinate to, the frozen source:

- `spec/derived/AURUMV_RECOVERY_SCHEMA_V1.json`
- `spec/derived/AURUMV_RECOVERY_FIXTURES_V1.json`
- `spec/derived/AURUMV_RECOVERY_IMPLEMENTATION_GUIDANCE_V1.md`

Each derived artifact binds to the frozen source SHA-256. Tooling must fail closed if the local frozen source bytes do not reproduce the recorded byte count and digest.

### Successor-only change policy

The frozen specification MUST NOT be edited in place. Any future semantic change must be introduced as a new successor artifact with a distinct identifier/version and newly computed byte count and SHA-256. Existing frozen bytes remain permanently addressable by the digest above.
