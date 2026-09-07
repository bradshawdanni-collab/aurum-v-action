# AURUM-V Recovery Implementation Guidance V1

**Status:** DERIVED / NON-AUTHORITY  
**Normative source:** `spec/AURUMV_RECOVERY_SPECIFICATION_FROZEN.txt`  
**Normative byte count:** `7814`  
**Normative SHA-256:** `d422b30ec51a95fd515c7e1a069cd223b0a8fce2313366921b1816b5678241f1`

## Read-only consumption rule

Downstream implementations MUST consume the frozen specification, derived schema, and conformance fixtures as read-only inputs.

1. The frozen source MUST NOT be modified in place.
2. Any implementation-specific adaptation MUST be created as a separate derived artifact.
3. Every derived artifact MUST record the frozen source SHA-256.
4. A locally recomputed digest mismatch MUST fail closed before schema validation, conformance testing, approval evaluation, or recovery execution.
5. A future semantic change requires a successor specification with a new identifier, version, byte count, and SHA-256.

## Mandatory startup preflight

Before any downstream recovery operation:

```text
EXPECTED_FILENAME = spec/AURUMV_RECOVERY_SPECIFICATION_FROZEN.txt
EXPECTED_BYTE_COUNT = 7814
EXPECTED_SHA256 = d422b30ec51a95fd515c7e1a069cd223b0a8fce2313366921b1816b5678241f1

VERIFY exact byte count
VERIFY SHA-256
VERIFY no UTF-8 BOM
VERIFY no CR bytes
REJECT on any mismatch
```

Then:

1. validate machine-readable configuration against `AURUMV_RECOVERY_SCHEMA_V1.json`;
2. execute `AURUMV_RECOVERY_FIXTURES_V1.json`;
3. preserve `RECOVERY_FAILURE_MODE = SILENCE`;
4. preserve the authority separation below.

## Authority separation

```text
THRESHOLD_RECONSTRUCTION != RECOVERY_AUTHORIZATION
RECOVERY_AUTHORIZATION != AAL_ACCEPTANCE
```

The schema, fixtures, implementation, logs, reports, and future successors may reference the frozen source. None may mutate or silently supersede it.
