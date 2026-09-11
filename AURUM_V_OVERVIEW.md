# AURUM-V

**A fail-closed systems architecture for governing when automated computation and action are admissible.**

AURUM-V separates **observation, estimation, authority, execution, audit, and recovery** so that computation does not automatically become permission to act.

> **Repository role:** this file is a public architectural overview. The `aurum-v-action` repository remains the public distribution repository for the AURUM-V GitHub Action. This overview is explanatory and does not create normative engineering authority.

## What AURUM-V does

Many automated systems follow a familiar pattern:

```text
INPUT → COMPUTE → OUTPUT
```

AURUM-V introduces explicit admissibility and authority layers:

```text
OBSERVATION
    ↓
EVIDENCE VALIDATION
    ↓
ADMISSIBILITY
    ↓
AUTHORITY CHECK
    ↓
COMPUTATION / EXECUTION
    ↓
AUDIT
    ↓
RECOVERY OR SILENCE
```

The design is intended for systems where a technically possible action should not automatically be treated as an authorised one.

Core principles include:

- **Admissibility before execution**
- **Estimator ≠ authority**
- **Missing or stale evidence contracts authority**
- **Fail-closed behaviour under unresolved conditions**
- **Explicit audit and provenance**
- **Recovery as a gated systems process**
- **Separation between public evidence and normative authority**

## Why it exists

High-capability systems can fail even when their computation is correct.

The failure may instead occur because:

- evidence was stale;
- authority was assumed rather than established;
- a model output was mistaken for permission;
- state changed after validation;
- replay or duplicate-use conditions were ignored; or
- execution continued when the safe answer should have been refusal.

AURUM-V treats these as architectural concerns rather than application-level exceptions.

## Core properties

### Fail closed

When required evidence or authority cannot be established, execution is withheld.

```text
UNKNOWN ≠ PASS
MISSING ≠ ASSUMED_VALID
STALE ≠ CURRENT
MODEL_OUTPUT ≠ AUTHORITY
```

### Exact binding

Where execution authority is issued, it should bind to the exact subject of the decision rather than an approximate or inferred target.

### Freshness

Evidence that was valid earlier is not automatically valid at execution time.

### Replay resistance

Authorisation should not silently become reusable permission unless reuse is explicitly part of the governing contract.

### Provenance

Released evidence should identify where it came from, what exact bytes were evaluated, and which revision produced it.

### Recovery

Recovery is not defined merely as returning output. It requires restoration of the conditions under which trustworthy comparison and controlled execution are possible.

## Public evidence model

Every formally released artifact should be traceable. A public release record can use a structure such as:

```json
{
  "artifact_id": "EXAMPLE_ARTIFACT_V1",
  "source_repository": "<controlled-source-repository>",
  "source_commit": "<40-character commit SHA>",
  "source_path": "<path>",
  "release_commit": "<40-character commit SHA>",
  "sha256": "<sha256>",
  "byte_count": 0,
  "classification": "PUBLIC_RELEASE",
  "authority_effect": "NONE"
}
```

The public surface is therefore a **publication and verification surface**, not a shadow authority source.

## Assurance boundaries

Public AURUM-V material may demonstrate:

- architecture;
- design rules;
- machine-verifiable evidence;
- selected implementation behaviour;
- reproducibility; and
- controlled demonstrations.

Publication alone should not be interpreted as establishing:

- universal correctness;
- production equivalence for every deployment;
- legal authority;
- scientific or clinical efficacy;
- absence of undisclosed bypasses; or
- fitness for safety-critical deployment.

Claims should remain bounded by the evidence attached to them.

## Public implementation

For a concrete public implementation of these principles, see this repository's GitHub Action. It verifies signed approval bundles, binds authorisation to an exact repository / pull request / head SHA, rejects tampered evidence, and fails closed when required conditions are not satisfied.

See [`README.md`](README.md) for installation and usage.

---

**AURUM-V operating constraint:** capability does not constitute authority.
