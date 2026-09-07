# AURUM-V SSS Normative Cryptographic Specification V0.1

```text
ARTIFACT_ID               = AURUMV_SSS_NORMATIVE_CRYPTOGRAPHIC_SPECIFICATION_V0.1
STATUS                    = NORMATIVE_WORKING_BASELINE
DERIVATION_ROLE           = SEPARATE_NORMATIVE_SSS_SPECIFICATION
SOURCE_SPEC_SHA256        = d422b30ec51a95fd515c7e1a069cd223b0a8fce2313366921b1816b5678241f1
AUTHORITY_EFFECT          = NONE_BY_ITSELF
IMPLEMENTATION_AUTHORISED = FALSE
SSS_AUTHORITY_CLAIM       = NOT_MADE
```

This artifact defines the cryptographic custody and reconstruction semantics for the AURUM-V Shamir Secret Sharing (SSS) recovery lane. It does not modify, supersede, or reinterpret `AURUMV_RECOVERY_SPECIFICATION_FROZEN.txt`.

The permanent authority invariant is:

```text
SSS_THRESHOLD_SATISFIED != RECOVERY_AUTHORISED
SSS_RECONSTRUCTION_CAPABILITY != RECOVERY_AUTHORITY
```

A successful threshold reconstruction produces recovery capability only. Recovery authorization and ordinary AAL acceptance remain separate downstream predicates.

---

## 1. Field Definition and Canonical Secret Encoding

```text
SSS_SCHEME_ID       = AURUMV-SSS-SHAMIR-FP25519-v1
FIELD               = F_p
p                   = 2^255 - 19
p_decimal           = 57896044618658097711785492504343953926634992332820282019728792003956564819949
p_hex               = 7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
FIELD_ELEMENT_BYTES = 32
BYTE_ORDER          = LITTLE_ENDIAN
```

A canonical field element is a 32-byte little-endian encoding of an integer `v` satisfying:

```text
0 <= v < p
```

Decoders MUST reject any 32-byte value representing an integer `>= p`. Non-canonical encodings are prohibited.

The recovery master secret `S` MUST be generated uniformly from `F_p` by rejection sampling. Arbitrary 32-byte strings MUST NOT be reduced modulo `p`.

```text
SECRET_ENCODING                         = CANONICAL_AND_INJECTIVE
FIELD_REDUCTION_OF_ARBITRARY_SECRET    = PROHIBITED
PRODUCTION_SECRET_GENERATION           = UNIFORM_REJECTION_SAMPLING_IN_F_p
```

A new secret `S` MUST be generated for each independently wrapped RAK/SRK object.

```text
SECRET_REUSE_ACROSS_WRAPPED_KEYS = PROHIBITED
```

---

## 2. Shamir Polynomial Construction

For threshold `t`, construct:

```text
f(x) = S + a_1*x + a_2*x^2 + ... + a_(t-1)*x^(t-1) mod p
```

where:

- `S` is the secret field element;
- `a_1 ... a_(t-2)` are independently uniform in `F_p`;
- `a_(t-1)` is independently uniform in `F_p \ {0}` so the polynomial has exact degree `t-1`;
- all production coefficients are generated with the CSPRNG/rejection-sampling procedure in Section 5.

The polynomial and all coefficients are ephemeral secret material and MUST be zeroised after successful provisioning or any provisioning failure.

```text
POLYNOMIAL_EXPORT        = PROHIBITED
COEFFICIENT_EXPORT       = PROHIBITED
POLYNOMIAL_PERSISTENCE   = PROHIBITED
```

---

## 3. Frozen n/t Profiles

The first normative profiles are:

| Secret role | Threshold `t` | Share count `n` | Profile |
|---|---:|---:|---|
| `RAK` | 2 | 3 | `AURUMV-SSS-RAK-2OF3-v1` |
| `SRK` | 3 | 5 | `AURUMV-SSS-SRK-3OF5-v1` |

No implementation may substitute a different `(t,n)` pair while claiming conformance to V0.1.

```text
RAK_THRESHOLD = 2
RAK_SHARE_COUNT = 3
SRK_THRESHOLD = 3
SRK_SHARE_COUNT = 5
```

Threshold satisfaction is necessary for reconstruction but has no authority effect by itself.

---

## 4. Share Coordinates and Share Encoding

For a profile with `n` shares, the x-coordinate of share `i` is:

```text
x_i = i, for i in {1, ..., n}
```

Coordinates MUST therefore be non-zero, unique, and within the selected profile's range.

The share value is:

```text
y_i = f(x_i) mod p
```

`y_i` MUST use the canonical 32-byte little-endian field-element encoding defined in Section 1.

```text
SHARE_INDEX_ZERO             = PROHIBITED
SHARE_INDEX_DUPLICATE        = REJECT
SHARE_VALUE_NONCANONICAL     = REJECT
SHARE_INDEX_PROFILE_MISMATCH = REJECT
```

`share_index` and the mathematical x-coordinate are the same value. No independent alternate coordinate is permitted.

---

## 5. Randomness and Coefficient Generation

All production randomness MUST originate from an operating-system or HSM-backed cryptographically secure random generator suitable for key material.

For each field element candidate:

1. obtain 32 random bytes;
2. interpret them as a little-endian unsigned integer;
3. accept only if the integer is `< p`;
4. otherwise discard and sample again.

For `a_(t-1)`, the value `0` MUST also be rejected.

```text
RNG_CLASS                      = CSPRNG_OR_HSM_CSPRNG
MODULO_BIAS                    = PROHIBITED
DETERMINISTIC_PRODUCTION_SEED  = PROHIBITED
TEST_VECTOR_FIXED_COEFFICIENTS = TEST_ONLY
```

Failure to obtain cryptographically secure randomness is a terminal provisioning failure.

---

## 6. Share Envelope, Confidentiality, and Authentication

A plaintext share value MUST NOT be stored persistently in production.

```text
SHARE_AT_REST_CONFIDENTIALITY = REQUIRED
PLAINTEXT_SHARE_PERSISTENCE   = PROHIBITED
```

Each share envelope has immutable metadata:

```json
{
  "scheme_id": "AURUMV-SSS-SHAMIR-FP25519-v1",
  "scheme_version": "1.0",
  "secret_id": "<uuid>",
  "secret_role": "RAK",
  "authority_epoch": "<epoch>",
  "share_index": 1,
  "threshold": 2,
  "share_count": 3,
  "wrapped_key_id": "<uuid>",
  "ledger_genesis_id": "<uuid>",
  "ceremony_policy_id": "<policy-id>",
  "custodian_id": "<custodian-id>"
}
```

`secret_role` MUST be exactly `RAK` or `SRK`, and the `threshold/share_count` pair MUST exactly match Section 3.

The encrypted share payload plaintext is JCS-encoded JSON:

```json
{
  "payload_version": "1.0",
  "share_value_hex": "<64-lowercase-hex-characters>"
}
```

The decoded `share_value_hex` MUST be exactly 32 bytes and MUST be canonical `< p`.

Share encryption uses a distinct profile:

```text
SHARE_AEAD_PROFILE_ID = AURUM-V-SSS-SHARE-XCHACHA20-POLY1305-v1
ALGORITHM             = XChaCha20-Poly1305 (crypto_aead_xchacha20poly1305_ietf)
KEY_SIZE_BYTES        = 32
NONCE_SIZE_BYTES      = 24
TAG_SIZE_BYTES        = 16
AAD                    = RFC8785_JCS(metadata)
NONCE_GENERATION       = FRESH_CSPRNG_PER_ENVELOPE
NONCE_REUSE_SAME_KEY  = PROHIBITED
```

The share-encryption key MUST be custodian-bound external key-management material and MUST NOT be derived from `S`, a Shamir coefficient, or the wrapped RAK/SRK private key.

```text
SHARE_ENCRYPTION_KEY_SOURCE   = CUSTODIAN_BOUND_EXTERNAL_KEY_MANAGEMENT
SHARE_ENCRYPTION_KEY_FROM_S   = FALSE
```

The envelope signature MUST follow the frozen recovery specification's canonical-signing construction:

```text
encrypted_share_payload_sha256 = SHA256(ciphertext)
signed_bytes = JCS({ metadata, encrypted_share_payload_sha256 })
ENVELOPE_SIGNATURE = Ed25519.Sign(custodian_sk, signed_bytes)
```

A signature authenticates the metadata and ciphertext digest; it does not by itself prove polynomial consistency.

---

## 7. Consistency and Admission Checks

Before a share may contribute to reconstruction, all of the following MUST pass:

```text
SHARE_SCHEMA_VALID
SHARE_ENVELOPE_AUTHENTIC
SHARE_AEAD_AUTHENTIC
SHARE_SCHEME_ID_MATCH
SHARE_SECRET_ID_MATCH
SHARE_ROLE_MATCH
SHARE_EPOCH_MATCH
SHARE_THRESHOLD_MATCH
SHARE_COUNT_MATCH
SHARE_WRAPPED_KEY_ID_MATCH
SHARE_LEDGER_GENESIS_MATCH
SHARE_CEREMONY_POLICY_MATCH
SHARE_INDEX_VALID
SHARE_INDEX_UNIQUE
SHARE_VALUE_CANONICAL
CUSTODIAN_ADMISSIBLE
```

A share failing any required predicate MUST be excluded. If fewer than `t` admissible shares remain, reconstruction MUST return `SILENCE`.

Envelope authenticity, schema validity, custodian admissibility, and threshold satisfaction are logically distinct predicates and MUST NOT be collapsed into one status.

---

## 8. Duplicate, Mixed-Epoch, and Cross-Context Rejection

A reconstruction set MUST be context-homogeneous.

The following conditions are terminal rejection conditions:

```text
DUPLICATE_SHARE_INDEX
MIXED_SECRET_ID
MIXED_SECRET_ROLE
MIXED_AUTHORITY_EPOCH
MIXED_THRESHOLD
MIXED_SHARE_COUNT
MIXED_WRAPPED_KEY_ID
MIXED_LEDGER_GENESIS_ID
MIXED_CEREMONY_POLICY_ID
CROSS_ROLE_SHARE_USE
```

No implementation may "repair" a mixed set by silently discarding context fields or rewriting metadata.

---

## 9. VSS Applicability

V0.1 does not define a concrete verifiable-secret-sharing commitment scheme.

The deployment policy MUST declare one of:

```text
VSS_ENABLED = FALSE
```

or:

```text
VSS_ENABLED = TRUE
VSS_PROFILE_ID = <separately frozen and approved VSS profile>
```

The conformance semantics are:

```text
VSS_ENABLED = FALSE
  => SHARE_CRYPTOGRAPHICALLY_CONSISTENT = NOT_APPLICABLE

VSS_ENABLED = TRUE
  => VSS_PROFILE_VALID = PASS
  => EACH_SHARE_VSS_VALID = PASS
  => SHARE_CRYPTOGRAPHICALLY_CONSISTENT = PASS
```

If `VSS_ENABLED = TRUE` and the referenced VSS profile is absent, invalid, stale, or unverified, reconstruction MUST return `SILENCE`.

A custodian signature MUST NOT be treated as VSS evidence.

---

## 10. Protected Reconstruction Algorithm

Input: a set of admitted shares for one homogeneous context.

1. Sort shares by ascending `share_index`.
2. Require at least `t` admitted unique shares.
3. Select the first `t` shares in sorted order.
4. Reconstruct at `x = 0` using Lagrange interpolation in `F_p`:

```text
S = sum_i(y_i * lambda_i) mod p

lambda_i = product_{j != i} (-x_j) * inverse(x_i - x_j) mod p
```

5. If more than `t` admitted shares were supplied and VSS is disabled, evaluate the reconstructed degree-`< t` polynomial against every additional share. Any inconsistency causes rejection of the entire reconstruction attempt.
6. Encode `S` canonically as 32-byte little-endian.
7. Place `S` directly into `SECRET_HANDLE_INTERNAL` inside the protected component.
8. Return only the opaque `SECRET_HANDLE_REFERENCE_TOKEN` defined by the frozen recovery specification.
9. Zeroise all plaintext share values, interpolation temporaries, coefficients, and local copies of `S` after handle creation or on any failure.

```text
RAW_RECONSTRUCTED_SECRET_EXPORT = PROHIBITED
RECONSTRUCTION_OUTPUT           = OPAQUE_REFERENCE_TOKEN_ONLY
```

A successful reconstruction MUST NOT perform HKDF, unwrap a RAK/SRK key, sign a recovery atom, or commit authority. Those operations remain downstream of recovery authorization.

---

## 11. Authority Separation and Failure Semantics

The normative state transition is:

```text
ADMISSIBLE SHARE SET
  -> THRESHOLD SATISFIED
  -> PROTECTED RECONSTRUCTION
  -> OPAQUE SECRET HANDLE
  -> RECOVERY AUTHORIZATION CHECK
  -> HKDF / KEY UNWRAP
  -> RECOVERY ATOM
  -> ORDINARY AAL VALIDATION
```

The following implications are prohibited:

```text
THRESHOLD_SATISFIED       !=> RECOVERY_AUTHORISED
RECONSTRUCTION_COMPLETE   !=> RECOVERY_AUTHORISED
RECOVERY_AUTHORISED       !=> AAL_ACCEPTED
SSS_CONFORMANCE_PASS      !=> AUTHORITY_GRANTED
```

Every SSS validation, decryption, interpolation, VSS, context, or threshold failure results in:

```text
SSS_FAILURE_MODE = SILENCE
```

and immediate destruction of plaintext share material and reconstruction intermediates.

---

## 12. Deterministic Conformance Vectors

All vectors in this section are synthetic and TEST-ONLY. Fixed coefficients MUST NOT be used in production.

### 12.1 Positive RAK 2-of-3 vector

```text
role = RAK
t = 2
n = 3
S = 42
a1 = 5
f(x) = 42 + 5x mod p
```

Expected shares:

| index `x` | value `y` | canonical 32-byte LE hex |
|---:|---:|---|
| 1 | 47 | `2f00000000000000000000000000000000000000000000000000000000000000` |
| 2 | 52 | `3400000000000000000000000000000000000000000000000000000000000000` |
| 3 | 57 | `3900000000000000000000000000000000000000000000000000000000000000` |

Any two distinct shares MUST reconstruct:

```text
S = 42
S_hex = 2a00000000000000000000000000000000000000000000000000000000000000
```

### 12.2 Positive SRK 3-of-5 vector

```text
role = SRK
t = 3
n = 5
S = 42
a1 = 5
a2 = 7
f(x) = 42 + 5x + 7x^2 mod p
```

Expected shares:

| index `x` | value `y` | canonical 32-byte LE hex |
|---:|---:|---|
| 1 | 54  | `3600000000000000000000000000000000000000000000000000000000000000` |
| 2 | 80  | `5000000000000000000000000000000000000000000000000000000000000000` |
| 3 | 120 | `7800000000000000000000000000000000000000000000000000000000000000` |
| 4 | 174 | `ae00000000000000000000000000000000000000000000000000000000000000` |
| 5 | 242 | `f200000000000000000000000000000000000000000000000000000000000000` |

Any three distinct shares MUST reconstruct the same canonical secret `S = 42`.

### 12.3 Canonical-field boundary vectors

```text
VALUE = p - 1
HEX   = ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
RESULT = ACCEPT

VALUE = p
HEX   = edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
RESULT = REJECT_NONCANONICAL
```

### 12.4 Required negative vectors

| ID | Condition | Expected result |
|---|---|---|
| N01 | fewer than `t` admissible shares | `SILENCE` |
| N02 | duplicate `share_index` | `REJECT_DUPLICATE_INDEX` |
| N03 | `share_index = 0` | `REJECT_INVALID_INDEX` |
| N04 | share value encodes integer `>= p` | `REJECT_NONCANONICAL_FIELD_ELEMENT` |
| N05 | mixed `secret_id` | `REJECT_CONTEXT_MISMATCH` |
| N06 | mixed `secret_role` | `REJECT_CONTEXT_MISMATCH` |
| N07 | mixed `authority_epoch` | `REJECT_CONTEXT_MISMATCH` |
| N08 | threshold/share-count mismatch from frozen role profile | `REJECT_PROFILE_MISMATCH` |
| N09 | ciphertext digest mutated after signature | `REJECT_SIGNATURE_OR_DIGEST_MISMATCH` |
| N10 | wrong JCS AAD during share decryption | `REJECT_AEAD_AUTHENTICATION` |
| N11 | custodian signature valid but VSS required and absent | `SILENCE` |
| N12 | extra share inconsistent with reconstructed polynomial when VSS disabled | `REJECT_INCONSISTENT_SHARE_SET` |
| N13 | cross-role RAK/SRK share mixing | `REJECT_CONTEXT_MISMATCH` |
| N14 | plaintext share requested for production export | `REJECT_EXPORT` |
| N15 | threshold reconstruction succeeds but recovery authorization is false | `DESTROY_HANDLE_AND_SILENCE` |
| N16 | arbitrary 32-byte secret reduced modulo `p` | `REJECT_NONCANONICAL_SECRET_INPUT` |

---

## 13. Provisioning Commit Rule

Provisioning is not complete merely because shares were mathematically generated.

The source secret `S` MUST NOT be destroyed until all of the following are established:

```text
ALL_REQUIRED_SHARE_ENVELOPES_CREATED
ALL_REQUIRED_SHARE_ENVELOPES_ENCRYPTED
ALL_REQUIRED_SHARE_ENVELOPES_SIGNED
CUSTODIAN_DISTRIBUTION_ACK_QUORUM_PASS
WRAPPED_KEY_OBJECT_PERSISTED
WRAPPED_KEY_OBJECT_FIXITY_PASS
PROVISIONING_RECORD_COMMITTED
```

Only after the provisioning commit may the source copy of `S` and all polynomial coefficients be destroyed.

A provisioning failure before commit MUST destroy incomplete share artifacts or mark them irrevocably invalid so that no partial set can later be mistaken for an active epoch.

---

## 14. Normative Status and Successor Rule

This V0.1 artifact is a normative working baseline. It has no authority effect by itself and does not authorize implementation.

```text
SSS_NORMATIVE_SPECIFICATION   = WORKING_BASELINE
SSS_CRYPTOGRAPHIC_CONFORMANCE = NOT_ESTABLISHED
SSS_AUTHORITY_CLAIM           = NOT_MADE
IMPLEMENTATION_AUTHORISED     = FALSE
```

Before implementation authority may be considered, this artifact must be independently reviewed, mechanically serialized, byte-counted, SHA-256 frozen, registered in durable provenance, and followed by separately derived schema and conformance fixtures.

Any semantic change after freeze MUST be issued as a successor artifact with a new identifier, version, byte count, SHA-256, and provenance record. The frozen predecessor must remain byte-identical.
