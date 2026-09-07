from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.signing import VerifyKey

from aurum_v.verification.verify_recovery_spec import (
    FROZEN_SPEC_SHA256,
    verify_frozen_recovery_spec,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "spec" / "derived" / "AURUMV_RECOVERY_SCHEMA_V1.json"
FIXTURES = ROOT / "spec" / "derived" / "AURUMV_RECOVERY_FIXTURES_V1.json"


def canonical_fixture_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def main() -> int:
    identity = verify_frozen_recovery_spec(ROOT / "spec" / "AURUMV_RECOVERY_SPECIFICATION_FROZEN.txt")
    assert identity.sha256 == FROZEN_SPEC_SHA256

    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert schema["properties"]["frozen_spec_sha256"]["const"] == FROZEN_SPEC_SHA256
    assert schema["$defs"]["metadata"]["properties"]["secret_role"]["enum"] == ["RAK", "SRK"]
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
    assert fixtures["derived_from_frozen_spec_sha256"] == FROZEN_SPEC_SHA256
    assert fixtures["production_secret_material"] == "ABSENT"

    jcs = fixtures["vectors"]["JCS_AAD_RAK_001"]
    metadata = jcs["metadata"]
    aad = canonical_fixture_json(metadata)
    assert aad.decode("utf-8") == jcs["canonical_utf8_text"]
    assert aad.hex() == jcs["canonical_utf8_hex"]
    assert hashlib.sha256(aad).hexdigest() == jcs["sha256"]

    hkdf = fixtures["vectors"]["HKDF_SHA256_RAK_001"]
    secret = bytes.fromhex(hkdf["S_bytes_hex"])
    salt = hkdf["salt_utf8"].encode("utf-8")
    info = hkdf["info_utf8"].encode("utf-8")
    prk = hkdf_extract(salt, secret)
    kek = hkdf_expand(prk, info, hkdf["KEK_length_bytes"])
    assert prk.hex() == hkdf["PRK_hex"]
    assert kek.hex() == hkdf["KEK_hex"]

    aead = fixtures["vectors"]["XCHACHA20_POLY1305_RAK_001"]
    nonce = bytes.fromhex(aead["nonce_hex"])
    plaintext = bytes.fromhex(aead["plaintext_key_hex"])
    expected_combined = bytes.fromhex(aead["combined_ciphertext_tag_hex"])
    actual_combined = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, kek)
    assert actual_combined == expected_combined
    assert crypto_aead_xchacha20poly1305_ietf_decrypt(actual_combined, aad, nonce, kek) == plaintext
    try:
        crypto_aead_xchacha20poly1305_ietf_decrypt(actual_combined, aad + b"x", nonce, kek)
    except Exception:
        pass
    else:
        raise AssertionError("wrong AAD was not rejected")

    sig = fixtures["vectors"]["ED25519_SHARE_ENVELOPE_001"]
    signed_bytes = bytes.fromhex(sig["signed_bytes_hex"])
    signature = bytes.fromhex(sig["signature_hex"])
    verify_key = VerifyKey(bytes.fromhex(sig["custodian_public_key_hex"]))
    verify_key.verify(signed_bytes, signature)
    try:
        verify_key.verify(signed_bytes + b" ", signature)
    except Exception:
        pass
    else:
        raise AssertionError("mutated signature message was not rejected")

    valid_instance = {
        "frozen_spec_sha256": FROZEN_SPEC_SHA256,
        "aead_profile": {
            "AEAD_PROFILE_ID": "AURUM-V-XCHACHA20-POLY1305-v1",
            "AEAD_ALGORITHM": "crypto_aead_xchacha20poly1305_ietf",
            "AEAD_KEY_SIZE_BYTES": 32,
            "AEAD_NONCE_SIZE_BYTES": 24,
            "AEAD_TAG_SIZE_BYTES": 16,
            "AEAD_NONCE_GENERATION": "CSPRNG_DERIVED_PER_KEY_WRAP",
            "AEAD_NONCE_STORAGE": "STORED_WITH_WRAPPED_KEY_OBJECT",
            "AEAD_NONCE_GENERATION_DURING_UNWRAP": "PROHIBITED",
            "AEAD_NONCE_REUSE_SAME_KEY": "PROHIBITED",
            "AEAD_AAD_ENCODING": "RFC8785_JCS",
            "AEAD_AUTHENTICATION_FAILURE": "REJECT_AND_ZEROISE",
        },
        "hkdf_profile": {
            "hash": "SHA-256",
            "salt_policy": "DEPLOYMENT_WIDE_RECOVERY_SPECIFIC_CONSTANT",
            "info": "AURUM-V/CIL-000/RAK/KEY-WRAP/v1",
            "output_length_bytes": 32,
        },
        "aad_metadata": metadata,
        "wrapped_key_object": {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(bytes.fromhex(aead["ciphertext_hex"])).decode("ascii"),
            "tag": base64.b64encode(bytes.fromhex(aead["tag_hex"])).decode("ascii"),
            "metadata": metadata,
        },
        "secret_handle_profile": {
            "SECRET_HANDLE_INTERNAL_EXPORTABLE": False,
            "SECRET_HANDLE_REFERENCE_TOKEN_SECRET_BEARING": False,
            "SECRET_HANDLE_CEREMONY_BOUND": True,
            "SECRET_HANDLE_SECRET_ID_BOUND": True,
            "SECRET_HANDLE_ROLE_BOUND": True,
            "SECRET_HANDLE_EPOCH_BOUND": True,
            "SECRET_HANDLE_SINGLE_USE": True,
            "SECRET_HANDLE_REPLAYABLE": False,
            "SECRET_HANDLE_EXPIRY_REQUIRED": True,
            "SECRET_HANDLE_MAX_LIFETIME_SECONDS": 86400,
        },
        "share_envelope": {
            "metadata": metadata,
            "encrypted_share_payload": base64.b64encode(bytes.fromhex(sig["encrypted_share_payload_hex"])).decode("ascii"),
            "encrypted_share_payload_sha256": sig["encrypted_share_payload_sha256"],
            "envelope_signature": base64.b64encode(signature).decode("ascii"),
        },
        "freeze_flags": {
            "SSS_ARCHITECTURAL_FIT": "ESTABLISHED",
            "SSS_ROLE": "RECOVERY_CUSTODY_MECHANISM",
            "SSS_IS_AUTHORITY_SOURCE": False,
            "THRESHOLD_SATISFACTION_IS_AUTHORITY": False,
            "SECRET_ENCODING": "CANONICAL_AND_INJECTIVE",
            "ARBITRARY_SECRET_FIELD_REDUCTION": "PROHIBITED",
            "RAW_RECONSTRUCTED_SECRET_EXPORT_PRODUCTION": "PROHIBITED",
            "SECRET_HANDLE_INTERNAL_EXPORTABLE": False,
            "SECRET_HANDLE_REFERENCE_TOKEN_SECRET_BEARING": False,
            "KEY_WRAP": "XCHACHA20_POLY1305_PROFILE_BOUND",
            "KEY_DERIVATION": "HKDF_SHA256",
            "AAD_CANONICAL_ENCODING": "RFC8785_JCS",
            "SHARE_INTEGRITY": "REQUIRED",
            "SHARE_PAYLOAD_BOUND_TO_SIGNATURE": "REQUIRED",
            "SHARE_CONFIDENTIALITY_AT_REST": "REQUIRED",
            "PRODUCTION_SECRET_OPERATIONS": "PROTECTED_NATIVE_OR_HSM_BOUNDARY",
            "RECOVERY_FAILURE_MODE": "SILENCE",
            "RECOVERY_PATH_BYPASSES_AAL": False,
            "SPECIFICATION_FREEZE_READINESS": "FROZEN",
        },
    }
    validator.validate(valid_instance)

    invalid_role = copy.deepcopy(valid_instance)
    invalid_role["aad_metadata"]["secret_role"] = "OTHER"
    assert list(validator.iter_errors(invalid_role)), "secret_role outside {RAK,SRK} was not rejected"

    print(f"RECOVERY_SPEC_SHA256={identity.sha256}")
    print("RECOVERY_SCHEMA=PASS")
    print("RECOVERY_FIXTURES=PASS")
    print("RECOVERY_CONFORMANCE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
