from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from jsonschema import Draft202012Validator
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

    fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
    assert fixtures["derived_from_frozen_spec_sha256"] == FROZEN_SPEC_SHA256
    assert fixtures["production_secret_material"] == "ABSENT"

    jcs = fixtures["vectors"]["JCS_AAD_RAK_001"]
    aad = canonical_fixture_json(jcs["metadata"])
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

    print(f"RECOVERY_SPEC_SHA256={identity.sha256}")
    print("RECOVERY_SCHEMA=PASS")
    print("RECOVERY_FIXTURES=PASS")
    print("RECOVERY_CONFORMANCE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
