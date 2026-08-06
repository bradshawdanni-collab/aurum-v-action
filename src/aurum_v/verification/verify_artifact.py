from __future__ import annotations

import argparse
import base64
import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROFILE = "AURUMV-C14N-JSON-1"
ALGORITHM = "Ed25519"
REQUIRED_FIELDS = {
    "artifact_version",
    "artifact_id",
    "artifact_type",
    "decision",
    "policy_id",
    "policy_version",
    "subject_id",
    "issued_at_utc",
    "canonicalization",
    "signature_algorithm",
    "key_id",
    "payload",
}


class ResultClass(str, Enum):
    VERIFIED = "VERIFIED"
    TAMPERED = "TAMPERED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    INVALID_ARTIFACT = "INVALID_ARTIFACT"
    UNSUPPORTED_PROFILE = "UNSUPPORTED_PROFILE"
    VERIFICATION_ERROR = "VERIFICATION_ERROR"


EXIT_CODES = {
    ResultClass.VERIFIED: 0,
    ResultClass.TAMPERED: 2,
    ResultClass.INVALID_SIGNATURE: 3,
    ResultClass.INVALID_ARTIFACT: 4,
    ResultClass.UNSUPPORTED_PROFILE: 5,
    ResultClass.VERIFICATION_ERROR: 6,
}


@dataclass(frozen=True)
class VerificationResult:
    result: ResultClass
    calculated_sha256: str | None = None
    expected_sha256: str | None = None
    artifact_type: str | None = None
    decision: str | None = None
    policy_id: str | None = None
    issued_at_utc: str | None = None
    message: str = ""

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.result]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(data, dict):
        raise ValueError("artifact root must be a JSON object")
    return data


def canonicalize(artifact: dict[str, Any]) -> bytes:
    return json.dumps(
        artifact,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _parse_manifest(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        digest, filename = stripped.split(maxsplit=1)
        entries[filename.strip()] = digest.lower()
    return entries


def _load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    return key


def _public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    canonical_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(canonical_der).hexdigest()


def verify_artifact(
    artifact_path: str | Path,
    signature_path: str | Path,
    public_key_path: str | Path,
    manifest_path: str | Path,
) -> VerificationResult:
    artifact_path = Path(artifact_path)
    signature_path = Path(signature_path)
    public_key_path = Path(public_key_path)
    manifest_path = Path(manifest_path)

    try:
        for required_path in (artifact_path, signature_path, public_key_path, manifest_path):
            if not required_path.is_file():
                return VerificationResult(
                    ResultClass.INVALID_ARTIFACT,
                    message=f"missing required input: {required_path}",
                )

        artifact = _load_json(artifact_path)
        missing = sorted(REQUIRED_FIELDS - artifact.keys())
        if missing:
            return VerificationResult(
                ResultClass.INVALID_ARTIFACT,
                message=f"missing required fields: {', '.join(missing)}",
            )

        if artifact["canonicalization"] != PROFILE:
            return VerificationResult(
                ResultClass.UNSUPPORTED_PROFILE,
                artifact_type=str(artifact.get("artifact_type")),
                decision=str(artifact.get("decision")),
                policy_id=str(artifact.get("policy_id")),
                issued_at_utc=str(artifact.get("issued_at_utc")),
                message=f"unsupported canonicalization profile: {artifact['canonicalization']}",
            )

        if artifact["signature_algorithm"] != ALGORITHM:
            return VerificationResult(
                ResultClass.UNSUPPORTED_PROFILE,
                message=f"unsupported signature algorithm: {artifact['signature_algorithm']}",
            )

        canonical_bytes = canonicalize(artifact)
        calculated_digest = hashlib.sha256(canonical_bytes).hexdigest()
        manifest = _parse_manifest(manifest_path)
        expected_digest = manifest.get(artifact_path.name)
        if expected_digest is None:
            return VerificationResult(
                ResultClass.INVALID_ARTIFACT,
                calculated_sha256=calculated_digest,
                message=f"manifest has no entry for {artifact_path.name}",
            )

        protected = {
            "artifact_type": str(artifact["artifact_type"]),
            "decision": str(artifact["decision"]),
            "policy_id": str(artifact["policy_id"]),
            "issued_at_utc": str(artifact["issued_at_utc"]),
        }

        if calculated_digest.lower() != expected_digest.lower():
            return VerificationResult(
                ResultClass.TAMPERED,
                calculated_sha256=calculated_digest,
                expected_sha256=expected_digest,
                **protected,
                message="artifact digest does not match manifest",
            )

        signature = base64.b64decode(signature_path.read_text(encoding="utf-8").strip(), validate=True)
        public_key = _load_public_key(public_key_path)

        expected_key_digest = manifest.get(public_key_path.name)
        calculated_key_digest = _public_key_fingerprint(public_key)
        if expected_key_digest is None or calculated_key_digest.lower() != expected_key_digest.lower():
            return VerificationResult(
                ResultClass.INVALID_SIGNATURE,
                calculated_sha256=calculated_digest,
                expected_sha256=expected_digest,
                **protected,
                message="public-key fingerprint does not match manifest",
            )

        try:
            public_key.verify(signature, canonical_bytes)
        except InvalidSignature:
            return VerificationResult(
                ResultClass.INVALID_SIGNATURE,
                calculated_sha256=calculated_digest,
                expected_sha256=expected_digest,
                **protected,
                message="detached signature is invalid",
            )

        return VerificationResult(
            ResultClass.VERIFIED,
            calculated_sha256=calculated_digest,
            expected_sha256=expected_digest,
            **protected,
            message="artifact digest and detached signature verified",
        )
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError, base64.binascii.Error) as exc:
        return VerificationResult(ResultClass.INVALID_ARTIFACT, message=str(exc))
    except Exception as exc:  # pragma: no cover - defensive fail-closed boundary
        return VerificationResult(ResultClass.VERIFICATION_ERROR, message=str(exc))


def _print_result(result: VerificationResult) -> None:
    print(f"result: {result.result.value}")
    if result.calculated_sha256:
        print(f"calculated_sha256: {result.calculated_sha256}")
    if result.expected_sha256:
        print(f"expected_sha256: {result.expected_sha256}")
    if result.artifact_type:
        print(f"artifact_type: {result.artifact_type}")
    if result.decision:
        print(f"decision: {result.decision}")
    if result.policy_id:
        print(f"policy_id: {result.policy_id}")
    if result.issued_at_utc:
        print(f"issued_at_utc: {result.issued_at_utc}")
    if result.message:
        print(f"message: {result.message}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a public AURUM-V artifact.")
    parser.add_argument("artifact")
    parser.add_argument("signature")
    parser.add_argument("public_key")
    parser.add_argument("manifest")
    args = parser.parse_args()

    result = verify_artifact(args.artifact, args.signature, args.public_key, args.manifest)
    _print_result(result)
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
