#!/usr/bin/env bash
set -euo pipefail

bundle_input="${1:-}"
expected_repository="${2:-}"
expected_pr_number="${3:-}"
expected_head_sha="${4:-}"

python - "$bundle_input" "$expected_repository" "$expected_pr_number" "$expected_head_sha" <<'PY'
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from aurum_v.verification.verify_artifact import ResultClass, verify_artifact


def clean(value: Any) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()


def write_outputs(result: str, denial_code: str, decision_id: str, message: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    lines = {
        "result": clean(result),
        "denial-code": clean(denial_code),
        "decision-id": clean(decision_id),
        "message": clean(message),
    }
    if output_path:
        with open(output_path, "a", encoding="utf-8", newline="\n") as output:
            for key, value in lines.items():
                output.write(f"{key}={value}\n")
    for key, value in lines.items():
        print(f"{key}: {value}")


def fail(result: str, denial_code: str, message: str, decision_id: str = "", exit_code: int = 1) -> int:
    write_outputs(result, denial_code, decision_id, message)
    return exit_code


bundle_arg, expected_repository, expected_pr_number, expected_head_sha = sys.argv[1:5]
workspace = Path(os.environ.get("GITHUB_WORKSPACE", "/github/workspace")).resolve()

if not bundle_arg:
    raise SystemExit(fail("INVALID_ARTIFACT", "APPROVAL_BUNDLE_REQUIRED", "approval bundle input is required"))

bundle = Path(bundle_arg)
if not bundle.is_absolute():
    bundle = workspace / bundle
bundle = bundle.resolve()

try:
    bundle.relative_to(workspace)
except ValueError:
    raise SystemExit(fail("INVALID_ARTIFACT", "BUNDLE_OUTSIDE_WORKSPACE", "approval bundle must be inside the checked-out workspace"))

if not bundle.is_dir():
    raise SystemExit(fail("INVALID_ARTIFACT", "APPROVAL_BUNDLE_NOT_FOUND", "approval bundle directory was not found"))

artifact_path = bundle / "approval.json"
signature_path = bundle / "approval.sig"
public_key_path = bundle / "public_key.pem"
manifest_path = bundle / "SHA256SUMS"

verification = verify_artifact(artifact_path, signature_path, public_key_path, manifest_path)
if verification.result is not ResultClass.VERIFIED:
    raise SystemExit(
        fail(
            verification.result.value,
            verification.result.value,
            verification.message or "approval bundle verification failed",
            exit_code=verification.exit_code,
        )
    )

try:
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    payload = artifact["payload"]
    if not isinstance(payload, dict):
        raise ValueError("signed payload must be an object")
except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
    raise SystemExit(fail("INVALID_ARTIFACT", "INVALID_SIGNED_PAYLOAD", clean(exc)))

decision_id = clean(payload.get("decision_id"))
decision = clean(payload.get("decision"))
if artifact.get("artifact_type") != "approval" or decision != "APPROVED":
    denial = clean(payload.get("denial_code")) or "DECISION_NOT_APPROVED"
    raise SystemExit(fail("REFUSED", denial, "signed artifact does not authorize execution", decision_id))

expected = {
    "repository": expected_repository,
    "pull_request_number": expected_pr_number,
    "expected_head_sha": expected_head_sha,
}
for field, expected_value in expected.items():
    if not clean(expected_value):
        raise SystemExit(fail("REFUSED", "EXPECTED_SCOPE_REQUIRED", f"missing expected value for {field}", decision_id))
    actual_value = payload.get(field)
    if field == "pull_request_number":
        try:
            actual_value = str(int(actual_value))
            expected_value = str(int(expected_value))
        except (TypeError, ValueError):
            raise SystemExit(fail("INVALID_ARTIFACT", "INVALID_PULL_REQUEST_NUMBER", "pull-request number is invalid", decision_id))
    if clean(actual_value) != clean(expected_value):
        denial_codes = {
            "repository": "REPOSITORY_MISMATCH",
            "pull_request_number": "PULL_REQUEST_MISMATCH",
            "expected_head_sha": "HEAD_SHA_MISMATCH",
        }
        raise SystemExit(fail("REFUSED", denial_codes[field], f"signed {field} does not match the expected target", decision_id))

write_outputs("VERIFIED", "", decision_id, "signed approval verified and target scope matched")
raise SystemExit(0)
PY
