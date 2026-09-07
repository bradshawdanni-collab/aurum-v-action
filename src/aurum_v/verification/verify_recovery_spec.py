from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

FROZEN_SPEC_FILENAME = "AURUMV_RECOVERY_SPECIFICATION_FROZEN.txt"
FROZEN_SPEC_SHA256 = "d422b30ec51a95fd515c7e1a069cd223b0a8fce2313366921b1816b5678241f1"
FROZEN_SPEC_BYTE_COUNT = 7814


@dataclass(frozen=True)
class FrozenSpecIdentity:
    path: Path
    byte_count: int
    sha256: str


def default_frozen_spec_path() -> Path:
    override = os.environ.get("AURUMV_RECOVERY_SPEC_PATH")
    if override:
        return Path(override)

    container_path = Path("/opt/aurum-v/spec") / FROZEN_SPEC_FILENAME
    if container_path.is_file():
        return container_path

    repository_root = Path(__file__).resolve().parents[3]
    return repository_root / "spec" / FROZEN_SPEC_FILENAME


def verify_frozen_recovery_spec(path: str | Path | None = None) -> FrozenSpecIdentity:
    spec_path = Path(path) if path is not None else default_frozen_spec_path()
    try:
        data = spec_path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"frozen recovery specification unavailable: {spec_path}: {exc}") from exc

    if data.startswith(b"\xef\xbb\xbf"):
        raise RuntimeError("frozen recovery specification has a prohibited UTF-8 BOM")
    if b"\r" in data:
        raise RuntimeError("frozen recovery specification contains prohibited CR bytes")
    if len(data) != FROZEN_SPEC_BYTE_COUNT:
        raise RuntimeError(
            f"frozen recovery specification byte-count mismatch: {len(data)} != {FROZEN_SPEC_BYTE_COUNT}"
        )

    digest = hashlib.sha256(data).hexdigest()
    if digest != FROZEN_SPEC_SHA256:
        raise RuntimeError(
            f"frozen recovery specification SHA-256 mismatch: {digest} != {FROZEN_SPEC_SHA256}"
        )

    return FrozenSpecIdentity(spec_path, len(data), digest)


if __name__ == "__main__":
    identity = verify_frozen_recovery_spec()
    print(f"filename: {identity.path.name}")
    print(f"byte_count: {identity.byte_count}")
    print(f"sha256: {identity.sha256}")
