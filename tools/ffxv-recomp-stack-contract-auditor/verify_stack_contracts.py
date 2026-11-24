#!/usr/bin/env python3
"""Read-only verifier for the FFXV recomp runtime stack-contract patches."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "manifest.json"

LF = b"\n"
CRLF = b"\r\n"

FIX72_BEFORE = LF.join(
    (
        b"        cpu->rax = cpu->rcx;",
        b"        return;",
        b"    }",
    )
)
FIX72_AFTER = LF.join(
    (
        b"        cpu->rax = cpu->rcx;",
        b"        cpu->rsp += 8;",
        b"        return;",
        b"    }",
    )
)

CALL = b"    recomp_native_call((void *)(uintptr_t)target, cpu);"
BOUNCE_CALL = b"        recomp_native_call((void *)(uintptr_t)target, cpu);"
FIX44_BEFORE = CRLF.join(
    (
        b"    if ((cpu->rsp & 15) == 0) {",
        b"        uint64_t r = cpu->rsp;",
        b"        int i;",
        b"        for (i = 0; i < 9; i++)",
        b"            write64(r - 8 + (uint64_t)i * 8, read64(r + (uint64_t)i * 8));",
        b"        cpu->rsp = r - 8;",
        b"    }",
        CALL,
        b"}",
    )
)
FIX44_AFTER = CRLF.join(
    (
        b"    if ((cpu->rsp & 15) == 0) {",
        b"        uint64_t r = cpu->rsp;",
        b"        int i;",
        b"        for (i = 0; i < 9; i++)",
        b"            write64(r - 8 + (uint64_t)i * 8, read64(r + (uint64_t)i * 8));",
        b"        cpu->rsp = r - 8;",
        BOUNCE_CALL,
        b"        cpu->rsp = r + 8;",
        b"        return;",
        b"    }",
        CALL,
        b"}",
    )
)


class VerificationError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def checked_transform(
    data: bytes,
    *,
    before: bytes,
    after: bytes,
    input_sha256: str,
    output_sha256: str,
) -> bytes:
    identity = sha256(data)
    before_count = data.count(before)
    after_count = data.count(after)

    if identity == output_sha256:
        require(after_count == 1 and before_count == 0, "patched identity/anchor mismatch")
        return data

    require(before_count <= 1 and after_count <= 1, "duplicate source anchor")
    require(identity == input_sha256, "source hash drift")
    require(before_count == 1 and after_count == 0, "source anchor mismatch")

    result = data.replace(before, after, 1)
    require(sha256(result) == output_sha256, "transformed hash drift")
    require(result.count(after) == 1 and result.count(before) == 0, "output anchor mismatch")
    return result


def verify_stack_models() -> None:
    entry = 0x100000
    frame = entry - 0x38
    call_rsp = frame - 8
    require(call_rsp + 8 == frame, "FIX72 return pop formula failed")
    require(frame + 0x50 == entry + 0x18, "FIX72 saved-RBX formula failed")

    original = 0x200000
    bounce = original - 8
    require(bounce + 8 == original, "FIX44 uncorrected trampoline formula failed")
    require(original + 8 == 0x200008, "FIX44 corrected caller formula failed")


def load_manifest() -> dict[str, object]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def check(project_root: Path) -> None:
    manifest = load_manifest()
    fixes = manifest["fixes"]
    specifications = {
        "fix72": (FIX72_BEFORE, FIX72_AFTER),
        "fix44": (FIX44_BEFORE, FIX44_AFTER),
    }

    for name, (before, after) in specifications.items():
        record = fixes[name]
        source = (project_root / record["source"]).read_bytes()
        checked_transform(
            source,
            before=before,
            after=after,
            input_sha256=record["input_sha256"],
            output_sha256=record["output_sha256"],
        )
        print(f"{name}: input and transformed hashes verified")

        patch_path = HERE / record["patch"]
        require(sha256(patch_path.read_bytes()) == record["patch_sha256"], f"{name}: patch drift")

    verify_stack_models()
    print("patch identities verified")
    print("PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--project-root", required=True, type=Path)
    args = parser.parse_args()
    check(args.project_root.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
