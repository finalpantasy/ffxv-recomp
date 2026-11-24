#!/usr/bin/env python3
"""Read-only audit of the captured FFXV CRT-constructor corridor.

Reads generated/runtime-oep inputs, never writes there, and emits audit.json
beside this script. Pass the retail PE as --exe. Input files are hashed and
checked for stable content before they are accepted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from datetime import datetime, timezone
from pathlib import Path

import pefile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ANALYSIS = ROOT / "analysis"
RUNTIME = ROOT / "generated" / "runtime-oep"
LINK_DUMP = ANALYSIS / "runtime_link.bin"
TABLE_ORIGIN = 0x3067EA0
FIRST_INDEX = 1658
LAST_INDEX = 1690


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def read_stable(path: Path) -> bytes:
    """Read twice and reject inputs that change during the snapshot window."""
    before = path.stat()
    first = path.read_bytes()
    middle = path.stat()
    second = path.read_bytes()
    after = path.stat()
    if (
        len(first) != before.st_size
        or len(second) != after.st_size
        or sha256(first) != sha256(second)
        or before.st_mtime_ns != middle.st_mtime_ns
        or middle.st_mtime_ns != after.st_mtime_ns
    ):
        raise RuntimeError(f"input changed while being read: {path.name}")
    return first


def decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def dispatch_args(source: str) -> list[str]:
    """Extract balanced argument text from recomp_cpu_dispatch(cpu, arg)."""
    out: list[str] = []
    needle = "recomp_cpu_dispatch"
    pos = 0
    while True:
        start = source.find(needle, pos)
        if start < 0:
            break
        open_paren = source.find("(", start + len(needle))
        if open_paren < 0:
            break
        depth = 1
        i = open_paren + 1
        while i < len(source) and depth:
            if source[i] == "(":
                depth += 1
            elif source[i] == ")":
                depth -= 1
            i += 1
        if depth:
            break
        call = source[open_paren + 1 : i - 1]
        comma = call.find(",")
        if comma >= 0:
            out.append(call[comma + 1 :].strip())
        pos = i
    return out


def parse_dispatches(source: str, imports: dict[int, str]) -> dict:
    direct: set[int] = set()
    slots: set[int] = set()
    other: list[str] = []
    for arg in dispatch_args(source):
        m = re.fullmatch(r"UINT64_C\(\s*(0x[0-9a-fA-F]+)\s*\)", arg)
        if m:
            direct.add(int(m.group(1), 16))
            continue
        slot_match = re.search(
            r"read64\s*\(.*?image_base\s*\+\s*UINT64_C\(\s*(0x[0-9a-fA-F]+)",
            arg,
            re.S,
        )
        if slot_match:
            slot = int(slot_match.group(1), 16)
            slots.add(slot)
        else:
            other.append(" ".join(arg.split())[:180])
    return {
        "dispatch_count": len(dispatch_args(source)),
        "direct_targets": [f"0x{x:x}" for x in sorted(direct)],
        "dynamic_slots": [f"0x{slot:x}" for slot in sorted(slots)],
        "other_dynamic_dispatches": other,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=Path, help="retail ffxv_s.exe")
    args = parser.parse_args()

    exe = args.exe.resolve(strict=True)
    exe_hash = file_sha256(exe)
    pe = pefile.PE(str(exe), fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    imports: dict[int, str] = {}
    for dll in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = dll.dll.decode("ascii", errors="replace")
        for imp in dll.imports:
            name = imp.name.decode("ascii", errors="replace") if imp.name else f"ordinal:{imp.ordinal}"
            imports[imp.address - image_base] = f"{dll_name}!{name}"

    runtime_paths = {
        "harness.c": RUNTIME / "harness.c",
        "recomp_runtime.c": RUNTIME / "recomp_runtime.c",
        "supp_table.h": RUNTIME / "supp_table.h",
    }
    runtime_bytes = {name: read_stable(path) for name, path in runtime_paths.items()}
    harness = decode(runtime_bytes["harness.c"])
    registry_source = decode(runtime_bytes["supp_table.h"])
    registry = {
        int(m.group(1), 16)
        for m in re.finditer(
            r"\{\s*UINT64_C\(0x([0-9a-fA-F]+)\),\s*lifted_fn_[0-9a-fA-F]+_cpu\s*\}",
            registry_source,
        )
    }
    skip_match = re.search(
        r"static\s+const\s+uint64_t\s+skip_rvas\[\]\s*=\s*\{(.*?)\};",
        harness,
        re.S,
    )
    if not skip_match:
        raise RuntimeError("could not locate skip_rvas[] in harness.c")
    skip_body = re.sub(r"/\*.*?\*/|//[^\n]*", "", skip_match.group(1), flags=re.S)
    skipped = {int(x, 16) for x in re.findall(r"UINT64_C\(0x([0-9a-fA-F]+)\)", skip_body)}

    link_bytes = LINK_DUMP.read_bytes()
    link_hash = sha256(link_bytes)
    link_section = next(
        s for s in pe.sections if s.Name.rstrip(b"\0").decode("ascii", errors="replace") == ".link"
    )
    link_rva = link_section.VirtualAddress
    if len(link_bytes) < link_section.Misc_VirtualSize:
        raise RuntimeError("captured runtime_link.bin is shorter than the PE .link virtual size")

    def resolve_dynamic_slots(slots: list[str]) -> list[dict]:
        resolved = []
        for slot_text in slots:
            slot = int(slot_text, 16)
            if slot in imports:
                resolved.append({"slot_rva": slot_text, "kind": "import", "import": imports[slot]})
                continue
            if link_rva <= slot <= link_rva + len(link_bytes) - 8:
                raw = struct.unpack_from("<Q", link_bytes, slot - link_rva)[0]
                if image_base <= raw < image_base + pe.OPTIONAL_HEADER.SizeOfImage:
                    target = raw - image_base
                    resolved.append({
                        "slot_rva": slot_text,
                        "kind": "guest_function_pointer",
                        "raw_target": f"0x{raw:x}",
                        "target_rva": f"0x{target:x}",
                        "target_registered": target in registry,
                        "target_skipped": target in skipped,
                    })
                else:
                    resolved.append({
                        "slot_rva": slot_text,
                        "kind": "external_host_pointer",
                        "note": "captured value is outside the guest image; raw address omitted",
                    })
                continue
            resolved.append({"slot_rva": slot_text, "kind": "unclassified_indirect_slot"})
        return resolved

    entries: list[dict] = []
    source_cache: dict[int, tuple[str, str] | None] = {}

    def function_source(rva: int) -> tuple[str, str] | None:
        if rva in source_cache:
            return source_cache[rva]
        path = RUNTIME / "supp" / f"fn_{rva:x}_cpu.c"
        if not path.is_file():
            source_cache[rva] = None
            return None
        raw = read_stable(path)
        result = (decode(raw), sha256(raw))
        source_cache[rva] = result
        return result

    for index in range(FIRST_INDEX, LAST_INDEX + 1):
        slot_rva = TABLE_ORIGIN + index * 8
        offset = slot_rva - link_rva
        raw_target = struct.unpack_from("<Q", link_bytes, offset)[0]
        target_rva = raw_target - image_base if image_base <= raw_target < image_base + pe.OPTIONAL_HEADER.SizeOfImage else raw_target
        src = function_source(target_rva)
        body = parse_dispatches(src[0], imports) if src else {
            "dispatch_count": 0,
            "direct_targets": [],
            "dynamic_slots": [],
            "other_dynamic_dispatches": [],
        }
        source_path = RUNTIME / "supp" / f"fn_{target_rva:x}_cpu.c"
        direct_checks = []
        for target in (int(x, 16) for x in body["direct_targets"]):
            direct_checks.append({
                "target_rva": f"0x{target:x}",
                "source_present": (RUNTIME / "supp" / f"fn_{target:x}_cpu.c").is_file(),
                "registered": target in registry,
                "skipped": target in skipped,
            })
        entries.append({
            "index": index,
            "slot_rva": f"0x{slot_rva:x}",
            "raw_target": f"0x{raw_target:x}",
            "ctor_rva": f"0x{target_rva:x}",
            "source_present": src is not None,
            "source_sha256": src[1] if src else None,
            "registered": target_rva in registry,
            "skipped": target_rva in skipped,
            **body,
            "resolved_dynamic_slots": resolve_dynamic_slots(body["dynamic_slots"]),
            "direct_target_checks": direct_checks,
        })

    unique_targets = sorted({
        int(target, 16)
        for entry in entries
        for target in entry["direct_targets"]
    })
    first_level_checks = [{
        "target_rva": f"0x{target:x}",
        "source_present": (RUNTIME / "supp" / f"fn_{target:x}_cpu.c").is_file(),
        "registered": target in registry,
        "skipped": target in skipped,
    } for target in unique_targets]

    # Bounded transitive closure of the first constructor's ordinary code calls (four edges).
    transitive: list[dict] = []
    queue = [(int(entries[0]["ctor_rva"], 16), 0)]
    seen: set[int] = set()
    while queue and len(seen) < 512:
        rva, depth = queue.pop(0)
        if rva in seen:
            continue
        seen.add(rva)
        src = function_source(rva)
        body = parse_dispatches(src[0], imports) if src else {
            "dispatch_count": 0,
            "direct_targets": [],
            "dynamic_slots": [],
            "other_dynamic_dispatches": [],
        }
        transitive.append({
            "depth": depth,
            "function_rva": f"0x{rva:x}",
            "source_present": src is not None,
            "registered": rva in registry,
            "skipped": rva in skipped,
            **body,
            "resolved_dynamic_slots": resolve_dynamic_slots(body["dynamic_slots"]),
        })
        if depth < 4:
            queue.extend((int(target, 16), depth + 1) for target in body["direct_targets"])
    if queue:
        raise RuntimeError("transitive target cap hit; narrow the audit before publication")

    slot_queries = []
    for slot in (0xFE2A818, 0xFE2AC60):
        raw_off = pe.get_offset_from_rva(slot)
        slot_queries.append({
            "slot_rva": f"0x{slot:x}",
            "import": imports.get(slot),
            "raw_value": f"0x{int.from_bytes(pe.__data__[raw_off:raw_off + 8], 'little'):x}",
        })

    manifest_path = ANALYSIS / "ctor-tranche-1426-1681-corrected-manifest-2026-11-23.json"
    manifest_note = None
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        legacy_entry = next((e for e in manifest.get("entries", []) if e.get("index") == FIRST_INDEX), None)
        manifest_note = {
            "path": "analysis/ctor-tranche-1426-1681-corrected-manifest-2026-11-23.json",
            "sha256": file_sha256(manifest_path),
            "legacy_index_1658_ctor_rva": legacy_entry.get("ctor_rva") if legacy_entry else None,
            "captured_table_index_1658_ctor_rva": entries[0]["ctor_rva"],
            "note": "legacy manifest slot origin is one qword later than the captured runtime_link table origin used here",
        }

    all_ctor_sources = all(e["source_present"] and e["registered"] and not e["skipped"] for e in entries)
    all_direct_targets = all(c["source_present"] and c["registered"] and not c["skipped"] for c in first_level_checks)
    audit = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {"first_index": FIRST_INDEX, "last_index": LAST_INDEX, "count": len(entries)},
        "inputs": {
            "retail_executable": {"basename": exe.name, "sha256": exe_hash, "image_base": f"0x{image_base:x}"},
            "runtime_link": {"path": "analysis/runtime_link.bin", "sha256": link_hash, "size": len(link_bytes), "section_rva": f"0x{link_rva:x}"},
            "harness": {"path": "generated/runtime-oep/harness.c", "sha256": sha256(runtime_bytes["harness.c"])},
            "recomp_runtime": {"path": "generated/runtime-oep/recomp_runtime.c", "sha256": sha256(runtime_bytes["recomp_runtime.c"])},
            "supp_table": {"path": "generated/runtime-oep/supp_table.h", "sha256": sha256(runtime_bytes["supp_table.h"])},
        },
        "registration_audit": {
            "registered_function_count": len(registry),
            "skip_count": len(skipped),
            "all_33_ctor_bodies_present_registered_and_not_skipped": all_ctor_sources,
            "unique_first_level_direct_target_count": len(unique_targets),
            "all_first_level_direct_targets_present_registered_and_not_skipped": all_direct_targets,
            "first_level_direct_targets": first_level_checks,
        },
        "transitive_path_from_first_ctor": transitive,
        "import_slots": slot_queries,
        "legacy_manifest_cross_check": manifest_note,
        "entries": entries,
    }
    out = HERE / "audit.json"
    out.write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": "analysis/lane-421-next-ctor-corridor/audit.json",
        "scope": audit["scope"],
        "all_ctor_bodies_present_registered_and_not_skipped": all_ctor_sources,
        "unique_first_level_targets": len(unique_targets),
        "all_first_level_targets_present_registered_and_not_skipped": all_direct_targets,
        "import_slots": slot_queries,
        "input_sha256": {k: v["sha256"] for k, v in audit["inputs"].items()},
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
