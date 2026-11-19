import argparse
import ctypes
import json
import random
import shutil
import subprocess
import sys
import tempfile
from _ctypes import FreeLibrary
from pathlib import Path

import pefile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import lift


def run(args, directory):
    result = subprocess.run(args, cwd=directory, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise AssertionError(f"{args} exited {result.returncode}\n{result.stdout}{result.stderr}")


def valid_stack_exits(instructions):
    start = min(instructions)
    deltas = {start: 0}
    pending = [start]
    while pending:
        address = pending.pop()
        instruction = instructions[address]
        delta = deltas[address]
        if instruction.mnemonic == "ret" and delta != 0:
            return False
        effect = 0
        if instruction.mnemonic == "push":
            effect = -8
        elif instruction.mnemonic == "pop":
            effect = 8
        elif instruction.mnemonic in {"add", "sub"} and instruction.operands[0].register == "rsp":
            immediate = instruction.operands[1].value
            if immediate is None:
                return False
            effect = immediate if instruction.mnemonic == "add" else -immediate
        for successor in instruction.successors:
            updated = delta + effect
            if successor not in deltas:
                deltas[successor] = updated
                pending.append(successor)
            elif deltas[successor] != updated:
                return False
    return True


def selected_functions(image, records, limit):
    selected = []
    for record in records:
        if record["call_targets"] or record["image_rvas"] or record["stack_arguments"]:
            continue
        start = int(record["rva"], 16)
        instructions = lift.discover(start, image.get_data(start, record["size"]))
        if any(
            operand.memory and operand.base != "rsp"
            for instruction in instructions.values() for operand in instruction.operands
        ):
            continue
        if not valid_stack_exits(instructions):
            continue
        preserved = {*lift.CALLEE_SAVED, *lift.CALLEE_SAVED_XMM}
        if any(
            instruction.reads & preserved
            for instruction in instructions.values()
        ):
            continue
        selected.append(record)
        if len(selected) >= limit:
            break
    return selected


def inputs(count):
    edge = (0, 1, 2, 31, 32, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x100000000,
            0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF)
    cases = [(left, right, edge[(index * 3) % len(edge)], edge[(index * 5) % len(edge)])
             for index, left in enumerate(edge) for right in edge]
    rng = random.Random(912731)
    cases.extend(tuple(rng.getrandbits(64) for _ in range(4)) for _ in range(count))
    return cases


def domain_cases(record, cases):
    if record["rva"] in {"0x962a790", "0xa5f9ba0"}:
        return [(0, index, 0, 0) for index in range(4)]
    if record["rva"] == "0xa8b7f60":
        return [(kind, index, 0, 0) for kind in (0, 1, 2, 8, 9, 10, 0xFFFFFFFF) for index in range(5)]
    return cases


def main():
    parser = argparse.ArgumentParser(description="Differential-test pure functions from a batch manifest")
    parser.add_argument("image", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--limit", type=int, default=64)
    parser.add_argument("--cases", type=int, default=128)
    parser.add_argument("--optimization", default="/O2")
    args = parser.parse_args()
    if not shutil.which("cl"):
        raise SystemExit("cl is missing. Run from an x64 MSVC developer prompt.")
    records = json.loads(args.manifest.read_text(encoding="utf-8"))["functions"]
    cases = inputs(args.cases)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
    comparisons = 0
    with pefile.PE(str(args.image), fast_load=True) as image:
        selected = selected_functions(image, records, args.limit)
        if not selected:
            raise SystemExit("no eligible functions found")
        with tempfile.TemporaryDirectory(prefix="recomp-batch-test-") as temporary:
            directory = Path(temporary)
            for offset in range(0, len(selected), 12):
                group = selected[offset:offset + 12]
                sources = [args.manifest.parent / record["source"] for record in group]
                output = directory / f"lifted_{offset}.dll"
                run([
                    "cl", "/nologo", "/TC", "/std:c11", "/W4", "/WX", args.optimization, "/LD",
                    *map(str, sources), "/link", f"/out:{output}",
                    *(f"/export:lifted_{record['name']}" for record in group),
                ], directory)
                library = ctypes.WinDLL(str(output))
                try:
                    for record in group:
                        start = int(record["rva"], 16)
                        code = image.get_data(start, record["size"])
                        address = kernel32.VirtualAlloc(None, len(code), 0x3000, 0x40)
                        if not address:
                            raise SystemExit(f"VirtualAlloc failed: {ctypes.get_last_error()}")
                        try:
                            ctypes.memmove(address, code, len(code))
                            native = ctypes.CFUNCTYPE(ctypes.c_uint64, *([ctypes.c_uint64] * 4))(address)
                            actual = getattr(library, f"lifted_{record['name']}")
                            actual.argtypes = [ctypes.c_uint64] * 4
                            actual.restype = ctypes.c_uint64
                            for case in domain_cases(record, cases):
                                expected_result = native(*case)
                                actual_result = actual(*case)
                                if expected_result != actual_result:
                                    raise AssertionError(
                                        f"{record['rva']} {case}: expected {expected_result:#x}, got {actual_result:#x}"
                                    )
                                comparisons += 1
                        finally:
                            kernel32.VirtualFree(address, 0, 0x8000)
                finally:
                    FreeLibrary(library._handle)
    print(f"Passed {comparisons:,} comparisons across {len(selected)} batch-generated functions.")


if __name__ == "__main__":
    main()
