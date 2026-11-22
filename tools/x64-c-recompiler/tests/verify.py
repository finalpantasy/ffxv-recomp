import ctypes
import random
import shutil
import subprocess
import sys
import tempfile
from _ctypes import FreeLibrary
from contextlib import contextmanager
from pathlib import Path

import pefile


ROOT = Path(__file__).resolve().parents[1]
FUNCTIONS = ("mix64", "fold32", "classify64", "condition_mask32", "imul_flags", "conditional_move", "prefixed_nop", "rip_relative", "rip_relative_negative", "extend_values", "shift_values", "shift_flags", "rotate_flags", "rotate_flag_preservation", "neg_not", "xchg_andnot", "sign_masks", "sign_extend16", "partial_registers", "partial_flags", "partial_cmp", "set_conditions", "bit_tests", "dynamic_bits", "bit_scans", "imul_three", "bit_reset", "imul_one64", "imul_one32", "mul_one16", "imul_one16", "mul_one64", "mul_one32", "sbb_flags", "adc_flags", "double_shifts", "double_shifts_cl", "carry_rotates", "rotate_values", "bit_operations", "crc32_values", "jump_rcx", "push_flags", "push_stack_sources")
MEMORY_FUNCTIONS = ("memory_read", "memory_write", "stack_roundtrip")
STACK_FUNCTIONS = ("stack_argument",)
XMM_FUNCTIONS = ("xmm_roundtrip",)
DIRECT_FUNCTIONS = ("direct_call", "direct_stack_call")
INDIRECT_FUNCTIONS = ("indirect_call", "indirect_register_call")
BUILD_ONLY_FUNCTIONS = ("scalar_moves", "narrow_memory", "string_scans", "string_copies", "lock_xadd", "tail_call", "indirect_tail", "register_tail", "compare_float", "float_startup", "scalar_double_convert", "scalar_int_double", "scalar_double", "vector_general", "vector_float", "vector_andnot", "vector_shuffle", "vector_unpack64", "vector_shuffle_double", "vector_horizontal", "vector_int", "vector_integer", "vector_int_arith", "vector_int_double", "vector_convert", "vector_mixed", "vector_compare", "vector_minmax", "vector_approx", "vector_byteshift", "signed_division", "unsigned_division", "signed_division8", "unsigned_division8", "scalar_minmax", "scalar_sqrt", "tls_read", "ret_immediate", "cpu_identification", "trap_instruction")
CONTEXT_ONLY_FUNCTIONS = {"tail_call", "indirect_tail", "register_tail", "compare_float", "float_startup", "scalar_double_convert", "scalar_int_double", "scalar_double", "vector_general", "vector_float", "vector_andnot", "vector_shuffle", "vector_unpack64", "vector_shuffle_double", "vector_horizontal", "vector_int", "vector_integer", "vector_int_arith", "vector_int_double", "vector_convert", "vector_mixed", "vector_compare", "vector_minmax", "vector_approx", "vector_byteshift", "signed_division", "unsigned_division", "signed_division8", "unsigned_division8", "scalar_minmax", "scalar_sqrt", "tls_read", "ret_immediate", "cpu_identification", "trap_instruction", "string_scans", "string_copies", "lock_xadd"}
ALL_FUNCTIONS = (*FUNCTIONS, *MEMORY_FUNCTIONS, *STACK_FUNCTIONS, *XMM_FUNCTIONS, *DIRECT_FUNCTIONS, *INDIRECT_FUNCTIONS, *BUILD_ONLY_FUNCTIONS)
FAST_FUNCTIONS = tuple(name for name in ALL_FUNCTIONS if name not in CONTEXT_ONLY_FUNCTIONS)
REJECTED = {
    "undefined_path": "uninitialized state: r10",
    "branch_outside": "outside the selected code range",
    "relocated_constant": "base relocation in the selected code range",
    "unsupported_indirect_call": "uninitialized state: rax",
}
EXPORTS = {}


def run(args, directory, error=None):
    result = subprocess.run(
        args, cwd=directory, capture_output=True, text=True, timeout=30
    )
    output = result.stdout + result.stderr
    if error is None and result.returncode != 0:
        raise AssertionError(f"{args} exited {result.returncode}\n{output}")
    if error is not None and (result.returncode == 0 or error not in output):
        raise AssertionError(f"{args} should fail with {error!r}\n{output}")


def build_fixture(directory):
    global EXPORTS
    symbols = [part for name in (*ALL_FUNCTIONS, *REJECTED) for part in (name, name + "_end")]
    run(["ml64", "/nologo", "/c", "/Fofixtures.obj", ROOT / "tests/fixtures.asm"], directory)
    run(
        ["link", "/nologo", "/dll", "/noentry", "/out:native.dll", "fixtures.obj"]
        + [f"/export:{name}" for name in symbols],
        directory,
    )
    with pefile.PE(str(directory / "native.dll")) as image:
        addresses = {
            export.name.decode("ascii"): export.address
            for export in image.DIRECTORY_ENTRY_EXPORT.symbols
        }
    EXPORTS = addresses
    return {name: addresses[name + "_end"] - addresses[name] for name in (*ALL_FUNCTIONS, *REJECTED)}

def lift(directory, name, size, output, *, error=None, binary="native.dll", rva=None, stack_arguments=0, cpu_context=False):
    command = [
        sys.executable, ROOT / "lift.py", binary, name,
        "--size", str(size), "--output", output,
    ]
    if rva is not None:
        command.extend(["--rva", str(rva)])
    if stack_arguments:
        command.extend(["--stack-arguments", str(stack_arguments)])
    if cpu_context:
        command.append("--cpu-context")
    run(command, directory, error)


@contextmanager
def load_library(path):
    library = ctypes.WinDLL(str(path))
    try:
        yield library
    finally:
        FreeLibrary(library._handle)


def get_function(library, name, argument_count=4):
    function = getattr(library, name)
    function.argtypes = [ctypes.c_uint64] * argument_count
    function.restype = ctypes.c_uint64
    return function


def inputs():
    edge_values = (
        0, 1, 31, 32, 2**31 - 1, 2**31, 2**32 - 1, 2**32, 2**63 - 1, 2**63, 2**64 - 1,
    )
    cases = [
        (left, right, edge_values[(i + j) % len(edge_values)], 0xABCD000043210123)
        for i, left in enumerate(edge_values)
        for j, right in enumerate(edge_values)
    ]
    rng = random.Random(7301)
    cases.extend(tuple(rng.getrandbits(64) for _ in range(4)) for _ in range(1024))
    return cases


def verify_memory(native, lifted, flag):
    for name in MEMORY_FUNCTIONS:
        expected = get_function(native, name)
        actual = get_function(lifted, f"lifted_{name}")
        for iteration in range(128):
            initial = [
                ((iteration + 1) * 0x9E3779B97F4A7C15 + index * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
                for index in range(64)
            ]
            value = ((iteration * 0xF1357AEA2E62A9C5) << 1) & 0xFFFFFFFFFFFFFFFF
            expected_buffer = (ctypes.c_uint64 * 64)(*initial)
            actual_buffer = (ctypes.c_uint64 * 64)(*initial)
            expected_result = expected(ctypes.addressof(expected_buffer), value, 0, 0)
            observed_result = actual(ctypes.addressof(actual_buffer), value, 0, 0)
            if observed_result != expected_result or list(actual_buffer) != list(expected_buffer):
                raise AssertionError(
                    f"{flag} {name} case {iteration}: expected {expected_result:#x}/{list(expected_buffer)}, "
                    f"got {observed_result:#x}/{list(actual_buffer)}"
                )


def verify_stack_arguments(native, lifted, flag, cases):
    for name in STACK_FUNCTIONS:
        expected = get_function(native, name, 5)
        actual = get_function(lifted, f"lifted_{name}", 5)
        for case in cases:
            extended = (*case, case[0] ^ case[3] ^ 0xF00DF00DF00DF00D)
            expected_result = expected(*extended)
            observed_result = actual(*extended)
            if observed_result != expected_result:
                raise AssertionError(
                    f"{flag} {name}{extended}: expected {expected_result:#x}, got {observed_result:#x}"
                )


def verify_xmm(native, lifted, flag):
    for name in XMM_FUNCTIONS:
        expected = get_function(native, name)
        actual = get_function(lifted, f"lifted_{name}")
        for iteration in range(128):
            initial = bytes((iteration * 37 + index * 19) & 0xFF for index in range(16))
            expected_input = ctypes.create_string_buffer(initial, 16)
            actual_input = ctypes.create_string_buffer(initial, 16)
            expected_output = ctypes.create_string_buffer(b'\xCC' * 16, 16)
            actual_output = ctypes.create_string_buffer(b'\xCC' * 16, 16)
            expected_zero = ctypes.create_string_buffer(b'\xCC' * 16, 16)
            actual_zero = ctypes.create_string_buffer(b'\xCC' * 16, 16)
            expected_result = expected(
                ctypes.addressof(expected_input), ctypes.addressof(expected_output), ctypes.addressof(expected_zero), 0,
            )
            actual_result = actual(
                ctypes.addressof(actual_input), ctypes.addressof(actual_output), ctypes.addressof(actual_zero), 0,
            )
            expected_low = int.from_bytes(expected_output.raw[:8], 'little')
            actual_low = int.from_bytes(actual_output.raw[:8], 'little')
            if (
                expected_result != actual_result or expected_low != actual_low
                or expected_output.raw != actual_output.raw or expected_zero.raw != actual_zero.raw
                or expected_zero.raw != bytes(16)
            ):
                raise AssertionError(f"{flag} {name} case {iteration}: native/C XMM mismatch")


def verify_direct_calls(native, lifted, flag, cases):
    callback_type = ctypes.CFUNCTYPE(ctypes.c_uint64, *([ctypes.c_uint64] * 6))
    lifted_mix = get_function(lifted, "lifted_mix64")
    lifted_stack = get_function(lifted, "lifted_stack_argument", 5)

    def dispatch(target, rcx, rdx, r8, r9, guest_rsp):
        if target == EXPORTS["mix64"]:
            return lifted_mix(rcx, rdx, r8, r9)
        if target == EXPORTS["stack_argument"]:
            fifth = ctypes.c_uint64.from_address(guest_rsp + 0x28).value
            return lifted_stack(rcx, rdx, r8, r9, fifth)
        raise AssertionError(f"unexpected call target {target:#x}")

    callback = callback_type(dispatch)
    for name in DIRECT_FUNCTIONS:
        setter = getattr(lifted, f"lifted_{name}_set_call_dispatcher")
        setter.argtypes = [callback_type]
        setter(callback)
        expected = get_function(native, name)
        actual = get_function(lifted, f"lifted_{name}")
        for case in cases:
            expected_result = expected(*case)
            observed_result = actual(*case)
            if observed_result != expected_result:
                raise AssertionError(
                    f"{flag} {name}{case}: expected {expected_result:#x}, got {observed_result:#x}"
                )


def verify_indirect_calls(native, lifted, flag, cases):
    callback_type = ctypes.CFUNCTYPE(ctypes.c_uint64, *([ctypes.c_uint64] * 6))
    lifted_mix = get_function(lifted, "lifted_mix64")

    def dispatch(target, rcx, rdx, r8, r9, guest_rsp):
        if target == EXPORTS["mix64"]:
            return lifted_mix(rcx, rdx, r8, r9)
        raise AssertionError(f"unexpected indirect target {target:#x}")

    callback = callback_type(dispatch)
    for name in INDIRECT_FUNCTIONS:
        call_setter = getattr(lifted, f"lifted_{name}_set_call_dispatcher")
        call_setter.argtypes = [callback_type]
        call_setter(callback)
        image_setter = getattr(lifted, f"lifted_{name}_set_image_base")
        image_setter.argtypes = [ctypes.c_uint64]
        image_setter(ctypes.c_uint64(native._handle))
        expected = get_function(native, name)
        actual = get_function(lifted, f"lifted_{name}")
        for case in cases:
            expected_result = expected(*case)
            observed_result = actual(*case)
            if observed_result != expected_result:
                raise AssertionError(
                    f"{flag} {name}{case}: expected {expected_result:#x}, got {observed_result:#x}"
                )


def verify_matches(directory, flag, cases):
    filename = f"generated_{flag[1:]}.dll"
    run(
        ["cl", "/nologo", "/TC", "/std:c11", "/W4", "/WX", flag, "/LD"]
        + [f"{name}.c" for name in FAST_FUNCTIONS]
        + ["/link", f"/out:{filename}"]
        + [f"/export:lifted_{name}" for name in FAST_FUNCTIONS]
        + ["/export:lifted_rip_relative_set_image_base"]
        + ["/export:lifted_rip_relative_negative_set_image_base"]
        + [f"/export:lifted_{name}_set_call_dispatcher" for name in DIRECT_FUNCTIONS]
        + [f"/export:lifted_{name}_set_call_dispatcher" for name in INDIRECT_FUNCTIONS]
        + [f"/export:lifted_{name}_set_image_base" for name in INDIRECT_FUNCTIONS],
        directory,
    )
    with load_library(directory / "native.dll") as native, load_library(directory / filename) as lifted:
        for name in FUNCTIONS:
            expected = get_function(native, name)
            actual = get_function(lifted, f"lifted_{name}")
            if name in {"rip_relative", "rip_relative_negative"}:
                setter = getattr(lifted, f"lifted_{name}_set_image_base")
                setter.argtypes = [ctypes.c_uint64]
                setter(ctypes.c_uint64(native._handle))
            for case in cases:
                expected_result = expected(*case)
                observed_result = actual(*case)
                if observed_result != expected_result:
                    raise AssertionError(
                        f"{flag} {name}{case}: expected {expected_result:#x}, got {observed_result:#x}"
                    )
        verify_memory(native, lifted, flag)
        verify_stack_arguments(native, lifted, flag, cases)
        verify_xmm(native, lifted, flag)
        verify_direct_calls(native, lifted, flag, cases)
        verify_indirect_calls(native, lifted, flag, cases)


def verify_rejections(directory, sizes):
    for name, error in REJECTED.items():
        lift(directory, name, sizes[name], "rejected.c", error=error)
    lift(directory, "mix64", 1, "rejected.c", error="invalid or truncated instruction")
    lift(directory, "missing", 1, "rejected.c", error="export 'missing' was not found")
    with pefile.PE(str(directory / "native.dll")) as image:
        mix_rva = next(
            export.address for export in image.DIRECTORY_ENTRY_EXPORT.symbols
            if export.name == b"mix64"
        )
    lift(directory, "mix_by_rva", sizes["mix64"], "mix_by_rva.c", rva=mix_rva)
    if not (directory / "mix_by_rva.c").is_file():
        raise AssertionError("RVA lifting did not create its output")
    (directory / "bad.dll").write_bytes(b"not a PE file")
    lift(directory, "mix64", 1, "rejected.c", binary="bad.dll", error="invalid PE image")
    if (directory / "rejected.c").exists():
        raise AssertionError("A rejected lift created a C file")
    original = (directory / "mix64.c").read_bytes()
    lift(directory, "mix64", sizes["mix64"], "mix64.c", error="File exists")
    if (directory / "mix64.c").read_bytes() != original:
        raise AssertionError("The original output was overwritten")
    return len(REJECTED) + 5


def main():
    for command in ("ml64", "link", "cl"):
        if not shutil.which(command):
            raise SystemExit(f"{command} is missing. Run from an x64 MSVC developer prompt.")
    with tempfile.TemporaryDirectory(prefix="recomp-test-") as temporary:
        directory = Path(temporary)
        sizes = build_fixture(directory)
        for name in FAST_FUNCTIONS:
            lift(
                directory, name, sizes[name], f"{name}.c",
                stack_arguments=0,
            )
        cases = inputs()
        for flag in ("/Od", "/O2"):
            verify_matches(directory, flag, cases)
        rejections = verify_rejections(directory, sizes)
    arithmetic = len(FUNCTIONS) * len(cases) * 2
    memory = len(MEMORY_FUNCTIONS) * 128 * 2
    stack = len(STACK_FUNCTIONS) * len(cases) * 2
    direct = len(DIRECT_FUNCTIONS) * len(cases) * 2
    xmm = len(XMM_FUNCTIONS) * 128 * 2
    indirect = len(INDIRECT_FUNCTIONS) * len(cases) * 2
    print(f"Passed {arithmetic + memory + stack + direct + xmm + indirect:,} native/C comparisons and {rejections} rejection/RVA checks.")


if __name__ == "__main__":
    main()
