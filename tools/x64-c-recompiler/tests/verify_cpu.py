import ctypes
import struct
import tempfile
from pathlib import Path

import verify


ROOT = Path(__file__).resolve().parents[1]
FUNCTIONS = ("mix64", "direct_call", "indirect_call", "tail_call", "indirect_tail", "register_tail")
CONTEXT_FUNCTIONS = (*FUNCTIONS, "xmm_roundtrip", "scalar_moves", "narrow_memory", "compare_float", "float_startup", "vector_general", "vector_float", "vector_int")


class Xmm(ctypes.Structure):
    _fields_ = [("lanes", ctypes.c_uint64 * 2)]


GENERAL = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
           "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")


class Cpu(ctypes.Structure):
    _fields_ = (
        [(name, ctypes.c_uint64) for name in GENERAL]
        + [("xmm", Xmm * 16), ("rip", ctypes.c_uint64), ("image_base", ctypes.c_uint64)]
        + [(name, ctypes.c_int) for name in ("cf", "of", "sf", "zf", "pf", "af")]
    )


def verify_xmm_context(native, lifted, flag):
    expected = verify.get_function(native, "xmm_roundtrip")
    actual = getattr(lifted, "lifted_xmm_roundtrip_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    comparisons = 0
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
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_input)
        cpu.rdx = ctypes.addressof(actual_output)
        cpu.r8 = ctypes.addressof(actual_zero)
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        if (
            cpu.rax != expected_result or expected_output.raw != actual_output.raw
            or expected_zero.raw != actual_zero.raw or actual_zero.raw != bytes(16)
            or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
        ):
            raise AssertionError(f"{flag} XMM context case {iteration} failed")
        comparisons += 1
    return comparisons


def verify_scalar_context(native, lifted, flag):
    expected = verify.get_function(native, "scalar_moves")
    actual = getattr(lifted, "lifted_scalar_moves_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    comparisons = 0
    for iteration in range(128):
        initial = bytes((iteration * 41 + index * 23) & 0xFF for index in range(24))
        expected_input = ctypes.create_string_buffer(initial, 24)
        actual_input = ctypes.create_string_buffer(initial, 24)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        expected_second = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        actual_second = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        expected_result = expected(
            ctypes.addressof(expected_input), ctypes.addressof(expected_output), ctypes.addressof(expected_second), 0,
        )
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_input)
        cpu.rdx = ctypes.addressof(actual_output)
        cpu.r8 = ctypes.addressof(actual_second)
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        if (
            cpu.rax != expected_result or expected_output.raw != actual_output.raw
            or expected_second.raw != actual_second.raw or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
        ):
            raise AssertionError(f"{flag} scalar context case {iteration} failed")
        comparisons += 1
    return comparisons


def verify_narrow_context(native, lifted, flag):
    expected = verify.get_function(native, "narrow_memory")
    actual = getattr(lifted, "lifted_narrow_memory_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    comparisons = 0
    for iteration in range(128):
        initial = bytes((iteration * 29 + index * 31) & 0xFF for index in range(8))
        expected_input = ctypes.create_string_buffer(initial, 8)
        actual_input = ctypes.create_string_buffer(initial, 8)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        expected_result = expected(ctypes.addressof(expected_input), 0, ctypes.addressof(expected_output), 0)
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_input)
        cpu.r8 = ctypes.addressof(actual_output)
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        if (
            cpu.rax != expected_result or expected_output.raw != actual_output.raw
            or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
        ):
            raise AssertionError(f"{flag} narrow context case {iteration} failed")
        comparisons += 1
    return comparisons


def verify_compare_context(native, lifted, flag):
    expected = verify.get_function(native, "compare_float")
    actual = getattr(lifted, "lifted_compare_float_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    pairs = [
        (0x3F800000, 0x3F800000), (0x3F800000, 0x40000000), (0x40000000, 0x3F800000),
        (0x80000000, 0), (0x7F800000, 0x3F800000), (0xFF800000, 0x3F800000),
        (0x7FC00000, 0x3F800000), (0x3F800000, 0x7FC00000), (0x7FC00000, 0x7FC00000),
    ]
    comparisons = 0
    for left, right in pairs:
        raw = left.to_bytes(4, 'little') + right.to_bytes(4, 'little')
        expected_input = ctypes.create_string_buffer(raw, 8)
        actual_input = ctypes.create_string_buffer(raw, 8)
        expected_result = expected(ctypes.addressof(expected_input), 0, 0, 0)
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_input)
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        if cpu.rax != expected_result or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8:
            raise AssertionError(
                f"{flag} compare {left:#x}/{right:#x}: expected {expected_result:#x}, got {cpu.rax:#x}"
            )
        comparisons += 1
    return comparisons


def verify_float_startup(native, lifted, flag):
    expected = verify.get_function(native, "float_startup")
    actual = getattr(lifted, "lifted_float_startup_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        (1.5, 2.0, 7), (-2.25, 0.5, -3), (10.0, 0.25, 100),
        (0.0, 4.0, 0), (1e20, 2.0, -1), (float('nan'), 1.0, 5),
    ]
    comparisons = 0
    for value, multiplier, integer in cases:
        raw = bytearray(32)
        struct.pack_into('<d', raw, 0, value)
        struct.pack_into('<f', raw, 16, multiplier)
        struct.pack_into('<i', raw, 24, integer)
        expected_input = ctypes.create_string_buffer(bytes(raw), 32)
        actual_input = ctypes.create_string_buffer(bytes(raw), 32)
        expected_int = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        actual_int = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        expected_float = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        actual_float = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        expected_result = expected(
            ctypes.addressof(expected_input), ctypes.addressof(expected_int), ctypes.addressof(expected_float), 0,
        )
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_input)
        cpu.rdx = ctypes.addressof(actual_int)
        cpu.r8 = ctypes.addressof(actual_float)
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        if (
            cpu.rax != expected_result or expected_int.raw != actual_int.raw
            or expected_float.raw != actual_float.raw or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
        ):
            raise AssertionError(f"{flag} float startup case {value}/{multiplier}/{integer} failed")
        comparisons += 1
    return comparisons


def verify_vector_general(native, lifted, flag):
    expected = verify.get_function(native, "vector_general")
    actual = getattr(lifted, "lifted_vector_general_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    comparisons = 0
    for iteration in range(32):
        first = iteration * 0x102030405 + 0x7F
        second = iteration * 0x1020304050607 + 0x12345678
        first &= 0xFFFFFFFFFFFFFFFF
        second &= 0xFFFFFFFFFFFFFFFF
        expected_first = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        actual_first = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        expected_second = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        actual_second = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        expected_result = expected(first, ctypes.addressof(expected_first), second, ctypes.addressof(expected_second))
        cpu = Cpu()
        cpu.rcx = first
        cpu.rdx = ctypes.addressof(actual_first)
        cpu.r8 = second
        cpu.r9 = ctypes.addressof(actual_second)
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        if (
            cpu.rax != expected_result or expected_first.raw != actual_first.raw
            or expected_second.raw != actual_second.raw or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
        ):
            raise AssertionError(f"{flag} vector/general case {iteration} failed")
        comparisons += 1
    return comparisons


def aligned_input(raw):
    storage = ctypes.create_string_buffer(len(raw) + 15)
    address = (ctypes.addressof(storage) + 15) & ~15
    ctypes.memmove(address, raw, len(raw))
    return storage, address


def verify_vector_float(native, lifted, flag):
    expected = verify.get_function(native, "vector_float")
    actual = getattr(lifted, "lifted_vector_float_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        ([1.0, 2.0, 3.0, 4.0], [0.5, -1.0, 2.0, 0.25]),
        ([-2.0, 0.0, 10.0, 100.0], [4.0, 3.0, -5.0, 0.1]),
        ([1e10, -1e-10, 0.25, -0.75], [2.0, 0.5, -8.0, 16.0]),
    ]
    comparisons = 0
    for left, right in cases:
        left_raw = struct.pack('<4f', *left)
        right_raw = struct.pack('<4f', *right)
        expected_left, expected_left_address = aligned_input(left_raw)
        actual_left, actual_left_address = aligned_input(left_raw)
        expected_right, expected_right_address = aligned_input(right_raw)
        actual_right, actual_right_address = aligned_input(right_raw)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        expected_result = expected(
            expected_left_address, expected_right_address, ctypes.addressof(expected_output), 0,
        )
        cpu = Cpu()
        cpu.rcx = actual_left_address
        cpu.rdx = actual_right_address
        cpu.r8 = ctypes.addressof(actual_output)
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        if (
            cpu.rax != expected_result or expected_output.raw != actual_output.raw
            or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
        ):
            raise AssertionError(f"{flag} packed float case failed")
        comparisons += 1
    return comparisons


def verify_vector_int(native, lifted, flag):
    expected = verify.get_function(native, "vector_int")
    actual = getattr(lifted, "lifted_vector_int_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [[0, 1, -1, 2], [1000, -2000, 3000, -4000], [0x7FFFFFFF, -0x80000000, 123456789, -987654321]]
    comparisons = 0
    for values in cases:
        raw = struct.pack('<4i', *values)
        expected_input = ctypes.create_string_buffer(raw, 16)
        actual_input = ctypes.create_string_buffer(raw, 16)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        expected_result = expected(ctypes.addressof(expected_input), ctypes.addressof(expected_output), 0, 0)
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_input)
        cpu.rdx = ctypes.addressof(actual_output)
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        if (
            cpu.rax != expected_result or expected_output.raw != actual_output.raw
            or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
        ):
            raise AssertionError(f"{flag} packed integer conversion case failed")
        comparisons += 1
    return comparisons


def main():
    with tempfile.TemporaryDirectory(prefix="recomp-cpu-test-") as temporary:
        directory = Path(temporary)
        sizes = verify.build_fixture(directory)
        for name in CONTEXT_FUNCTIONS:
            verify.lift(directory, name, sizes[name], f"{name}_cpu.c", cpu_context=True)
        target = verify.EXPORTS["mix64"]
        (directory / "cpu_runtime.c").write_text(
            '#include "recomp_cpu.h"\n'
            'void lifted_mix64_cpu(RecompCpu *cpu);\n'
            'void recomp_cpu_dispatch(RecompCpu *cpu, uint64_t target)\n'
            '{\n'
            f'    if (target == UINT64_C(0x{target:x})) {{ lifted_mix64_cpu(cpu); return; }}\n'
            '    cpu->rax = 0;\n'
            '}\n'
        )
        cases = verify.inputs()
        comparisons = 0
        with verify.load_library(directory / "native.dll") as native:
            for flag in ("/Od", "/O2"):
                filename = f"cpu_{flag[1:]}.dll"
                try:
                    verify.run([
                        "cl", "/nologo", "/TC", "/std:c11", "/W4", "/WX", flag, "/LD",
                        "/I", ROOT / "runtime",
                        *(f"{name}_cpu.c" for name in CONTEXT_FUNCTIONS), "cpu_runtime.c",
                        "/link", f"/out:{filename}",
                        *(f"/export:lifted_{name}_cpu" for name in CONTEXT_FUNCTIONS),
                    ], directory)
                except AssertionError:
                    for name in FUNCTIONS:
                        print(f"--- {name}_cpu.c ---")
                        print((directory / f"{name}_cpu.c").read_text())
                    raise
                with verify.load_library(directory / filename) as lifted:
                    for name in FUNCTIONS:
                        expected = verify.get_function(native, name)
                        actual = getattr(lifted, f"lifted_{name}_cpu")
                        actual.argtypes = [ctypes.POINTER(Cpu)]
                        actual.restype = None
                        for case in cases:
                            expected_result = expected(*case)
                            cpu = Cpu()
                            cpu.rcx, cpu.rdx, cpu.r8, cpu.r9 = case
                            cpu.image_base = native._handle
                            stack = (ctypes.c_uint64 * 1024)()
                            entry_rsp = ctypes.addressof(stack) + 4096 + 8
                            sentinel = 0xF00DF00D12345678
                            cpu.rsp = entry_rsp
                            ctypes.c_uint64.from_address(entry_rsp).value = sentinel
                            actual(ctypes.byref(cpu))
                            if cpu.rax != expected_result or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8:
                                raise AssertionError(
                                    f"{flag} {name}{case}: expected RAX {expected_result:#x}, "
                                    f"got {cpu.rax:#x}; RIP={cpu.rip:#x}; RSP={cpu.rsp:#x}"
                                )
                            comparisons += 1
                    comparisons += verify_xmm_context(native, lifted, flag)
                    comparisons += verify_scalar_context(native, lifted, flag)
                    comparisons += verify_narrow_context(native, lifted, flag)
                    comparisons += verify_compare_context(native, lifted, flag)
                    comparisons += verify_float_startup(native, lifted, flag)
                    comparisons += verify_vector_general(native, lifted, flag)
                    comparisons += verify_vector_float(native, lifted, flag)
                    comparisons += verify_vector_int(native, lifted, flag)
        print(f"Passed {comparisons:,} full CPU-context native/C comparisons.")


if __name__ == "__main__":
    main()
