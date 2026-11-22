import ctypes
import struct
import tempfile
from pathlib import Path

import verify


ROOT = Path(__file__).resolve().parents[1]
FUNCTIONS = ("mix64", "direct_call", "indirect_call", "tail_call", "indirect_tail", "register_tail", "prefixed_nop")
CONTEXT_FUNCTIONS = (*FUNCTIONS, "mul_one64", "mul_one32", "rotate_flags", "rotate_flag_preservation", "xchg_andnot", "bit_scans", "push_flags", "sign_extend16", "dynamic_bits", "neg_not", "adc_flags", "double_shifts", "carry_rotates", "rotate_values", "bit_operations", "crc32_values", "jump_rcx", "xmm_roundtrip", "scalar_moves", "narrow_memory", "string_scans", "string_copies", "lock_xadd", "compare_float", "float_startup", "scalar_double_convert", "scalar_int_double", "scalar_double", "vector_general", "vector_float", "vector_andnot", "vector_shuffle", "vector_unpack64", "vector_shuffle_double", "vector_horizontal", "vector_int", "vector_integer", "vector_int_arith", "vector_int_double", "vector_convert", "vector_mixed", "vector_compare", "vector_minmax", "vector_approx", "vector_byteshift", "signed_division", "unsigned_division", "scalar_minmax", "scalar_sqrt", "tls_read", "ret_immediate", "cpu_identification", "trap_instruction")


class Xmm(ctypes.Structure):
    _fields_ = [("lanes", ctypes.c_uint64 * 2)]


GENERAL = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
           "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")


class Cpu(ctypes.Structure):
    _fields_ = (
        [(name, ctypes.c_uint64) for name in GENERAL]
        + [("xmm", Xmm * 16), ("rip", ctypes.c_uint64), ("image_base", ctypes.c_uint64)]
        + [(name, ctypes.c_int) for name in ("cf", "of", "sf", "zf", "pf", "af")]
        + [("tls_base", ctypes.c_uint64)]
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


def verify_string_scans(native, lifted, flag):
    expected = verify.get_function(native, "string_scans")
    actual = getattr(lifted, "lifted_string_scans_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        ((1, 0, 2, 3, 4, 5), 0, 6),
        ((1, 0, 2, 3, 4, 5), 2, 6),
        ((1, 0, 2, 3, 4, 5), 9, 6),
        ((1, 0, 2, 3, 4, 5), 1, 6),
        ((1, 0, 2, 3, 4, 5), 0, 0),
        ((0xFFFF, 0x8000, 0x7FFF, 0x1234, 0, 0), 0x8000, 6),
        ((0xFFFF, 0x8000, 0x7FFF, 0x1234, 0, 0), 0x8001, 6),
    ]
    comparisons = 0
    for values, target, count in cases:
        raw = struct.pack('<6H', *values)
        expected_input = ctypes.create_string_buffer(raw, len(raw))
        actual_input = ctypes.create_string_buffer(raw, len(raw))
        expected_result = expected(ctypes.addressof(expected_input), count, target, 0)
        expected_offset = expected_result - ctypes.addressof(expected_input)
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_input)
        cpu.rdx = count
        cpu.r8 = target
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        actual_offset = cpu.rax - ctypes.addressof(actual_input)
        if actual_offset != expected_offset or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8:
            raise AssertionError(
                f"{flag} string scan {values}/{target:#x}/{count}: expected offset {expected_offset}, got {actual_offset}"
            )
        comparisons += 1
    return comparisons


def verify_string_copies(native, lifted, flag):
    expected = verify.get_function(native, "string_copies")
    actual = getattr(lifted, "lifted_string_copies_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    comparisons = 0
    for count in (0, 1, 2, 3, 7):
        initial = bytes((index * 37 + count * 19) & 0xFF for index in range(160))
        expected_source = ctypes.create_string_buffer(initial, 160)
        actual_source = ctypes.create_string_buffer(initial, 160)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 160, 160)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 160, 160)
        expected_result = expected(
            ctypes.addressof(expected_source), ctypes.addressof(expected_output), count, 0,
        )
        expected_offset = expected_result - ctypes.addressof(expected_output)
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_source)
        cpu.rdx = ctypes.addressof(actual_output)
        cpu.r8 = count
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        actual_offset = cpu.rax - ctypes.addressof(actual_output)
        if (
            actual_offset != expected_offset or expected_output.raw != actual_output.raw
            or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
        ):
            difference = next((index for index, pair in enumerate(zip(expected_output.raw, actual_output.raw)) if pair[0] != pair[1]), None)
            raise AssertionError(
                f"{flag} string copy/fill case {count}: expected offset {expected_offset}, got {actual_offset}; "
                f"RIP={cpu.rip:#x}; RSP={cpu.rsp:#x}; first output difference={difference}; "
                f"{expected_output.raw[:16].hex()} != {actual_output.raw[:16].hex()}"
            )
        comparisons += 1
    return comparisons


def verify_lock_xadd(native, lifted, flag):
    expected = verify.get_function(native, "lock_xadd")
    actual = getattr(lifted, "lifted_lock_xadd_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        (0, 0), (0, 1), (1, 2), (0x7FFFFFFF, 1), (0xFFFFFFFF, 1),
        (0xFFFFFFFE, 2), (0x12345678, 0x9ABCDEF0), (0x80000000, 0x80000000),
    ]
    comparisons = 0
    for initial, source in cases:
        expected_input = ctypes.create_string_buffer(struct.pack('<I', initial), 4)
        actual_input = ctypes.create_string_buffer(struct.pack('<I', initial), 4)
        expected_result = expected(ctypes.addressof(expected_input), source, 0, 0)
        expected_value = struct.unpack('<I', expected_input.raw)[0]
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_input)
        cpu.rdx = source
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        actual_value = struct.unpack('<I', actual_input.raw)[0]
        if (
            cpu.rax != expected_result or actual_value != expected_value
            or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
        ):
            raise AssertionError(
                f"{flag} lock xadd {initial:#x}/{source:#x}: expected {expected_result:#x}/{expected_value:#x}, "
                f"got {cpu.rax:#x}/{actual_value:#x}"
            )
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
        (1.5, 1.0, 0), (2.5, 1.0, 0), (-2.5, 1.0, 0),
    ]
    comparisons = 0
    for value, multiplier, integer in cases:
        raw = bytearray(32)
        struct.pack_into('<d', raw, 0, value)
        struct.pack_into('<f', raw, 16, multiplier)
        struct.pack_into('<i', raw, 24, integer)
        expected_input = ctypes.create_string_buffer(bytes(raw), 32)
        actual_input = ctypes.create_string_buffer(bytes(raw), 32)
        expected_int = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        actual_int = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        expected_float = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        actual_float = ctypes.create_string_buffer(b'\xCC' * 16, 16)
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


def verify_scalar_double_convert(native, lifted, flag):
    expected = verify.get_function(native, "scalar_double_convert")
    actual = getattr(lifted, "lifted_scalar_double_convert_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        (1.5, 2.25, 2.25, 0),
        (2.5, 1.0, 2.0, 1),
        (3.5, 3.0, 2.0, 2),
        (4.5, float('nan'), 1.0, 4),
        (-0.0, -0.0, 0.0, 0),
    ]
    comparisons = 0
    for single, left, right, expected_code in cases:
        raw = struct.pack('<f', single) + b'\0' * 4 + struct.pack('<2d', left, right)
        expected_input = ctypes.create_string_buffer(raw, 24)
        actual_input = ctypes.create_string_buffer(raw, 24)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 8, 8)
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
            cpu.rax != expected_result or cpu.rax != expected_code
            or expected_output.raw != actual_output.raw
            or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
        ):
            raise AssertionError(f"{flag} scalar double conversion failed for {single}/{left}/{right}")
        comparisons += 1
    return comparisons


def verify_scalar_int_double(native, lifted, flag):
    expected = verify.get_function(native, "scalar_int_double")
    actual = getattr(lifted, "lifted_scalar_int_double_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        (2.9, -3.9, 42),
        (-2.9, 3.9, -7),
        (1e10, -1e10, 0),
        (float('nan'), 1.5, 5),
        (1e100, -1e100, 0),
    ]
    comparisons = 0
    for first, second, integer in cases:
        raw = struct.pack('<2d', first, second) + struct.pack('<i', integer) + b'\0' * 4
        expected_input = ctypes.create_string_buffer(raw, 24)
        actual_input = ctypes.create_string_buffer(raw, 24)
        expected_int = ctypes.create_string_buffer(b'\xCC' * 4, 4)
        actual_int = ctypes.create_string_buffer(b'\xCC' * 4, 4)
        expected_double = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        actual_double = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        expected_result = expected(
            ctypes.addressof(expected_input), ctypes.addressof(expected_int), ctypes.addressof(expected_double), 0,
        )
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_input)
        cpu.rdx = ctypes.addressof(actual_int)
        cpu.r8 = ctypes.addressof(actual_double)
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        if (
            cpu.rax != expected_result or expected_int.raw != actual_int.raw
            or expected_double.raw != actual_double.raw or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
        ):
            raise AssertionError(f"{flag} scalar int/double conversion failed for {first}/{second}/{integer}")
        comparisons += 1
    return comparisons


def verify_scalar_double(native, lifted, flag):
    expected = verify.get_function(native, "scalar_double")
    actual = getattr(lifted, "lifted_scalar_double_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        (8.0, 2.0, 2.0, 4.0),
        (-3.0, 1.5, 0.5, -2.0),
        (1e10, 2.0, -5.0, 0.25),
        (-0.0, 1.0, 2.0, -0.0),
    ]
    comparisons = 0
    for a, b, c, d in cases:
        raw = struct.pack('<4d', a, c, b, d)
        expected_input_left = ctypes.create_string_buffer(raw[:16], 16)
        actual_input_left = ctypes.create_string_buffer(raw[:16], 16)
        expected_input_right = ctypes.create_string_buffer(raw[16:], 16)
        actual_input_right = ctypes.create_string_buffer(raw[16:], 16)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        expected_result = expected(
            ctypes.addressof(expected_input_left), ctypes.addressof(expected_input_right), ctypes.addressof(expected_output), 0,
        )
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_input_left)
        cpu.rdx = ctypes.addressof(actual_input_right)
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
            raise AssertionError(f"{flag} scalar double failed for {a}/{b}/{c}/{d}")
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


def verify_vector_andnot(native, lifted, flag):
    expected = verify.get_function(native, "vector_andnot")
    actual = getattr(lifted, "lifted_vector_andnot_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        ((0, 0, 0, 0), (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)),
        ((0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF), (0, 0, 0, 0)),
        ((0xAAAAAAAA, 0x55555555, 0x12345678, 0x80000000), (0x55555555, 0xAAAAAAAA, 0x87654321, 0x7FFFFFFF)),
        ((0x10203040, 0x50607080, 0x90A0B0C0, 0xD0E0F000), (0x13579BDF, 0x2468ACE0, 0xDEADBEEF, 0xCAFEBABE)),
    ]
    comparisons = 0
    for left, right in cases:
        left_raw = struct.pack('<4I', *left)
        right_raw = struct.pack('<4I', *right)
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
            raise AssertionError(f"{flag} vector andnot failed for {left}/{right}")
        comparisons += 1
    return comparisons


def verify_vector_shuffle(native, lifted, flag):
    expected = verify.get_function(native, "vector_shuffle")
    actual = getattr(lifted, "lifted_vector_shuffle_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        ((0, 1, 2, 3), (4, 5, 6, 7)),
        ((0x3F800000, 0x40000000, 0x40400000, 0x40800000), (0x40A00000, 0x40C00000, 0x40E00000, 0x41000000)),
        ((0xFFFFFFFF, 0x80000000, 0x7FFFFFFF, 0x00000001), (0x7FC00000, 0xFF800000, 0x80000001, 0x12345678)),
        ((0x10203040, 0x50607080, 0x90A0B0C0, 0xD0E0F000), (0x13579BDF, 0x2468ACE0, 0xDEADBEEF, 0xCAFEBABE)),
    ]
    comparisons = 0
    for left, right in cases:
        left_raw = struct.pack('<4I', *left)
        right_raw = struct.pack('<4I', *right)
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
            raise AssertionError(
                f"{flag} vector shuffle failed: expected {expected_output.raw.hex()}, got {actual_output.raw.hex()}"
            )
        comparisons += 1
    return comparisons


def verify_vector_unpack64(native, lifted, flag):
    expected = verify.get_function(native, "vector_unpack64")
    actual = getattr(lifted, "lifted_vector_unpack64_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        ((0, 1), (2, 3)),
        ((0x3FF0000000000000, 0x4000000000000000), (0x4008000000000000, 0x4010000000000000)),
        ((0xFFFFFFFFFFFFFFFF, 0x8000000000000000), (0x7FFFFFFFFFFFFFFF, 0x123456789ABCDEF)),
        ((0x1020304050607080, 0x90A0B0C0D0E0F000), (0x13579BDF2468ACE0, 0xDEADBEEFCAFEBABE)),
    ]
    comparisons = 0
    for left, right in cases:
        left_raw = struct.pack('<2Q', *left)
        right_raw = struct.pack('<2Q', *right)
        expected_left = ctypes.create_string_buffer(left_raw, 16)
        actual_left = ctypes.create_string_buffer(left_raw, 16)
        expected_right = ctypes.create_string_buffer(right_raw, 16)
        actual_right = ctypes.create_string_buffer(right_raw, 16)
        expected_output, expected_output_address = aligned_input(b'\xCC' * 128)
        actual_output, actual_output_address = aligned_input(b'\xCC' * 128)
        expected_result = expected(
            ctypes.addressof(expected_left), ctypes.addressof(expected_right), expected_output_address, 0,
        )
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_left)
        cpu.rdx = ctypes.addressof(actual_right)
        cpu.r8 = actual_output_address
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
            raise AssertionError(f"{flag} vector unpack64 failed for {left}/{right}")
        comparisons += 1
    return comparisons


def verify_vector_shuffle_double(native, lifted, flag):
    expected = verify.get_function(native, "vector_shuffle_double")
    actual = getattr(lifted, "lifted_vector_shuffle_double_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        ([1.0, 2.0, 3.0, 4.0], [4.0, 3.0, 2.0, 1.0], [1.0, 2.0], [4.0, 3.0]),
        ([-0.0, 0.0, float('inf'), float('-inf')], [-0.0, -0.0, float('inf'), float('-inf')], [1.0, -1.0], [2.0, -2.0]),
        ([float('nan'), 1.0, float('nan'), 2.0], [float('nan'), float('nan'), 2.0, 2.0], [1.5, -2.5], [0.5, 4.0]),
        ([2.0 ** -140, -(2.0 ** -140), 3.5, -7.25], [2.0 ** -140, 2.0 ** -140, -3.5, 7.25], [2.0 ** -140, -(2.0 ** -140)], [2.0 ** -140, 2.0 ** -140]),
    ]
    comparisons = 0
    for left, right, left_double, right_double in cases:
        left_raw = struct.pack('<4f', *left)
        right_raw = struct.pack('<4f', *right)
        expected_left, expected_left_address = aligned_input(left_raw)
        actual_left, actual_left_address = aligned_input(left_raw)
        expected_right, expected_right_address = aligned_input(right_raw)
        actual_right, actual_right_address = aligned_input(right_raw)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 224, 224)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 224, 224)
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
            difference = next((index for index, pair in enumerate(zip(expected_output.raw, actual_output.raw)) if pair[0] != pair[1]), None)
            raise AssertionError(f"{flag} vector shuffle double failed for {left}/{right} at byte {difference}: {expected_output.raw[difference:difference + 16].hex()} != {actual_output.raw[difference:difference + 16].hex()}")
        comparisons += 1
    return comparisons


def verify_vector_horizontal(native, lifted, flag):
    expected = verify.get_function(native, "vector_horizontal")
    actual = getattr(lifted, "lifted_vector_horizontal_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        ([1.0, 2.0, 3.0, 4.0], [5.0, 6.0, 7.0, 8.0]),
        ([-1.0, 0.5, 10.0, -20.0], [0.25, 2.0, -4.0, 100.0]),
        ([1e10, -1e-10, 0.0, -0.0], [1e-10, -1e10, 2.5, -3.5]),
        ([2.0 ** -140, -(2.0 ** -140), 1.0, -1.0], [2.0 ** -140, 2.0 ** -140, 4.0, 8.0]),
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
            raise AssertionError(
                f"{flag} vector horizontal failed: expected {expected_output.raw.hex()}, got {actual_output.raw.hex()}"
            )
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


def verify_vector_integer(native, lifted, flag):
    expected = verify.get_function(native, "vector_integer")
    actual = getattr(lifted, "lifted_vector_integer_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        ([0, 1, 2, 3], [0, 1, 2, 3]),
        ([0, 1, 2, 3], [3, 2, 1, 0]),
        ([-1, 0, 0x7FFFFFFF, -0x80000000], [-1, 0, 0x7FFFFFFF, -0x80000000]),
        ([0x10203040, 0x50607080, 0x90A0B0C0, 0xD0E0F000], [0x13579BDF, 0x2468ACE0, 0xDEADBEEF, 0xCAFEBABE]),
    ]
    comparisons = 0
    for left, right in cases:
        left_raw = struct.pack('<4I', *(value & 0xFFFFFFFF for value in left))
        right_raw = struct.pack('<4I', *(value & 0xFFFFFFFF for value in right))
        expected_left, expected_left_address = aligned_input(left_raw)
        actual_left, actual_left_address = aligned_input(left_raw)
        expected_right, expected_right_address = aligned_input(right_raw)
        actual_right, actual_right_address = aligned_input(right_raw)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 160, 160)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 160, 160)
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
            raise AssertionError(f"{flag} vector integer failed for {left}/{right}")
        comparisons += 1
    return comparisons


def verify_vector_int_arith(native, lifted, flag):
    expected = verify.get_function(native, "vector_int_arith")
    actual = getattr(lifted, "lifted_vector_int_arith_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        ([0, 1, 2, 3], [0, 1, 2, 3]),
        ([1, 2, 3, 4], [4, 3, 2, 1]),
        ([-1, 0, 0x7FFFFFFF, -0x80000000], [-1, 0, 0x7FFFFFFF, -0x80000000]),
        ([0x10203040, 0x50607080, 0x90A0B0C0, 0xD0E0F000], [0x13579BDF, 0x2468ACE0, 0xDEADBEEF, 0xCAFEBABE]),
    ]
    comparisons = 0
    for left, right in cases:
        left_raw = struct.pack('<4I', *(value & 0xFFFFFFFF for value in left))
        right_raw = struct.pack('<4I', *(value & 0xFFFFFFFF for value in right))
        expected_left, expected_left_address = aligned_input(left_raw)
        actual_left, actual_left_address = aligned_input(left_raw)
        expected_right, expected_right_address = aligned_input(right_raw)
        actual_right, actual_right_address = aligned_input(right_raw)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 224, 224)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 224, 224)
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
            difference = next((index for index, pair in enumerate(zip(expected_output.raw, actual_output.raw)) if pair[0] != pair[1]), None)
            raise AssertionError(f"{flag} vector integer arithmetic failed for {left}/{right} at byte {difference}: {expected_output.raw[difference:difference + 16].hex()} != {actual_output.raw[difference:difference + 16].hex()}")
        comparisons += 1
    return comparisons


def verify_vector_int_double(native, lifted, flag):
    expected = verify.get_function(native, "vector_int_double")
    actual = getattr(lifted, "lifted_vector_int_double_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [[0, 1], [-1, 2], [1000, -2000], [0x7FFFFFFF, -0x80000000]]
    comparisons = 0
    for values in cases:
        raw = struct.pack('<2i', *values)
        expected_input = ctypes.create_string_buffer(raw, 8)
        actual_input = ctypes.create_string_buffer(raw, 8)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 32, 32)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 32, 32)
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
            raise AssertionError(f"{flag} vector int/double conversion failed for {values}")
        comparisons += 1
    return comparisons


def verify_vector_convert(native, lifted, flag):
    expected = verify.get_function(native, "vector_convert")
    actual = getattr(lifted, "lifted_vector_convert_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        ([0.0, -0.0, 2.25, -1.5], [0.0, -0.0]),
        ([1e10, -1e-10, float('inf'), float('-inf')], [1e100, -1e100]),
        ([16777217.0, 0.1, -0.0, 1.0], [0.1, 1e-40]),
        ([2.0 ** -140, 2.0 ** -149, 3.141592653589793, -2.718281828459045], [2.0 ** -140, 2.0 ** -149]),
    ]
    comparisons = 0
    for singles, doubles in cases:
        single_raw = struct.pack('<4f', *singles)
        double_raw = struct.pack('<2d', *doubles)
        expected_singles = ctypes.create_string_buffer(single_raw, 16)
        actual_singles = ctypes.create_string_buffer(single_raw, 16)
        expected_doubles = ctypes.create_string_buffer(double_raw, 16)
        actual_doubles = ctypes.create_string_buffer(double_raw, 16)
        expected_double_output = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        actual_double_output = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        expected_single_output = ctypes.create_string_buffer(b'\xCC' * 32, 32)
        actual_single_output = ctypes.create_string_buffer(b'\xCC' * 32, 32)
        expected_result = expected(
            ctypes.addressof(expected_singles), ctypes.addressof(expected_doubles),
            ctypes.addressof(expected_double_output), ctypes.addressof(expected_single_output),
        )
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_singles)
        cpu.rdx = ctypes.addressof(actual_doubles)
        cpu.r8 = ctypes.addressof(actual_double_output)
        cpu.r9 = ctypes.addressof(actual_single_output)
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        if (
            cpu.rax != expected_result or expected_double_output.raw != actual_double_output.raw
            or expected_single_output.raw != actual_single_output.raw
            or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
        ):
            raise AssertionError(f"{flag} vector conversion failed for {singles}/{doubles}")
        comparisons += 1
    return comparisons


def verify_vector_mixed(native, lifted, flag):
    expected = verify.get_function(native, "vector_mixed")
    actual = getattr(lifted, "lifted_vector_mixed_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        ([1.0, 2.0, 3.0, 4.0], [4.0, 3.0, 2.0, 1.0]),
        ([-1.0, 0.5, 10.0, -20.0], [0.25, 2.0, -4.0, 100.0]),
        ([1e10, -1e-10, 0.0, -0.0], [1e-10, -1e10, 2.5, -3.5]),
        ([float('nan'), 1.0, float('inf'), -0.0], [float('nan'), float('nan'), 2.0, 2.0]),
    ]
    comparisons = 0
    for left, right in cases:
        left_raw = struct.pack('<4f', *left)
        right_raw = struct.pack('<4f', *right)
        expected_left, expected_left_address = aligned_input(left_raw)
        actual_left, actual_left_address = aligned_input(left_raw)
        expected_right, expected_right_address = aligned_input(right_raw)
        actual_right, actual_right_address = aligned_input(right_raw)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 48, 48)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 48, 48)
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
            raise AssertionError(f"{flag} vector mixed operation failed for {left}/{right}")
        comparisons += 1
    return comparisons


def verify_vector_compare(native, lifted, flag):
    expected = verify.get_function(native, "vector_compare")
    actual = getattr(lifted, "lifted_vector_compare_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        ([1.0, 2.0, 3.0, 4.0], [1.0, 2.0, 3.0, 4.0]),
        ([1.0, 2.0, 3.0, 4.0], [4.0, 3.0, 2.0, 1.0]),
        ([-0.0, 0.0, float('inf'), float('-inf')], [-0.0, -0.0, float('inf'), float('-inf')]),
        ([float('nan'), 1.0, float('nan'), 2.0], [float('nan'), float('nan'), 2.0, 2.0]),
    ]
    comparisons = 0
    for left, right in cases:
        left_raw = struct.pack('<4f', *left)
        right_raw = struct.pack('<4f', *right)
        expected_left, expected_left_address = aligned_input(left_raw)
        actual_left, actual_left_address = aligned_input(left_raw)
        expected_right, expected_right_address = aligned_input(right_raw)
        actual_right, actual_right_address = aligned_input(right_raw)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 48, 48)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 48, 48)
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
            raise AssertionError(
                f"{flag} vector comparison failed: expected {expected_output.raw.hex()}/{expected_result:#x}, "
                f"got {actual_output.raw.hex()}/{cpu.rax:#x}"
            )
        comparisons += 1
    return comparisons


def verify_vector_minmax(native, lifted, flag):
    expected = verify.get_function(native, "vector_minmax")
    actual = getattr(lifted, "lifted_vector_minmax_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        ([1.0, 2.0, 3.0, 4.0], [4.0, 3.0, 2.0, 1.0]),
        ([-0.0, 0.0, float('inf'), float('-inf')], [-0.0, -0.0, float('inf'), float('-inf')]),
        ([float('nan'), 1.0, float('nan'), 2.0], [float('nan'), float('nan'), 2.0, 2.0]),
        ([2.0 ** -140, -(2.0 ** -140), 3.5, -7.25], [2.0 ** -140, 2.0 ** -140, -3.5, 7.25]),
    ]
    comparisons = 0
    for left, right in cases:
        left_raw = struct.pack('<4f', *left)
        right_raw = struct.pack('<4f', *right)
        expected_left, expected_left_address = aligned_input(left_raw)
        actual_left, actual_left_address = aligned_input(left_raw)
        expected_right, expected_right_address = aligned_input(right_raw)
        actual_right, actual_right_address = aligned_input(right_raw)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 40, 40)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 40, 40)
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
            raise AssertionError(f"{flag} vector min/max failed for {left}/{right}")
        comparisons += 1
    return comparisons


def verify_vector_approx(native, lifted, flag):
    expected = verify.get_function(native, "vector_approx")
    actual = getattr(lifted, "lifted_vector_approx_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        ([1.0, 4.0, 16.0, 0.25], [1.0, 4.0]),
        ([0.0, float('inf'), -0.0, -1.0], [0.0, float('inf')]),
        ([1e10, 1e-10, 2.25, -2.25], [1e100, 1e-100]),
        ([2.0 ** -140, 2.0 ** -149, 3.5, -7.25], [2.0 ** -140, 2.0 ** -149]),
    ]
    comparisons = 0
    for singles, doubles in cases:
        single_raw = struct.pack('<4f', *singles)
        double_raw = struct.pack('<2d', *doubles)
        expected_singles, expected_singles_address = aligned_input(single_raw)
        actual_singles, actual_singles_address = aligned_input(single_raw)
        expected_doubles, expected_doubles_address = aligned_input(double_raw)
        actual_doubles, actual_doubles_address = aligned_input(double_raw)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 64, 64)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 64, 64)
        expected_result = expected(
            expected_singles_address, expected_doubles_address, ctypes.addressof(expected_output), 0,
        )
        cpu = Cpu()
        cpu.rcx = actual_singles_address
        cpu.rdx = actual_doubles_address
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
            raise AssertionError(f"{flag} vector approximate/sqrt failed for {singles}/{doubles}")
        comparisons += 1
    return comparisons


def verify_vector_byteshift(native, lifted, flag):
    expected = verify.get_function(native, "vector_byteshift")
    actual = getattr(lifted, "lifted_vector_byteshift_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        bytes(range(16)),
        bytes.fromhex('ffeeddccbbaa99887766554433221100'),
        bytes.fromhex('0123456789abcdeffedcba9876543210'),
        bytes.fromhex('80000000000000000000000000000001'),
    ]
    comparisons = 0
    for raw in cases:
        expected_input = ctypes.create_string_buffer(raw, 16)
        actual_input = ctypes.create_string_buffer(raw, 16)
        expected_output = ctypes.create_string_buffer(b'\xCC' * 32, 32)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 32, 32)
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
            raise AssertionError(f"{flag} vector byte shift failed for {raw.hex()}")
        comparisons += 1
    return comparisons


def verify_division(native, lifted, flag):
    comparisons = 0
    configurations = {
        "signed_division": [
            (100, 0, 7), (0xFFFFFFFFFFFFFF9C, 0xFFFFFFFFFFFFFFFF, 7),
            (1000, 0, 0xFFFFFFFFFFFFFFE7), (0xFFFFFFFFFFFFFC18, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFE7),
        ],
        "unsigned_division": [(100, 0, 7), (1000, 0, 25), (0xFFFFFFFFFFFFFFF0, 0, 31)],
    }
    for name, cases in configurations.items():
        expected = verify.get_function(native, name)
        actual = getattr(lifted, f"lifted_{name}_cpu")
        actual.argtypes = [ctypes.POINTER(Cpu)]
        actual.restype = None
        for low, high, divisor in cases:
            expected_remainder = ctypes.c_uint64(0xCCCCCCCCCCCCCCCC)
            actual_remainder = ctypes.c_uint64(0xCCCCCCCCCCCCCCCC)
            expected_result = expected(low, high, divisor, ctypes.addressof(expected_remainder))
            cpu = Cpu()
            cpu.rcx = low
            cpu.rdx = high
            cpu.r8 = divisor
            cpu.r9 = ctypes.addressof(actual_remainder)
            stack = (ctypes.c_uint64 * 1024)()
            entry_rsp = ctypes.addressof(stack) + 4096 + 8
            sentinel = 0xF00DF00D12345678
            cpu.rsp = entry_rsp
            ctypes.c_uint64.from_address(entry_rsp).value = sentinel
            actual(ctypes.byref(cpu))
            if (
                cpu.rax != expected_result or actual_remainder.value != expected_remainder.value
                or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
            ):
                raise AssertionError(f"{flag} {name} division case failed")
            comparisons += 1
    return comparisons


def verify_minmax(native, lifted, flag):
    expected = verify.get_function(native, "scalar_minmax")
    actual = getattr(lifted, "lifted_scalar_minmax_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    pairs = [
        (0x3F800000, 0x40000000), (0x40000000, 0x3F800000), (0x80000000, 0), (0, 0x80000000),
        (0x7FC00000, 0x3F800000), (0x3F800000, 0x7FC00000), (0x7F800000, 0xFF800000),
    ]
    comparisons = 0
    for left, right in pairs:
        raw = left.to_bytes(4, 'little') + right.to_bytes(4, 'little')
        expected_input = ctypes.create_string_buffer(raw, 8)
        actual_input = ctypes.create_string_buffer(raw, 8)
        expected_max = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        actual_max = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        expected_min = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        actual_min = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        expected_result = expected(
            ctypes.addressof(expected_input), ctypes.addressof(expected_max), ctypes.addressof(expected_min), 0,
        )
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_input)
        cpu.rdx = ctypes.addressof(actual_max)
        cpu.r8 = ctypes.addressof(actual_min)
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        if (
            cpu.rax != expected_result or expected_max.raw != actual_max.raw or expected_min.raw != actual_min.raw
            or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
        ):
            raise AssertionError(f"{flag} scalar min/max case failed")
        comparisons += 1
    return comparisons


def verify_scalar_sqrt(native, lifted, flag):
    expected = verify.get_function(native, "scalar_sqrt")
    actual = getattr(lifted, "lifted_scalar_sqrt_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    cases = [
        (0.0, 0.0), (-0.0, -0.0), (1.0, 1.0), (2.25, 2.25),
        (1e10, 1e100), (float('inf'), float('inf')), (-1.0, -1.0),
    ]
    comparisons = 0
    for single, double in cases:
        raw = struct.pack('<f', single) + b'\0' * 4 + struct.pack('<d', double)
        expected_input = ctypes.create_string_buffer(raw, 16)
        actual_input = ctypes.create_string_buffer(raw, 16)
        expected_float = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        actual_float = ctypes.create_string_buffer(b'\xCC' * 16, 16)
        expected_double = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        actual_double = ctypes.create_string_buffer(b'\xCC' * 8, 8)
        expected_result = expected(
            ctypes.addressof(expected_input), ctypes.addressof(expected_float), ctypes.addressof(expected_double), 0,
        )
        cpu = Cpu()
        cpu.rcx = ctypes.addressof(actual_input)
        cpu.rdx = ctypes.addressof(actual_float)
        cpu.r8 = ctypes.addressof(actual_double)
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        if (
            cpu.rax != expected_result or expected_float.raw != actual_float.raw
            or expected_double.raw != actual_double.raw or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8
        ):
            raise AssertionError(f"{flag} scalar sqrt failed for {single}/{double}")
        comparisons += 1
    return comparisons


def verify_tls(native, lifted, flag):
    expected = verify.get_function(native, "tls_read")
    actual = getattr(lifted, "lifted_tls_read_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    current_tls_base = getattr(lifted, "current_tls_base")
    current_tls_base.restype = ctypes.c_uint64
    expected_result = expected(0, 0, 0, 0)
    cpu = Cpu()
    cpu.tls_base = current_tls_base()
    stack = (ctypes.c_uint64 * 1024)()
    entry_rsp = ctypes.addressof(stack) + 4096 + 8
    sentinel = 0xF00DF00D12345678
    cpu.rsp = entry_rsp
    ctypes.c_uint64.from_address(entry_rsp).value = sentinel
    actual(ctypes.byref(cpu))
    if cpu.rax != expected_result or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8:
        raise AssertionError(f"{flag} TLS comparison failed: {expected_result:#x}/{cpu.rax:#x}")
    return 1


def verify_mul_context(native, lifted, flag):
    comparisons = 0
    cases = verify.inputs()
    for name in ("mul_one64", "mul_one32", "rotate_flags", "rotate_flag_preservation", "xchg_andnot", "bit_scans", "push_flags", "sign_extend16", "dynamic_bits", "neg_not", "adc_flags", "double_shifts", "carry_rotates", "rotate_values", "bit_operations", "crc32_values", "jump_rcx"):
        expected = verify.get_function(native, name)
        actual = getattr(lifted, f"lifted_{name}_cpu")
        actual.argtypes = [ctypes.POINTER(Cpu)]
        actual.restype = None
        for case in cases:
            expected_result = expected(*case)
            cpu = Cpu()
            cpu.rcx, cpu.rdx, cpu.r8, cpu.r9 = case
            stack = (ctypes.c_uint64 * 1024)()
            entry_rsp = ctypes.addressof(stack) + 4096 + 8
            sentinel = 0xF00DF00D12345678
            cpu.rsp = entry_rsp
            ctypes.c_uint64.from_address(entry_rsp).value = sentinel
            actual(ctypes.byref(cpu))
            if cpu.rax != expected_result or cpu.rip != sentinel or cpu.rsp != entry_rsp + 8:
                raise AssertionError(
                    f"{flag} {name}{case}: expected RAX {expected_result:#x}, got {cpu.rax:#x}; "
                    f"RIP={cpu.rip:#x}; RSP={cpu.rsp:#x}"
                )
            comparisons += 1
    return comparisons


def verify_ret_immediate(native, lifted, flag):
    expected = verify.get_function(native, "ret_immediate")
    actual = getattr(lifted, "lifted_ret_immediate_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    comparisons = 0
    for case in verify.inputs()[:32]:
        expected_result = expected(*case)
        cpu = Cpu()
        cpu.rcx, cpu.rdx, cpu.r8, cpu.r9 = case
        stack = (ctypes.c_uint64 * 1024)()
        entry_rsp = ctypes.addressof(stack) + 4096 + 8
        sentinel = 0xF00DF00D12345678
        cpu.rsp = entry_rsp
        ctypes.c_uint64.from_address(entry_rsp).value = sentinel
        actual(ctypes.byref(cpu))
        if cpu.rax != expected_result or cpu.rip != sentinel or cpu.rsp != entry_rsp + 16:
            raise AssertionError(
                f"{flag} immediate ret failed: RAX={cpu.rax:#x}/{expected_result:#x}, "
                f"RIP={cpu.rip:#x}, RSP={cpu.rsp:#x}/{entry_rsp + 16:#x}"
            )
        comparisons += 1
    return comparisons


def verify_cpuid(native, lifted, flag):
    expected = verify.get_function(native, "cpu_identification")
    actual = getattr(lifted, "lifted_cpu_identification_cpu")
    actual.argtypes = [ctypes.POINTER(Cpu)]
    actual.restype = None
    comparisons = 0
    for leaf, subleaf in ((0, 0), (1, 0), (7, 0), (0x80000000, 0), (0x80000001, 0), (0x10, 0)):
        expected_output = ctypes.create_string_buffer(b'\xCC' * 24, 24)
        actual_output = ctypes.create_string_buffer(b'\xCC' * 24, 24)
        expected_result = expected(leaf, subleaf, ctypes.addressof(expected_output), 0)
        cpu = Cpu()
        cpu.rcx = leaf
        cpu.rdx = subleaf
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
            raise AssertionError(f"{flag} CPUID leaf {leaf:#x}/{subleaf:#x} failed")
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
            '#include <intrin.h>\n'
            'uint64_t current_tls_base(void) { return __readgsqword(0x30); }\n'
            'void lifted_mix64_cpu(RecompCpu *cpu);\n'
            'void recomp_cpu_dispatch(RecompCpu *cpu, uint64_t target)\n'
            '{\n'
            f'    if (target == UINT64_C(0x{target:x})) {{ lifted_mix64_cpu(cpu); return; }}\n'
            '    cpu->rax = 0;\n'
            '}\n'
            'void recomp_cpu_trap(RecompCpu *cpu, uint64_t address)\n'
            '{\n'
            '    (void)address;\n'
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
                        "/export:current_tls_base",
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
                    comparisons += verify_mul_context(native, lifted, flag)
                    comparisons += verify_xmm_context(native, lifted, flag)
                    comparisons += verify_scalar_context(native, lifted, flag)
                    comparisons += verify_narrow_context(native, lifted, flag)
                    comparisons += verify_string_scans(native, lifted, flag)
                    comparisons += verify_string_copies(native, lifted, flag)
                    comparisons += verify_lock_xadd(native, lifted, flag)
                    comparisons += verify_compare_context(native, lifted, flag)
                    comparisons += verify_float_startup(native, lifted, flag)
                    comparisons += verify_scalar_double_convert(native, lifted, flag)
                    comparisons += verify_scalar_int_double(native, lifted, flag)
                    comparisons += verify_scalar_double(native, lifted, flag)
                    comparisons += verify_vector_general(native, lifted, flag)
                    comparisons += verify_vector_float(native, lifted, flag)
                    comparisons += verify_vector_andnot(native, lifted, flag)
                    comparisons += verify_vector_shuffle(native, lifted, flag)
                    comparisons += verify_vector_unpack64(native, lifted, flag)
                    comparisons += verify_vector_shuffle_double(native, lifted, flag)
                    comparisons += verify_vector_horizontal(native, lifted, flag)
                    comparisons += verify_vector_int(native, lifted, flag)
                    comparisons += verify_vector_integer(native, lifted, flag)
                    comparisons += verify_vector_int_arith(native, lifted, flag)
                    comparisons += verify_vector_int_double(native, lifted, flag)
                    comparisons += verify_vector_convert(native, lifted, flag)
                    comparisons += verify_vector_mixed(native, lifted, flag)
                    comparisons += verify_vector_compare(native, lifted, flag)
                    comparisons += verify_vector_minmax(native, lifted, flag)
                    comparisons += verify_vector_approx(native, lifted, flag)
                    comparisons += verify_vector_byteshift(native, lifted, flag)
                    comparisons += verify_division(native, lifted, flag)
                    comparisons += verify_minmax(native, lifted, flag)
                    comparisons += verify_scalar_sqrt(native, lifted, flag)
                    comparisons += verify_tls(native, lifted, flag)
                    comparisons += verify_ret_immediate(native, lifted, flag)
                    comparisons += verify_cpuid(native, lifted, flag)
        print(f"Passed {comparisons:,} full CPU-context native/C comparisons.")


if __name__ == "__main__":
    main()
