"""Lift a Win64 integer function from an x86-64 PE image to C11."""

import argparse
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path

import capstone
import pefile
from capstone import x86_const


ARGUMENTS = ("rcx", "rdx", "r8", "r9")
CALLEE_SAVED = ("rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15")
XMM_REGISTERS = tuple(f"xmm{index}" for index in range(16))
CALLEE_SAVED_XMM = tuple(f"xmm{index}" for index in range(6, 16))
REGISTER_ALIASES = {
    "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx",
    "ah": "rax", "bh": "rbx", "ch": "rcx", "dh": "rdx",
    "sil": "rsi", "dil": "rdi", "bpl": "rbp", "spl": "rsp",
    "r8b": "r8", "r9b": "r9", "r10b": "r10", "r11b": "r11",
    "r12b": "r12", "r13b": "r13", "r14b": "r14", "r15b": "r15",
    "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
    "si": "rsi", "di": "rdi", "bp": "rbp", "sp": "rsp",
    "r8w": "r8", "r9w": "r9", "r10w": "r10", "r11w": "r11",
    "r12w": "r12", "r13w": "r13", "r14w": "r14", "r15w": "r15",
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
    "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
    "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15",
}
REGISTERS = frozenset(("rax", *ARGUMENTS, *CALLEE_SAVED, "rsp", "r10", "r11", *XMM_REGISTERS))
ARITHMETIC = {
    "add": "+", "adc": "+", "sub": "-", "sbb": "-", "cmp": "-", "and": "&", "test": "&", "or": "|", "xor": "^",
}
COMPARISONS = {"cmp", "test"}
SHIFTS = {"shl", "sal", "shr", "sar", "rol", "ror"}
DOUBLE_SHIFTS = {"shld", "shrd"}
CARRY_ROTATES = {"rcl", "rcr"}
FLOAT_SCALAR = {"addss", "subss", "mulss", "divss"}
FLOAT_DOUBLE_SCALAR = {"addsd", "subsd", "mulsd", "divsd"}
FLOAT_MINMAX = {"maxss", "minss"}
FLOAT_PACKED_MINMAX = {"minps", "maxps"}
FLOAT_DOUBLE_MINMAX = {"minsd", "maxsd"}
FLOAT_SQRT = {"sqrtss", "sqrtsd"}
FLOAT_APPROX_VECTOR = {"rsqrtps", "rcpps"}
FLOAT_APPROX_SCALAR = {"rsqrtss", "rcpss"}
FLOAT_SQRT_VECTOR = {"sqrtps", "sqrtpd"}
FLOAT_VECTOR = {"addps", "subps", "mulps", "divps"}
FLOAT_PACKED_CONVERSIONS = {"cvtdq2ps"}
FLOAT_PACKED_FLOAT_CONVERSIONS = {"cvtps2pd", "cvtpd2ps", "cvttpd2dq"}
FLOAT_PACKED_INT_CONVERSIONS = {"cvtps2dq", "cvttps2dq"}
FLOAT_PACKED_INT_DOUBLE = {"cvtdq2pd", "pmovsxdq"}
FLOAT_INT_DOUBLE = {"cvtsi2sd", "cvttsd2si"}
VECTOR_SHUFFLES = {"shufps", "pshufd", "shufpd", "movhlps", "movlhps", "unpcklps", "unpckhps", "unpcklpd", "unpckhpd", "punpcklqdq", "punpckldq", "punpcklwd"}
VECTOR_HORIZONTAL = {"haddps", "hsubps"}
VECTOR_ADDSUB = {"addsubps"}
VECTOR_COMPARE = {"cmpeqps", "cmpltps", "cmpleps", "cmpneqps"}
VECTOR_DOUBLE_COMPARE = {"cmpeqpd", "cmpltpd", "cmplepd", "cmpneqpd", "cmpnltpd"}
SCALAR_COMPARE = {"cmpless", "cmpltss", "cmpleqss"}
VECTOR_DOUBLE_HORIZONTAL = {"haddpd", "hsubpd"}
VECTOR_INT_COMPARE = {"pcmpeqd", "pcmpgtd"}
VECTOR_INT_ARITHMETIC = {"paddd", "psubd", "paddq", "psubq", "psadbw", "pmulld", "paddw"}
VECTOR_INT_SHIFTS = {"psrld", "pslld", "psrlq", "psllq", "psrad"}
FLOAT_DOUBLE_VECTOR = {"addpd", "subpd", "mulpd", "divpd"}
VECTOR_BYTE_SHIFTS = {"psrldq", "pslldq"}
BIT_SCANS = {"bsr", "bsf"}
STRING_OPERATIONS = {
    "rep movsb": 8, "rep movsw": 16, "rep movsd": 32, "rep movsq": 64,
    "rep stosb": 8, "rep stosw": 16, "rep stosd": 32, "rep stosq": 64,
}
FLOAT_CONVERSIONS = {"cvtsd2ss", "cvtss2sd", "cvttss2si", "cvtss2si", "cvtsi2ss"}
FLOAT_COMPARE_DOUBLE = {"comisd", "ucomisd"}
CONDITIONAL_JUMPS = {
    "je": "zf", "jz": "zf", "jne": "!zf", "jnz": "!zf",
    "ja": "!cf && !zf", "jae": "!cf", "jb": "cf", "jbe": "cf || zf",
    "jg": "!zf && sf == of", "jge": "sf == of", "jl": "sf != of", "jle": "zf || sf != of",
    "jo": "of", "jno": "!of", "js": "sf", "jns": "!sf", "jp": "pf", "jnp": "!pf", "jrcxz": "rcx == 0",
}
CONDITIONAL_MOVES = {
    "cmove": "zf", "cmovz": "zf", "cmovne": "!zf", "cmovnz": "!zf",
    "cmova": "!cf && !zf", "cmovae": "!cf", "cmovb": "cf", "cmovbe": "cf || zf",
    "cmovg": "!zf && sf == of", "cmovge": "sf == of",
    "cmovl": "sf != of", "cmovle": "zf || sf != of",
    "cmovo": "of", "cmovno": "!of", "cmovs": "sf", "cmovns": "!sf", "cmovp": "pf", "cmovnp": "!pf",
}
SET_CONDITIONS = {
    "sete": "zf", "setz": "zf", "setne": "!zf", "setnz": "!zf",
    "seta": "!cf && !zf", "setae": "!cf", "setb": "cf", "setbe": "cf || zf",
    "setg": "!zf && sf == of", "setge": "sf == of", "setl": "sf != of", "setle": "zf || sf != of",
    "seto": "of", "setno": "!of", "sets": "sf", "setns": "!sf", "setp": "pf", "setnp": "!pf",
}
CONDITIONS = {**CONDITIONAL_JUMPS, **CONDITIONAL_MOVES, **SET_CONDITIONS}
MAX_CODE_SIZE = 1048576


class LiftError(Exception):
    """An input whose execution the lifter cannot reproduce."""


@dataclass(frozen=True)
class Operand:
    register: str | None
    value: int | None = None
    memory: bool = False
    base: str | None = None
    index: str | None = None
    scale: int = 1
    displacement: int = 0
    image_rva: int | None = None
    segment: str | None = None
    high_byte: bool = False

    @property
    def address_registers(self):
        return frozenset(register for register in (self.base, self.index) if register is not None)

    def address_c(self):
        if self.image_rva is not None:
            return f"(uint64_t)(image_base + UINT64_C(0x{self.image_rva:x}))"
        terms = []
        if self.base is not None:
            terms.append(self.base)
        if self.index is not None:
            terms.append(self.index if self.scale == 1 else f"{self.index} * {self.scale}")
        expression = " + ".join(terms) or "0"
        if self.segment == "gs":
            expression = f"tls_base + ({expression})"
        if self.displacement > 0:
            expression += f" + UINT64_C(0x{self.displacement:x})"
        elif self.displacement < 0:
            expression += f" - UINT64_C(0x{-self.displacement:x})"
        return f"(uint64_t)({expression})"

    def as_c(self, width):
        if self.register is not None:
            if width == 128:
                return self.register
            if self.high_byte:
                return f"(uint8_t)({self.register} >> 8)"
            return f"(uint{width}_t){self.register}"
        if self.memory:
            return f"read{width}({self.address_c()})"
        return f"UINT{width}_C(0x{self.value % (1 << width):x})"

    def write_c(self, value, width):
        if self.register is not None:
            if width == 128:
                return f"{self.register} = {value};"
            if self.high_byte:
                return f"{self.register} = ({self.register} & ~UINT64_C(0xff00)) | ((uint8_t)({value}) << 8);"
            if width == 8:
                return f"{self.register} = ({self.register} & ~UINT64_C(0xff)) | (uint8_t)({value});"
            if width == 16:
                return f"{self.register} = ({self.register} & ~UINT64_C(0xffff)) | (uint16_t)({value});"
            return f"{self.register} = (uint{width}_t)({value});"
        if self.memory:
            if width == 128:
                return f"write128({self.address_c()}, {value});"
            return f"write{width}({self.address_c()}, (uint{width}_t)({value}));"
        raise LiftError("an immediate operand is not writable")


@dataclass(frozen=True)
class Instruction:
    address: int
    length: int
    mnemonic: str
    successors: tuple[int, ...]
    reads: frozenset[str]
    writes: frozenset[str]
    width: int = 0
    operands: tuple[Operand, ...] = ()
    source_width: int = 0

    @property
    def zeroing_xor(self):
        return self.mnemonic == "xor" and self.operands[0] == self.operands[1]


def read_range(path, start, size):
    with pefile.PE(str(path), fast_load=True) as image:
        if image.FILE_HEADER.Machine != 0x8664 or image.OPTIONAL_HEADER.Magic != 0x20B:
            raise LiftError("expected an x86-64 PE32+ image")
        section = image.get_section_by_rva(start)
        if section is None or not section.Characteristics & 0x20000000:
            raise LiftError("the selected code must be in an executable section")
        offset = start - section.VirtualAddress
        section_size = min(section.SizeOfRawData, section.Misc_VirtualSize or section.SizeOfRawData)
        if offset < 0 or offset + size > section_size:
            raise LiftError("selected code range extends beyond file-backed executable bytes")
        image.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]])
        absolute = pefile.RELOCATION_TYPE["IMAGE_REL_BASED_ABSOLUTE"]
        for block in getattr(image, "DIRECTORY_ENTRY_BASERELOC", ()):
            for relocation in block.entries:
                if relocation.type != absolute and start <= relocation.rva < start + size:
                    raise LiftError(f"RVA 0x{relocation.rva:x}: base relocation in the selected code range")
        code = section.get_data(start, size)
        if len(code) != size:
            raise LiftError("selected code range is truncated in the file")
        return start, code


def read_export(path, name, size):
    with pefile.PE(str(path), fast_load=True) as image:
        if image.FILE_HEADER.Machine != 0x8664 or image.OPTIONAL_HEADER.Magic != 0x20B:
            raise LiftError("expected an x86-64 PE32+ image")
        image.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        exports = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
        symbols = exports.symbols if exports else ()
        encoded_name = name.encode("ascii")
        symbol = next((entry for entry in symbols if entry.name == encoded_name), None)
        if symbol is None:
            raise LiftError(f"export {name!r} was not found")
        if symbol.forwarder is not None:
            raise LiftError(f"export {name!r} is a forwarder")
        start = symbol.address
    return read_range(path, start, size)


def canonical_register(decoded, register):
    if not register:
        return None
    name = decoded.reg_name(register)
    return REGISTER_ALIASES.get(name, name)


def read_operand(decoded, operand, width):
    if operand.type == x86_const.X86_OP_IMM:
        return Operand(None, operand.imm)
    if operand.type == x86_const.X86_OP_REG and operand.size * 8 == width:
        name = decoded.reg_name(operand.reg)
        canonical = canonical_register(decoded, operand.reg)
        if canonical in REGISTERS:
            return Operand(canonical, high_byte=name in {"ah", "bh", "ch", "dh"})
    if operand.type == x86_const.X86_OP_MEM and (operand.size * 8 == width or decoded.mnemonic in {"comisd", "ucomisd", "pmovsxdq", "cvtps2pd"} and width == 64 and operand.size == 16):
        memory = operand.mem
        segment = decoded.reg_name(memory.segment) if memory.segment else None
        if segment not in (None, "gs", "ds"):
            raise LiftError(f"RVA 0x{decoded.address:x}: {segment or 'unknown'} segment overrides are unsupported")
        base = canonical_register(decoded, memory.base)
        index = canonical_register(decoded, memory.index)
        if base == "rip":
            if index is not None:
                raise LiftError(f"RVA 0x{decoded.address:x}: unsupported RIP-relative index")
            return Operand(
                None, memory=True, image_rva=decoded.address + decoded.size + memory.disp,
                scale=memory.scale,
            )
        if base == "eip":
            raise LiftError(f"RVA 0x{decoded.address:x}: EIP-relative operands are unsupported")
        if base is not None and base not in REGISTERS or index is not None and index not in REGISTERS:
            raise LiftError(f"RVA 0x{decoded.address:x}: unsupported address register")
        return Operand(
            None, memory=True, base=base, index=index,
            scale=memory.scale, displacement=memory.disp, segment=segment,
        )
    raise LiftError(f"RVA 0x{decoded.address:x}: unsupported operand in {decoded.mnemonic} {decoded.op_str}")


def operand_reads(operand):
    reads = set(operand.address_registers)
    if operand.register is not None:
        reads.add(operand.register)
    return reads


def read_xmm_operand(decoded, operand, width):
    if operand.type == x86_const.X86_OP_REG:
        name = decoded.reg_name(operand.reg)
        if name in XMM_REGISTERS:
            return Operand(name)
    return read_operand(decoded, operand, width)


def lower(decoded, allow_tail_calls=False):
    address = decoded.address
    length = decoded.size
    following = address + length
    mnemonic = "mov" if decoded.mnemonic == "movabs" else decoded.mnemonic
    operands = decoded.operands
    empty = frozenset()
    if mnemonic in {"nop", "cld"}:
        return Instruction(address, length, mnemonic, (following,), empty, empty)
    if any(prefix not in (0, 0x65, 0x66) and not (mnemonic == "push" and prefix == 0x64) and not (mnemonic == "cmp" and prefix == 0x3e) and not (mnemonic in CONDITIONAL_JUMPS and prefix == 0x2e) and not (mnemonic == "lea" and operands[0].size == 4 and prefix == 0x67) and not ((mnemonic in STRING_OPERATIONS or mnemonic == "pause") and prefix == 0xf3) and not (mnemonic == "repne scasw" and prefix == 0xf2) and not (mnemonic in {"lock xadd", "lock inc", "lock dec", "lock add", "lock and", "lock or", "lock cmpxchg"} and prefix == 0xf0) for prefix in decoded.prefix):
        raise LiftError(f"RVA 0x{address:x}: unsupported instruction prefix")
    if mnemonic in {"lock inc", "lock dec", "lock add", "lock and", "lock or"}:
        mnemonic = mnemonic[5:]
    if allow_tail_calls and mnemonic == "int3" and not operands:
        return Instruction(address, length, "trap", (), empty, empty)
    if mnemonic == "repne scasw":
        return Instruction(
            address, length, mnemonic, (following,),
            frozenset({"rax", "rcx", "rdi"}), frozenset({"rax", "rcx", "rdi", "flags"}), 16,
        )
    if mnemonic in STRING_OPERATIONS:
        reads = {"rcx", "rdi"}
        writes = {"rcx", "rdi"}
        if mnemonic.startswith("rep movs"):
            reads.add("rsi")
            writes.add("rsi")
        else:
            reads.add("rax")
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset(writes), STRING_OPERATIONS[mnemonic],
        )
    if mnemonic == "lock cmpxchg" and len(operands) == 2 and operands[0].size in (1, 2, 4, 8):
        width = operands[0].size * 8
        left, right = (read_operand(decoded, operand, width) for operand in operands)
        if left.value is not None or right.value is not None:
            raise LiftError(f"RVA 0x{address:x}: lock cmpxchg requires writable operands")
        reads = {"rax", *operand_reads(left), *operand_reads(right), *left.address_registers, *right.address_registers}
        writes = {"rax", "flags"}
        if left.register is not None:
            writes.add(left.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads), frozenset(writes), width, (left, right),
        )
    if mnemonic == "lock xadd" and len(operands) == 2 and operands[0].size in (1, 2, 4, 8):
        width = operands[0].size * 8
        left, right = (read_operand(decoded, operand, width) for operand in operands)
        if left.value is not None or right.value is not None:
            raise LiftError(f"RVA 0x{address:x}: lock xadd requires writable operands")
        reads = set(left.address_registers) | set(right.address_registers)
        reads.update(operand_reads(left))
        reads.update(operand_reads(right))
        writes = {"flags"}
        if left.register is not None:
            writes.add(left.register)
        if right.register is not None:
            writes.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads), frozenset(writes), width, (left, right),
        )
    if mnemonic in {"stmxcsr", "ldmxcsr"} and len(operands) == 1 and operands[0].type == x86_const.X86_OP_MEM:
        operand = read_operand(decoded, operands[0], 32)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(operand.address_registers), empty, 32, (operand,),
        )
    if mnemonic in {"prefetcht0", "prefetchnta", "prefetch"} and len(operands) == 1:
        operand = read_operand(decoded, operands[0], operands[0].size * 8)
        return Instruction(address, length, mnemonic, (following,), frozenset(operand.address_registers), empty)
    if mnemonic == "pause" and not operands:
        return Instruction(address, length, mnemonic, (following,), empty, empty)
    if mnemonic == "wait" and not operands:
        return Instruction(address, length, mnemonic, (following,), empty, empty)
    if allow_tail_calls and mnemonic in {"int", "cli", "hlt"}:
        return Instruction(address, length, "trap", (), empty, empty)
    if mnemonic == "bswap" and len(operands) == 1 and operands[0].size in (4, 8):
        width = operands[0].size * 8
        operand = read_operand(decoded, operands[0], width)
        if operand.register is None:
            raise LiftError(f"RVA 0x{address:x}: bswap requires a register destination")
        return Instruction(
            address, length, mnemonic, (following,), frozenset({operand.register}),
            frozenset({operand.register}), width, (operand,),
        )
    if mnemonic == "popcnt" and len(operands) == 2 and operands[0].size in (2, 4, 8) and operands[0].size == operands[1].size:
        width = operands[0].size * 8
        left = read_operand(decoded, operands[0], width)
        right = read_operand(decoded, operands[1], width)
        if left.register is None:
            raise LiftError(f"RVA 0x{address:x}: popcnt requires a register destination")
        return Instruction(
            address, length, mnemonic, (following,), frozenset(operand_reads(right)),
            frozenset({left.register, "flags"}), width, (left, right),
        )
    if mnemonic in BIT_SCANS and len(operands) == 2 and operands[0].size in (2, 4, 8):
        width = operands[0].size * 8
        left = read_operand(decoded, operands[0], width)
        right = read_operand(decoded, operands[1], width)
        if left.register is None:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires a register destination")
        return Instruction(
            address, length, mnemonic, (following,), frozenset(operand_reads(right)),
            frozenset({left.register, "flags"}), width, (left, right),
        )
    if mnemonic == "xchg" and len(operands) == 2 and operands[0].size in (1, 2, 4, 8):
        width = operands[0].size * 8
        left, right = (read_operand(decoded, operand, width) for operand in operands)
        if left.value is not None or right.value is not None:
            raise LiftError(f"RVA 0x{address:x}: xchg requires writable operands")
        reads = set(left.address_registers) | set(right.address_registers)
        reads.update(operand_reads(left))
        reads.update(operand_reads(right))
        writes = set()
        if left.register is not None:
            writes.add(left.register)
        if right.register is not None:
            writes.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads), frozenset(writes), width, (left, right),
        )
    if mnemonic == "crc32" and len(operands) == 2 and operands[0].type == x86_const.X86_OP_REG and operands[0].size in (4, 8) and operands[1].size in (1, 2, 4, 8):
        destination_width = operands[0].size * 8
        source_width = operands[1].size * 8
        left = read_operand(decoded, operands[0], destination_width)
        right = read_operand(decoded, operands[1], source_width)
        reads = {left.register, *operand_reads(right)}
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads), frozenset({left.register}),
            source_width, (left, right), destination_width,
        )
    if mnemonic == "xgetbv" and not operands:
        return Instruction(address, length, mnemonic, (following,), frozenset({"rcx"}), frozenset({"rax", "rdx"}))
    if mnemonic == "cpuid" and not operands:
        return Instruction(
            address, length, mnemonic, (following,), frozenset({"rax", "rcx"}),
            frozenset({"rax", "rbx", "rcx", "rdx"}),
        )
    if mnemonic == "popfq" and not operands:
        return Instruction(address, length, mnemonic, (following,), frozenset({"rsp"}), frozenset({"rsp", "flags"}), 64)
    if mnemonic == "sahf" and not operands:
        return Instruction(address, length, mnemonic, (following,), frozenset({"rax", "flags"}), frozenset({"flags"}))
    if mnemonic in {"stc", "cmc"} and not operands:
        reads = {"flags"} if mnemonic == "cmc" else set()
        return Instruction(address, length, mnemonic, (following,), frozenset(reads), frozenset({"flags"}))
    if mnemonic == "pushfq" and not operands:
        return Instruction(address, length, mnemonic, (following,), frozenset({"rsp", "flags"}), frozenset({"rsp"}), 64)
    if allow_tail_calls and mnemonic == "ret" and len(operands) == 1 and operands[0].type == x86_const.X86_OP_IMM:
        return Instruction(
            address, length, mnemonic, (), frozenset({"rax"}), empty,
            0, (), max(0, operands[0].imm),
        )
    if mnemonic == "ret" and not operands:
        return Instruction(address, length, mnemonic, (), frozenset({"rax"}), empty)
    if mnemonic == "call" and len(operands) == 1 and operands[0].type == x86_const.X86_OP_IMM:
        target = operands[0].imm
        return Instruction(
            address, length, mnemonic, (following,),
            frozenset({"rsp", *ARGUMENTS}),
            frozenset({"rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "flags"}),
            0, (Operand(None, target),),
        )
    if mnemonic == "call" and len(operands) == 1 and operands[0].type in {x86_const.X86_OP_REG, x86_const.X86_OP_MEM}:
        target = read_operand(decoded, operands[0], 64)
        return Instruction(
            address, length, mnemonic, (following,),
            frozenset({"rsp", *ARGUMENTS, *operand_reads(target)}),
            frozenset({"rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "flags"}),
            0, (target,), 1,
        )
    if allow_tail_calls and mnemonic == "jmp" and len(operands) == 1 and operands[0].type in {x86_const.X86_OP_REG, x86_const.X86_OP_MEM}:
        target = read_operand(decoded, operands[0], 64)
        return Instruction(
            address, length, "tail", (), frozenset(operand_reads(target)), empty,
            0, (target,), 1,
        )
    if mnemonic == "jrcxz" and len(operands) == 1 and operands[0].type == x86_const.X86_OP_IMM:
        return Instruction(address, length, mnemonic, (operands[0].imm, following), frozenset({"rcx"}), empty)
    if (mnemonic == "jmp" or mnemonic in CONDITIONAL_JUMPS) and len(operands) == 1:
        if operands[0].type == x86_const.X86_OP_IMM:
            target = operands[0].imm
            if mnemonic == "jmp":
                return Instruction(address, length, mnemonic, (target,), empty, empty)
            return Instruction(address, length, mnemonic, (target, following), frozenset({"flags"}), empty)
    if mnemonic in {"push", "pop"} and len(operands) == 1:
        operand = read_operand(decoded, operands[0], 64)
        if mnemonic == "push":
            return Instruction(
                address, length, mnemonic, (following,),
                frozenset({"rsp", *operand_reads(operand)}), frozenset({"rsp"}), 64, (operand,),
            )
        if operand.value is not None:
            raise LiftError(f"RVA 0x{address:x}: pop requires a writable operand")
        writes = {"rsp"}
        if operand.register is not None:
            writes.add(operand.register)
        return Instruction(
            address, length, mnemonic, (following,),
            frozenset({"rsp", *operand.address_registers}), frozenset(writes), 64, (operand,),
        )
    if mnemonic == "lea" and len(operands) == 2 and operands[0].size in (4, 8):
        width = operands[0].size * 8
        left = read_operand(decoded, operands[0], width)
        right = read_operand(decoded, operands[1], width)
        if left.register is None or not right.memory:
            raise LiftError(f"RVA 0x{address:x}: invalid lea operands")
        return Instruction(
            address, length, mnemonic, (following,), right.address_registers,
            frozenset({left.register}), width, (left, right),
        )
    if mnemonic in SET_CONDITIONS and len(operands) == 1 and operands[0].size == 1:
        operand = read_operand(decoded, operands[0], 8)
        if operand.value is not None:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires a writable operand")
        writes = {operand.register} if operand.register is not None else set()
        return Instruction(
            address, length, mnemonic, (following,),
            frozenset({"flags", *operand.address_registers}), frozenset(writes), 8, (operand,),
        )
    if mnemonic in {"movzx", "movsx"} and len(operands) == 2:
        destination_width = operands[0].size * 8
        source_width = operands[1].size * 8
        if destination_width not in (16, 32, 64) or source_width not in (8, 16):
            raise LiftError(f"RVA 0x{address:x}: unsupported {mnemonic} widths")
        left = read_operand(decoded, operands[0], destination_width)
        right = read_operand(decoded, operands[1], source_width)
        if left.register is None:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires a register destination")
        return Instruction(
            address, length, mnemonic, (following,), frozenset(operand_reads(right)),
            frozenset({left.register}), destination_width, (left, right), source_width,
        )
    if mnemonic == "cwde" and not operands:
        return Instruction(address, length, mnemonic, (following,), frozenset({"rax"}), frozenset({"rax"}), 32)
    if mnemonic in {"cdq", "cqo", "cdqe"} and not operands:
        if mnemonic == "cdq":
            return Instruction(address, length, mnemonic, (following,), frozenset({"rax"}), frozenset({"rdx"}), 32)
        return Instruction(address, length, mnemonic, (following,), frozenset({"rax"}), frozenset({"rax" if mnemonic == "cdqe" else "rdx"}), 64)
    if mnemonic in {"bt", "btr", "bts", "btc"} and len(operands) == 2 and operands[0].type == x86_const.X86_OP_REG and operands[1].type in {x86_const.X86_OP_IMM, x86_const.X86_OP_REG}:
        width = operands[0].size * 8
        left = read_operand(decoded, operands[0], width)
        index = Operand(None, operands[1].imm) if operands[1].type == x86_const.X86_OP_IMM else read_operand(decoded, operands[1], operands[1].size * 8)
        reads = {left.register}
        if index.register is not None:
            reads.add(index.register)
        writes = {"flags"}
        if mnemonic != "bt":
            writes.add(left.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset({left.register}),
            frozenset(writes), width, (left, index),
        )
    if mnemonic in CARRY_ROTATES and len(operands) == 2 and operands[0].size in (2, 4, 8) and operands[1].type == x86_const.X86_OP_IMM:
        width = operands[0].size * 8
        left = read_operand(decoded, operands[0], width)
        count = read_operand(decoded, operands[1], 64).value
        if left.value is not None:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires a writable destination")
        writes = {"flags"}
        if left.register is not None:
            writes.add(left.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset({"flags", *operand_reads(left), *left.address_registers}),
            frozenset(writes), width, (left,), count & 31,
        )
    if mnemonic in DOUBLE_SHIFTS and len(operands) == 3 and operands[0].size in (2, 4, 8) and operands[0].size == operands[1].size:
        width = operands[0].size * 8
        left = read_operand(decoded, operands[0], width)
        right = read_operand(decoded, operands[1], width)
        count = read_operand(decoded, operands[2], 64).value
        if left.value is not None or count is None:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires a writable destination and immediate count")
        reads = set(left.address_registers) | set(right.address_registers)
        reads.update(operand_reads(left))
        reads.update(operand_reads(right))
        writes = {"flags"}
        if left.register is not None:
            writes.add(left.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads), frozenset(writes),
            width, (left, right), count & (width - 1),
        )
    if mnemonic in SHIFTS and len(operands) == 2 and operands[0].size in (1, 2, 4, 8):
        width = operands[0].size * 8
        if width in (8, 16) and operands[1].type == x86_const.X86_OP_IMM and not 1 <= operands[1].imm < width:
            raise LiftError(f"RVA 0x{address:x}: shift count exceeds the supported narrow range")
        left = read_operand(decoded, operands[0], width)
        if left.value is not None:
            raise LiftError(f"RVA 0x{address:x}: shift destination is not writable")
        count_operand = operands[1]
        if count_operand.type == x86_const.X86_OP_IMM:
            count = Operand(None, count_operand.imm)
            count_reads = set()
        elif count_operand.type == x86_const.X86_OP_REG and decoded.reg_name(count_operand.reg) == "cl":
            count = Operand("rcx")
            count_reads = {"rcx"}
        else:
            raise LiftError(f"RVA 0x{address:x}: unsupported shift count")
        reads = {*operand_reads(left), *left.address_registers, *count_reads}
        writes = {"flags"}
        if left.register is not None:
            writes.add(left.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset(writes), width, (left, count),
        )
    if mnemonic in {"neg", "not"} and len(operands) == 1 and operands[0].size in (1, 2, 4, 8):
        width = operands[0].size * 8
        operand = read_operand(decoded, operands[0], width)
        if operand.value is not None:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires a writable operand")
        writes = {"flags"} if mnemonic == "neg" else set()
        if operand.register is not None:
            writes.add(operand.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(operand_reads(operand)),
            frozenset(writes), width, (operand,),
        )
    if mnemonic == "movsxd" and len(operands) == 2:
        left = read_operand(decoded, operands[0], 64)
        right = read_operand(decoded, operands[1], 32)
        if left.register is None:
            raise LiftError(f"RVA 0x{address:x}: movsxd requires a register destination")
        return Instruction(
            address, length, mnemonic, (following,), frozenset(operand_reads(right)),
            frozenset({left.register}), 64, (left, right),
        )
    if mnemonic in CONDITIONAL_MOVES and len(operands) == 2:
        width = operands[0].size * 8
        if width not in (16, 32, 64):
            raise LiftError(f"RVA 0x{address:x}: unsupported conditional-move width")
        left, right = (read_operand(decoded, operand, width) for operand in operands)
        if left.register is None:
            raise LiftError(f"RVA 0x{address:x}: conditional move requires a register destination")
        reads = {"flags", left.register, *operand_reads(right), *right.address_registers}
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), width, (left, right),
        )
    if mnemonic in {"inc", "dec"} and len(operands) == 1 and operands[0].size in (1, 2, 4, 8):
        width = operands[0].size * 8
        operand = read_operand(decoded, operands[0], width)
        if operand.value is not None:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires a writable operand")
        writes = {"flags"}
        if operand.register is not None:
            writes.add(operand.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(operand_reads(operand)),
            frozenset(writes), width, (operand,),
        )
    if allow_tail_calls and mnemonic in {"idiv", "div"} and len(operands) == 1 and operands[0].size in (4, 8):
        width = operands[0].size * 8
        source = read_operand(decoded, operands[0], width)
        return Instruction(
            address, length, mnemonic, (following,),
            frozenset({"rax", "rdx", *operand_reads(source)}),
            frozenset({"rax", "rdx", "flags"}), width, (source,),
        )
    if mnemonic in {"imul", "mul"} and len(operands) == 1 and operands[0].size in (4, 8):
        width = operands[0].size * 8
        source = read_operand(decoded, operands[0], width)
        return Instruction(
            address, length, mnemonic, (following,),
            frozenset({"rax", *operand_reads(source)}), frozenset({"rax", "rdx", "flags"}),
            width, (source,),
        )
    if mnemonic == "imul" and len(operands) in (2, 3) and operands[0].size in (4, 8):
        width = operands[0].size * 8
        destination = read_operand(decoded, operands[0], width)
        if destination.register is None:
            raise LiftError(f"RVA 0x{address:x}: imul requires a register destination")
        left = read_operand(decoded, operands[1], width)
        if len(operands) == 3:
            right = read_operand(decoded, operands[2], width)
            reads = {*operand_reads(left), *left.address_registers, *right.address_registers}
            operands_out = (destination, left, right)
        else:
            right = left
            left = destination
            reads = {destination.register, *operand_reads(right), *right.address_registers}
            operands_out = (left, right)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({destination.register, "flags"}), width, operands_out,
        )
    if (mnemonic in {"shufps", "pshufd", "shufpd"} and len(operands) == 3) or (mnemonic in {"movhlps", "movlhps", "unpcklps", "unpckhps", "unpcklpd", "unpckhpd", "punpcklqdq", "punpckldq", "punpcklwd"} and len(operands) == 2):
        left = read_xmm_operand(decoded, operands[0], 128)
        right = read_xmm_operand(decoded, operands[1], 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        operands_out = (left, right)
        immediate = 0
        if mnemonic in {"shufps", "pshufd", "shufpd"}:
            immediate = read_operand(decoded, operands[2], 64).value
            operands_out = (*operands_out, Operand(None, immediate))
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 128, operands_out, immediate,
        )
    if mnemonic in FLOAT_PACKED_INT_DOUBLE and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 128)
        right = read_xmm_operand(decoded, operands[1], 64 if mnemonic == "pmovsxdq" else 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = set(right.address_registers)
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 128, (left, right),
        )
    if mnemonic in FLOAT_PACKED_INT_CONVERSIONS and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 128)
        right = read_xmm_operand(decoded, operands[1], 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = set(right.address_registers)
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 128, (left, right),
        )
    if mnemonic in FLOAT_PACKED_FLOAT_CONVERSIONS and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 128)
        right = read_xmm_operand(decoded, operands[1], 64 if mnemonic == "cvtps2pd" else 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = set(right.address_registers)
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 128, (left, right),
        )
    if mnemonic in FLOAT_PACKED_CONVERSIONS and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 128)
        right = read_xmm_operand(decoded, operands[1], 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = set(right.address_registers)
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 128, (left, right),
        )
    if mnemonic in VECTOR_BYTE_SHIFTS and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        immediate = read_operand(decoded, operands[1], 64).value
        return Instruction(
            address, length, mnemonic, (following,), frozenset({left.register}),
            frozenset({left.register}), 128, (left,), immediate,
        )
    if mnemonic in VECTOR_INT_ARITHMETIC and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 128)
        right = read_xmm_operand(decoded, operands[1], 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 128, (left, right),
        )
    if mnemonic in {"psllw", "pslld", "psllq"} and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = {left.register}
        if operands[1].type == x86_const.X86_OP_IMM:
            immediate = read_operand(decoded, operands[1], 64).value
            operands_out = (left,)
        else:
            right = read_xmm_operand(decoded, operands[1], 128)
            if right.register not in XMM_REGISTERS:
                raise LiftError(f"RVA 0x{address:x}: variable {mnemonic} requires an XMM count")
            reads.add(right.register)
            immediate = -1
            operands_out = (left, right)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 128, operands_out, immediate,
        )
    if mnemonic in VECTOR_INT_SHIFTS and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        immediate = read_operand(decoded, operands[1], 64).value
        return Instruction(
            address, length, mnemonic, (following,), frozenset({left.register}),
            frozenset({left.register}), 128, (left,), immediate,
        )
    if mnemonic in VECTOR_INT_COMPARE and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 128)
        right = read_xmm_operand(decoded, operands[1], 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 128, (left, right),
        )
    if mnemonic in {*VECTOR_COMPARE, *VECTOR_DOUBLE_COMPARE} and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 128)
        right = read_xmm_operand(decoded, operands[1], 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 128, (left, right),
        )
    if mnemonic == "vpminsw" and len(operands) == 3:
        destination = read_xmm_operand(decoded, operands[0], 128)
        left = read_xmm_operand(decoded, operands[1], 128)
        right = read_xmm_operand(decoded, operands[2], 128)
        if destination.register not in XMM_REGISTERS or left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: vpminsw requires XMM destination and first source")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({destination.register}), 128, (destination, left, right),
        )
    if mnemonic == "pinsrw" and len(operands) == 3:
        left = read_xmm_operand(decoded, operands[0], 128)
        source_width = operands[1].size * 8
        right = read_operand(decoded, operands[1], source_width)
        immediate = read_operand(decoded, operands[2], 64).value
        if left.register not in XMM_REGISTERS or right.register is not None and source_width != 32 or immediate not in range(8):
            raise LiftError(f"RVA 0x{address:x}: pinsrw requires an XMM destination, 16/32-bit source, and word index")
        reads = {left.register, *operand_reads(right)}
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads), frozenset({left.register}),
            128, (left, right, Operand(None, immediate)), 16,
        )
    if mnemonic == "pextrw" and len(operands) == 3:
        destination_width = operands[0].size * 8
        left = read_operand(decoded, operands[0], destination_width)
        right = read_xmm_operand(decoded, operands[1], 128)
        immediate = read_operand(decoded, operands[2], 64).value
        if left.register is None or right.register not in XMM_REGISTERS or immediate not in range(8):
            raise LiftError(f"RVA 0x{address:x}: pextrw requires a general destination, XMM source, and word index")
        return Instruction(
            address, length, mnemonic, (following,), frozenset({right.register}),
            frozenset({left.register}), destination_width, (left, right), immediate,
        )
    if mnemonic in {"movmskps", "pmovmskb", "movmskpd"} and len(operands) == 2:
        left = read_operand(decoded, operands[0], 32)
        right = read_xmm_operand(decoded, operands[1], 128)
        if left.register is None or right.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires a general destination and XMM source")
        reads = {right.register, *right.address_registers}
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 32, (left, right),
        )
    if mnemonic in {*FLOAT_VECTOR, *VECTOR_HORIZONTAL, *VECTOR_ADDSUB, "andps", "andnps", "andpd", "orps", "pand", "pandn", "por", "pxor", "xorpd"} and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 128)
        right = read_xmm_operand(decoded, operands[1], 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 128, (left, right),
        )
    if mnemonic in {"movhpd", "movlps", "movhps"} and len(operands) == 2:
        left_name = decoded.reg_name(operands[0].reg) if operands[0].type == x86_const.X86_OP_REG else None
        right_name = decoded.reg_name(operands[1].reg) if operands[1].type == x86_const.X86_OP_REG else None
        if left_name in XMM_REGISTERS:
            left = Operand(left_name)
            right = read_operand(decoded, operands[1], 64)
            reads = {left_name, *right.address_registers}
        elif right_name in XMM_REGISTERS:
            left = read_operand(decoded, operands[0], 64)
            right = Operand(right_name)
            reads = {right_name, *left.address_registers}
        else:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM operand")
        if not left.memory and left.register not in XMM_REGISTERS or not right.memory and right.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires a 64-bit memory operand")
        writes = {left.register} if left.register in XMM_REGISTERS else set()
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads), frozenset(writes), 64, (left, right),
        )
    if mnemonic in {"movd", "movq"} and len(operands) == 2:
        width = 32 if mnemonic == "movd" else 64
        left_name = decoded.reg_name(operands[0].reg) if operands[0].type == x86_const.X86_OP_REG else None
        right_name = decoded.reg_name(operands[1].reg) if operands[1].type == x86_const.X86_OP_REG else None
        if left_name in XMM_REGISTERS:
            left = Operand(left_name)
            right = read_xmm_operand(decoded, operands[1], width)
        elif right_name in XMM_REGISTERS:
            left = read_operand(decoded, operands[0], width)
            right = Operand(right_name)
        else:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM operand")
        reads = set(left.address_registers) | set(right.address_registers)
        if right.register is not None:
            reads.add(right.register)
        writes = {left.register} if left.register is not None else set()
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset(writes), width, (left, right),
        )
    if mnemonic in {*FLOAT_SCALAR, *FLOAT_MINMAX} and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 32)
        right = read_xmm_operand(decoded, operands[1], 32)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 32, (left, right),
        )
    if mnemonic in FLOAT_DOUBLE_SCALAR and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 64)
        right = read_xmm_operand(decoded, operands[1], 64)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 64, (left, right),
        )
    if mnemonic in FLOAT_APPROX_SCALAR and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 32)
        right = read_xmm_operand(decoded, operands[1], 32)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = set(right.address_registers)
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 32, (left, right),
        )
    if mnemonic in {*FLOAT_APPROX_VECTOR, *FLOAT_SQRT_VECTOR} and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 128)
        right = read_xmm_operand(decoded, operands[1], 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = set(right.address_registers)
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 128, (left, right),
        )
    if mnemonic in {*FLOAT_DOUBLE_VECTOR, *VECTOR_DOUBLE_HORIZONTAL} and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 128)
        right = read_xmm_operand(decoded, operands[1], 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 128, (left, right),
        )
    if mnemonic in FLOAT_PACKED_MINMAX and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 128)
        right = read_xmm_operand(decoded, operands[1], 128)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 128, (left, right),
        )
    if mnemonic in FLOAT_DOUBLE_MINMAX and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 64)
        right = read_xmm_operand(decoded, operands[1], 64)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 64, (left, right),
        )
    if mnemonic in FLOAT_SQRT and len(operands) == 2:
        width = 32 if mnemonic == "sqrtss" else 64
        left = read_xmm_operand(decoded, operands[0], width)
        right = read_xmm_operand(decoded, operands[1], width)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), width, (left, right),
        )
    if mnemonic in FLOAT_INT_DOUBLE and len(operands) == 2:
        source_width = operands[1].size * 8 if mnemonic == "cvtsi2sd" else operands[0].size * 8
        left = read_xmm_operand(decoded, operands[0], 64) if mnemonic == "cvtsi2sd" else read_operand(decoded, operands[0], source_width)
        right = read_xmm_operand(decoded, operands[1], 64) if mnemonic == "cvttsd2si" else read_operand(decoded, operands[1], source_width)
        if left.register is None:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires a register destination")
        reads = set(right.address_registers)
        if right.register is not None:
            reads.add(right.register)
        if mnemonic == "cvtsi2sd":
            reads.add(left.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 64, (left, right), source_width,
        )
    if mnemonic in FLOAT_CONVERSIONS and len(operands) == 2:
        if mnemonic == "cvtsd2ss":
            left = read_xmm_operand(decoded, operands[0], 64)
            right = read_xmm_operand(decoded, operands[1], 64)
            source_width = 64
        elif mnemonic == "cvtss2sd":
            left = read_xmm_operand(decoded, operands[0], 64)
            right = read_xmm_operand(decoded, operands[1], 32)
            source_width = 32
        elif mnemonic in {"cvttss2si", "cvtss2si"}:
            destination_width = operands[0].size * 8
            left = read_operand(decoded, operands[0], destination_width)
            right = read_xmm_operand(decoded, operands[1], 32)
            source_width = destination_width
        else:
            left = read_xmm_operand(decoded, operands[0], 32)
            source_width = operands[1].size * 8
            right = read_operand(decoded, operands[1], source_width)
        if left.register is None:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires a register destination")
        reads = set(right.address_registers)
        if right.register is not None:
            reads.add(right.register)
        if mnemonic not in {"cvttss2si", "cvtss2si"}:
            reads.add(left.register)
        writes = {left.register}
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset(writes), 32, (left, right), source_width,
        )
    if mnemonic in SCALAR_COMPARE and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 32)
        right = read_xmm_operand(decoded, operands[1], 32)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM destination")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 32, (left, right),
        )
    if mnemonic in {"comiss", "ucomiss"} and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 32)
        right = read_xmm_operand(decoded, operands[1], 32)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM first operand")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({"flags"}), 32, (left, right),
        )
    if mnemonic in FLOAT_COMPARE_DOUBLE and len(operands) == 2:
        left = read_xmm_operand(decoded, operands[0], 64)
        right = read_xmm_operand(decoded, operands[1], 64)
        if left.register not in XMM_REGISTERS:
            raise LiftError(f"RVA 0x{address:x}: {mnemonic} requires an XMM first operand")
        reads = {left.register, *right.address_registers}
        if right.register is not None:
            reads.add(right.register)
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({"flags"}), 64, (left, right),
        )
    if mnemonic == "movsd" and len(operands) == 2 and operands[0].type == x86_const.X86_OP_MEM and operands[1].type == x86_const.X86_OP_MEM:
        if operands[0].size != 4 or operands[1].size != 4:
            raise LiftError(f"RVA 0x{address:x}: unsupported string move width")
        return Instruction(
            address, length, "string movs", (following,),
            frozenset({"rsi", "rdi"}), frozenset({"rsi", "rdi"}), 32,
        )
    if mnemonic in {"movss", "movsd"} and len(operands) == 2:
        width = 32 if mnemonic == "movss" else 64
        left = read_xmm_operand(decoded, operands[0], width)
        right = read_xmm_operand(decoded, operands[1], width)
        if left.value is not None or right.value is not None:
            raise LiftError(f"RVA 0x{address:x}: invalid scalar move operands")
        if left.register is None and right.register is None:
            raise LiftError(f"RVA 0x{address:x}: scalar move requires an XMM operand")
        reads = set(left.address_registers) | set(right.address_registers)
        if right.register is not None:
            reads.add(right.register)
        if left.register is not None:
            reads.add(left.register)
        writes = {left.register} if left.register is not None else set()
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset(writes), width, (left, right),
        )
    if mnemonic == "xorps" and len(operands) == 2 and operands[0].size == 16:
        left, right = (read_operand(decoded, operand, 128) for operand in operands)
        if left.register is None:
            raise LiftError(f"RVA 0x{address:x}: xorps requires an XMM destination")
        reads = set(right.address_registers) | set(left.address_registers)
        if left == right:
            reads.clear()
        else:
            reads.update(operand_reads(left))
            reads.update(operand_reads(right))
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register}), 128, (left, right),
        )
    if mnemonic in {"mov", "movaps", "movups", "movapd", "movdqa", "movdqu", "movntps"} or mnemonic in ARITHMETIC:
        vector_move = mnemonic in {"movaps", "movups", "movapd", "movdqa", "movdqu", "movntps"}
        if len(operands) == 2 and (operands[0].size in (1, 2, 4, 8) or vector_move and operands[0].size == 16):
            width = operands[0].size * 8
            left, right = (read_operand(decoded, operand, width) for operand in operands)
            if left.value is not None:
                raise LiftError(f"RVA 0x{address:x}: destination is not writable")
            reads = set(left.address_registers) | set(right.address_registers)
            if right.register is not None:
                reads.add(right.register)
            if mnemonic == "xor" and left == right:
                reads.clear()
            elif mnemonic != "mov":
                reads.update(operand_reads(left))
            if mnemonic in {"sbb", "adc"}:
                reads.add("flags")
            writes = set()
            if mnemonic not in COMPARISONS and left.register is not None:
                writes.add(left.register)
            if mnemonic in ARITHMETIC:
                writes.add("flags")
            return Instruction(
                address, length, mnemonic, (following,), frozenset(reads),
                frozenset(writes), width, (left, right),
            )
    raise LiftError(f"RVA 0x{address:x}: unsupported instruction {decoded.mnemonic} {decoded.op_str}".rstrip())


def discover(start, code, allow_tail_calls=False):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = {}
    pending = [start]
    while pending:
        address = pending.pop()
        if address in instructions:
            continue
        offset = address - start
        if not 0 <= offset < len(code):
            raise LiftError(f"RVA 0x{address:x} is outside the selected code range")
        decoded = next(decoder.disasm(code[offset:offset + 15], address, count=1), None)
        if decoded is None:
            raise LiftError(f"RVA 0x{address:x}: invalid or truncated instruction")
        instruction = lower(decoded, allow_tail_calls)
        if allow_tail_calls and instruction.mnemonic == "jmp":
            target = instruction.successors[0]
            if not start <= target < start + len(code):
                instruction = Instruction(
                    address, instruction.length, "tail", (), frozenset(), frozenset(), 0,
                    (Operand(None, target),),
                )
        instructions[address] = instruction
        pending.extend(instruction.successors)
    ordered = sorted(instructions.values(), key=lambda instruction: instruction.address)
    for previous, current in zip(ordered, ordered[1:]):
        if previous.address + previous.length > current.address:
            raise LiftError(f"RVA 0x{current.address:x}: overlapping instruction streams")
    return instructions


def check_initialized(start, instructions, full_state=False):
    initial = frozenset((*REGISTERS, "flags")) if full_state else frozenset((*ARGUMENTS, *CALLEE_SAVED, *CALLEE_SAVED_XMM, "rsp", "flags"))
    incoming = {start: initial}
    pending = deque([start])
    while pending:
        address = pending.popleft()
        instruction = instructions[address]
        outgoing = incoming[address] | instruction.writes
        for successor in instruction.successors:
            previous = incoming.get(successor)
            merged = outgoing if previous is None else previous & outgoing
            if previous != merged:
                incoming[successor] = merged
                pending.append(successor)
    for address in sorted(instructions):
        missing = instructions[address].reads - incoming[address]
        if missing:
            raise LiftError(f"RVA 0x{address:x}: uninitialized state: {', '.join(sorted(missing))}")


def infer_stack_arguments(instructions):
    start = min(instructions)
    deltas = {start: 0}
    pending = deque([start])
    maximum = 0
    while pending:
        address = pending.popleft()
        instruction = instructions[address]
        delta = deltas[address]
        for operand in instruction.operands:
            if operand.memory and operand.base == "rsp":
                offset = delta + operand.displacement
                if offset >= 0x28:
                    maximum = max(maximum, (offset - 0x28) // 8 + 1)
        mnemonic = instruction.mnemonic
        effect = 0
        if mnemonic in {"push", "pushfq"}:
            effect = -8
        elif mnemonic in {"pop", "popfq"}:
            effect = 8
        elif mnemonic in {"add", "sub"} and instruction.operands[0].register == "rsp":
            immediate = instruction.operands[1].value
            if immediate is None:
                raise LiftError(f"RVA 0x{address:x}: dynamic stack-pointer adjustment")
            effect = immediate if mnemonic == "add" else -immediate
        elif "rsp" in instruction.writes and mnemonic != "call":
            raise LiftError(f"RVA 0x{address:x}: dynamic stack-pointer assignment")
        for successor in instruction.successors:
            updated = delta + effect
            previous = deltas.get(successor)
            if previous is None:
                deltas[successor] = updated
                pending.append(successor)
            elif previous != updated:
                raise LiftError(f"RVA 0x{successor:x}: inconsistent stack depth across control-flow paths")
    return maximum


def condition_flags(mnemonic):
    if mnemonic == "jrcxz":
        return set()
    return set(re.findall(r"[a-z]+", CONDITIONS.get(mnemonic, "")))


def defined_flags(instruction):
    mnemonic = instruction.mnemonic
    if mnemonic in ARITHMETIC or mnemonic == "call":
        return {"cf", "of", "sf", "zf", "pf"}
    if mnemonic in {"inc", "dec"}:
        return {"of", "sf", "zf", "pf", "af"}
    if mnemonic in SHIFTS or mnemonic in DOUBLE_SHIFTS and instruction.source_width != 0:
        return {"cf", "of", "sf", "zf", "pf"}
    if mnemonic in CARRY_ROTATES and instruction.source_width % (instruction.width + 1) != 0:
        return {"cf", "of"}
    if mnemonic == "neg":
        return {"cf", "of", "sf", "zf", "pf", "af"}
    if mnemonic in {"repne scasw", "lock xadd", "lock cmpxchg", "popfq"}:
        return {"cf", "of", "sf", "zf", "pf", "af"}
    if mnemonic in {"imul", "mul"}:
        return {"cf", "of", "sf", "zf", "pf"}
    if mnemonic in {"comiss", "ucomiss", *FLOAT_COMPARE_DOUBLE}:
        return {"cf", "of", "sf", "zf", "pf", "af"}
    if mnemonic == "sahf":
        return {"cf", "sf", "zf", "pf", "af"}
    if mnemonic in {"bt", "btr", "bts", "btc", "stc", "cmc"}:
        return {"cf"}
    if mnemonic in BIT_SCANS:
        return {"zf"}
    if mnemonic in {"idiv", "div", "popcnt"}:
        return {"cf", "of", "sf", "zf", "pf", "af"}
    return set()


def check_flag_liveness(instructions):
    incoming = {address: set() for address in instructions}
    outgoing = {address: set() for address in instructions}
    changed = True
    while changed:
        changed = False
        for address in sorted(instructions, reverse=True):
            instruction = instructions[address]
            after = set().union(*(incoming[successor] for successor in instruction.successors)) if instruction.successors else set()
            before = condition_flags(instruction.mnemonic) | (after - defined_flags(instruction))
            if after != outgoing[address] or before != incoming[address]:
                outgoing[address] = after
                incoming[address] = before
                changed = True
    for address, instruction in instructions.items():
        if instruction.mnemonic in {"imul", "mul"} and outgoing[address] & {"sf", "zf", "pf", "af"}:
            raise LiftError(f"RVA 0x{address:x}: {instruction.mnemonic} leaves subsequently used SF, ZF, PF, or AF undefined")
        if instruction.mnemonic in {*SHIFTS, *DOUBLE_SHIFTS} and "af" in outgoing[address]:
            raise LiftError(f"RVA 0x{address:x}: {instruction.mnemonic} leaves subsequently used AF undefined")
        if instruction.mnemonic in SHIFTS and instruction.width in (8, 16) and instruction.operands[1].value is None and "cf" in outgoing[address]:
            raise LiftError(f"RVA 0x{address:x}: variable narrow shift leaves CF undefined for out-of-range counts")
        if instruction.mnemonic in {*SHIFTS, *DOUBLE_SHIFTS, *CARRY_ROTATES} and "of" in outgoing[address]:
            count = instruction.source_width if instruction.mnemonic in {*DOUBLE_SHIFTS, *CARRY_ROTATES} else instruction.operands[1].value
            if count != 1:
                raise LiftError(f"RVA 0x{address:x}: shift leaves a subsequently used OF undefined")
        if instruction.mnemonic in {"bt", "btr", "bts", "btc"} and outgoing[address] - {"cf"}:
            raise LiftError(f"RVA 0x{address:x}: {instruction.mnemonic} leaves a subsequently used non-CF flag undefined")
        if instruction.mnemonic in BIT_SCANS and outgoing[address] - {"zf"}:
            raise LiftError(f"RVA 0x{address:x}: {instruction.mnemonic} leaves subsequently used non-ZF flag undefined")
        if instruction.mnemonic in {"idiv", "div"} and outgoing[address]:
            raise LiftError(f"RVA 0x{address:x}: {instruction.mnemonic} leaves subsequently used flags undefined")


def arithmetic_to_c(instruction, flags):
    mnemonic = instruction.mnemonic
    lhs, rhs = instruction.operands
    c_type = f"uint{instruction.width}_t"
    sign_bit = f"UINT{instruction.width}_C(0x{1 << (instruction.width - 1):x})"
    if instruction.zeroing_xor:
        lines = [f"{c_type} result = 0;"]
        left = right = "0"
    else:
        result_expression = f"left {ARITHMETIC[mnemonic]} right"
        if mnemonic == "sbb":
            result_expression += " - cf"
        elif mnemonic == "adc":
            result_expression += " + cf"
        lines = [
            f"{c_type} left = {lhs.as_c(instruction.width)};",
            f"{c_type} right = {rhs.as_c(instruction.width)};",
            f"{c_type} result = ({c_type})({result_expression});",
        ]
        left = right = None
    carry = overflow = "0"
    if mnemonic in {"add", "adc"}:
        carry = "result < left || (cf && result == left)" if mnemonic == "adc" else "result < left"
        overflow = f"((left ^ result) & (right ^ result) & {sign_bit}) != 0"
    elif mnemonic in {"sub", "sbb", "cmp"}:
        carry = "left < right || (cf && left == right)" if mnemonic == "sbb" else "left < right"
        overflow = f"((left ^ right) & (left ^ result) & {sign_bit}) != 0"
    formulas = {
        "cf": carry, "of": overflow, "sf": f"(result & {sign_bit}) != 0", "zf": "result == 0",
        "pf": "parity(result)",
    }
    if mnemonic in {"add", "adc"}:
        formulas["af"] = "((left ^ right ^ result) & 0x10) != 0"
    elif mnemonic in {"sub", "sbb", "cmp"}:
        formulas["af"] = "((left ^ right ^ result) & 0x10) != 0"
    else:
        formulas["af"] = "0"
    lines.extend(f"{flag} = {formulas[flag]};" for flag in flags)
    if mnemonic not in COMPARISONS:
        lines.append(lhs.write_c("result", instruction.width))
    else:
        lines.append("(void)result;")
    return lines


def unary_to_c(instruction, flags):
    operand = instruction.operands[0]
    width = instruction.width
    c_type = f"uint{width}_t"
    sign_bit = f"UINT{width}_C(0x{1 << (width - 1):x})"
    operator = "+" if instruction.mnemonic == "inc" else "-"
    overflow = f"left == {sign_bit} - 1" if instruction.mnemonic == "inc" else f"left == {sign_bit}"
    formulas = {
        "of": overflow, "sf": f"(result & {sign_bit}) != 0", "zf": "result == 0", "pf": "parity(result)",
        "af": "((left ^ 1 ^ result) & 0x10) != 0",
    }
    lines = [
        f"{c_type} left = {operand.as_c(width)};",
        f"{c_type} result = ({c_type})(left {operator} 1);",
    ]
    lines.extend(f"{flag} = {formulas[flag]};" for flag in flags if flag in formulas)
    lines.append(operand.write_c("result", width))
    return lines


def shift_to_c(instruction, flags):
    if instruction.mnemonic in {"rol", "ror"}:
        lhs, count_operand = instruction.operands
        width = instruction.width
        c_type = f"uint{width}_t"
        mask = 63 if width == 64 else 31
        rotate_left = instruction.mnemonic == "rol"
        lines = [
            f"uint64_t count = (uint64_t)({count_operand.as_c(64)}) & {mask};",
            "if (count != 0) {",
            f"    {c_type} left = {lhs.as_c(width)};",
        ]
        if rotate_left:
            lines.append(f"    {c_type} result = ({c_type})((left << count) | (left >> ({width} - count)));")
            carry_expression = "result & 1"
            overflow_expression = f"count == 1 && (((result >> {width - 1}) ^ result) & 1)"
        else:
            lines.append(f"    {c_type} result = ({c_type})((left >> count) | (left << ({width} - count)));")
            carry_expression = f"(result >> {width - 1}) & 1"
            overflow_expression = f"count == 1 && (((result >> {width - 1}) ^ (result >> {width - 2})) & 1)"
        formulas = {
            "cf": carry_expression,
            "of": overflow_expression,
            "sf": f"(result & UINT{width}_C(0x{1 << (width - 1):x})) != 0",
            "zf": "result == 0",
            "pf": "parity(result)",
            "af": "0",
        }
        lines.extend(f"    {flag} = {formulas[flag]};" for flag in flags)
        lines.append(f"    {lhs.write_c('result', width)}")
        lines.append("}")
        return lines
    mnemonic = "shl" if instruction.mnemonic == "sal" else instruction.mnemonic
    lhs, count_operand = instruction.operands
    width = instruction.width
    c_type = f"uint{width}_t"
    signed_type = f"int{width}_t"
    sign_bit = f"UINT{width}_C(0x{1 << (width - 1):x})"
    mask = 63 if width == 64 else 31
    variable_narrow = width in (8, 16) and count_operand.value is None
    result_expression = {
        "shl": f"({c_type})(count < {width} ? left << count : 0)" if variable_narrow else f"({c_type})(left << count)",
        "shr": f"({c_type})(count < {width} ? left >> count : 0)" if variable_narrow else f"({c_type})(left >> count)",
        "sar": f"({c_type})(count >= {width - 1} ? (left & {sign_bit} ? ({c_type})-1 : 0) : ({signed_type})left >> count)" if variable_narrow else f"({c_type})(({signed_type})left >> count)",
    }[mnemonic]
    carry_expression = {
        "shl": f"count <= {width} && ((left >> ({width} - count)) & 1)" if variable_narrow else f"(left >> ({width} - count)) & 1",
        "shr": f"count <= {width} && ((left >> (count - 1)) & 1)" if variable_narrow else "(left >> (count - 1)) & 1",
        "sar": f"count <= {width} && ((({signed_type})left >> (count - 1)) & 1)" if variable_narrow else f"(({signed_type})left >> (count - 1)) & 1",
    }[mnemonic]
    overflow_expression = {
        "shl": f"count == 1 && ((left ^ result) & {sign_bit}) != 0",
        "shr": f"count == 1 && (left & {sign_bit}) != 0",
        "sar": "0",
    }[mnemonic]
    lines = [
        f"uint64_t count = (uint64_t)({count_operand.as_c(64)}) & {mask};",
        "if (count != 0) {",
        f"    {c_type} left = {lhs.as_c(width)};",
        f"    {c_type} result = {result_expression};",
    ]
    formulas = {
        "cf": carry_expression,
        "of": overflow_expression,
        "sf": f"(result & {sign_bit}) != 0",
        "zf": "result == 0",
        "pf": "parity(result)",
        "af": "0",
    }
    lines.extend(f"    {flag} = {formulas[flag]};" for flag in flags)
    lines.append(f"    {lhs.write_c('result', width)}")
    lines.append("}")
    return lines


def neg_to_c(instruction, flags):
    operand = instruction.operands[0]
    width = instruction.width
    c_type = f"uint{width}_t"
    sign_bit = f"UINT{width}_C(0x{1 << (width - 1):x})"
    lines = [
        f"{c_type} left = {operand.as_c(width)};",
        f"{c_type} result = ({c_type})(0 - left);",
    ]
    formulas = {
        "cf": "left != 0", "of": f"left == {sign_bit}",
        "sf": f"(result & {sign_bit}) != 0", "zf": "result == 0", "pf": "parity(result)",
        "af": "(left & 0xf) != 0",
    }
    lines.extend(f"{flag} = {formulas[flag]};" for flag in flags)
    lines.append(operand.write_c("result", width))
    return lines


def imul_to_c(instruction, flags):
    mnemonic = instruction.mnemonic
    if len(instruction.operands) == 1:
        source = instruction.operands[0]
        width = instruction.width
        carry = "&cf" if "cf" in flags else "0"
        overflow = "&of" if "of" in flags else "0"
        if width == 32:
            if mnemonic == "mul":
                lines = [
                    f"uint64_t product = (uint64_t)(uint32_t)rax * (uint64_t)(uint32_t){source.as_c(32)};",
                    "int exceeded = product > UINT32_MAX;",
                    "(void)exceeded;",
                ]
            else:
                lines = [
                    f"int64_t product = (int64_t)(int32_t)rax * (int64_t)(int32_t){source.as_c(32)};",
                    "int exceeded = product != (int64_t)(int32_t)product;",
                    "(void)exceeded;",
                ]
            if "cf" in flags:
                lines.append("cf = exceeded;")
            if "of" in flags:
                lines.append("of = exceeded;")
            lines.extend(["rax = (uint32_t)product;", "rdx = (uint32_t)(product >> 32);"])
            return lines
        if mnemonic == "mul":
            return [
                "uint64_t high = 0;",
                f"uint64_t low = mul_full64(rax, {source.as_c(64)}, &high, {carry}, {overflow});",
                "rax = low;",
                "rdx = high;",
            ]
        return [
            "uint64_t high = 0;",
            f"uint64_t low = imul_full64(rax, {source.as_c(64)}, &high, {carry}, {overflow});",
            "rax = low;",
            "rdx = high;",
        ]
    if len(instruction.operands) == 3:
        destination, lhs, rhs = instruction.operands
    else:
        lhs, rhs = instruction.operands
        destination = lhs
    width = instruction.width
    carry = "&cf" if "cf" in flags else "0"
    overflow = "&of" if "of" in flags else "0"
    return [
        f"uint{width}_t left = {lhs.as_c(width)};",
        f"uint{width}_t right = {rhs.as_c(width)};",
        destination.write_c(f"imul{width}(left, right, {carry}, {overflow})", width),
    ]


def memory_helpers(include_xmm=False, narrow=False):
    lines = ["#include <string.h>"]
    widths = (8, 16, 32, 64) if narrow else (32, 64)
    if include_xmm:
        widths = (*widths, 128)
    for width in widths:
        c_type = f"uint{width}_t"
        lines.extend([
            f"static inline {c_type} read{width}(uint64_t address)",
            "{",
            f"    {c_type} value;",
            f"    memcpy(&value, (const void *)(uintptr_t)address, sizeof(value));",
            "    return value;",
            "}",
            f"static inline void write{width}(uint64_t address, {c_type} value)",
            "{",
            "    memcpy((void *)(uintptr_t)address, &value, sizeof(value));",
            "}",
        ])
    return lines


def imul_helpers(widths):
    lines = []
    if 32 in widths:
        lines.extend([
            "static inline uint32_t imul32(uint32_t left, uint32_t right, int *carry, int *overflow)",
            "{",
            "    int64_t product = (int64_t)(int32_t)left * (int64_t)(int32_t)right;",
            "    uint32_t result = (uint32_t)product;",
            "    int exceeded = product != (int64_t)(int32_t)result;",
            "    if (carry) *carry = exceeded;",
            "    if (overflow) *overflow = exceeded;",
            "    return result;",
            "}",
        ])
    if 64 in widths:
        lines.extend([
            "static inline uint64_t imul64(uint64_t left, uint64_t right, int *carry, int *overflow)",
            "{",
            "    uint64_t a0 = (uint32_t)left, a1 = left >> 32;",
            "    uint64_t b0 = (uint32_t)right, b1 = right >> 32;",
            "    uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;",
            "    uint64_t middle = (p00 >> 32) + (uint32_t)p01 + (uint32_t)p10;",
            "    uint64_t result = (uint32_t)p00 | (middle << 32);",
            "    uint64_t high = p11 + (p01 >> 32) + (p10 >> 32) + (middle >> 32);",
            "    if (left >> 63) high -= right;",
            "    if (right >> 63) high -= left;",
            "    int exceeded = high != ((result >> 63) ? UINT64_MAX : 0);",
            "    if (carry) *carry = exceeded;",
            "    if (overflow) *overflow = exceeded;",
            "    return result;",
            "}",
            "static inline uint64_t imul_full64(uint64_t left, uint64_t right, uint64_t *high_out, int *carry, int *overflow)",
            "{",
            "    uint64_t a0 = (uint32_t)left, a1 = left >> 32;",
            "    uint64_t b0 = (uint32_t)right, b1 = right >> 32;",
            "    uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;",
            "    uint64_t middle = (p00 >> 32) + (uint32_t)p01 + (uint32_t)p10;",
            "    uint64_t result = (uint32_t)p00 | (middle << 32);",
            "    uint64_t high = p11 + (p01 >> 32) + (p10 >> 32) + (middle >> 32);",
            "    if (left >> 63) high -= right;",
            "    if (right >> 63) high -= left;",
            "    int exceeded = high != ((result >> 63) ? UINT64_MAX : 0);",
            "    if (high_out) *high_out = high;",
            "    if (carry) *carry = exceeded;",
            "    if (overflow) *overflow = exceeded;",
            "    return result;",
            "}",
            "static inline uint64_t mul_full64(uint64_t left, uint64_t right, uint64_t *high_out, int *carry, int *overflow)",
            "{",
            "    uint64_t a0 = (uint32_t)left, a1 = left >> 32;",
            "    uint64_t b0 = (uint32_t)right, b1 = right >> 32;",
            "    uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;",
            "    uint64_t middle = (p00 >> 32) + (uint32_t)p01 + (uint32_t)p10;",
            "    uint64_t result = (uint32_t)p00 | (middle << 32);",
            "    uint64_t high = p11 + (p01 >> 32) + (p10 >> 32) + (middle >> 32);",
            "    int exceeded = high != 0;",
            "    if (high_out) *high_out = high;",
            "    if (carry) *carry = exceeded;",
            "    if (overflow) *overflow = exceeded;",
            "    return result;",
            "}",
        ])
    return lines


def division_helpers(widths):
    lines = []
    if 64 in widths:
        lines.extend([
            "#ifdef _MSC_VER",
            "#include <intrin.h>",
            "#endif",
            "static inline int idiv64_impl(uint64_t low, uint64_t high, uint64_t divisor, uint64_t *quotient, uint64_t *remainder)",
            "{",
            "    if (!divisor) return 0;",
            "#ifdef _MSC_VER",
            "    int64_t signed_remainder;",
            "    int64_t signed_quotient = _div128((int64_t)high, low, (int64_t)divisor, &signed_remainder);",
            "    *quotient = (uint64_t)signed_quotient;",
            "    *remainder = (uint64_t)signed_remainder;",
            "#else",
            "    unsigned __int128 bits = ((unsigned __int128)high << 64) | low;",
            "    __int128 dividend = (__int128)bits;",
            "    int64_t signed_quotient = (int64_t)(dividend / (int64_t)divisor);",
            "    *quotient = (uint64_t)signed_quotient;",
            "    *remainder = (uint64_t)(dividend % (int64_t)divisor);",
            "#endif",
            "    return 1;",
            "}",
            "static inline int udiv64_impl(uint64_t low, uint64_t high, uint64_t divisor, uint64_t *quotient, uint64_t *remainder)",
            "{",
            "    if (!divisor) return 0;",
            "#ifdef _MSC_VER",
            "    *quotient = _udiv128(high, low, divisor, remainder);",
            "#else",
            "    unsigned __int128 dividend = ((unsigned __int128)high << 64) | low;",
            "    *quotient = (uint64_t)(dividend / divisor);",
            "    *remainder = (uint64_t)(dividend % divisor);",
            "#endif",
            "    return 1;",
            "}",
        ])
    if 32 in widths:
        lines.extend([
            "static inline int idiv32_impl(uint32_t low, uint32_t high, uint32_t divisor, uint32_t *quotient, uint32_t *remainder)",
            "{",
            "    if (!divisor) return 0;",
            "    int64_t dividend = (int64_t)(((uint64_t)high << 32) | low);",
            "    int64_t signed_divisor = (int32_t)divisor;",
            "    if (dividend == INT64_MIN && signed_divisor == -1) return 0;",
            "    int64_t q = dividend / signed_divisor;",
            "    if (q > INT32_MAX || q < INT32_MIN) return 0;",
            "    *quotient = (uint32_t)q;",
            "    *remainder = (uint32_t)(dividend % signed_divisor);",
            "    return 1;",
            "}",
            "static inline int udiv32_impl(uint32_t low, uint32_t high, uint32_t divisor, uint32_t *quotient, uint32_t *remainder)",
            "{",
            "    if (!divisor) return 0;",
            "    uint64_t dividend = ((uint64_t)high << 32) | low;",
            "    uint64_t q = dividend / divisor;",
            "    if (q > UINT32_MAX) return 0;",
            "    *quotient = (uint32_t)q;",
            "    *remainder = (uint32_t)(dividend % divisor);",
            "    return 1;",
            "}",
        ])
    return lines


def emit_c(name, start, instructions, stack_arguments=0, cpu_context=False):
    check_flag_liveness(instructions)
    registers = set()
    uses_memory = False
    uses_narrow_memory = False
    uses_tls = False
    uses_image = False
    uses_dispatcher = any(instruction.mnemonic == "call" for instruction in instructions.values())
    uses_float = any(
        instruction.mnemonic in {"comiss", "ucomiss", *FLOAT_COMPARE_DOUBLE, *FLOAT_SCALAR, *FLOAT_DOUBLE_SCALAR, *FLOAT_DOUBLE_VECTOR, *VECTOR_DOUBLE_COMPARE, *SCALAR_COMPARE, *VECTOR_DOUBLE_HORIZONTAL, *FLOAT_MINMAX, *FLOAT_PACKED_MINMAX, *FLOAT_DOUBLE_MINMAX, *FLOAT_SQRT, *FLOAT_APPROX_VECTOR, *FLOAT_APPROX_SCALAR, *FLOAT_SQRT_VECTOR, *FLOAT_VECTOR, *VECTOR_HORIZONTAL, *VECTOR_ADDSUB, *VECTOR_COMPARE, *FLOAT_PACKED_CONVERSIONS, *FLOAT_PACKED_FLOAT_CONVERSIONS, *FLOAT_PACKED_INT_CONVERSIONS, *FLOAT_PACKED_INT_DOUBLE, *FLOAT_INT_DOUBLE, *FLOAT_CONVERSIONS}
        for instruction in instructions.values()
    )
    uses_xmm = any(
        instruction.width == 128 or any(
            operand.register in XMM_REGISTERS for operand in instruction.operands
        )
        for instruction in instructions.values()
    )
    imul_widths = set()
    division_widths = {instruction.width for instruction in instructions.values() if instruction.mnemonic in {"idiv", "div"}}
    conditions = set()
    for instruction in instructions.values():
        registers.update(instruction.reads | instruction.writes)
        uses_memory = uses_memory or any(operand.memory for operand in instruction.operands)
        uses_narrow_memory = uses_narrow_memory or any(
            operand.memory for operand in instruction.operands
        ) and (instruction.width in (8, 16) or instruction.source_width in (8, 16))
        uses_image = uses_image or any(operand.image_rva is not None for operand in instruction.operands)
        uses_tls = uses_tls or any(operand.segment == "gs" for operand in instruction.operands)
        uses_image = uses_image or instruction.mnemonic == "call" and instruction.source_width == 1
        if instruction.mnemonic == "repne scasw" or instruction.mnemonic in STRING_OPERATIONS:
            uses_memory = True
            if instruction.width in (8, 16):
                uses_narrow_memory = True
        if instruction.mnemonic in {"imul", "mul"}:
            imul_widths.add(instruction.width)
        if instruction.mnemonic in CONDITIONS:
            conditions.add(instruction.mnemonic)
    locals_used = sorted((registers & REGISTERS) - set(ARGUMENTS) - {"rsp"})
    flags = sorted(set().union(*(condition_flags(mnemonic) for mnemonic in conditions)) if conditions else set())
    if any(instruction.mnemonic in {"sbb", "adc", *CARRY_ROTATES} for instruction in instructions.values()) and "cf" not in flags:
        flags.append("cf")
        flags.sort()
    if any(instruction.mnemonic == "pushfq" for instruction in instructions.values()):
        flags = sorted(set(flags) | {"cf", "of", "sf", "zf", "pf", "af"})
    stack_names = [f"stack_arg{index}" for index in range(5, 5 + stack_arguments)]
    signature = ", ".join(
        [f"uint64_t {arg}" for arg in ARGUMENTS]
        + [f"uint64_t {arg}" for arg in stack_names]
    )
    lines = ["#include <stdint.h>"]
    if cpu_context:
        lines.append('#include "recomp_cpu.h"')
    if any(instruction.mnemonic == "cpuid" for instruction in instructions.values()):
        lines.append("#include <intrin.h>")
    if any(instruction.mnemonic == "crc32" for instruction in instructions.values()):
        lines.append("#include <nmmintrin.h>")
    if any(instruction.mnemonic == "xgetbv" for instruction in instructions.values()):
        lines.append("#include <immintrin.h>")
    if uses_float:
        lines.extend([
            "#include <math.h>", "#include <string.h>",
            "static inline float float32(uint32_t value)",
            "{",
            "    float result;",
            "    memcpy(&result, &value, sizeof(result));",
            "    return result;",
            "}",
            "static inline uint32_t bits32(float value)",
            "{",
            "    uint32_t result;",
            "    memcpy(&result, &value, sizeof(result));",
            "    return result;",
            "}",
            "static inline double float64(uint64_t value)",
            "{",
            "    double result;",
            "    memcpy(&result, &value, sizeof(result));",
            "    return result;",
            "}",
            "static inline uint64_t bits64(double value)",
            "{",
            "    uint64_t result;",
            "    memcpy(&result, &value, sizeof(result));",
            "    return result;",
            "}",
            "static inline int32_t cvt32(float value)",
            "{",
            "    if (isnan(value) || value >= 2147483648.0f || value < -2147483648.0f) return INT32_MIN;",
            "    return (int32_t)nearbyintf(value);",
            "}",
            "static inline int64_t cvt64(float value)",
            "{",
            "    if (isnan(value) || value >= 9223372036854775808.0f || value < -9223372036854775808.0f) return INT64_MIN;",
            "    return (int64_t)nearbyintf(value);",
            "}",
            "static inline int32_t cvtt32(float value)",
            "{",
            "    if (isnan(value) || value >= 2147483648.0f || value < -2147483648.0f) return INT32_MIN;",
            "    return (int32_t)value;",
            "}",
            "static inline int64_t cvtt64(float value)",
            "{",
            "    if (isnan(value) || value >= 9223372036854775808.0f || value < -9223372036854775808.0f) return INT64_MIN;",
            "    return (int64_t)value;",
            "}",
            "static inline int32_t cvttsd32(double value)",
            "{",
            "    if (isnan(value) || value >= 2147483648.0 || value < -2147483648.0) return INT32_MIN;",
            "    return (int32_t)value;",
            "}",
            "static inline int64_t cvttsd64(double value)",
            "{",
            "    if (isnan(value) || value >= 9223372036854775808.0 || value < -9223372036854775808.0) return INT64_MIN;",
            "    return (int64_t)value;",
            "}",
        ])
    if any(instruction.mnemonic in {"stmxcsr", "ldmxcsr"} for instruction in instructions.values()):
        lines.append("#include <xmmintrin.h>")
    if any(instruction.mnemonic in {*FLOAT_APPROX_VECTOR, *FLOAT_APPROX_SCALAR} for instruction in instructions.values()):
        lines.extend([
            "#include <xmmintrin.h>",
            "static inline uint32_t rsqrt32(uint32_t value)",
            "{",
            "    __m128 input, result;",
            "    memcpy(&input, &value, sizeof(value));",
            "    result = _mm_rsqrt_ss(input);",
            "    memcpy(&value, &result, sizeof(value));",
            "    return value;",
            "}",
            "static inline uint32_t rcp32(uint32_t value)",
            "{",
            "    __m128 input, result;",
            "    memcpy(&input, &value, sizeof(value));",
            "    result = _mm_rcp_ss(input);",
            "    memcpy(&value, &result, sizeof(value));",
            "    return value;",
            "}",
        ])
    if uses_xmm:
        lines.append("typedef RecompXmm uint128_t;" if cpu_context else "typedef struct { uint64_t lanes[2]; } uint128_t;")
    if uses_memory or "rsp" in registers or cpu_context:
        lines.extend(memory_helpers(uses_xmm, uses_narrow_memory))
    if imul_widths:
        lines.extend(imul_helpers(imul_widths))
    if division_widths:
        lines.extend(division_helpers(division_widths))
    if "pf" in flags:
        lines.extend([
            "static inline int parity(uint64_t value)",
            "{",
            "    value &= 0xff;",
            "    value ^= value >> 4;",
            "    value ^= value >> 2;",
            "    value ^= value >> 1;",
            "    return (value & 1) == 0;",
            "}",
        ])
    if uses_dispatcher and not cpu_context:
        lines.extend([
            "typedef uint64_t (*CallDispatcher)(uint64_t target, uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9, uint64_t guest_rsp);",
            "static CallDispatcher call_dispatcher;",
            f"void lifted_{name}_set_call_dispatcher(CallDispatcher value)",
            "{",
            "    call_dispatcher = value;",
            "}",
        ])
    if uses_image and not cpu_context:
        lines.extend([
            "static uint64_t image_base;",
            f"void lifted_{name}_set_image_base(uint64_t value)",
            "{",
            "    image_base = value;",
            "}",
        ])
    if uses_tls and not cpu_context:
        lines.extend([
            "static uint64_t tls_base;",
            f"void lifted_{name}_set_tls_base(uint64_t value)",
            "{",
            "    tls_base = value;",
            "}",
        ])
    if cpu_context:
        for register in sorted(REGISTERS):
            if register in XMM_REGISTERS:
                index = XMM_REGISTERS.index(register)
                lines.append(f"#define {register} (cpu->xmm[{index}])")
            else:
                lines.append(f"#define {register} (cpu->{register})")
        for flag in ("cf", "of", "sf", "zf", "pf", "af"):
            lines.append(f"#define {flag} (cpu->{flag})")
        lines.append("#define image_base (cpu->image_base)")
        lines.append("#define tls_base (cpu->tls_base)")
        lines.append("#define rip (cpu->rip)")
        lines.extend(["", f"void lifted_{name}_cpu(RecompCpu *cpu)", "{"])
    else:
        lines.extend(["", f"uint64_t lifted_{name}({signature})", "{"])
        lines.extend(
            f"    {'uint128_t' if register in XMM_REGISTERS else 'uint64_t'} {register} = "
            f"{'{{0, 0}}' if register in XMM_REGISTERS else '0'};"
            for register in locals_used
        )
        if "rsp" in registers:
            lines.extend([
                "    _Alignas(16) unsigned char stack[1024];",
                "    uint64_t rsp = (uint64_t)(uintptr_t)(stack + 520);",
            ])
            lines.extend(
                f"    write64(rsp + UINT64_C(0x{0x28 + index * 8:x}), {stack_name});"
                for index, stack_name in enumerate(stack_names)
            )
        lines.extend(f"    int {flag} = 0;" for flag in flags)
        lines.extend(f"    (void){register};" for register in (*ARGUMENTS, *stack_names, *locals_used))
    lines.extend([f"    goto rva_{start:x};", ""])
    for address, instruction in sorted(instructions.items()):
        mnemonic = instruction.mnemonic
        lines.append(f"rva_{address:x}: {{")
        if mnemonic == "ret":
            if cpu_context:
                lines.append("    rip = read64(rsp);")
                lines.append("    rsp += 8;")
                if instruction.source_width:
                    lines.append(f"    rsp += {instruction.source_width};")
                lines.append("    return;")
            else:
                lines.append("    return rax;")
        else:
            if mnemonic == "trap":
                lines.append(f"    recomp_cpu_trap(cpu, UINT64_C(0x{address:x}));")
                lines.append("    return;")
            elif mnemonic == "tail":
                operand = instruction.operands[0]
                if instruction.source_width == 1:
                    target_value = f"read64({operand.address_c()})" if operand.memory else operand.as_c(64)
                    target_expression = f"({target_value} - image_base)"
                else:
                    target_expression = f"UINT64_C(0x{operand.value:x})"
                lines.append(f"    recomp_cpu_dispatch(cpu, {target_expression});")
                lines.append("    return;")
            elif mnemonic == "call":
                operand = instruction.operands[0]
                if instruction.source_width == 1:
                    if operand.memory:
                        target_value = f"read64({operand.address_c()})"
                    else:
                        target_value = operand.as_c(64)
                    target_expression = f"({target_value} - image_base)"
                else:
                    target_expression = f"UINT64_C(0x{operand.value:x})"
                lines.append("    rsp -= 8;")
                lines.append(f"    write64(rsp, UINT64_C(0x{instruction.successors[0]:x}));")
                if cpu_context:
                    lines.append(f"    recomp_cpu_dispatch(cpu, {target_expression});")
                else:
                    lines.append(
                        f"    rax = call_dispatcher({target_expression}, rcx, rdx, r8, r9, rsp);"
                    )
                    lines.append("    rsp += 8;")
            elif mnemonic in {"stmxcsr", "ldmxcsr"}:
                operand = instruction.operands[0]
                if mnemonic == "stmxcsr":
                    lines.append(f"    write32({operand.address_c()}, _mm_getcsr());")
                else:
                    lines.append(f"    _mm_setcsr(read32({operand.address_c()}));")
            elif mnemonic in {"prefetcht0", "prefetchnta", "prefetch", "pause", "wait"}:
                pass
            elif mnemonic == "bswap":
                operand = instruction.operands[0]
                width = instruction.width
                lines.extend([
                    f"    uint{width}_t source = {operand.as_c(width)};",
                    "    uint64_t result = 0;",
                ])
                for byte in range(width // 8):
                    lines.append(f"    result |= ((source >> {byte * 8}) & 0xff) << {width - byte * 8 - 8};")
                lines.append(f"    {operand.write_c('result', width)}")
            elif mnemonic == "popcnt":
                lhs, rhs = instruction.operands
                width = instruction.width
                lines.extend([
                    f"    uint{width}_t source = {rhs.as_c(width)};",
                    f"    uint{width}_t result = 0;",
                ])
                for bit in range(width):
                    lines.append(f"    result += (source >> {bit}) & 1;")
                formulas = {"cf": "0", "of": "0", "sf": "0", "zf": "source == 0", "pf": "0", "af": "0"}
                lines.extend(f"    {flag} = {formulas[flag]};" for flag in flags)
                lines.append(f"    {lhs.write_c('result', width)}")
            elif mnemonic in BIT_SCANS:
                lhs, rhs = instruction.operands
                width = instruction.width
                lines.extend([
                    f"    uint{width}_t source = {rhs.as_c(width)};",
                    "    if (source == 0) {",
                    "        zf = 1;",
                    "    } else {",
                    "        zf = 0;",
                ])
                if mnemonic == "bsr":
                    lines.extend([
                        f"        uint{width}_t index = {width - 1};",
                        "        while (((source >> index) & 1) == 0) index--;",
                    ])
                else:
                    lines.extend([
                        "        uint64_t index = 0;",
                        "        while (((source >> index) & 1) == 0) index++;",
                    ])
                lines.extend([
                    f"        {lhs.write_c('index', width)}",
                    "    }",
                ])
            elif mnemonic == "xchg":
                lhs, rhs = instruction.operands
                width = instruction.width
                lines.extend([
                    f"    uint{width}_t left = {lhs.as_c(width)};",
                    f"    uint{width}_t right = {rhs.as_c(width)};",
                    f"    {lhs.write_c('right', width)}",
                    f"    {rhs.write_c('left', width)}",
                ])
            elif mnemonic in {"mov", "movaps", "movups", "movapd", "movdqa", "movdqu", "movntps"}:
                lhs, rhs = instruction.operands
                lines.append(f"    {lhs.write_c(rhs.as_c(instruction.width), instruction.width)}")
            elif mnemonic in VECTOR_SHUFFLES:
                lhs, rhs = instruction.operands[:2]
                if mnemonic == "shufpd":
                    immediate = instruction.source_width
                    lines.extend([
                        f"    uint128_t left = {lhs.as_c(128)};",
                        f"    uint128_t right = {rhs.as_c(128)};",
                        f"    uint128_t result = {{left.lanes[{immediate & 1}], right.lanes[{(immediate >> 1) & 1}]}};",
                        f"    {lhs.write_c('result', 128)}",
                    ])
                elif mnemonic == "punpcklwd":
                    lines.extend([
                        f"    uint128_t left = {lhs.as_c(128)};",
                        f"    uint128_t right = {rhs.as_c(128)};",
                        "    uint128_t result = {0, 0};",
                    ])
                    for output in range(8):
                        source = "left" if output % 2 == 0 else "right"
                        index = output // 2
                        word = output // 4
                        shift = output % 4 * 16
                        lines.append(
                            f"    result.lanes[{word}] |= (uint64_t)(({source}.lanes[{index // 4}] >> {index % 4 * 16}) & 0xffff) << {shift};"
                        )
                    lines.append(f"    {lhs.write_c('result', 128)}")
                elif mnemonic in {"movhlps", "movlhps"}:
                    result = "{right.lanes[1], left.lanes[1]}" if mnemonic == "movhlps" else "{left.lanes[0], right.lanes[0]}"
                    lines.extend([
                        f"    uint128_t left = {lhs.as_c(128)};",
                        f"    uint128_t right = {rhs.as_c(128)};",
                        f"    uint128_t result = {result};",
                    ])
                elif mnemonic in {"unpcklpd", "punpcklqdq"}:
                    lines.extend([
                        f"    uint128_t left = {lhs.as_c(128)};",
                        f"    uint128_t right = {rhs.as_c(128)};",
                        "    uint128_t result = {left.lanes[0], right.lanes[0]};",
                    ])
                elif mnemonic == "unpckhpd":
                    lines.extend([
                        f"    uint128_t left = {lhs.as_c(128)};",
                        f"    uint128_t right = {rhs.as_c(128)};",
                        "    uint128_t result = {left.lanes[1], right.lanes[1]};",
                    ])
                else:
                    lines.extend([
                        f"    uint128_t left = {lhs.as_c(128)};",
                        f"    uint128_t right = {rhs.as_c(128)};",
                        "    uint128_t result = {0, 0};",
                    ])
                    for source in (("left", "right") if mnemonic != "pshufd" else ("left",)):
                        lines.append(
                            f"    uint32_t {source}_words[4] = {{(uint32_t){source}.lanes[0], "
                            f"(uint32_t)({source}.lanes[0] >> 32), (uint32_t){source}.lanes[1], "
                            f"(uint32_t)({source}.lanes[1] >> 32)}};"
                        )
                if mnemonic == "pshufd":
                    lines.append("    (void)right;")
                if mnemonic in {"shufps", "pshufd", "unpcklps", "unpckhps", "punpckldq"}:
                    if mnemonic == "pshufd":
                        immediate = instruction.source_width
                        indices = [("left", immediate & 3), ("left", (immediate >> 2) & 3), ("left", (immediate >> 4) & 3), ("left", (immediate >> 6) & 3)]
                    elif mnemonic == "shufps":
                        immediate = instruction.source_width
                        indices = [
                            ("left", immediate & 3), ("left", (immediate >> 2) & 3),
                            ("right", (immediate >> 4) & 3), ("right", (immediate >> 6) & 3),
                        ]
                    elif mnemonic in {"unpcklps", "punpckldq"}:
                        indices = [("left", 0), ("right", 0), ("left", 1), ("right", 1)]
                    else:
                        indices = [("left", 2), ("right", 2), ("left", 3), ("right", 3)]
                    for lane, (source, index) in enumerate(indices):
                        word = lane // 2
                        shift = lane % 2 * 32
                        lines.append(
                            f"    result.lanes[{word}] = (result.lanes[{word}] & ~(UINT64_C(0xffffffff) << {shift})) | "
                            f"((uint64_t){source}_words[{index}] << {shift});"
                        )
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in FLOAT_PACKED_INT_DOUBLE:
                lhs, rhs = instruction.operands
                right_value = f"{{read64({rhs.address_c()}), 0}}" if mnemonic == "pmovsxdq" and rhs.memory else rhs.as_c(128)
                lines.extend([
                    f"    uint128_t right = {right_value};",
                    "    uint128_t result = {0, 0};",
                ])
                for lane in range(2):
                    shift = lane * 32
                    value = (
                        f"(uint64_t)(int64_t)(int32_t)(right.lanes[0] >> {shift})"
                        if mnemonic == "pmovsxdq" else f"bits64((double)(int32_t)(right.lanes[0] >> {shift}))"
                    )
                    lines.append(f"    result.lanes[{lane}] = {value};")
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in FLOAT_PACKED_INT_CONVERSIONS:
                lhs, rhs = instruction.operands
                lines.extend([
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result = {0, 0};",
                ])
                helper = "cvtt32" if mnemonic == "cvttps2dq" else "cvt32"
                for lane in range(4):
                    word = lane // 2
                    shift = lane % 2 * 32
                    lines.append(
                        f"    result.lanes[{word}] |= (uint64_t)(uint32_t){helper}(float32((uint32_t)(right.lanes[{word}] >> {shift}))) << {shift};"
                    )
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in FLOAT_PACKED_FLOAT_CONVERSIONS:
                lhs, rhs = instruction.operands
                right_value = f"{{read64({rhs.address_c()}), 0}}" if mnemonic == "cvtps2pd" and rhs.memory else rhs.as_c(128)
                lines.extend([
                    f"    uint128_t right = {right_value};",
                    "    uint128_t result = {0, 0};",
                ])
                for lane in range(2):
                    if mnemonic == "cvtps2pd":
                        shift = lane * 32
                        lines.append(
                            f"    result.lanes[{lane}] = bits64((double)float32((uint32_t)(right.lanes[0] >> {shift})));"
                        )
                    elif mnemonic == "cvttpd2dq":
                        lines.append(f"    result.lanes[0] |= (uint64_t)(uint32_t)cvttsd32(float64(right.lanes[{lane}])) << {lane * 32};")
                    else:
                        shift = lane * 32
                        lines.append(
                            f"    result.lanes[0] |= (uint64_t)bits32((float)float64(right.lanes[{lane}])) << {shift};"
                        )
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in FLOAT_PACKED_CONVERSIONS:
                lhs, rhs = instruction.operands
                lines.extend([
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result;",
                ])
                for word in range(2):
                    lines.extend([
                        f"    uint32_t low{word} = bits32((float)(int32_t)right.lanes[{word}]);",
                        f"    uint32_t high{word} = bits32((float)(int32_t)(right.lanes[{word}] >> 32));",
                        f"    result.lanes[{word}] = (uint64_t)low{word} | ((uint64_t)high{word} << 32);",
                    ])
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in VECTOR_HORIZONTAL:
                lhs, rhs = instruction.operands
                operator = "+" if mnemonic == "haddps" else "-"
                lines.extend([
                    f"    uint128_t left = {lhs.as_c(128)};",
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result = {0, 0};",
                ])
                for source in ("left", "right"):
                    lines.append(
                        f"    uint32_t {source}_words[4] = {{(uint32_t){source}.lanes[0], "
                        f"(uint32_t)({source}.lanes[0] >> 32), (uint32_t){source}.lanes[1], "
                        f"(uint32_t)({source}.lanes[1] >> 32)}};"
                    )
                for lane in range(4):
                    source = "left" if lane < 2 else "right"
                    index = lane * 2 if lane < 2 else (lane - 2) * 2
                    word = lane // 2
                    shift = lane % 2 * 32
                    lines.append(
                        f"    result.lanes[{word}] |= (uint64_t)bits32(float32({source}_words[{index}]) {operator} "
                        f"float32({source}_words[{index + 1}])) << {shift};"
                    )
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in VECTOR_BYTE_SHIFTS:
                lhs = instruction.operands[0]
                immediate = instruction.source_width
                lines.append(f"    uint128_t left = {lhs.as_c(128)};")
                if immediate == 0:
                    lines.append("    uint128_t result = left;")
                elif immediate >= 16:
                    lines.extend(["    uint128_t result = {0, 0};", "    (void)left;"])
                elif immediate >= 8:
                    bits = (immediate - 8) * 8
                    if mnemonic == "psrldq":
                        lines.append(f"    uint128_t result = {{left.lanes[1] >> {bits}, 0}};")
                    else:
                        lines.append(f"    uint128_t result = {{0, left.lanes[0] << {bits}}};")
                elif mnemonic == "psrldq":
                    bits = immediate * 8
                    lines.extend([
                        "    uint128_t result;",
                        f"    result.lanes[0] = (left.lanes[0] >> {bits}) | (left.lanes[1] << {64 - bits});",
                        f"    result.lanes[1] = left.lanes[1] >> {bits};",
                    ])
                else:
                    bits = immediate * 8
                    lines.extend([
                        "    uint128_t result;",
                        f"    result.lanes[0] = left.lanes[0] << {bits};",
                        f"    result.lanes[1] = (left.lanes[1] << {bits}) | (left.lanes[0] >> {64 - bits});",
                    ])
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic == "paddw":
                lhs, rhs = instruction.operands
                lines.extend([
                    f"    uint128_t left = {lhs.as_c(128)};",
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result = {0, 0};",
                ])
                for lane in range(8):
                    word = lane // 4
                    shift = lane % 4 * 16
                    lines.append(
                        f"    result.lanes[{word}] |= (uint64_t)((((left.lanes[{word}] >> {shift}) & 0xffff) + "
                        f"((right.lanes[{word}] >> {shift}) & 0xffff)) & 0xffff) << {shift};"
                    )
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic == "pmulld":
                lhs, rhs = instruction.operands
                lines.extend([
                    f"    uint128_t left = {lhs.as_c(128)};",
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result = {0, 0};",
                ])
                for source in ("left", "right"):
                    lines.append(
                        f"    uint32_t {source}_words[4] = {{(uint32_t){source}.lanes[0], "
                        f"(uint32_t)({source}.lanes[0] >> 32), (uint32_t){source}.lanes[1], "
                        f"(uint32_t)({source}.lanes[1] >> 32)}};"
                    )
                for lane in range(4):
                    word = lane // 2
                    shift = lane % 2 * 32
                    lines.append(f"    result.lanes[{word}] |= (uint64_t)(left_words[{lane}] * right_words[{lane}]) << {shift};")
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic == "psadbw":
                lhs, rhs = instruction.operands
                lines.extend([
                    f"    uint128_t left = {lhs.as_c(128)};",
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result = {0, 0};",
                ])
                for lane in range(2):
                    for byte in range(8):
                        shift = byte * 8
                        left = f"((left.lanes[{lane}] >> {shift}) & 0xff)"
                        right = f"((right.lanes[{lane}] >> {shift}) & 0xff)"
                        lines.append(f"    result.lanes[{lane}] += {left} > {right} ? {left} - {right} : {right} - {left};")
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in VECTOR_INT_ARITHMETIC:
                lhs, rhs = instruction.operands
                operator = "+" if mnemonic in {"paddd", "paddq"} else "-"
                lines.extend([
                    f"    uint128_t left = {lhs.as_c(128)};",
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result = {0, 0};",
                ])
                for source in ("left", "right"):
                    lines.append(
                        f"    uint32_t {source}_words[4] = {{(uint32_t){source}.lanes[0], "
                        f"(uint32_t)({source}.lanes[0] >> 32), (uint32_t){source}.lanes[1], "
                        f"(uint32_t)({source}.lanes[1] >> 32)}};"
                    )
                for lane in range(4):
                    word = lane // 2
                    shift = lane % 2 * 32
                    lines.append(
                        f"    result.lanes[{word}] |= (uint64_t)(left_words[{lane}] {operator} right_words[{lane}]) << {shift};"
                    )
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in {"psllw", "pslld", "psllq"}:
                lhs = instruction.operands[0]
                immediate = instruction.source_width
                bits = {"psllw": 16, "pslld": 32, "psllq": 64}[mnemonic]
                mask = "UINT64_MAX" if bits == 64 else f"UINT64_C(0x{(1 << bits) - 1:x})"
                lines.append(f"    uint128_t left = {lhs.as_c(128)};")
                count = str(immediate) if immediate >= 0 else f"{instruction.operands[1].register}.lanes[0]"
                lines.extend([
                    f"    uint64_t count = {count};",
                    "    uint128_t result = {0, 0};",
                ])
                for lane in range(128 // bits):
                    word = lane * bits // 64
                    shift = lane * bits % 64
                    lines.append(f"    uint64_t left_word{lane} = (left.lanes[{word}] >> {shift}) & {mask};")
                    lines.append(f"    if (count < {bits}) result.lanes[{word}] |= (uint64_t)((left_word{lane} << count) & {mask}) << {shift};")
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in VECTOR_INT_SHIFTS:
                lhs = instruction.operands[0]
                immediate = instruction.source_width
                lines.append(f"    uint128_t left = {lhs.as_c(128)};")
                if immediate == 0:
                    lines.append("    uint128_t result = left;")
                else:
                    lines.append("    uint128_t result = {0, 0};")
                    if mnemonic in {"psrld", "pslld", "psrad"}:
                        lines.append("    uint32_t left_words[4] = {(uint32_t)left.lanes[0], (uint32_t)(left.lanes[0] >> 32), (uint32_t)left.lanes[1], (uint32_t)(left.lanes[1] >> 32)};")
                        for lane in range(4):
                            word = lane // 2
                            shift = lane % 2 * 32
                            if mnemonic == "psrad":
                                value = f"(uint32_t)((int32_t)left_words[{lane}] >> {min(immediate, 31)})"
                            elif immediate < 32:
                                operator = ">>" if mnemonic == "psrld" else "<<"
                                value = f"left_words[{lane}] {operator} {immediate}"
                            else:
                                continue
                            lines.append(f"    result.lanes[{word}] |= (uint64_t)({value}) << {shift};")
                    elif immediate < 64:
                        for lane in range(2):
                            operator = ">>" if mnemonic == "psrlq" else "<<"
                            lines.append(f"    result.lanes[{lane}] = left.lanes[{lane}] {operator} {immediate};")
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in VECTOR_INT_COMPARE:
                lhs, rhs = instruction.operands
                lines.extend([
                    f"    uint128_t left = {lhs.as_c(128)};",
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result = {0, 0};",
                ])
                for source in ("left", "right"):
                    lines.append(
                        f"    uint32_t {source}_words[4] = {{(uint32_t){source}.lanes[0], "
                        f"(uint32_t)({source}.lanes[0] >> 32), (uint32_t){source}.lanes[1], "
                        f"(uint32_t)({source}.lanes[1] >> 32)}};"
                    )
                for lane in range(4):
                    word = lane // 2
                    shift = lane % 2 * 32
                    comparison = (
                        f"(int32_t)left_words[{lane}] > (int32_t)right_words[{lane}]"
                        if mnemonic == "pcmpgtd" else f"left_words[{lane}] == right_words[{lane}]"
                    )
                    lines.append(
                        f"    result.lanes[{word}] |= ({comparison} ? "
                        f"UINT64_C(0xffffffff) : 0) << {shift};"
                    )
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in VECTOR_DOUBLE_COMPARE:
                lhs, rhs = instruction.operands
                comparison = {"cmpeqpd": "==", "cmpltpd": "<", "cmplepd": "<=", "cmpneqpd": "!=", "cmpnltpd": ">="}[mnemonic]
                lines.extend([
                    f"    uint128_t left = {lhs.as_c(128)};",
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result = {0, 0};",
                ])
                for lane in range(2):
                    expression = (
                        f"!(float64(left.lanes[{lane}]) < float64(right.lanes[{lane}]))"
                        if mnemonic == "cmpnltpd" else f"float64(left.lanes[{lane}]) {comparison} float64(right.lanes[{lane}])"
                    )
                    lines.append(f"    result.lanes[{lane}] = {expression} ? UINT64_MAX : 0;")
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in VECTOR_COMPARE:
                lhs, rhs = instruction.operands
                comparison = {"cmpeqps": "==", "cmpltps": "<", "cmpleps": "<=", "cmpneqps": "!="}[mnemonic]
                lines.extend([
                    f"    uint128_t left = {lhs.as_c(128)};",
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result = {0, 0};",
                ])
                for source in ("left", "right"):
                    lines.append(
                        f"    uint32_t {source}_words[4] = {{(uint32_t){source}.lanes[0], "
                        f"(uint32_t)({source}.lanes[0] >> 32), (uint32_t){source}.lanes[1], "
                        f"(uint32_t)({source}.lanes[1] >> 32)}};"
                    )
                for lane in range(4):
                    word = lane // 2
                    shift = lane % 2 * 32
                    lines.append(
                        f"    result.lanes[{word}] |= (float32(left_words[{lane}]) {comparison} float32(right_words[{lane}]) ? "
                        f"UINT64_C(0xffffffff) : 0) << {shift};"
                    )
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic == "pextrw":
                lhs, rhs = instruction.operands
                immediate = instruction.source_width
                lines.extend([
                    f"    uint128_t right = {rhs.as_c(128)};",
                    f"    {lhs.write_c(f'(right.lanes[{immediate // 4}] >> {immediate % 4 * 16}) & 0xffff', instruction.width)}",
                ])
            elif mnemonic == "vpminsw":
                destination, left_operand, right_operand = instruction.operands
                lines.extend([
                    f"    uint128_t left = {left_operand.as_c(128)};",
                    f"    uint128_t right = {right_operand.as_c(128)};",
                    "    uint128_t result = {0, 0};",
                ])
                for lane in range(8):
                    word = lane // 4
                    shift = lane % 4 * 16
                    left = f"((left.lanes[{word}] >> {shift}) & 0xffff)"
                    right = f"((right.lanes[{word}] >> {shift}) & 0xffff)"
                    lines.append(
                        f"    result.lanes[{word}] |= (uint64_t)((int16_t){left} < (int16_t){right} ? {left} : {right}) << {shift};"
                    )
                lines.append(f"    {destination.write_c('result', 128)}")
            elif mnemonic == "pinsrw":
                lhs, rhs, immediate = instruction.operands
                index = immediate.value
                lane = index // 4
                shift = index % 4 * 16
                right_value = f"read16({rhs.address_c()})" if rhs.memory else f"(uint16_t){rhs.as_c(32)}"
                lines.extend([
                    f"    uint128_t result = {lhs.as_c(128)};",
                    f"    result.lanes[{lane}] = (result.lanes[{lane}] & ~(UINT64_C(0xffff) << {shift})) | ((uint64_t)({right_value}) << {shift});",
                    f"    {lhs.write_c('result', 128)}",
                ])
            elif mnemonic in {"movmskps", "pmovmskb", "movmskpd"}:
                lhs, rhs = instruction.operands
                lines.extend([
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint32_t result = 0;",
                ])
                if mnemonic == "movmskps":
                    for lane in range(4):
                        word = lane // 2
                        shift = lane % 2 * 32 + 31
                        lines.append(f"    result |= (uint32_t)((right.lanes[{word}] >> {shift}) & 1) << {lane};")
                elif mnemonic == "pmovmskb":
                    for lane in range(16):
                        word = lane // 8
                        shift = lane % 8 * 8 + 7
                        lines.append(f"    result |= (uint32_t)((right.lanes[{word}] >> {shift}) & 1) << {lane};")
                else:
                    for lane in range(2):
                        lines.append(f"    result |= (uint32_t)((right.lanes[{lane}] >> 63) & 1) << {lane};")
                lines.append(f"    {lhs.write_c('result', 32)}")
            elif mnemonic in VECTOR_ADDSUB:
                lhs, rhs = instruction.operands
                lines.extend([
                    f"    uint128_t left = {lhs.as_c(128)};",
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result = {0, 0};",
                ])
                for source in ("left", "right"):
                    lines.append(
                        f"    uint32_t {source}_words[4] = {{(uint32_t){source}.lanes[0], "
                        f"(uint32_t)({source}.lanes[0] >> 32), (uint32_t){source}.lanes[1], "
                        f"(uint32_t)({source}.lanes[1] >> 32)}};"
                    )
                for lane in range(4):
                    operator = "-" if lane % 2 == 0 else "+"
                    word = lane // 2
                    shift = lane % 2 * 32
                    lines.append(
                        f"    result.lanes[{word}] |= (uint64_t)bits32(float32(left_words[{lane}]) {operator} "
                        f"float32(right_words[{lane}])) << {shift};"
                    )
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in {*FLOAT_VECTOR, "andps", "andnps", "andpd", "orps", "pand", "pandn", "por", "pxor", "xorpd"}:
                lhs, rhs = instruction.operands
                if mnemonic in {"andps", "andnps", "andpd", "orps", "pand", "pandn", "por", "pxor", "xorpd"}:
                    operator = "|" if mnemonic in {"orps", "por"} else "^" if mnemonic in {"pxor", "xorpd"} else "&"
                    left = f"~left.lanes[0]" if mnemonic in {"andnps", "pandn"} else "left.lanes[0]"
                    second = f"~left.lanes[1]" if mnemonic in {"andnps", "pandn"} else "left.lanes[1]"
                    lines.extend([
                        f"    uint128_t left = {lhs.as_c(128)};",
                        f"    uint128_t right = {rhs.as_c(128)};",
                        f"    uint128_t result = {{{left} {operator} right.lanes[0], {second} {operator} right.lanes[1]}};",
                        f"    {lhs.write_c('result', 128)}",
                    ])
                else:
                    operator = {"addps": "+", "subps": "-", "mulps": "*", "divps": "/"}[mnemonic]
                    lines.extend([
                        f"    uint128_t left = {lhs.as_c(128)};",
                        f"    uint128_t right = {rhs.as_c(128)};",
                        "    uint128_t result = left;",
                    ])
                    for lane in range(4):
                        word = lane // 2
                        shift = lane % 2 * 32
                        left_value = f"(uint32_t)(left.lanes[{word}] >> {shift})"
                        right_value = f"(uint32_t)(right.lanes[{word}] >> {shift})"
                        lines.append(
                            f"    result.lanes[{word}] = (result.lanes[{word}] & ~(UINT64_C(0xffffffff) << {shift})) | "
                            f"((uint64_t)bits32(float32({left_value}) {operator} float32({right_value})) << {shift});"
                        )
                    lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in {"movhpd", "movlps", "movhps"}:
                lhs, rhs = instruction.operands
                lane = 0 if mnemonic == "movlps" else 1
                if lhs.register in XMM_REGISTERS:
                    lines.extend([
                        f"    uint128_t result = {lhs.as_c(128)};",
                        f"    result.lanes[{lane}] = read64({rhs.address_c()});",
                        f"    {lhs.write_c('result', 128)}",
                    ])
                else:
                    lines.append(f"    write64({lhs.address_c()}, {rhs.register}.lanes[{lane}]);")
            elif mnemonic in {"movd", "movq"}:
                lhs, rhs = instruction.operands
                width = instruction.width
                if lhs.register in XMM_REGISTERS:
                    right_value = f"{rhs.register}.lanes[0]" if rhs.register in XMM_REGISTERS else rhs.as_c(width)
                    lines.extend([
                        "    uint128_t result = {{0, 0}};",
                        f"    result.lanes[0] = (uint64_t)({right_value});",
                        f"    {lhs.write_c('result', 128)}",
                    ])
                else:
                    lines.append(f"    {lhs.write_c(f'{rhs.register}.lanes[0]', width)}")
            elif mnemonic in FLOAT_APPROX_SCALAR:
                lhs, rhs = instruction.operands
                helper = "rsqrt32" if mnemonic == "rsqrtss" else "rcp32"
                right_value = f"read32({rhs.address_c()})" if rhs.memory else f"(uint32_t){rhs.register}.lanes[0]"
                lines.extend([
                    f"    uint128_t result = {lhs.as_c(128)};",
                    f"    result.lanes[0] = (result.lanes[0] & ~UINT64_C(0xffffffff)) | {helper}({right_value});",
                    f"    {lhs.write_c('result', 128)}",
                ])
            elif mnemonic in FLOAT_APPROX_VECTOR:
                lhs, rhs = instruction.operands
                helper = "rsqrt32" if mnemonic == "rsqrtps" else "rcp32"
                lines.extend([
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result = {0, 0};",
                ])
                for lane in range(4):
                    word = lane // 2
                    shift = lane % 2 * 32
                    lines.append(f"    result.lanes[{word}] |= (uint64_t){helper}((uint32_t)(right.lanes[{word}] >> {shift})) << {shift};")
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in FLOAT_SQRT_VECTOR:
                lhs, rhs = instruction.operands
                lines.extend([
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result = {0, 0};",
                ])
                if mnemonic == "sqrtps":
                    for lane in range(4):
                        word = lane // 2
                        shift = lane % 2 * 32
                        lines.append(
                            f"    result.lanes[{word}] |= (uint64_t)bits32(sqrtf(float32((uint32_t)(right.lanes[{word}] >> {shift})))) << {shift};"
                        )
                else:
                    for lane in range(2):
                        lines.append(f"    result.lanes[{lane}] = bits64(sqrt(float64(right.lanes[{lane}])));")
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in VECTOR_DOUBLE_HORIZONTAL:
                lhs, rhs = instruction.operands
                operator = "+" if mnemonic == "haddpd" else "-"
                lines.extend([
                    f"    uint128_t left = {lhs.as_c(128)};",
                    f"    uint128_t right = {rhs.as_c(128)};",
                    f"    uint128_t result = {{bits64(float64(left.lanes[0]) {operator} float64(left.lanes[1])), bits64(float64(right.lanes[0]) {operator} float64(right.lanes[1]))}};",
                    f"    {lhs.write_c('result', 128)}",
                ])
            elif mnemonic in FLOAT_DOUBLE_VECTOR:
                lhs, rhs = instruction.operands
                lines.extend([
                    f"    uint128_t left = {lhs.as_c(128)};",
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result;",
                ])
                operator = {"addpd": "+", "subpd": "-", "mulpd": "*", "divpd": "/"}[mnemonic]
                for lane in range(2):
                    lines.append(
                        f"    result.lanes[{lane}] = bits64(float64(left.lanes[{lane}]) {operator} float64(right.lanes[{lane}]));"
                    )
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in FLOAT_PACKED_MINMAX:
                lhs, rhs = instruction.operands
                comparison = ">" if mnemonic == "maxps" else "<"
                lines.extend([
                    f"    uint128_t left = {lhs.as_c(128)};",
                    f"    uint128_t right = {rhs.as_c(128)};",
                    "    uint128_t result = {0, 0};",
                ])
                for source in ("left", "right"):
                    lines.append(
                        f"    uint32_t {source}_words[4] = {{(uint32_t){source}.lanes[0], "
                        f"(uint32_t)({source}.lanes[0] >> 32), (uint32_t){source}.lanes[1], "
                        f"(uint32_t)({source}.lanes[1] >> 32)}};"
                    )
                for lane in range(4):
                    word = lane // 2
                    shift = lane % 2 * 32
                    lines.extend([
                        f"    float left{lane} = float32(left_words[{lane}]);",
                        f"    float right{lane} = float32(right_words[{lane}]);",
                        f"    float selected{lane} = left{lane} {comparison} right{lane} ? left{lane} : right{lane};",
                        f"    result.lanes[{word}] |= (uint64_t)bits32(selected{lane}) << {shift};",
                    ])
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in FLOAT_DOUBLE_MINMAX:
                lhs, rhs = instruction.operands
                right_bits = f"read64({rhs.address_c()})" if rhs.memory else f"{rhs.register}.lanes[0]"
                comparison = ">" if mnemonic == "maxsd" else "<"
                lines.extend([
                    f"    uint128_t result = {lhs.as_c(128)};",
                    f"    double left = float64({lhs.register}.lanes[0]);",
                    f"    double right = float64({right_bits});",
                    f"    double selected = left {comparison} right ? left : right;",
                    "    result.lanes[0] = bits64(selected);",
                    f"    {lhs.write_c('result', 128)}",
                ])
            elif mnemonic in FLOAT_DOUBLE_SCALAR:
                lhs, rhs = instruction.operands
                right_bits = f"read64({rhs.address_c()})" if rhs.memory else f"{rhs.register}.lanes[0]"
                operator = {"addsd": "+", "subsd": "-", "mulsd": "*", "divsd": "/"}[mnemonic]
                lines.extend([
                    f"    uint128_t result = {lhs.as_c(128)};",
                    f"    double left = float64({lhs.register}.lanes[0]);",
                    f"    double right = float64({right_bits});",
                    f"    result.lanes[0] = bits64(left {operator} right);",
                    f"    {lhs.write_c('result', 128)}",
                ])
            elif mnemonic in FLOAT_SQRT:
                lhs, rhs = instruction.operands
                lines.append(f"    uint128_t result = {lhs.as_c(128)};")
                if mnemonic == "sqrtss":
                    right_bits = f"read32({rhs.address_c()})" if rhs.memory else f"(uint32_t){rhs.register}.lanes[0]"
                    lines.extend([
                        f"    float right = float32({right_bits});",
                        "    result.lanes[0] = (result.lanes[0] & ~UINT64_C(0xffffffff)) | bits32(sqrtf(right));",
                    ])
                else:
                    right_bits = f"read64({rhs.address_c()})" if rhs.memory else f"{rhs.register}.lanes[0]"
                    lines.extend([
                        f"    double right = float64({right_bits});",
                        "    result.lanes[0] = bits64(sqrt(right));",
                    ])
                lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic in FLOAT_MINMAX:
                lhs, rhs = instruction.operands
                right_bits = f"read32({rhs.address_c()})" if rhs.memory else f"(uint32_t){rhs.register}.lanes[0]"
                comparison = ">" if mnemonic == "maxss" else "<"
                lines.extend([
                    f"    uint128_t result = {lhs.as_c(128)};",
                    f"    float left = float32((uint32_t){lhs.register}.lanes[0]);",
                    f"    float right = float32({right_bits});",
                    f"    float selected = left {comparison} right ? left : right;",
                    "    result.lanes[0] = (result.lanes[0] & ~UINT64_C(0xffffffff)) | bits32(selected);",
                    f"    {lhs.write_c('result', 128)}",
                ])
            elif mnemonic in FLOAT_SCALAR:
                lhs, rhs = instruction.operands
                right_bits = f"read32({rhs.address_c()})" if rhs.memory else f"(uint32_t){rhs.register}.lanes[0]"
                operator = {"addss": "+", "subss": "-", "mulss": "*", "divss": "/"}[mnemonic]
                lines.extend([
                    f"    uint128_t result = {lhs.as_c(128)};",
                    f"    float left = float32((uint32_t){lhs.register}.lanes[0]);",
                    f"    float right = float32({right_bits});",
                    f"    result.lanes[0] = (result.lanes[0] & ~UINT64_C(0xffffffff)) | bits32(left {operator} right);",
                    f"    {lhs.write_c('result', 128)}",
                ])
            elif mnemonic == "cvtss2sd":
                lhs, rhs = instruction.operands
                right_bits = f"read32({rhs.address_c()})" if rhs.memory else f"(uint32_t){rhs.register}.lanes[0]"
                lines.extend([
                    f"    uint128_t result = {lhs.as_c(128)};",
                    f"    float right = float32({right_bits});",
                    "    result.lanes[0] = bits64((double)right);",
                    f"    {lhs.write_c('result', 128)}",
                ])
            elif mnemonic == "cvtsi2sd":
                lhs, rhs = instruction.operands
                right_value = rhs.as_c(instruction.source_width)
                lines.extend([
                    f"    uint128_t result = {lhs.as_c(128)};",
                    f"    result.lanes[0] = bits64((double)(int{instruction.source_width}_t){right_value});",
                    f"    {lhs.write_c('result', 128)}",
                ])
            elif mnemonic == "cvttsd2si":
                lhs, rhs = instruction.operands
                right_bits = f"read64({rhs.address_c()})" if rhs.memory else f"{rhs.register}.lanes[0]"
                lines.append(
                    f"    {lhs.write_c(f'cvttsd{instruction.source_width}(float64({right_bits}))', instruction.source_width)}"
                )
            elif mnemonic == "cvtsd2ss":
                lhs, rhs = instruction.operands
                right_value = f"read64({rhs.address_c()})" if rhs.memory else f"{rhs.register}.lanes[0]"
                lines.extend([
                    f"    uint128_t result = {lhs.as_c(128)};",
                    f"    double right = float64({right_value});",
                    "    result.lanes[0] = (result.lanes[0] & ~UINT64_C(0xffffffff)) | bits32((float)right);",
                    f"    {lhs.write_c('result', 128)}",
                ])
            elif mnemonic in {"cvttss2si", "cvtss2si"}:
                lhs, rhs = instruction.operands
                right_bits = f"read32({rhs.address_c()})" if rhs.memory else f"(uint32_t){rhs.register}.lanes[0]"
                helper = "cvtt" if mnemonic == "cvttss2si" else "cvt"
                lines.append(
                    f"    {lhs.write_c(f'{helper}{instruction.source_width}(float32({right_bits}))', instruction.source_width)}"
                )
            elif mnemonic == "cvtsi2ss":
                lhs, rhs = instruction.operands
                right_value = rhs.as_c(instruction.source_width)
                lines.extend([
                    f"    uint128_t result = {lhs.as_c(128)};",
                    f"    float right = (float)(int{instruction.source_width}_t){right_value};",
                    "    result.lanes[0] = (result.lanes[0] & ~UINT64_C(0xffffffff)) | bits32(right);",
                    f"    {lhs.write_c('result', 128)}",
                ])
            elif mnemonic in FLOAT_COMPARE_DOUBLE:
                lhs, rhs = instruction.operands
                left_bits = f"{lhs.register}.lanes[0]"
                right_bits = f"read64({rhs.address_c()})" if rhs.memory else f"{rhs.register}.lanes[0]"
                lines.extend([
                    f"    double left = float64({left_bits});",
                    f"    double right = float64({right_bits});",
                    "    int unordered = isnan(left) || isnan(right);",
                ])
                formulas = {
                    "cf": "unordered || left < right",
                    "zf": "unordered || left == right",
                    "pf": "unordered",
                    "of": "0", "sf": "0", "af": "0",
                }
                lines.extend(f"    {flag} = {formulas[flag]};" for flag in flags)
            elif mnemonic in SCALAR_COMPARE:
                lhs, rhs = instruction.operands
                comparison = {"cmpless": "<=", "cmpltss": "<", "cmpleqss": "<="}[mnemonic]
                lines.extend([
                    f"    uint128_t result = {lhs.as_c(128)};",
                    f"    uint32_t left = (uint32_t){lhs.register}.lanes[0];",
                    f"    uint32_t right = {f'(uint32_t){rhs.register}.lanes[0]' if rhs.register in XMM_REGISTERS else rhs.as_c(32)};",
                    f"    result.lanes[0] = (result.lanes[0] & ~UINT64_C(0xffffffff)) | (float32(left) {comparison} float32(right) ? UINT64_C(0xffffffff) : 0);",
                    f"    {lhs.write_c('result', 128)}",
                ])
            elif mnemonic in {"comiss", "ucomiss"}:
                lhs, rhs = instruction.operands
                left_bits = f"(uint32_t){lhs.register}.lanes[0]"
                right_bits = f"read32({rhs.address_c()})" if rhs.memory else f"(uint32_t){rhs.register}.lanes[0]"
                lines.extend([
                    f"    float left = float32({left_bits});",
                    f"    float right = float32({right_bits});",
                    "    int unordered = isnan(left) || isnan(right);",
                ])
                formulas = {
                    "cf": "unordered || left < right",
                    "zf": "unordered || left == right",
                    "pf": "unordered",
                    "of": "0", "sf": "0", "af": "0",
                }
                lines.extend(f"    {flag} = {formulas[flag]};" for flag in flags)
            elif mnemonic in {"movss", "movsd"}:
                lhs, rhs = instruction.operands
                width = instruction.width
                mask = f"UINT64_C(0x{(1 << width) - 1:x})"
                if lhs.memory:
                    lines.append(f"    {lhs.write_c(f'{rhs.register}.lanes[0]', width)}")
                else:
                    if rhs.memory:
                        lines.append("    uint128_t result = {{0, 0}};")
                        lines.append(f"    result.lanes[0] = (uint64_t)(read{width}({rhs.address_c()}));")
                    else:
                        lines.append(f"    uint128_t result = {lhs.as_c(128)};")
                        lines.append(
                            f"    result.lanes[0] = (result.lanes[0] & ~{mask}) | ({rhs.register}.lanes[0] & {mask});"
                        )
                    lines.append(f"    {lhs.write_c('result', 128)}")
            elif mnemonic == "xorps":
                lhs, rhs = instruction.operands
                if lhs == rhs:
                    lines.append(f"    {lhs.write_c('(uint128_t){{0, 0}}', 128)}")
                else:
                    lines.extend([
                        f"    uint128_t left = {lhs.as_c(128)};",
                        f"    uint128_t right = {rhs.as_c(128)};",
                        "    uint128_t result = {{left.lanes[0] ^ right.lanes[0], left.lanes[1] ^ right.lanes[1]}};",
                        f"    {lhs.write_c('result', 128)}",
                    ])
            elif mnemonic == "lock cmpxchg":
                lhs, rhs = instruction.operands
                width = instruction.width
                c_type = f"uint{width}_t"
                sign_bit = f"UINT{width}_C(0x{1 << (width - 1):x})"
                lines.extend([
                    f"    {c_type} left = {lhs.as_c(width)};",
                    f"    {c_type} source = {rhs.as_c(width)};",
                    f"    {c_type} accumulator = ({c_type})rax;",
                    f"    {c_type} result = ({c_type})(accumulator - left);",
                    "    (void)result;",
                ])
                formulas = {
                    "cf": "accumulator < left",
                    "of": f"((accumulator ^ left) & (accumulator ^ result) & {sign_bit}) != 0",
                    "sf": f"(result & {sign_bit}) != 0",
                    "zf": "accumulator == left",
                    "pf": "parity(result)",
                    "af": "((accumulator ^ left ^ result) & 0x10) != 0",
                }
                lines.extend(f"    {flag} = {formulas[flag]};" for flag in flags if flag in formulas)
                lines.extend([
                    "    if (accumulator == left) {",
                    f"        {lhs.write_c('source', width)}",
                    "    } else {",
                    f"        {Operand('rax').write_c('left', width)}",
                    "    }",
                ])
            elif mnemonic == "lock xadd":
                lhs, rhs = instruction.operands
                width = instruction.width
                c_type = f"uint{width}_t"
                sign_bit = f"UINT{width}_C(0x{1 << (width - 1):x})"
                lines.extend([
                    f"    {c_type} left = {lhs.as_c(width)};",
                    f"    {c_type} right = {rhs.as_c(width)};",
                    f"    {c_type} result = ({c_type})(left + right);",
                    f"    {lhs.write_c('result', width)}",
                    f"    {rhs.write_c('left', width)}",
                ])
                formulas = {
                    "cf": "result < left",
                    "of": f"((left ^ result) & (right ^ result) & {sign_bit}) != 0",
                    "sf": f"(result & {sign_bit}) != 0",
                    "zf": "result == 0",
                    "pf": "parity(result)",
                    "af": "((left ^ right ^ result) & 0x10) != 0",
                }
                lines.extend(f"    {flag} = {formulas[flag]};" for flag in flags if flag in formulas)
            elif mnemonic == "repne scasw":
                sign_bit = f"UINT16_C(0x8000)"
                lines.extend([
                    "    while (rcx != 0) {",
                    "        uint16_t left = (uint16_t)rax;",
                    "        uint16_t right = read16(rdi);",
                    "        uint16_t result = (uint16_t)(left - right);",
                    "        rdi += 2;",
                    "        rcx -= 1;",
                ])
                formulas = {
                    "cf": "left < right",
                    "of": f"((left ^ right) & (left ^ result) & {sign_bit}) != 0",
                    "sf": "(result & 0x8000) != 0",
                    "zf": "result == 0",
                    "pf": "parity(result)",
                    "af": "((left ^ right ^ result) & 0x10) != 0",
                }
                lines.extend(f"        {flag} = {formulas[flag]};" for flag in flags if flag in formulas)
                lines.extend([
                    "        if (result == 0) break;",
                    "    }",
                ])
            elif mnemonic == "string movs":
                lines.extend([
                    "    write32(rdi, read32(rsi));",
                    "    rdi += 4;",
                    "    rsi += 4;",
                ])
            elif mnemonic in STRING_OPERATIONS:
                width = instruction.width
                value = f"read{width}(rsi)" if mnemonic.startswith("rep movs") else f"(uint{width}_t)rax"
                lines.extend([
                    "    while (rcx != 0) {",
                    f"        write{width}(rdi, {value});",
                    f"        rdi += {width // 8};",
                ])
                if mnemonic.startswith("rep movs"):
                    lines.append(f"        rsi += {width // 8};")
                lines.extend([
                    "        rcx -= 1;",
                    "    }",
                ])
            elif mnemonic in ARITHMETIC:
                lines.extend(f"    {line}" for line in arithmetic_to_c(instruction, flags))
            elif mnemonic in {"inc", "dec"}:
                lines.extend(f"    {line}" for line in unary_to_c(instruction, flags))
            elif mnemonic in {"idiv", "div"}:
                source = instruction.operands[0]
                prefix = "i" if mnemonic == "idiv" else "u"
                width = instruction.width
                lines.extend([
                    f"uint{width}_t quotient = 0;",
                    f"uint{width}_t remainder = 0;",
                    f"if (!{prefix}div{width}_impl((uint{width}_t)rax, (uint{width}_t)rdx, {source.as_c(width)}, &quotient, &remainder)) {{",
                    f"    recomp_cpu_trap(cpu, UINT64_C(0x{address:x}));",
                    "    return;",
                    "}",
                    f"rax = (uint{width}_t)quotient;",
                    f"rdx = (uint{width}_t)remainder;",
                ])
            elif mnemonic in {"imul", "mul"}:
                lines.extend(f"    {line}" for line in imul_to_c(instruction, flags))
            elif mnemonic == "lea":
                lhs, rhs = instruction.operands
                lines.append(f"    {lhs.write_c(rhs.address_c(), instruction.width)}")
            elif mnemonic in SET_CONDITIONS:
                operand = instruction.operands[0]
                lines.append(f"    {operand.write_c(f'({CONDITIONS[mnemonic]}) ? 1 : 0', 8)}")
            elif mnemonic in {"movzx", "movsx"}:
                lhs, rhs = instruction.operands
                value = rhs.as_c(instruction.source_width)
                if mnemonic == "movsx":
                    value = f"(int64_t)(int{instruction.source_width}_t){value}"
                lines.append(f"    {lhs.write_c(value, instruction.width)}")
            elif mnemonic == "cwde":
                lines.append("    rax = (uint32_t)(int32_t)(int16_t)rax;")
            elif mnemonic == "cdq":
                lines.append(f"    rdx = (uint32_t)((int32_t)rax < 0 ? UINT32_C(0xffffffff) : 0);")
            elif mnemonic == "cqo":
                lines.append("    rdx = (uint64_t)((int64_t)rax < 0 ? UINT64_MAX : 0);")
            elif mnemonic == "cdqe":
                lines.append("    rax = (uint64_t)(int64_t)(int32_t)rax;")
            elif mnemonic in {"bt", "btr", "bts", "btc"}:
                lhs, index = instruction.operands
                index_expression = str(index.value) if index.value is not None else f"(uint64_t)({index.as_c(64)}) & {63 if instruction.width == 64 else 31}"
                lines.append(f"    uint64_t index = {index_expression};")
                lines.append("    uint64_t mask = index < 64 ? UINT64_C(1) << index : 0;")
                if "cf" in flags:
                    lines.append(f"    cf = ({lhs.as_c(instruction.width)} & mask) != 0;")
                if mnemonic != "bt":
                    operator = "& ~" if mnemonic == "btr" else "^" if mnemonic == "btc" else "|"
                    lines.append(f"    {lhs.write_c(f'{lhs.as_c(instruction.width)} {operator}mask', instruction.width)}")
            elif mnemonic in CARRY_ROTATES:
                lhs = instruction.operands[0]
                count = instruction.source_width % (instruction.width + 1)
                width = instruction.width
                if count:
                    sign_bit = f"UINT{width}_C(0x{1 << (width - 1):x})"
                    lines.extend([
                        f"    uint{width}_t left = {lhs.as_c(width)};",
                        f"    uint{width}_t result = left;",
                        "    uint64_t next_cf = cf;",
                        f"    uint64_t count = {count};",
                        "    while (count-- != 0) {",
                        "        next_cf = cf;",
                    ])
                    if mnemonic == "rcl":
                        lines.extend([
                            f"        cf = (result >> {width - 1}) & 1;",
                            f"        result = (uint{width}_t)((result << 1) | next_cf);",
                        ])
                    else:
                        lines.extend([
                            "        cf = result & 1;",
                            f"        result = (uint{width}_t)((result >> 1) | (next_cf << {width - 1}));",
                        ])
                    lines.append("    }")
                    if "of" in flags:
                        overflow = f"(((result >> {width - 1}) ^ cf) & 1) != 0" if mnemonic == "rcl" else f"((left ^ result) & {sign_bit}) != 0"
                        lines.append(f"    of = {overflow};")
                    lines.append(f"    {lhs.write_c('result', width)}")
            elif mnemonic in DOUBLE_SHIFTS:
                lhs, rhs = instruction.operands
                count = instruction.source_width
                width = instruction.width
                if count:
                    sign_bit = f"UINT{width}_C(0x{1 << (width - 1):x})"
                    if mnemonic == "shld":
                        result = f"((uint64_t)left << {count}) | ((uint64_t)right >> {width - count})"
                        carry = f"(left >> {width - count}) & 1"
                    else:
                        result = f"((uint64_t)left >> {count}) | ((uint64_t)right << {width - count})"
                        carry = f"(left >> {count - 1}) & 1"
                    lines.extend([
                        f"    uint{width}_t left = {lhs.as_c(width)};",
                        f"    uint{width}_t right = {rhs.as_c(width)};",
                        f"    uint{width}_t result = (uint{width}_t)({result});",
                    ])
                    formulas = {
                        "cf": carry,
                        "of": f"((left ^ result) & {sign_bit}) != 0",
                        "sf": f"(result & {sign_bit}) != 0",
                        "zf": "result == 0",
                        "pf": "parity(result)",
                        "af": "0",
                    }
                    lines.extend(f"    {flag} = {formulas[flag]};" for flag in flags)
                    lines.append(f"    {lhs.write_c('result', width)}")
            elif mnemonic in SHIFTS:
                lines.extend(f"    {line}" for line in shift_to_c(instruction, flags))
            elif mnemonic == "neg":
                lines.extend(f"    {line}" for line in neg_to_c(instruction, flags))
            elif mnemonic == "not":
                operand = instruction.operands[0]
                lines.append(f"    {operand.write_c(f'~{operand.as_c(instruction.width)}', instruction.width)}")
            elif mnemonic == "movsxd":
                lhs, rhs = instruction.operands
                lines.append(f"    {lhs.write_c(f'(int64_t)(int32_t){rhs.as_c(32)}', 64)}")
            elif mnemonic in CONDITIONAL_MOVES:
                lhs, rhs = instruction.operands
                lines.append(f"    if ({CONDITIONS[mnemonic]}) {{")
                lines.append(f"        {lhs.write_c(rhs.as_c(instruction.width), instruction.width)}")
                lines.append("    }")
            elif mnemonic == "sahf":
                if flags:
                    lines.append("    uint64_t value = (rax >> 8) & 0xff;")
                    bits = {"cf": 0, "pf": 2, "af": 4, "zf": 6, "sf": 7}
                    lines.extend(f"    {flag} = (value >> {bits[flag]}) & 1;" for flag in flags if flag in bits)
            elif mnemonic in {"stc", "cmc"}:
                lines.append("    cf = 1;" if mnemonic == "stc" else "    cf = !cf;")
            elif mnemonic == "pushfq":
                lines.extend([
                    "    rsp -= 8;",
                    "    write64(rsp, UINT64_C(0x202) | (uint64_t)cf | ((uint64_t)pf << 2) | ((uint64_t)af << 4) | ((uint64_t)zf << 6) | ((uint64_t)sf << 7) | ((uint64_t)of << 11));",
                ])
            elif mnemonic == "crc32":
                lhs, rhs = instruction.operands
                width = instruction.width
                destination_width = instruction.source_width
                source = rhs.as_c(width)
                lines.append(
                    f"    {lhs.write_c(f'_mm_crc32_u{width}((uint{destination_width}_t){lhs.as_c(destination_width)}, {source})', destination_width)}"
                )
            elif mnemonic == "xgetbv":
                lines.extend([
                    "    uint64_t value = _xgetbv((unsigned int)rcx);",
                    "    rax = (uint32_t)value;",
                    "    rdx = (uint32_t)(value >> 32);",
                ])
            elif mnemonic == "cpuid":
                lines.extend([
                    "    int info[4];",
                    "    __cpuidex(info, (int)rax, (int)rcx);",
                    "    rax = (uint32_t)info[0];",
                    "    rbx = (uint32_t)info[1];",
                    "    rcx = (uint32_t)info[2];",
                    "    rdx = (uint32_t)info[3];",
                ])
            elif mnemonic == "popfq":
                lines.append("    rsp += 8;")
                if flags:
                    lines.append("    uint64_t value = read64(rsp - 8);")
                    bits = {"cf": 0, "pf": 2, "af": 4, "zf": 6, "sf": 7, "of": 11}
                    lines.extend(f"    {flag} = (value >> {bits[flag]}) & 1;" for flag in flags)
            elif mnemonic == "push":
                operand = instruction.operands[0]
                lines.append("    rsp -= 8;")
                lines.append(f"    write64(rsp, {operand.as_c(64)});")
            elif mnemonic == "pop":
                operand = instruction.operands[0]
                lines.append(f"    {operand.write_c('read64(rsp)', 64)}")
                lines.append("    rsp += 8;")
            elif mnemonic in CONDITIONAL_JUMPS:
                target = instruction.successors[0]
                lines.append(f"    if ({CONDITIONS[mnemonic]}) goto rva_{target:x};")
            if mnemonic not in {"tail", "trap"}:
                lines.append(f"    goto rva_{instruction.successors[-1]:x};")
        lines.append("}")
    lines.extend(["}", ""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="x86-64 PE executable or DLL")
    parser.add_argument("name", help="named export, or a C identifier to use with --rva")
    parser.add_argument("--rva", type=lambda value: int(value, 0), help="function RVA instead of an export")
    parser.add_argument("--stack-arguments", type=int, default=None,
                        help="number of Win64 stack arguments; omitted means auto-detect")
    parser.add_argument("--size", type=lambda value: int(value, 0), required=True,
                        help="maximum code span in bytes from the function RVA, in decimal or hex")
    parser.add_argument("--output", type=Path, required=True, help="new C output file")
    parser.add_argument("--cpu-context", action="store_true", help="emit a full RecompCpu function")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", args.name):
        parser.error("name must be a C identifier")
    if not 1 <= args.size <= MAX_CODE_SIZE:
        parser.error(f"--size must be from 1 to {MAX_CODE_SIZE} bytes")
    if args.stack_arguments is not None and not 0 <= args.stack_arguments <= 52:
        parser.error("--stack-arguments must be from 0 to 52")
    try:
        if args.rva is None:
            start, code = read_export(args.image, args.name, args.size)
        else:
            start, code = read_range(args.image, args.rva, args.size)
        instructions = discover(start, code, args.cpu_context)
        check_initialized(start, instructions, args.cpu_context)
        stack_arguments = args.stack_arguments
        if stack_arguments is None:
            stack_arguments = infer_stack_arguments(instructions)
        source = emit_c(args.name, start, instructions, stack_arguments, args.cpu_context)
        with args.output.open("x", encoding="utf-8", newline="\n") as output:
            output.write(source)
    except pefile.PEFormatError as error:
        parser.exit(1, f"error: invalid PE image: {error}\n")
    except (LiftError, OSError, capstone.CsError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
