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
    "add": "+", "sub": "-", "cmp": "-", "and": "&", "test": "&", "or": "|", "xor": "^",
}
COMPARISONS = {"cmp", "test"}
SHIFTS = {"shl", "sal", "shr", "sar"}
FLOAT_SCALAR = {"addss", "subss", "mulss", "divss"}
FLOAT_VECTOR = {"addps", "subps", "mulps"}
FLOAT_PACKED_CONVERSIONS = {"cvtdq2ps"}
FLOAT_CONVERSIONS = {"cvtsd2ss", "cvttss2si", "cvtsi2ss"}
CONDITIONAL_JUMPS = {
    "je": "zf", "jz": "zf", "jne": "!zf", "jnz": "!zf",
    "ja": "!cf && !zf", "jae": "!cf", "jb": "cf", "jbe": "cf || zf",
    "jg": "!zf && sf == of", "jge": "sf == of", "jl": "sf != of", "jle": "zf || sf != of",
    "jo": "of", "jno": "!of", "js": "sf", "jns": "!sf", "jp": "pf", "jnp": "!pf",
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
MAX_CODE_SIZE = 65536


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
        if self.displacement > 0:
            expression += f" + UINT64_C(0x{self.displacement:x})"
        elif self.displacement < 0:
            expression += f" - UINT64_C(0x{-self.displacement:x})"
        return f"(uint64_t)({expression})"

    def as_c(self, width):
        if self.register is not None:
            if width == 128:
                return self.register
            return f"(uint{width}_t){self.register}"
        if self.memory:
            return f"read{width}({self.address_c()})"
        return f"UINT{width}_C(0x{self.value % (1 << width):x})"

    def write_c(self, value, width):
        if self.register is not None:
            if width == 128:
                return f"{self.register} = {value};"
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
        canonical = canonical_register(decoded, operand.reg)
        if canonical in REGISTERS:
            return Operand(canonical)
    if operand.type == x86_const.X86_OP_MEM and operand.size * 8 == width:
        memory = operand.mem
        if memory.segment:
            raise LiftError(f"RVA 0x{decoded.address:x}: segment overrides are unsupported")
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
            scale=memory.scale, displacement=memory.disp,
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
    if mnemonic == "nop":
        return Instruction(address, length, mnemonic, (following,), empty, empty)
    if any(prefix not in (0, 0x66) for prefix in decoded.prefix):
        raise LiftError(f"RVA 0x{address:x}: unsupported instruction prefix")
    if allow_tail_calls and mnemonic == "int3" and not operands:
        return Instruction(address, length, "trap", (), empty, empty)
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
    if mnemonic in {"cdq", "cqo", "cdqe"} and not operands:
        if mnemonic == "cdq":
            return Instruction(address, length, mnemonic, (following,), frozenset({"rax"}), frozenset({"rdx"}), 32)
        return Instruction(address, length, mnemonic, (following,), frozenset({"rax"}), frozenset({"rax" if mnemonic == "cdqe" else "rdx"}), 64)
    if mnemonic == "bt" and len(operands) == 2 and operands[0].type == x86_const.X86_OP_REG and operands[1].type == x86_const.X86_OP_IMM:
        width = operands[0].size * 8
        left = read_operand(decoded, operands[0], width)
        index = Operand(None, operands[1].imm)
        return Instruction(
            address, length, mnemonic, (following,), frozenset({left.register}),
            frozenset({"flags"}), width, (left, index),
        )
    if mnemonic in SHIFTS and len(operands) == 2 and operands[0].size in (1, 2, 4, 8):
        width = operands[0].size * 8
        if width in (8, 16) and operands[1].type == x86_const.X86_OP_IMM and not 1 <= operands[1].imm < width:
            raise LiftError(f"RVA 0x{address:x}: shift count exceeds the supported narrow range")
        if width in (8, 16) and operands[1].type != x86_const.X86_OP_IMM:
            raise LiftError(f"RVA 0x{address:x}: variable narrow shifts are unsupported")
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
    if mnemonic == "imul" and len(operands) == 2 and operands[0].size in (4, 8):
        width = operands[0].size * 8
        left, right = (read_operand(decoded, operand, width) for operand in operands)
        if left.register is None:
            raise LiftError(f"RVA 0x{address:x}: two-operand imul requires a register destination")
        reads = {left.register, *operand_reads(right), *right.address_registers}
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset({left.register, "flags"}), width, (left, right),
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
    if mnemonic in {*FLOAT_VECTOR, "andps"} and len(operands) == 2:
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
    if mnemonic in {"movd", "movq"} and len(operands) == 2:
        width = 32 if mnemonic == "movd" else 64
        left_name = decoded.reg_name(operands[0].reg) if operands[0].type == x86_const.X86_OP_REG else None
        right_name = decoded.reg_name(operands[1].reg) if operands[1].type == x86_const.X86_OP_REG else None
        if left_name in XMM_REGISTERS:
            left = Operand(left_name)
            right = read_operand(decoded, operands[1], width)
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
    if mnemonic in FLOAT_SCALAR and len(operands) == 2:
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
    if mnemonic in FLOAT_CONVERSIONS and len(operands) == 2:
        if mnemonic == "cvtsd2ss":
            left = read_xmm_operand(decoded, operands[0], 64)
            right = read_xmm_operand(decoded, operands[1], 64)
            source_width = 64
        elif mnemonic == "cvttss2si":
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
        if mnemonic != "cvttss2si":
            reads.add(left.register)
        writes = {left.register}
        return Instruction(
            address, length, mnemonic, (following,), frozenset(reads),
            frozenset(writes), 32, (left, right), source_width,
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
    if mnemonic in {"mov", "movaps", "movups", "movdqa", "movdqu"} or mnemonic in ARITHMETIC:
        vector_move = mnemonic in {"movaps", "movups", "movdqa", "movdqu"}
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
    initial = frozenset((*REGISTERS, "flags")) if full_state else frozenset((*ARGUMENTS, *CALLEE_SAVED, *CALLEE_SAVED_XMM, "rsp"))
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
        if mnemonic == "push":
            effect = -8
        elif mnemonic == "pop":
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
    return set(re.findall(r"[a-z]+", CONDITIONS.get(mnemonic, "")))


def defined_flags(instruction):
    mnemonic = instruction.mnemonic
    if mnemonic in ARITHMETIC or mnemonic == "call":
        return {"cf", "of", "sf", "zf", "pf"}
    if mnemonic in {"inc", "dec"}:
        return {"of", "sf", "zf", "pf"}
    if mnemonic in SHIFTS or mnemonic == "neg":
        return {"cf", "of", "sf", "zf", "pf"}
    if mnemonic == "imul":
        return {"cf", "of", "sf", "zf", "pf"}
    if mnemonic in {"comiss", "ucomiss"}:
        return {"cf", "of", "sf", "zf", "pf", "af"}
    if mnemonic == "bt":
        return {"cf"}
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
        if instruction.mnemonic == "imul" and outgoing[address] & {"sf", "zf", "pf"}:
            raise LiftError(f"RVA 0x{address:x}: imul leaves subsequently used SF, ZF, or PF undefined")
        if instruction.mnemonic in SHIFTS and "of" in outgoing[address]:
            count = instruction.operands[1]
            if count.value != 1:
                raise LiftError(f"RVA 0x{address:x}: shift leaves a subsequently used OF undefined")
        if instruction.mnemonic == "bt" and outgoing[address] - {"cf"}:
            raise LiftError(f"RVA 0x{address:x}: bt leaves a subsequently used non-CF flag undefined")


def arithmetic_to_c(instruction, flags):
    mnemonic = instruction.mnemonic
    lhs, rhs = instruction.operands
    c_type = f"uint{instruction.width}_t"
    sign_bit = f"UINT{instruction.width}_C(0x{1 << (instruction.width - 1):x})"
    if instruction.zeroing_xor:
        lines = [f"{c_type} result = 0;"]
        left = right = "0"
    else:
        lines = [
            f"{c_type} left = {lhs.as_c(instruction.width)};",
            f"{c_type} right = {rhs.as_c(instruction.width)};",
            f"{c_type} result = ({c_type})(left {ARITHMETIC[mnemonic]} right);",
        ]
        left = right = None
    carry = overflow = "0"
    if mnemonic == "add":
        carry = "result < left"
        overflow = f"((left ^ result) & (right ^ result) & {sign_bit}) != 0"
    elif mnemonic in {"sub", "cmp"}:
        carry = "left < right"
        overflow = f"((left ^ right) & (left ^ result) & {sign_bit}) != 0"
    formulas = {
        "cf": carry, "of": overflow, "sf": f"(result & {sign_bit}) != 0", "zf": "result == 0",
        "pf": "parity(result)",
    }
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
    formulas = {"of": overflow, "sf": f"(result & {sign_bit}) != 0", "zf": "result == 0", "pf": "parity(result)"}
    lines = [
        f"{c_type} left = {operand.as_c(width)};",
        f"{c_type} result = ({c_type})(left {operator} 1);",
    ]
    lines.extend(f"{flag} = {formulas[flag]};" for flag in flags if flag in formulas)
    lines.append(operand.write_c("result", width))
    return lines


def shift_to_c(instruction, flags):
    mnemonic = "shl" if instruction.mnemonic == "sal" else instruction.mnemonic
    lhs, count_operand = instruction.operands
    width = instruction.width
    c_type = f"uint{width}_t"
    signed_type = f"int{width}_t"
    sign_bit = f"UINT{width}_C(0x{1 << (width - 1):x})"
    mask = 63 if width == 64 else 31
    result_expression = {
        "shl": f"({c_type})(left << count)",
        "shr": f"({c_type})(left >> count)",
        "sar": f"({c_type})(({signed_type})left >> count)",
    }[mnemonic]
    carry_expression = {
        "shl": f"(left >> ({width} - count)) & 1",
        "shr": "(left >> (count - 1)) & 1",
        "sar": f"(({signed_type})left >> (count - 1)) & 1",
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
    }
    lines.extend(f"{flag} = {formulas[flag]};" for flag in flags)
    lines.append(operand.write_c("result", width))
    return lines


def imul_to_c(instruction, flags):
    lhs, rhs = instruction.operands
    width = instruction.width
    carry = "&cf" if "cf" in flags else "0"
    overflow = "&of" if "of" in flags else "0"
    return [
        f"uint{width}_t left = {lhs.as_c(width)};",
        f"uint{width}_t right = {rhs.as_c(width)};",
        lhs.write_c(f"imul{width}(left, right, {carry}, {overflow})", width),
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
        ])
    return lines


def emit_c(name, start, instructions, stack_arguments=0, cpu_context=False):
    check_flag_liveness(instructions)
    registers = set()
    uses_memory = False
    uses_narrow_memory = False
    uses_image = False
    uses_dispatcher = any(instruction.mnemonic == "call" for instruction in instructions.values())
    uses_float = any(
        instruction.mnemonic in {"comiss", "ucomiss", *FLOAT_SCALAR, *FLOAT_VECTOR, *FLOAT_PACKED_CONVERSIONS, *FLOAT_CONVERSIONS}
        for instruction in instructions.values()
    )
    uses_xmm = any(
        instruction.width == 128 or any(
            operand.register in XMM_REGISTERS for operand in instruction.operands
        )
        for instruction in instructions.values()
    )
    imul_widths = set()
    conditions = set()
    for instruction in instructions.values():
        registers.update(instruction.reads | instruction.writes)
        uses_memory = uses_memory or any(operand.memory for operand in instruction.operands)
        uses_narrow_memory = uses_narrow_memory or any(
            operand.memory for operand in instruction.operands
        ) and (instruction.width in (8, 16) or instruction.source_width in (8, 16))
        uses_image = uses_image or any(operand.image_rva is not None for operand in instruction.operands)
        uses_image = uses_image or instruction.mnemonic == "call" and instruction.source_width == 1
        if instruction.mnemonic == "imul":
            imul_widths.add(instruction.width)
        if instruction.mnemonic in CONDITIONS:
            conditions.add(instruction.mnemonic)
    locals_used = sorted((registers & REGISTERS) - set(ARGUMENTS) - {"rsp"})
    flags = sorted(set().union(*(condition_flags(mnemonic) for mnemonic in conditions)) if conditions else set())
    stack_names = [f"stack_arg{index}" for index in range(5, 5 + stack_arguments)]
    signature = ", ".join(
        [f"uint64_t {arg}" for arg in ARGUMENTS]
        + [f"uint64_t {arg}" for arg in stack_names]
    )
    lines = ["#include <stdint.h>"]
    if cpu_context:
        lines.append('#include "recomp_cpu.h"')
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
        ])
    if uses_xmm:
        lines.append("typedef RecompXmm uint128_t;" if cpu_context else "typedef struct { uint64_t lanes[2]; } uint128_t;")
    if uses_memory or "rsp" in registers or cpu_context:
        lines.extend(memory_helpers(uses_xmm, uses_narrow_memory))
    if imul_widths:
        lines.extend(imul_helpers(imul_widths))
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
            elif mnemonic in {"mov", "movaps", "movups", "movdqa", "movdqu"}:
                lhs, rhs = instruction.operands
                lines.append(f"    {lhs.write_c(rhs.as_c(instruction.width), instruction.width)}")
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
            elif mnemonic in {*FLOAT_VECTOR, "andps"}:
                lhs, rhs = instruction.operands
                if mnemonic == "andps":
                    lines.extend([
                        f"    uint128_t left = {lhs.as_c(128)};",
                        f"    uint128_t right = {rhs.as_c(128)};",
                        "    uint128_t result = {{left.lanes[0] & right.lanes[0], left.lanes[1] & right.lanes[1]}};",
                        f"    {lhs.write_c('result', 128)}",
                    ])
                else:
                    operator = {"addps": "+", "subps": "-", "mulps": "*"}[mnemonic]
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
            elif mnemonic in {"movd", "movq"}:
                lhs, rhs = instruction.operands
                width = instruction.width
                if lhs.register in XMM_REGISTERS:
                    lines.extend([
                        "    uint128_t result = {{0, 0}};",
                        f"    result.lanes[0] = (uint64_t)({rhs.as_c(width)});",
                        f"    {lhs.write_c('result', 128)}",
                    ])
                else:
                    lines.append(f"    {lhs.write_c(f'{rhs.register}.lanes[0]', width)}")
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
            elif mnemonic == "cvtsd2ss":
                lhs, rhs = instruction.operands
                right_value = f"read64({rhs.address_c()})" if rhs.memory else f"{rhs.register}.lanes[0]"
                lines.extend([
                    f"    uint128_t result = {lhs.as_c(128)};",
                    f"    double right = float64({right_value});",
                    "    result.lanes[0] = (result.lanes[0] & ~UINT64_C(0xffffffff)) | bits32((float)right);",
                    f"    {lhs.write_c('result', 128)}",
                ])
            elif mnemonic == "cvttss2si":
                lhs, rhs = instruction.operands
                right_bits = f"read32({rhs.address_c()})" if rhs.memory else f"(uint32_t){rhs.register}.lanes[0]"
                lines.append(
                    f"    {lhs.write_c(f'cvtt{instruction.source_width}(float32({right_bits}))', instruction.source_width)}"
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
            elif mnemonic in ARITHMETIC:
                lines.extend(f"    {line}" for line in arithmetic_to_c(instruction, flags))
            elif mnemonic in {"inc", "dec"}:
                lines.extend(f"    {line}" for line in unary_to_c(instruction, flags))
            elif mnemonic == "imul":
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
            elif mnemonic == "cdq":
                lines.append(f"    rdx = (uint32_t)((int32_t)rax < 0 ? UINT32_C(0xffffffff) : 0);")
            elif mnemonic == "cqo":
                lines.append("    rdx = (uint64_t)((int64_t)rax < 0 ? UINT64_MAX : 0);")
            elif mnemonic == "cdqe":
                lines.append("    rax = (uint64_t)(int64_t)(int32_t)rax;")
            elif mnemonic == "bt":
                lhs, index = instruction.operands
                if "cf" in flags:
                    lines.append(f"    cf = ({lhs.as_c(instruction.width)} >> {index.value}) & 1;")
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
