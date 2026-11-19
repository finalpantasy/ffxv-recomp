"""Generate a C dispatch runtime for a batch-lift manifest."""

import argparse
import json
from pathlib import Path


DISPATCHER = "uint64_t target, uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9, uint64_t guest_rsp"


def select_functions(records, roots):
    if not roots:
        return list(records), set()
    by_rva = {int(record["rva"], 16): record for record in records}
    selected = {}
    pending = list(roots)
    external = set()
    while pending:
        rva = pending.pop()
        if rva in selected:
            continue
        record = by_rva.get(rva)
        if record is None:
            external.add(rva)
            continue
        selected[rva] = record
        pending.extend(record["call_targets"])
        pending.extend(record.get("tail_targets", []))
    return [selected[rva] for rva in sorted(selected)], external


def generate(records, external):
    header = [
        "#pragma once", "#include <stdint.h>", "",
        "void recomp_runtime_initialize(uint64_t image_base);",
        f"uint64_t recomp_dispatch({DISPATCHER});",
        "void recomp_runtime_missing_target(uint64_t target);",
        "",
    ]
    lines = [
        '#include "recomp_runtime.h"', "#include <stddef.h>", "#include <string.h>", "",
        f"typedef uint64_t (*CallDispatcher)({DISPATCHER});",
        "typedef uint64_t (*FunctionWrapper)(uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9, const uint64_t *stack);",
        "",
    ]
    for record in records:
        name = record["name"]
        arguments = ["uint64_t rcx", "uint64_t rdx", "uint64_t r8", "uint64_t r9"]
        arguments.extend(f"uint64_t stack_{index}" for index in range(record["stack_arguments"]))
        lines.append(f"uint64_t lifted_{name}({', '.join(arguments)});")
        if record["call_targets"]:
            lines.append(f"void lifted_{name}_set_call_dispatcher(CallDispatcher value);")
        if record["image_rvas"]:
            lines.append(f"void lifted_{name}_set_image_base(uint64_t value);")
    lines.append("")
    for record in records:
        name = record["name"]
        arguments = ["rcx", "rdx", "r8", "r9"]
        arguments.extend(f"stack[{index}]" for index in range(record["stack_arguments"]))
        lines.extend([
            f"static uint64_t wrap_{name}(uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9, const uint64_t *stack)",
            "{",
            *([] if record["stack_arguments"] else ["    (void)stack;"]),
            f"    return lifted_{name}({', '.join(arguments)});",
            "}",
        ])
    lines.extend([
        "typedef struct { uint64_t rva; FunctionWrapper wrapper; } FunctionEntry;",
        "static const FunctionEntry functions[] = {",
    ])
    lines.extend(f"    {{ UINT64_C(0x{int(record['rva'], 16):x}), wrap_{record['name']} }}," for record in records)
    lines.extend([
        "};",
        "",
        f"uint64_t recomp_dispatch({DISPATCHER})",
        "{",
        "    size_t low = 0;",
        "    size_t high = sizeof(functions) / sizeof(functions[0]);",
        "    uint64_t stack[52] = {0};",
        "    if (guest_rsp) {",
        "        memcpy(stack, (const void *)(uintptr_t)(guest_rsp + 0x28), sizeof(stack));",
        "    }",
        "    while (low < high) {",
        "        size_t middle = low + (high - low) / 2;",
        "        if (functions[middle].rva < target) low = middle + 1;",
        "        else high = middle;",
        "    }",
        "    if (low < sizeof(functions) / sizeof(functions[0]) && functions[low].rva == target) {",
        "        return functions[low].wrapper(rcx, rdx, r8, r9, stack);",
        "    }",
        "    recomp_runtime_missing_target(target);",
        "    return 0;",
        "}",
        "",
        "void recomp_runtime_initialize(uint64_t image_base)",
        "{",
    ])
    for record in records:
        if record["call_targets"]:
            lines.append(f"    lifted_{record['name']}_set_call_dispatcher(recomp_dispatch);")
        if record["image_rvas"]:
            lines.append(f"    lifted_{record['name']}_set_image_base(image_base);")
    lines.extend(["}", ""])
    lines.append(f"/* Unresolved direct-call targets: {', '.join(f'0x{rva:x}' for rva in sorted(external)) or 'none'} */")
    lines.append("")
    return "\n".join(header), "\n".join(lines)


def generate_cpu(records, external):
    header = [
        "#pragma once", '#include "recomp_cpu.h"', "",
        "void recomp_cpu_dispatch(RecompCpu *cpu, uint64_t target);",
        "void recomp_cpu_missing_target(RecompCpu *cpu, uint64_t target);",
        "",
    ]
    lines = [
        '#include "recomp_runtime.h"', "#include <stddef.h>", "",
    ]
    for record in records:
        lines.append(f"void lifted_{record['name']}_cpu(RecompCpu *cpu);")
    lines.extend([
        "",
        "typedef struct { uint64_t rva; RecompCpuFunction function; } FunctionEntry;",
        "static const FunctionEntry functions[] = {",
    ])
    lines.extend(
        f"    {{ UINT64_C(0x{int(record['rva'], 16):x}), lifted_{record['name']}_cpu }},"
        for record in records
    )
    lines.extend([
        "};",
        "",
        "void recomp_cpu_dispatch(RecompCpu *cpu, uint64_t target)",
        "{",
        "    size_t low = 0;",
        "    size_t high = sizeof(functions) / sizeof(functions[0]);",
        "    while (low < high) {",
        "        size_t middle = low + (high - low) / 2;",
        "        if (functions[middle].rva < target) low = middle + 1;",
        "        else high = middle;",
        "    }",
        "    if (low < sizeof(functions) / sizeof(functions[0]) && functions[low].rva == target) {",
        "        cpu->rip = target;",
        "        functions[low].function(cpu);",
        "        return;",
        "    }",
        "    recomp_cpu_missing_target(cpu, target);",
        "}",
        "",
    ])
    lines.append(f"/* Unresolved direct-call targets: {', '.join(f'0x{rva:x}' for rva in sorted(external)) or 'none'} */")
    lines.append("")
    return "\n".join(header), "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--root", type=lambda value: int(value, 0), action="append", default=[])
    args = parser.parse_args()
    if args.output_directory.exists():
        parser.error("output directory already exists")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    records, external = select_functions(manifest["functions"], args.root)
    if not records:
        parser.error("no functions selected")
    header, source = generate_cpu(records, external) if manifest.get("cpu_context") else generate(records, external)
    args.output_directory.mkdir(parents=True)
    (args.output_directory / "recomp_runtime.h").write_text(header, encoding="utf-8", newline="\n")
    (args.output_directory / "recomp_runtime.c").write_text(source, encoding="utf-8", newline="\n")
    sources = [str(args.manifest.parent / record["source"]) for record in records]
    sources.append(str(args.output_directory / "recomp_runtime.c"))
    (args.output_directory / "sources.txt").write_text("\n".join(sources) + "\n", encoding="utf-8")
    metadata = {
        "function_count": len(records),
        "external_call_targets": [f"0x{rva:x}" for rva in sorted(external)],
        "source_count": len(sources),
        "cpu_context": bool(manifest.get("cpu_context")),
    }
    (args.output_directory / "selection.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
