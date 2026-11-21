"""Batch-lift Win64 exception-table functions to C with a coverage manifest."""

import argparse
import bisect
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path

import capstone
import pefile

import lift


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def error_kind(error):
    text = str(error)
    if "unsupported instruction " in text:
        return "unsupported_instruction"
    if "unsupported operand" in text:
        return "unsupported_operand"
    if "uninitialized state" in text:
        return "uninitialized_state"
    if "outside the selected code range" in text:
        return "branch_outside"
    if "base relocation" in text:
        return "relocation"
    if "undefined" in text:
        return "undefined_flags"
    if "overlapping instruction streams" in text:
        return "overlap"
    if "invalid or truncated instruction" in text:
        return "invalid"
    if "stack" in text:
        return "stack_analysis"
    return "other"


def discover_funclets(image, ranges, range_starts, start, end, cpu_context=False):
    code_start = start
    code_end = end
    for _ in range(64):
        try:
            instructions = lift.discover(start, image.get_data(code_start, code_end - code_start), cpu_context)
            first = bisect.bisect_left(range_starts, code_start)
            last = bisect.bisect_left(range_starts, code_end)
            covered = ranges[first:last]
            return instructions, code_end, covered
        except lift.LiftError as error:
            match = re.search(r"RVA 0x([0-9a-f]+) is outside the selected code range", str(error))
            if match is None:
                raise
            target = int(match.group(1), 16)
            if target < start - lift.MAX_CODE_SIZE or target >= start + lift.MAX_CODE_SIZE:
                raise
            index = bisect.bisect_right(range_starts, target) - 1
            if index < 0 or ranges[index][0] > target or ranges[index][1] <= target:
                next_index = bisect.bisect_right(range_starts, target)
                if next_index >= len(ranges):
                    raise
                code_end = max(code_end, range_starts[next_index])
                continue
            target_start, target_end = ranges[index]
            if target_start < code_start:
                code_start = target_start
                code_end = max(code_end, target_end)
            elif target_end > code_end:
                code_end = target_end
            else:
                raise
    raise lift.LiftError(f"RVA 0x{start:x}: too many linked funclets")


def save_manifest(args, manifest_path, image_digest, records, failures, summary, complete):
    records.sort(key=lambda record: int(record["rva"], 16))
    failures.sort(key=lambda record: int(record["rva"], 16))
    manifest = {
        "image": str(args.image),
        "image_sha256": image_digest,
        "cpu_context": args.cpu_context,
        "complete": complete,
        "generated_count": len(records),
        "failure_count": len(failures),
        "covered_funclet_count": sum(len(record.get("covered_funclets", [])) for record in records),
        "last_run_summary": dict(summary),
        "functions": records,
        "failures": failures,
    }
    temporary = manifest_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, manifest_path)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--retry-failures", action="store_true")
    parser.add_argument("--cpu-context", action="store_true")
    parser.add_argument("--regenerate", action="store_true")
    args = parser.parse_args()
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    if args.output_directory.exists() and not args.resume:
        parser.error("output directory exists; select --resume to continue it")
    args.output_directory.mkdir(parents=True, exist_ok=args.resume)
    manifest_path = args.output_directory / "manifest.json"
    records = []
    failures = []
    if args.resume and manifest_path.is_file():
        previous = json.loads(manifest_path.read_text(encoding="utf-8"))
        records = previous.get("functions", [])
        failures = previous.get("failures", [])
        if args.retry_failures or args.regenerate:
            failures = []
        if args.regenerate:
            records = []
    completed = {record["rva"] for record in records}
    failed = {record["rva"] for record in failures}
    previously_covered = {
        int(rva, 16) for record in records for rva in record.get("covered_funclets", [])
    }
    summary = Counter()
    attempted = 0
    image_digest = sha256(args.image)
    with pefile.PE(str(args.image), fast_load=True) as image:
        if image.FILE_HEADER.Machine != 0x8664 or image.OPTIONAL_HEADER.Magic != 0x20B:
            parser.error("expected an x86-64 PE32+ image")
        image.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
        ranges = sorted(
            (item.struct.BeginAddress, item.struct.EndAddress)
            for item in getattr(image, "DIRECTORY_ENTRY_EXCEPTION", [])
        )
        range_starts = [item[0] for item in ranges]
        covered_funclets = set(previously_covered)
        for original_start, original_end in ranges:
            start = original_start
            end = original_end
            if start in covered_funclets:
                continue
            key = f"0x{start:x}"
            if key in completed or key in failed:
                continue
            if args.limit is not None and attempted >= args.limit:
                break
            attempted += 1
            if attempted % 5000 == 0:
                save_manifest(args, manifest_path, image_digest, records, failures, summary, False)
            size = end - start
            if not 1 <= size <= lift.MAX_CODE_SIZE:
                index = bisect.bisect_right(range_starts, start)
                clamped_end = ranges[index][0] if index < len(ranges) else None
                if end > start:
                    far_end = start + lift.MAX_CODE_SIZE
                    clamped_end = min(clamped_end, far_end) if clamped_end else far_end
                if clamped_end is None or not 1 <= clamped_end - start <= lift.MAX_CODE_SIZE:
                    failures.append({"rva": key, "size": size, "kind": "size", "error": "invalid or excessive function size"})
                    summary["size"] += 1
                    continue
                end = clamped_end
                size = end - start
            try:
                instructions, code_end, covered = discover_funclets(
                    image, ranges, range_starts, start, end, args.cpu_context,
                )
                size = code_end - start
                lift.check_initialized(start, instructions, args.cpu_context)
                lift.check_flag_liveness(instructions)
                stack_arguments = 0 if args.cpu_context else lift.infer_stack_arguments(instructions)
                name = f"fn_{start:x}"
                source = lift.emit_c(name, start, instructions, stack_arguments, args.cpu_context)
                source_name = f"{name}{'_cpu' if args.cpu_context else ''}.c"
                output = args.output_directory / source_name
                if args.regenerate:
                    temporary_output = output.with_suffix(output.suffix + ".tmp")
                    temporary_output.write_text(source, encoding="utf-8", newline="\n")
                    os.replace(temporary_output, output)
                elif args.resume and output.is_file():
                    if output.read_text(encoding="utf-8") != source:
                        raise lift.LiftError(f"RVA 0x{start:x}: existing C output conflicts with regenerated source")
                    summary["recovered"] += 1
                else:
                    with output.open("x", encoding="utf-8", newline="\n") as destination:
                        destination.write(source)
                covered_funclets.update(item[0] for item in covered if item[0] != start)
                record = {
                    "rva": key,
                    "size": size,
                    "name": name,
                    "source": output.name,
                    "stack_arguments": stack_arguments,
                    "call_targets": sorted({
                        instruction.operands[0].value
                        for instruction in instructions.values()
                        if instruction.mnemonic == "call" and instruction.source_width == 0
                    }),
                    "tail_targets": sorted({
                        instruction.operands[0].value
                        for instruction in instructions.values()
                        if instruction.mnemonic == "tail" and instruction.source_width == 0
                    }),
                    "has_indirect_calls": any(
                        instruction.mnemonic in {"call", "tail"} and instruction.source_width == 1
                        for instruction in instructions.values()
                    ),
                    "image_rvas": sorted({
                        operand.image_rva
                        for instruction in instructions.values()
                        for operand in instruction.operands if operand.image_rva is not None
                    }),
                    "instruction_count": len(instructions),
                    "covered_funclets": [f"0x{item[0]:x}" for item in covered if item[0] != start],
                }
                records.append(record)
                summary["generated"] += 1
            except (lift.LiftError, capstone.CsError) as error:
                kind = error_kind(error)
                failures.append({"rva": key, "size": size, "kind": kind, "error": str(error)})
                summary[kind] += 1
            except OSError as error:
                parser.exit(1, f"error: {error}\n")
    manifest = save_manifest(
        args, manifest_path, image_digest, records, failures, summary, args.limit is None,
    )
    print(json.dumps({key: manifest[key] for key in ("generated_count", "failure_count", "complete", "last_run_summary")}, indent=2))


if __name__ == "__main__":
    main()
