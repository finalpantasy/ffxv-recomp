# x86-64 to C recompiler

`lift.py` lifts a named export or explicit RVA from a Windows x64 PE image to C11. It follows reachable direct branches and translates integer register, memory, stack, arithmetic, logic, conditional-move, and flag-dependent control-flow operations. Functions use the four Win64 register arguments; `--stack-arguments` models additional arguments passed on the stack. Generated memory helpers currently use native process addresses so lifted code can be compared directly with the original function.

The prototype supports direct internal calls through a generated dispatcher setter. It still rejects indirect calls and branches, base relocations inside the selected code span, uninitialized volatile state, and instructions whose semantics are not implemented. RIP-relative operands use a generated per-function image-base setter. Pass the function span with `--size`; a linker map, assembly listing, unwind table, or disassembler can supply boundaries.

## Run the tests

Open an x64 MSVC developer prompt in this folder with Python 3.10 or later.

```bat
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe tests\verify.py
```

The test assembles the original fixtures into a DLL, lifts four exports, and compares the native functions with the generated C compiled at `/Od` and `/O2` using edge cases and seeded random inputs. Rejection tests check the diagnostics and output files.

## Generate a C file

Run from the project root. Use a fresh `demo` folder.

```bat
mkdir demo
cd demo
ml64 /nologo /c /Fofixtures.obj ..\tests\fixtures.asm
link /nologo /dll /noentry /out:native.dll /export:mix64 fixtures.obj
..\.venv\Scripts\python.exe ..\lift.py native.dll mix64 --size 24 --output mix64.c
cl /nologo /TC /std:c11 /O2 /LD mix64.c /link /out:lifted.dll /export:lifted_mix64
```

`mix64.c` is the generated source. `lifted.dll` exports `lifted_mix64`.

## Batch lift unwind functions

`--cpu-context` emits `void lifted_<name>_cpu(RecompCpu *cpu)` instead of the limited four-argument/RAX ABI. Include `runtime/recomp_cpu.h` on the compiler include path. Context functions carry all general registers, XMM registers, flags, RIP, and image base; direct/indirect calls and tail jumps use `recomp_cpu_dispatch`.

`batch_lift.py` reads the PE exception table, merges forward branch-connected funclets, infers Win64 stack arguments, and writes one C file per supported function plus a resumable `manifest.json`. The manifest records call targets, image references, covered funclets, and rejection reasons.

```bat
python batch_lift.py path\to\game.exe path\to\generated
```

Use `--limit N` for a bounded run or `--resume` to continue an existing output directory. Existing C files are regenerated in memory and must match before being indexed. Use `--resume --retry-failures` after extending the lifter so earlier unsupported functions are tried again. Use `--resume --regenerate` to atomically rebuild every derived source after changing code generation itself.

## Generate a call-dispatch runtime

`generate_runtime.py` emits exact-signature wrappers, a binary-search direct-call dispatcher, image/call setter initialization, a build source list, and unresolved-target diagnostics.

```bat
python generate_runtime.py path\to\manifest.json path\to\runtime --root 0x55830a0
```

Repeat `--root` to include multiple entry points. Without a root, every generated function is selected. The final program supplies `recomp_runtime_missing_target` for calls outside the selected lifted set.
