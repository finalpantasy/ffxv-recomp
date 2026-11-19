# FFXV Recomp

A static x86-64 recompilation and future portable runtime for Final Fantasy XV Windows Edition, with one-to-one behavior as the baseline and a modern renderer, measured performance improvements, and comprehensive modding as the goals.

This repository contains analysis and recompilation tooling only. Game executables, dumps, extracted assets, runtime captures, and generated game-code output are not included.

## Current state

- Batch PE exception-table and funclet analysis
- Fast integer ABI and full `RecompCpu` code generation
- Direct, indirect, and tail-call dispatch runtimes
- Integer, memory, scalar/packed vector, conversion, and comparison coverage
- Differential native/C test suites

The game is not playable yet. Startup integration, imports, platform/renderer layers, and the comprehensive modding API remain active work.

## Tooling

The tools live in `tools/x64-c-recompiler`. They require Python 3.10 or later, the packages in `requirements.txt`, and an x64 MSVC developer prompt for native/C verification.

```bat
cd tools\x64-c-recompiler
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe tests\verify.py
.venv\Scripts\python.exe tests\verify_cpu.py
```

See `tools/x64-c-recompiler/README.md` for single-function, batch, CPU-context, and runtime-generation commands.
