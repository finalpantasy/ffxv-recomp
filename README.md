# FFXV Recomp

A static x86-64 recompilation of Final Fantasy XV Windows Edition to portable C, with a clean-room runtime, a modern renderer, and a modding system that can touch *anything* in the game.

The end state: one portable executable that runs the retail game one-to-one with the original — same gameplay, content, world, saves — but faster, on more platforms, with Denuvo completely gone, and with documented data-driven interfaces so modders can add or replace weapons, enemies, drops, maps, world connections, quests, characters, voices, music, graphics, lighting, and arbitrary behavior.

> **Status: early. Not playable yet.** Tooling and verified milestones live here; the game itself does not. See [Current state](#current-state) and [Roadmap](#roadmap).

## Why

- **Performance.** The original renderer is D3D11-era and the PC port is known for stutter. Recompiling to portable C lets us build a modern renderer (Vulkan/DX12-class) and fix frame pacing with measured before/after benchmarks.
- **Portability.** x86-64 Windows PE in, portable C out. Once the CPU side is lifted, the platform surface (Win32, D3D11, middleware shims) becomes a replaceable boundary instead of a wall.
- **Preservation.** A Denuvo-free build that runs from a plain folder, offline, forever.
- **Modding.** Content becomes data with stable identities and override layers — not a hardcoded mod list. If the base game can express it, a mod should be able to add or replace it.

## What this repo contains

Analysis and recompilation tooling only. Game executables, dumps, extracted assets, keys, runtime captures, and generated game-code output are **not** tracked and never will be. You need your own legitimate copy of the game to use the tooling on real data.

## Pipeline

```
ffxv_s.exe (Steam, x86-64 PE)
      │
      ▼
 analyze ── PE exception table, function ranges, strings, xrefs,
      │      cross-build matching (demo / UWP as clean references)
      ▼
   lift ──── each x86-64 function → portable C (integer, memory,
      │       SSE scalar/packed, conversions, comparisons, calls,
      │       RIP-relative image access, TLS, full CPU context)
      ▼
 verify ──── every lifted function is compiled by MSVC /Od and /O2
      │       and differentially executed against the native original
      ▼
 runtime ─── dispatch core walks the lifted call graph from the OEP,
      │        maps the original image, resolves imports, models
      │        memory — protection-specific paths are isolated
      ▼
 platform ── Win32 / D3D11 / middleware shim boundary → modern
      │        renderer (future)
      ▼
   mods ──── stable content IDs, data-driven registries,
             virtual-file override layers, scripting hooks (future)
```

## Current state

Verified, reproducible milestones (details in `AGENTS.md`):

- **Lifter:** fast integer-ABI and full `RecompCpu`-context code generation from arbitrary x86-64 function ranges — integer/memory ops, low-width and partial registers, stack semantics, conditional moves, branches, direct/indirect/tail calls, Win64 stack arguments, RIP-relative image addressing, scalar and packed SSE math, conversions, comparisons, shuffles, string ops, atomics, TLS, flag-accurate arithmetic.
- **Test suites:** **99,494** native/C fast-ABI differential comparisons plus **51,560** full CPU-context comparisons (RIP/RSP, tail control flow, float/vector, SIMD shuffles, string scans, atomics, TLS, division) — passing at both `/Od` and `/O2`.
- **Batch lifting:** **136,004** functions generated from the retail PE's exception-table ranges (169,723 ranges total across `.edata`/`.arch`), with per-function diagnostics and a resumable manifest. **79** functions remain unresolved; the rest fail only in bounded, categorized ways (cross-image branches, malformed ranges, privileged instructions).
- **Differential verification:** individual lifted functions validated against the native original (e.g. 258 RIP-relative image cases on one function, 30 direct-call cases on another).
- **Runtime dispatch core:** nested lifted calls, global state, repeated dispatch, unresolved-target handling, root-based reachability closure — tested at `/Od` and `/O2`.
- **Startup integration (in progress):** the diagnostic harness maps the retail image, resolves all 630 imports, and enters lifted code at the original entry point. It advances through the Denuvo protected-link chain, offline Steam-interface initialization, and locale/language setup; through the C runtime's C++ global-constructor phase (`_initterm`, a thousand-plus static initializers); and into early engine initialization — heap/allocator and arena setup and C-runtime environment/string processing. Execution now reaches a repeatable wall at the same point every run (guest dispatch ~1.13M), deep in that early-init path. No rendered frame yet; clearing this wall gates renderer bring-up.
- **Current wall — two characterized faults (under analysis):**
  - *A copy/move leaf receives a 64-bit register of the form `0xffffffff00000008`* — correct low 32 bits, high 32 bits set — and dereferences it as an address. It fires deterministically (the same three generated sites every run). Still being resolved: whether this is a lifter zero-extension defect on one 32-bit-destination instruction upstream (x86-64 zero-extends 32-bit writes; one site may not), or a legitimate packed field the generated copy mishandles. Two things are ruled out: the value is **not** read from a corrupted structure (the rooted structure holds valid data, including live environment strings), and it is **not** caused by the harness's host environment (scrubbing the host environment down to a clean set does not move the wall).
  - *A page-backing wall:* the allocator reserves a large region, then the runtime faults on sub-64 KB free gaps wedged between committed pages. Windows virtual-memory reservation is 64 KB-granular, so these gaps cannot be reserved reactively at fault time — characterized as an allocation-modeling gap in the runtime's memory layer, not a lifter defect. Several reactive-reservation strategies were tried and defeated by the sub-granularity gaps.
- **Denuvo research:** protection layout mapped; license-bound `.link` slots and protected code paths identified; the official demo (verified playable, zero Denuvo identifiers) and the UWP build are in use as clean cross-reference images. 51k+ normalized function matches between demo and retail support function recovery.

## Roadmap

1. **Milestone 1 — Denuvo-off retail playability.** Retail game runs with Denuvo fully disconnected. (The official demo already runs Denuvo-free as a reference; this milestone is about the full retail game.)
2. **Milestone 2 — complete the static recomp.** Close the remaining 79 functions, integrate startup, imports, and the full call graph into the portable runtime until the game runs from lifted code one-to-one.
3. **Milestone 3 — modern renderer.** Replace the D3D11 path, fix stutter, and publish measured performance gains against the original on reference hardware.
4. **Milestone 4 — universal modding.** Stable content IDs, data-driven registries, override layers, and scripting hooks; prove add/replace for every content family (weapons, enemies, drops, maps, world links, quests, characters, voices, music, graphics, lighting) and arbitrary behavior extension.

Done means: the Steam game runs without its original executable as a one-to-one recompilation — gameplay, content, world connections, presentation, and save behavior match the original except for explicitly selected improvements — with measured performance gains and the full modding surface above. One portable executable, CLI flags for every option.

## Repository layout

```
AGENTS.md                  project state, decisions, rules, next gates
FEASIBILITY.md             original feasibility assessment
tools/x64-c-recompiler/    the lifter, batch driver, runtime dispatch core,
                           and differential test suites
```

`analysis/`, `generated/`, and `build/` are intentionally git-ignored — they hold local-only artifacts derived from the game binary.

## Getting started

Requirements: Windows, Python 3.10+, the Python packages in `tools/x64-c-recompiler/requirements.txt`, and an x64 MSVC developer prompt for native verification.

```bat
cd tools\x64-c-recompiler
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe tests\verify.py        :: fast-ABI differential suite
.venv\Scripts\python.exe tests\verify_cpu.py    :: full CPU-context suite
.venv\Scripts\python.exe tests\verify_batch.py  :: batch/funclet checks
```

See `tools/x64-c-recompiler/README.md` for single-function lifting, batch lifting, CPU-context generation, and runtime-closure commands.

## Contributing

This is a big, multi-discipline project — compiler-adjacent lifting, Windows internals, graphics, reverse engineering, tooling, and game-systems design all intersect here. Useful entry points, in rough order of approachability:

- Run the test suites, read `AGENTS.md`, and pick up one of the [milestone](#roadmap) threads.
- The 79 unresolved batch functions are a bounded, well-diagnosed set — each is a small lifter or analysis problem.
- Startup integration is the live debugging frontier; the current wall is in early engine initialization — a deterministic bad-pointer dereference in a generated copy leaf, plus a sub-64 KB page-backing gap in the runtime's memory layer (see [Current state](#current-state)).
- Cross-build matching (demo/UWP → Steam) has tens of thousands of candidate pairs that need per-function semantic validation.

Open an issue or discussion with what you want to take on before spending large effort, so work doesn't collide.

## Legal

This project is an independent interoperability and preservation effort. It contains no Square Enix code, assets, or data, and receives no endorsement from Square Enix. Final Fantasy XV and all game content are property of Square Enix. The tooling operates only on files you already own; do not use it to pirate the game or distribute copyrighted material.
