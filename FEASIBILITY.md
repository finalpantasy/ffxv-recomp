# Final Fantasy XV native recompilation feasibility

## Current direction

Target the **Steam Windows Edition with Royal Edition content**, specifically its `ffxv_s.exe`. The UWP `ffxv_u.exe` is not the selected target.

The owner withdrew the project-specific prohibition on removing or bypassing executable protection on 2026-11-19. Static recompilation remains the selected route. Anti-tamper is therefore a **technical obstacle to investigate**, not a route forbidden by project rules.

The latest inspection confirms ordinary x86-64 instructions in both `.edata` and `.arch`; `.arch` is not uniformly encrypted. The project now has a batch lifter, fast and full CPU-context runtimes, and more than 100,000 generated full-state functions. Generic and startup-shaped native/C suites cover control flow, memory, scalar/packed vector operations, conversions, and comparisons. This is substantial partial coverage, not a playable game or proof of whole-game correctness; startup integration, remaining instructions, imports, renderer, platform, and middleware work continue.

## Target and observed binary facts

- Target: Final Fantasy XV Windows Edition, Steam, with Royal Edition content.
- Owner goals: better performance, a modern renderer, easier modding, and modding tools.
- Selected implementation route: static recompilation of `ffxv_s.exe` to portable C/C++, replacing D3D11 and Win32 with portable layers.
- The previously inspected executable was a 241 MB x86-64 PE built on 2020-10-13.
- Its section names were scrambled. The 50.7 MB code section was mostly `0xCC` fill, while a 176.8 MB executable `.arch` section had high entropy consistent with protected or virtualized content. The entry point was only a small stub.
- The import inventory was comparatively small: about 630 imports covering Win32, the C runtime, PhysX 3, Bink 2, Steam, and NVIDIA GameWorks/DLSS.
- FFXV uses the Luminous Engine. Its PC version is already native x86-64; this is not an older-console binary with a small, stable address space that can be translated function by function in the usual N64-style workflow.

These are facts from the earlier read-only scan recorded in `AGENTS.md`; no new Steam executable inspection was performed for this revision. High entropy and section layout support the anti-tamper conclusion but do not identify a particular vendor or protection version.

## What recompiling to C or another language means

Static recompilation would lift original machine instructions, recover control flow and data references, and emit equivalent portable source plus replacements for operating-system and graphics calls. It would **not** automatically produce clean engine source, original C++ class designs, or faster algorithms. Even with accessible code, indirect branches, jump tables, SEH, SSE/AVX, and the Win32/D3D11 boundary would remain substantial engineering problems.

Changing C to C++ or Rust does not itself improve frame rate. A faithful translation initially preserves the original game's behavior and bottlenecks. Performance gains require profiling and targeted changes to rendering, scheduling, memory behavior, asset streaming, and shader handling.

Replacing the Luminous Engine with Unreal, Unity, Godot, or a new custom engine is a **reimplementation/remake**, not static recompilation. Gameplay, animation, physics, scripting, UI, save behavior, tools, and asset pipelines would need to be recreated and validated.

## Steam static-recompilation route

1. Use the exception table and disassembly to inventory function boundaries and classify unsupported instructions, image references, and calls.
2. Batch-lift accessible functions and validate them against original machine code; keep partial coverage and failures explicit.
3. Define portable Win32 and renderer boundaries; start with one modern graphics backend.
4. Build up a testable vertical slice before attempting whole-game translation.
5. Profile representative retail scenarios before making performance claims.

Use **C++20 for new native runtime and renderer code** unless a specific lifting toolchain requires C. C++ fits resource ownership and graphics tooling better than plain C and has no inherent runtime-speed penalty when used carefully. Rust remains viable for new tools or engine code but does not remove the reverse-engineering work.

A clean-room C++ reimplementation remains an optional fallback if usable code cannot be obtained. It is not the only permitted route. A full-game reimplementation would be team-scale, multi-year work with no assured compatibility endpoint.

## Route assessment

| Route | Assessment |
| --- | --- |
| Static recompilation of Steam `ffxv_s.exe` | **In progress.** Two bounded functions are differential-tested; whole-game instruction, call, image, runtime, and renderer coverage remains incomplete. |
| Hook and extend the retail game | Technically shorter, but rejected by the owner on 2026-11-18. |
| Rewrite everything in another language | Not a performance plan by itself and does not solve access to the original code. |
| Move assets into a general-purpose engine | A remake with major gameplay and asset-pipeline work, not a translation. |
| Clean-room C++ vertical slice | Optional fallback or independent prototype, not a mandatory direction. |

## Performance and release requirements

No performance claim should be made until representative retail scenarios have CPU/GPU captures and repeatable benchmarks. Asset I/O, shader compilation, main-thread work, and rendering cost are hypotheses to measure, not established causes of stutter in this project.

Any eventual distributable must follow the workspace standards: one executable that builds from the user's own dump and later plays directly; portable files beside the executable; CLI flags for launcher-independent operation; and a plain Linux tarball if Linux is supported.

## Bottom line

The **Steam executable is the target**, and a bounded static-lifting pipeline now works on ordinary code found in both major executable sections. The next work is expanding image-backed addressing and call coverage, batch-verifying functions, and building the runtime and renderer boundaries. The project is no longer stopped by the initial code-access hypothesis, but it remains far from a playable one-to-one recompilation or a validated performance claim.
