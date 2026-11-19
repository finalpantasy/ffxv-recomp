# Final Fantasy XV recomp / port

Done means: the Steam game runs without its original executable as a one-to-one recompilation; gameplay, content, world connections, presentation, and save behavior match the original except for explicitly selected improvements; a modern renderer delivers measured performance gains; and documented mod interfaces can replace or add any game content or behavior, including weapons, enemies, drops, maps, world links, quests, characters, voices, music, graphics, and lighting. The result remains one portable executable with CLI flags.

## Rules
- Target the Steam Windows Edition with Royal Edition content and its `ffxv_s.exe`; do not substitute the UWP `ffxv_u.exe`.
- No project-specific prohibition applies to removing or bypassing executable protection.
- No real name or user paths in anything pushed public.
- Release standards from F:\AI\Recomps\AGENTS.md apply (one exe, portable, CLI flags).
- Heavy runs: BelowNormal, one at a time, 10-minute cap; kill only own PIDs.

## Owner answers (2026-11-18)
- Copy: Windows Edition (Steam, Royal Edition content).
- Goals: one-to-one game behavior and content by default; modern renderer and lighting; measurably better performance; comprehensive modding and modding tools.
- Mods must be able to add or replace weapons, enemies, drops, maps, world connections, quests, characters, voices, music, graphics, lighting, and ultimately any other content or behavior. Treat content as data with stable identities and override layers rather than hardcoding a fixed mod list.

## Decision (owner, 2026-11-19): Steam static recomp
Owner rejected the hook-and-extend route on 2026-11-18. Goal: statically recompile the Steam `ffxv_s.exe` (x86-64 PE) to portable C/C++, with our own renderer layer replacing D3D11 and shims replacing Win32, so it can be ported to other systems and fixed for stutter/performance.

## Current implementation state (2026-11-19)
- Steam target located: revision 1287370, SHA-256 `78d29c1cbce8b94bf1e0fa2b67053a24521a8c49b763d487c1da29f63dca0c8c`.
- The PE exception table exposes 169,723 function ranges: 40,925 in `.edata` and 128,798 in `.arch`. Ordinary x86-64 instructions were confirmed in both sections; `.arch` is not uniformly encrypted.
- A focused Ghidra analysis copy excludes `.arch` bytes only to fit the 10-minute analysis cap. The ready session recovered 51,109 procedures and 78,745 defined strings from the remaining image. It references `ffxv_sp.pdb`, but no local PDB was found.
- The shared x64 lifter accepts RVAs and models integer memory access, low-width/partial registers, stack operations, conditional moves, direct branches, direct and indirect calls, Win64 stack arguments, RIP-relative image addressing, 128-bit XMM moves/zeroing, and scalar moves. Its generic fast-ABI suite passes 49,114 native/C comparisons plus rejection/RVA checks; the full CPU-context suite passes 14,608 comparisons including RIP/RSP, tail control flow, packed/scalar float math, conversions, comparisons, and XMM state.
- `generated/fn_140001120.c` passed 22 native/C differential cases at `/Od` and `/O2`. `generated/fn_145586f60.c` passed 30 such cases. `generated/fn_145c46a30.c` passed 258 RIP-relative image cases. `generated/fn_1455830a0.c` passed 32 direct-call cases. These are validated functions, not a playable game or evidence that whole-game lifting is solved.
- The optimized resumable batch driver has emitted 58,529 fast-ABI C functions and 104,815 full CPU-context functions with diagnostics. Tail-jump support reduced context branch-outside failures to about 550. Three safe standalone fast-ABI batch functions passed 43 domain-valid cases each at `/Od` and `/O2`.
- Low-impact runtime stack capture identified a persistent game-startup chain through `0x696e509`, `0x696e908`, `0x692f3ee`, `0x6928b14`, and `0x4d077e`. This is a bootstrap reference, not yet a proven OEP. Instruction work is targeting the actual blockers on this chain.
- The generated runtime dispatcher passed nested lifted-call, global-state, repeated-dispatch, and unresolved-target tests at `/Od` and `/O2`. Root-based runtime selection is available for building reachable call graphs.
- Runtime comparison of the licensed game found zero `.edata` changes and only 2,467 changed `.arch` bytes. The changes include license-dependent DWORDs and mutated padding/obfuscated paths, not wholesale code decryption. The UWP build is authorized as a reference for matching and recovering Steam functions, not as a replacement target.
- Cross-build analysis found 15,777 exact and 62,987 relocation-normalized unique UWP/Steam function matches. Twenty-eight of 195 Steam functions containing runtime-mutated bytes have normalized UWP candidates; these matches require semantic validation and address remapping before use.

## Next implementation gates
1. Add direct/indirect calls, imports, full register/SSE state, and robust function-boundary recovery.
2. Batch-lift accessible functions with differential verification and explicit unsupported-instruction diagnostics; analyze protected or nonuniform regions separately instead of excluding them from the final target.
3. Introduce the runtime memory model and portable Win32/renderer boundaries, then bootstrap enough subsystems for a playable vertical slice.
4. Build modding as stable content IDs, data-driven registries, virtual-file/override layers, and scripting hooks across gameplay and rendering. Prove additions and replacements for every required content family and arbitrary behavior extension.
5. Establish one-to-one reference scenarios and repeatable CPU/GPU benchmarks before claiming fidelity or performance improvements.

## Finding 2026-11-18: Steam exe appears anti-tamper protected (technical obstacle)
Read-only header scan of the owner's `ffxv_s.exe` (241 MB, built 2020-10-13): section names scrambled; the 50.7 MB code section was mostly `0xCC` fill (entropy ~1-3.5), and a 176.8 MB executable `.arch` section had entropy 7.0-7.7, consistent with obfuscated or virtualized code. The entry point sits in a tiny stub. This matches commercial anti-tamper, but the scan does not identify a vendor or protection version. A static recomp needs accessible ordinary instructions; protection is a technical obstacle to investigate, not a project-rule prohibition. Imports are small (about 630: Win32, CRT, PhysX 3, Bink 2, Steam, NVIDIA GameWorks/DLSS), so the surface was otherwise reasonable.

Main risks to check first: obtaining usable code from the protected exe, x64 lifting (indirect jumps, jump tables, SEH, SSE/AVX), size of the Win32/D3D11 import surface, and middleware DLLs (Havok, Wwise, etc.).

## Notes
- FFXV (Luminous Engine) is x86-64 on PC, PS4 and Xbox One, so classic N64-style static recomp does not map directly. Static lifting still requires accessible code and substantial control-flow, runtime, renderer, and middleware work.
