# Lane 421: CRT constructor corridor 1658–1690

## Finding

This tranche is statically complete in the audited supplemental build: all 33 constructor RVAs have source bodies, are registered in `supp_table.h`, and are absent from the harness skip list. Its seven direct code targets are also present, registered, and not skipped. That does **not** make blanket benign returns safe: constructor 1658 enters a stateful map/tree initialization path, and a bounded transitive walk reaches three functions that the harness does skip. Their branches and effects must be observed before treating those skips as harmless.

The captured `run.err.log` and `run.log` are stale for the current harness. Their copies were made under this folder before reading. They are byte-identical (SHA-256 `04B72C5C8EDADCFD3C8E1960CC7683B13CDE9F08ECEBFC15C489BE55AEFE17FA`), last modified November 23, 2026, and have 541 `initterm ctor rva` entries. The final logged constructor is line 1340, `initterm ctor rva 0x55d9c80`; neither copy contains constructor 1658 (`0x576b5d0`). These logs cannot establish whether the newer run reached this corridor.

## Corrected slot mapping

The retail PE has image base `0x140000000`; its `.link` section starts at RVA `0x3066000`. The captured `analysis/runtime_link.bin` is `0x144e000` bytes and has SHA-256 `289910C456893E048AFA86E5929003331521B4336E133A077F7AEF4DB69BEF3C`.

The constructor slot formula used here is `slot_rva(i) = 0x3067ea0 + 8*i`. Thus index 1658 is slot `0x306b270`, whose captured qword is VA `0x14576b5d0`, or function RVA `0x576b5d0`; index 1659 is slot `0x306b278` and function RVA `0x576b660`. The older `analysis/ctor-tranche-1426-1681-corrected-manifest-2026-11-23.json` labels `0x576b660` as index 1658 because its slot origin is one qword later. `audit.json` records both values and the correction.

Inputs recorded by `audit.json`:

- Retail `ffxv_s.exe`: `78D29C1CBCE8B94BF1E0FA2B67053A24521A8C49B763D487C1DA29F63DCA0C8C`
- Captured `runtime_link.bin`: `289910C456893E048AFA86E5929003331521B4336E133A077F7AEF4DB69BEF3C`
- `generated/runtime-oep/recomp_runtime.c`: `05C4F7571E0E437C34FE5BA4C2A966662628BB7F8F4EA8EAC71FAD802CFBEEE3`
- `generated/runtime-oep/supp_table.h`: `BE11AA6066D37E4A20901CD74331BCCC7C4E17A735A1DEEC196D8D8BFEF3FE0D`
- `generated/runtime-oep/harness.c` snapshot used for skip checks: `A8E5DEA12807D8DE28216954A48497061DFCEDE60685EF6257C54FC22ABB070B`

The generated harness changed while this audit was in progress. The hash above identifies the exact stable read used to produce `audit.json`; recheck skip membership if the harness is regenerated again.

## Corridor evidence

| Constructor index | RVA | Static behavior | Consequence |
|---:|---:|---|---|
| 1658 | `0x576b5d0` | Calls `0x8323240` with pointers derived from globals `0x4ce78a0` and `0x3297938`. | This is the first stateful constructor in the tranche. It reaches both a state/TLS helper and the map/tree path. |
| 1659 | `0x576b660` | Dispatches to `0x2e22278`. | Cleanup/registration behavior depends on that target’s result. |
| 1660–1670 | `0x576b7c0`–`0x576c480` | Mostly leaf/data-copy constructors; indices 1666–1667 call `0x38cd0`. | Source and registration are present; preserve copied globals exactly. |
| 1671 | `0x576c840` | Initializes a resource object; calls `0x38cd0`, `0x799c530`, `0x799d0a0`, then dispatches to `0x2e22278`. | Pointer and object state are load-bearing. |
| 1672 | `0x576d780` | Calls through IAT slot `0xfe2a818`, then `0x2e22278`. | The PE import is `kernel32.dll!InitializeCriticalSectionEx`. |
| 1673 | `0x576d900` | Dispatches to `0x839db90`; that body writes the result to global `0x4ce7a70`. | This publishes a singleton/object pointer consumed by downstream code. |
| 1674–1678 | `0x576d9e0`–`0x576e360` | Call `0xee80110`. | Constructor chain remains dependent on the callee’s state changes. |
| 1679–1680 | `0x576e440`, `0x576f390` | Call through `0xfe2a818`, then `0x2e22278`. | More critical-section initialization and cleanup. |
| 1681–1690 | `0x576ec60`–`0x576e960` | Mostly leaf/data-copy constructors; each dispatching body calls `0x38cd0`. | These are staged, but no saved log shows this tranche executing. |

Evidence for the first path is in `generated/runtime-oep/supp/fn_576b5d0_cpu.c:87`, `fn_8323240_cpu.c:151,169`, and `fn_ef35080_cpu.c:560`: `0x576b5d0 → 0x8323240 → 0xef35080 → 0x2de47a0`. Every target in that chain is registered. The four-edge audit also finds the `0x8323920` state path; it can dispatch to `0x2e22468` and `0x2e22408` (`fn_8323920_cpu.c:127,222`). Both RVAs are explicitly in `harness.c`’s `skip_rvas[]` (`harness.c:3957–3958`); the audited body at `0x2e22468` also dispatches to `0x2e2252c`, which is skipped. These are the skip-list nodes found within the visited four-edge closure; the audit does not validate successors beyond that depth. Whether these state branches execute in the current run is unknown.

The object publication is direct: `fn_576d900_cpu.c:71` dispatches to `0x839db90`, and `fn_839db90_cpu.c:253` stores to `image_base + 0x4ce7a70`. A zero/benign return from the allocator or initializer path can leave a globally published object invalid even though dispatch continues.

## Imported-call check: `0xfe2ac60`

The PE import table maps slot `0xfe2ac60` to `msvcp140.dll!?_Xlength_error@std@@YAXPEBD@Z`; its initial on-disk qword is name RVA `0xfe2f698`. The nearby slot `0xfe2a818` is `kernel32.dll!InitializeCriticalSectionEx`. The copied November 23 run log records name resolution for the latter at lines 801, 858, 888, 895, 900, 932, and 974. Those are resolver messages, not proof that constructors 1672/1679/1680 ran. The old log copies contain no `_Xlength_error` event.

`fn_ef360e0_cpu.c:311` dispatches through `0xfe2ac60` only on its length-overflow branch; the lifted body traps immediately after the imported helper returns. The helper is therefore an error path, not a success-path function that can safely be treated as a no-op. In the audited harness snapshot, the FIX90 IAT scan rejects names whose first byte is not a letter or underscore (`harness.c` around the `FIX90` slot/name check); this decorated name begins with `?` and does not pass that scan. The logs are too old to prove whether another resolver populated the slot. If the branch fires, capture the length and container bounds before deciding how to forward the exception helper.

## Next observation

Do not add another skip, return value, or memory repair based on this static audit. The current owner-reported wall is a native low-memory scan after a lifted thread returns `0`, using a poisoned base/bound and failing page commits with error 487; the captured November 23 logs predate that observation.

The cheapest decisive observation is a one-shot instruction-level trace that stops at the first bad input and does not continue:

1. At the native scanner’s first instruction, record the base, bound, stride, return address, and the exact guest struct fields that supplied them. Stop before the first failed commit or scan iteration.
2. Trace those fields backward to their last writer. At the constructor corridor, record entry/exit state for `0x576b5d0`, `0x8323240`, `0x8323920`, `0xef35080`, and `0x2de47a0`, including the state word at `0x4ce7898`, the object at `0x4ce7890`, the map/tree arguments, and allocator result. Record whether either skipped call (`0x2e22468`/`0x2e22408`) was reached and its arguments.
3. If the length-overflow branch at `0xef3615d` is taken, capture `rdi` and the owning container’s begin/end/capacity values, then stop. Do not turn the `_Xlength_error` return into a benign success.

This identifies the poison producer or confirms a separate branch. The corridor audit alone does not show a rendered frame and cannot certify the current run reached these constructors.

## Artifacts

- `inspect_ctor_tranche.py` is a read-only auditor; it hashes each generated source before accepting it and writes only `audit.json` beside itself.
- `audit.json` contains the 33 slot/body mappings, direct target checks, bounded transitive path, import names, and input hashes.
- The copied log files are local evidence only; they are not needed to regenerate the static audit and are not included in the GitHub change.
