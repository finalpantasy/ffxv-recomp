# Thread argument at the reported low-memory wall

The frozen `run-c108` trace records `0x13ffe8dfa50` as the argument passed to lifted start RVA `0xee35c10`. It records `result 0x0` for RVA `0x2ddb070`, a different start. No captured allocation result ties those values together.

| Snapshot line | Record |
|---:|---|
| 1560 | `lifted thread start 0x2ddb070 param 0x1` |
| 1561 | `lifted thread start 0xee35c10 param 0x13ffe8dfa50` |
| 1566 | `lifted thread exit 0x2ddb070 result 0x0` |

The lines come from separate worker entries, not one call stack. The log has no thread IDs and no exit for `0xee35c10`, so it cannot associate the later scan with either worker. Its following records are a different `COPYSTALL` at dispatch `1130088` (native RIPs `0x7ff63d9abb9d` and `0x7ff63d9abba4`, faults `0` or `8`). The reported `0x12e000` access and error 487 are absent.

## Harness dataflow

Local source snapshot: `analysis/harness-current-20261123.c`, SHA-256 `dfecfa08c892b77eeecb82d4dcec5b5253e2c36f01c3458cd61c16724df7372b`.

```text
_beginthreadex arguments: start=R8, arglist=R9
  -> call_native routes the import to emulated_create_thread
  -> calloc creates RecompThreadStart; thread->parameter = cpu->r9
  -> CreateThread starts recomp_thread_entry
  -> entry copies parameter to lifted RCX and dispatches start_rva
  -> entry reads result from lifted RAX, frees stack and wrapper, returns
```

Source lines 1073–1103 allocate the wrapper separately from its `parameter` field. Lines 1042–1070 pass that field to the lifted start and return the start's result to Windows. Thus `0x13ffe8dfa50` is a guest thread argument, not the harness wrapper's allocation result. The game's earlier producer for that argument is unknown.

One independent lifetime defect is confirmed: `recomp_thread_entry` sets TLS `recomp_current_cpu` to `&start->cpu` at line 1061, then frees `start` at line 1069 without clearing TLS. No evidence ties this defect to the bad array base or bound. The native boundary is `call_native` → `recomp_native_call`; saved disassembly places the host call on the emulated stack (harness RVAs `0x236a9`–`0x236b1`).

## Candidate scan paths

Local static analysis in `analysis/spin-wall-analysis.md` and `analysis/spin-wall-static-evidence-v6.json` identifies:

| Candidate | Static evidence | Limit |
|---|---|---|
| UCRT `qsort` | Protected width-eight calls at guest RVAs `0x4c5d9c`, `0x255f410`, `0x2561558`, `0x25617a3`, `0x25e3677`; object-derived tuples at `0x4c5d9c` (`RCX=[R14]`, `RDX=ESI`) and `0x25e3677` (`RCX=[R15+0x20]`, `RDX=R14`); protected slot `0x3067be8` resolves as `qsort`. | A live UCRT RIP and matching entry arguments are needed to identify this path. |
| Lifted array walk | RVA `0x2651650` reads four base/count pairs and advances by eight. Source snapshot `analysis/fn_2651650_cpu.snapshot.c`, SHA-256 `5fd7cee4a466ca16580d1b90b59feae8dcfdf522997f8099fa277055f54a423e`. | No trace links this function to the reported native loop. |
| Raw low address | RVA `0x12e000` maps to executable bytes at `0x14012e000` if treated as an image RVA. | It may instead be a damaged pointer. Error 487 says the requested address is invalid; it does not name the producer. |

## Evidence boundary

- No `analysis/lane-441` path was found in this checkout. The user-reported scan is not in the frozen logs reviewed here.
- `analysis/run-c108-20261123.err.snapshot.log` SHA-256: `4ffa56f0f46fec38edb0b7fd8a14541031cc2868d40a67613745b6b59704d43a`.
- `analysis/harness-current-20261123.c` SHA-256: `dfecfa08c892b77eeecb82d4dcec5b5253e2c36f01c3458cd61c16724df7372b`.
- `analysis/next-run-toolkit-20261123/harness-latest.map` SHA-256: `85ea36979b449496845f01b831dc96ee7ff3e5415f7f5e7f69788b8f988b7ab6`.
- `analysis/spin-wall-analysis.md` SHA-256: `4a91da6c2aa308e23aea95fada253f7689d3374df95cdea909e4121aaa040749`.
- `analysis/spin-wall-static-evidence-v6.json` SHA-256: `734ae4c58cbd715ea63b9c7d99469c22860e8824b17dfc01aeeb23e00354429a`.
- Steam `ffxv_s.exe` SHA-256: `78d29c1cbce8b94bf1e0fa2b67053a24521a8c49b763d487c1da29f63dca0c8c`.
- Raw snapshots remain outside the public commit. Runtime logs use printf text; there is no checked-in event schema for this path. `tools/ffxv-recomp-stack-contract-auditor/test_stack_contracts.py` covers separate stack-contract checks; no test was run or added here.

## Next decisive capture

Stop one strict run at the first access below `0x1000000`, before healing or resuming. Record native RIP, access address and type, all registers, TID, active native target, guest return RVA, and caller base/count fields. For a UCRT hit, capture the `qsort` tuple and guest call site. For RVA `0x2651650`, capture `RBX`, all four pairs, and the element index. For a cleanup hit, distinguish `VirtualFree`, `free`, post-return teardown, and another worker.
