# FFXV Recomp Stack Contract Auditor

Static verification for two guest-stack contract defects found while bootstrapping the Final Fantasy XV recompilation runtime.

This package contains only original runtime-tooling changes. It does not contain game executables, extracted assets, memory dumps, generated game functions, SDK files, or runtime logs.

## Findings

### FIX72 intercepted return

A lifted call pushes a synthetic return address before dispatching the `memcpy` thunk. The FIX72 zero-length/null-source shortcut returned from the dispatcher without consuming that address. The callee resumed with guest `RSP` eight bytes low and restored `RBX` from the saved-`R14` slot.

`patches/fix72-return-pop.diff` adds the missing `cpu->rsp += 8` before the shortcut returns.

### FIX44 alignment bounce

The generic native-call alignment bounce relocates the outgoing frame from original guest stack base `R` to `R-8`. The trampoline consumes the copied return and leaves `RSP=R`; the lifted caller requires `R+8`.

`patches/fix44-bounce-rsp.diff` invokes the trampoline inside the bounce branch, restores `RSP=R+8`, preserves the trampoline's `RIP`, and returns before the ordinary trampoline call.

## Verification

The verifier is read-only. It requires the exact local runtime sources and refuses stale or ambiguous inputs.

```powershell
python -I verify_stack_contracts.py check --project-root ..\..\..
python -I -m unittest discover -s . -p "test_*.py" -v
```

Expected output for the pinned source generation:

```text
fix72: input and transformed hashes verified
fix44: input and transformed hashes verified
patch identities verified
PASS
```

The patches should be integrated and run separately. The FIX72 patch is the minimal causal test for the first corruption boundary. The FIX44 patch is a second, independently proved stack correction and should follow in a separately attributable run.

Static verification does not establish that the game reaches a rendered frame. Runtime acceptance requires the old bad-pointer signature to disappear naturally, without a healing exception path, and subsequent execution to cross the prior dispatch boundary.
