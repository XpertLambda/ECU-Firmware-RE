# Anti-Tamper & Security Mechanisms

## Overview

The TC1766 firmware implements several layers of protection that activate during and after any SecurityAccess attempt. Understanding these is essential for anyone doing live analysis, debugger work, or attempting to patch the binary.

> **Clean-room rewrite note.** The anti-tamper validator (`FUN_8001971C`),
> the WDT reset trigger (`FUN_80018E40`), and the magic signatures in
> `EcuState` are all **unchanged** by the synthetic lab rewrites. Only the
> dispatcher (`FUN_80019EC2`) and the S2K core (`FUN_8001B57E`) were
> re-implemented; the post-attempt validator is still called
> unconditionally from the dispatcher's tail. Every reset path described
> below applies identically to the lab binary.

---

## 1. Post-Attempt Validation — `Validate_System_State` (0x8001971C)

This function is called **unconditionally** at the end of every SecurityAccess dispatch, regardless of success or failure or which dispatcher branch was taken (odd/even, RequestSeed/SendKey, AltHandler):

```c
// Always run anti-tamper validation after a security access attempt
Validate_System_State();
```

It performs three checks in sequence:

### 1a. Environment Check
```c
Check_Environment_Conditions();
```
Verifies the execution environment hasn't been tampered with. Exact checks are internal (not fully decompiled), but typical ECU implementations of this design check stack canaries, RAM CRC, and peripheral register states.

### 1b. Magic Signature Check
```c
if (EcuState.signature_1 != MAGIC_SIGNATURE_1 ||
    EcuState.signature_2 != MAGIC_SIGNATURE_2) {
    Trigger_Hardware_Reset(5, 0x2F, 1);
}
```

| Constant | Value | Two's Complement Source |
|----------|-------|------------------------|
| `MAGIC_SIGNATURE_1` | `0xA55A000F` | `-0x5AA50FF1` |
| `MAGIC_SIGNATURE_2` | `0xC33C1881` | `-0x3CC3E77F` |

These magic values must be present in the `EcuState` struct in LDRAM at all times. If a debugger modifies nearby memory or if the struct is relocated, this check fires.

### 1c. Execution Integrity Check
```c
if (Verify_Execution_Integrity() != 0) {
    Trigger_Hardware_Reset(5, 0x2F, 1);
}
```
Likely checks a code CRC or PC-range consistency — designed to catch patched flash or code injection.

### 1d. Timing Check (Anti-Debugger)
```c
if (Check_Execution_Timer() != 1) {
    Trigger_Hardware_Reset(5, 0x2F, 0);
}
```
Measures execution time. If the SecurityAccess handler took too long — as it would under single-step debugger control — this fires. The STM (System Timer) is used for measurement. Normal execution completes the S2K LFSR (35 iterations) in well under 1 ms. The Fibonacci-form rewrite has the same iteration count and roughly the same per-iteration cost (one shift + one branchless XOR + one mask), so the worst-case timing budget is unchanged.

---

## 2. Hardware Reset Trigger — `Trigger_Hardware_Reset` (0x80018E40)

When any tamper check fails, this function executes an immediate unrecoverable reset:

```c
void Trigger_Hardware_Reset(uint8_t reset_type, uint16_t error_code, uint32_t context) {
    // Log crash context to NVM
    CrashLog.error_code_inv = ~error_code;   // note: stored inverted
    CrashLog.return_address = __builtin_return_address(0);
    CrashLog.reset_type     = reset_type;
    CrashLog.context        = context;
    CrashLog.timer_state    = (STM_CAP * (STM_CLC >> 8 & 7)) | (STM_TIM0 * (STM_CLC >> 8 & 7));

    // Trap to debugger if one is attached (detectable via DBGSR bit 0)
    if (DBGSR & 1) {
        __debug();
    }

    // TriCore WDT unlock + reset sequence
    uint32_t wdt0 = WDT_CON0;
    uint32_t wdt1 = WDT_CON1;
    WDT_CON0 = ((wdt0 & 0xFFFFFFF3) | 0xF0 | (wdt1 & 0xC)) ^ 2;  // password access
    WDT_CON0 = (wdt0 & 0xFFFFFFF0) | 2;                            // WDT modify
    RST_REQ  = 4;                                                   // system reset request

    while (1) {}   // hang until WDT fires
}
```

**Crash log note:** `error_code` is stored as its bitwise complement. When reading crash logs from DFlash to diagnose a reset, XOR the stored value with `0xFFFF` to get the original code.

---

## 3. Debugger Detection (DBGSR Register)

The line `if (DBGSR & 1)` checks bit 0 of the Debug Status Register (DBGSR). On TriCore, this bit is set when a debugger (e.g., JTAG/DAP) is connected and the CPU is halted. If a debugger is attached, the ECU will call `__debug()` (a breakpoint trap) before issuing the reset — allowing the debugger to catch the crash, but also confirming that the ECU detected it.

**Implication for live analysis:** Attaching a debugger and stepping through `Validate_System_State` will always trigger the timing check and likely the debugger-presence check. The ECU will reset.

---

## 4. Seed Replay Prevention

```c
// Clear the seed active flag and lock state to prevent replay attacks
state->seed_active_flag &= ~2;
state->access_granted = 0;
```

On every SendKey attempt (even a failed one), the seed-active flag is cleared. This means:
- Only one key attempt is allowed per seed request
- After a failed key, a new RequestSeed must be sent before trying again
- The ECU likely enforces a retry delay or lockout counter in DFlash (not fully traced)

---

## 5. Security Level Boundary Check

```c
if (security_level > 0x7E) {
    state->seed_active_flag &= ~2;
    return 0x91;
}
```

Any sub-function ≥ 0x7F is rejected immediately, and any pending seed is also cleared. This prevents using the 0x7F/0x80 special sub-functions as a bypass into the standard LFSR path.

The parity-first dispatcher routes `0x7F`/`0x80` to the relocated AltHandler at **`0x8001B6D0`** before they ever reach the LFSR, so the boundary check above is a defence-in-depth gate, not a primary filter.

---

## 6. Summary — What Will and Won't Trigger a Reset

| Action | Triggers Reset? |
|--------|----------------|
| Standard RequestSeed + valid KeyGen response | No |
| Standard RequestSeed + wrong key | No (returns NRC 0x33; reset only via tamper checks) |
| JTAG single-step through S2K function | Yes (timing check) |
| Flash patch to S2K function (code CRC changes) | Yes (integrity check) |
| Memory write near EcuState struct | Yes (magic signature check) |
| Attaching JTAG (even passively) | Possibly (DBGSR check) |
| Sending sub-function ≥ 0x7F to LFSR path | No (rejected early, returns 0x91) |
| Replay of previous seed/key pair | No (seed flag cleared, returns 0x33) |
