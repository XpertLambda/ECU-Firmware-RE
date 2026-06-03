# Function Reference — UDS Security Access Call Chain

All functions involved in the UDS 0x27 SecurityAccess path on the synthetic TC1766 lab firmware.

---

## Call Graph

```
UDS_SecurityAccess_Dispatcher  (0x80019EC2)
├── SecurityAccess_Algorithm   (0x8001B57E)   ← core seed/key (bit-reversed Fibonacci LFSR)
├── SecurityAccess_AltHandler  (0x8001B6D0)   ← sub-functions 0x7F / 0x80   (relocated from 0x8001B688)
└── Validate_System_State      (0x8001971C)   ← always runs after any attempt
    ├── Check_Environment_Conditions  (internal)
    ├── Verify_Execution_Integrity    (internal)
    └── Trigger_Hardware_Reset (0x80018E40)   ← conditional: fires if tamper detected
```

> **Lab-rewrite note.** Both `0x80019EC2` and `0x8001B57E` have been
> re-implemented in a *clean-room* form for the synthetic lab binary. The
> control-flow shape of the dispatcher and the inner workings of the LFSR
> are different from the original Bosch firmware — but their input/output
> behaviour is preserved bit-for-bit, and the call interfaces are unchanged.

---

## FUN_00019EC2 — UDS SecurityAccess Dispatcher

| Field | Value |
|-------|-------|
| Address | `0x80019EC2` |
| Body size | 124 bytes (was 122) |
| Role | State machine routing for UDS Service 0x27 |
| Called by | Protocol state machine (CAN/UDS layer), entry from the 20-entry dispatch table at `0x8001BF48` |
| Calls | `SecurityAccess_Algorithm` (0x8001B57E), `SecurityAccess_AltHandler` (0x8001B6D0), `Validate_System_State` (0x8001971C) |

**Methodology (clean-room rewrite): parity-first split.**
The original implementation tested the sub-function value in a linear chain
(`0x7F → 0x80 → parity → else`). The rewrite pivots on the parity bit as the
outermost discriminator and identifies the special value inside each parity
branch. Output behaviour is identical.

**Key assembly excerpt:**
```asm
80019ec2:  lea     a3, [a4]0x18         ; a3 = req + 0x18
80019ec6:  mov.aa  a2, a4               ; a2 = req (saved)
80019ec8:  lea     a15, [a5]0x18        ; a15 = resp + 0x18 (status base)
80019ecc:  ld.bu   d15, [a3]#0x3        ; d15 = req[0x1B] = subfunc
80019ece:  extr.u  d9, d15, #0x0, #0x8  ; d9  = subfunc & 0xFF
80019ed2:  jz.t    d15, #0x0, even_path ; parity-first branch
```

**Routing logic:**
| Branch | Condition | Callee | Args | Tag stored |
|--------|-----------|--------|------|------------|
| Odd RequestSeed | `(subfunc & 1) && subfunc != 0x7F` | `0x8001B57E` | `(&resp.payload, subfunc, req.payload[0])` | `0x06` @ `resp+0x19`; rc → `resp+0x20` |
| Odd special     | `subfunc == 0x7F`                  | `0x8001B6D0` | `(&resp.payload, 0x7F)` | `0x0C` @ `resp+0x19`; rc → `resp+0x26` |
| Even SendKey    | `(subfunc & 1) == 0 && subfunc != 0x80` | `0x8001B57E` | `(&req.payload, subfunc, 0)` | `0x02` @ `resp+0x19`; rc → `resp+0x1C` |
| Even special    | `subfunc == 0x80`                  | `0x8001B6D0` | `(&req.payload, 0x80)` | `0x02` @ `resp+0x19`; rc → `resp+0x1C` |

**Response code handling:**
- UDS internal-success value = `0x34`
- On success: `rc` cleared to `0`, sub-function echoed to `resp[0x1B]`
- On failure: NRC propagated directly (e.g. `0x33` = SecurityAccessDenied, `0x91` = invalid length)
- Always tail-calls `FUN_8001971C` (integrity validator) before returning

---

## FUN_0001B57E — SecurityAccess Algorithm (S2K Core)

| Field | Value |
|-------|-------|
| Address | `0x8001B57E` |
| Body size | 332 bytes (was 266) |
| Role | LFSR-based seed generation and key verification |
| Called by | `UDS_SecurityAccess_Dispatcher` (0x80019EC2) |
| Calls | None |

**Methodology (clean-room rewrite): bit-reversed Fibonacci LFSR.**
The original implementation was a textbook Galois LFSR
(`state = (state << 1) ^ (msb ? poly : 0)`). The rewrite operates in
bit-reversed coordinates with a bit-reversed feedback polynomial
(`state_rev = (state_rev >> 1) ^ (-fb & poly_rev)`). Three
`bit_reverse_32` conversions sit around the LFSR loop so the seed emitted
to the response buffer and the expected key stored in
`g_expected_key` are both in Galois (natural) form — the bit-reversed
representation never leaks outside the function. Mathematical equivalence
proven by `bit_reverse(galois_step(s)) = fib_step(bit_reverse(s))` and
verified empirically by 1512 cross-checks in `synthetic_keygen.py
--self-test` plus 180 firmware-emulator trials via `KeygenOracle.java`.

**Signature:**
```c
uint8_t SecurityAccess_Algorithm(
    uint8_t* buffer,        // tx or rx buffer slice (param_1 / a4)
    uint8_t  security_level,// UDS sub-function (param_2 / d4)
    uint8_t  loop_modifier  // req.payload[0] from dispatcher (param_3 / d5)
);
// No state-pointer arg — globals are accessed via TriCore a0/a1 SDA bases.
```

**Internal globals (relative to a0/a1):**
```c
g_sec_state_flags  @ a0 - 0x55C0   // bit 1 = seed_pending
g_current_sec_lvl  @ a0 - 0x558C   // granted level byte
g_lfsr_state       @ a0 - 0x56FC   // rolling seed accumulator (Galois form)
g_expected_key     @ a0 - 0x581C   // expected key for SendKey compare
g_lfsr_poly_tbl[]  @ a1 - 0x7ECA   // 30 polynomials in Galois form
```

**Critical instruction — polynomial array access:**
```
Address: 0x8001B59A (offset 0x1C in the function body)
Bytes:   D9 12 36 48
Mnemonic: lea a2, [a1]-0x7ECA
Effect:  a2 = A1 - 0x7ECA = 0x8002DA38 - 0x7ECA = 0x80025B6E
```

This is where Ghidra's dataflow on `a2` leads you to the polynomial table.

**LFSR-loop signatures inside the body** (useful for fingerprinting):
- Three `bit_reverse_32` loops, each ending in `06 ?? FC FB` (TriCore `loop a15, BODY`) at offsets `0x6C`, `0x80`, `0xAE` inside the function body.
- Branchless mask `rsub d15, d15, #0x0` (bytes `8F 14 00 F1`) at offset `0x66` of the Fibonacci LFSR loop.

---

## FUN_0001971C — Security State Validator (Anti-Tamper)

| Field | Value |
|-------|-------|
| Address | `0x8001971C` |
| Role | Post-attempt integrity check — runs after every SecurityAccess call |
| Called by | `UDS_SecurityAccess_Dispatcher` (always, unconditionally) |
| Calls | `Check_Environment_Conditions`, `Verify_Execution_Integrity`, `Trigger_Hardware_Reset` |

**Behavior:** Unchanged by the clean-room rewrite.
1. Validates two magic signatures in `EcuState` memory
2. Runs `Verify_Execution_Integrity()` — checks code hasn't been patched
3. Checks `Check_Execution_Timer()` — detects debugger single-stepping
4. On any failure: calls `Trigger_Hardware_Reset(5, 0x2F, ...)` → immediate system reset

**Magic values checked:**
```c
#define MAGIC_SIGNATURE_1  0xA55AF00F   // two's complement of -0x5AA50FF1
#define MAGIC_SIGNATURE_2  0xC33C1881   // two's complement of -0x3CC3E77F
```

> **Reverse engineering implication:** Any attempt to patch the S2K function or set breakpoints in the SecurityAccess path will trigger the timer check and cause an ECU reset. See `06_anti_tamper.md`.

---

## FUN_00018E40 — Hardware Reset Trigger

| Field | Value |
|-------|-------|
| Address | `0x80018E40` |
| Role | Writes WDT unlock sequence and issues RST_REQ |
| Called by | `Validate_System_State` (0x8001971C) |
| Calls | None |

**Reset sequence (TriCore WDT protocol):** Unchanged by the clean-room rewrite.

```c
uint32_t wdt0 = WDT_CON0;
uint32_t wdt1 = WDT_CON1;
WDT_CON0 = ((wdt0 & 0xFFFFFFF3) | 0xF0 | (wdt1 & 0xC)) ^ 2;  // password access
WDT_CON0 = (wdt0 & 0xFFFFFFF0) | 2;                            // modify WDT
RST_REQ   = 4;                                                  // issue reset
while(1) {}                                                     // hang until reset
```

Before resetting, crash context is saved to NVM:
```c
CrashLog.error_code_inv = ~error_code;
CrashLog.return_address = __builtin_return_address(0);
CrashLog.reset_type     = reset_type;
CrashLog.timer_state    = (STM_CAP * (STM_CLC >> 8 & 7)) | (STM_TIM0 * (STM_CLC >> 8 & 7));
```

---

## FUN_0001B6D0 — Alternative Sub-Function Handler

| Field | Value |
|-------|-------|
| Address | **`0x8001B6D0`** (relocated from `0x8001B688`) |
| Body size | 40 bytes (unchanged) |
| Role | Handles the proprietary sub-functions 0x7F and 0x80 |
| Called by | `UDS_SecurityAccess_Dispatcher` (0x80019EC2) |
| Calls | Internal function pointers (state-dependent) |

> **Relocation note.** The new 332-byte body of `FUN_8001B57E` extends through
> `0x8001B6CA` and would have overwritten this routine at its original
> address. The function body is byte-for-byte identical to before; only its
> location moved. The two CALL sites in `FUN_80019EC2` were re-encoded with
> displacements pointing at `0x8001B6D0` (verifiable in any disassembler).

**Behavior:** Manages internal state flags and executes function pointers based on current security state. The exact semantics of sub-functions 0x7F/0x80 are ECU-specific extensions beyond the standard UDS 0x27 spec. They are not part of the standard seed/key exchange path and can be safely ignored for KeyGen purposes.
