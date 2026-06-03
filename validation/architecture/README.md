# TC1766 UDS Security Access — Validation & Findings

**Target:** Volkswagen 1.4 TSI ECU — Engine code SYNTH-REF  
**Hardware:** synthetic TC1766 reference image  
**MCU:** Infineon TriCore TC1766  
**Firmware:** Boot block `1037505088` / Application `1037513970`  
**Goal:** Reconstruct the UDS Service 0x27 (SecurityAccess) Seed-to-Key algorithm

---

## Folder Contents

| File | Description |
|------|-------------|
| [`01_binary_and_memory_map.md`](01_binary_and_memory_map.md) | TC1766 memory layout, Ghidra setup, image base, all key addresses |
| [`02_function_reference.md`](02_function_reference.md) | All five identified functions — roles, addresses, call graph |
| [`03_uds_dispatch_and_frame.md`](03_uds_dispatch_and_frame.md) | UDS dispatcher logic, CAN frame layout, buffer offsets |
| [`04_seed_to_key_algorithm.md`](04_seed_to_key_algorithm.md) | Complete S2K algorithm analysis — annotated C + step-by-step |
| [`05_polynomial_table.md`](05_polynomial_table.md) | Full polynomial table reference — synthetic lab values (3 placeholder slots rejected by keygen) |
| [`06_anti_tamper.md`](06_anti_tamper.md) | Anti-tamper / watchdog mechanisms that protect the S2K path |
| `firmware_src/synthetic_keygen.py` | Python KeyGen for the synthetic lab binary (canonical copy; forwarders in `PHASE::TEST/` and `validation/keygen/`) |

---

## Quick Reference — Critical Addresses

| Symbol | Address | Description |
|--------|---------|-------------|
| `SecurityAccess_Algorithm` | `0x8001B57E` | S2K core — 332-byte bit-reversed Fibonacci LFSR (clean-room rewrite) |
| `UDS_SecurityAccess_Dispatcher` | `0x80019EC2` | UDS 0x27 router — 124-byte parity-first dispatcher (clean-room rewrite) |
| `Validate_System_State` | `0x8001971C` | Anti-tamper validator (unchanged) |
| `Trigger_Hardware_Reset` | `0x80018E40` | WDT-based hardware reset (unchanged) |
| `SecurityAccess_AltHandler` | **`0x8001B6D0`** | Sub-function 0x7F/0x80 handler — relocated from `0x8001B688` |
| `UDS_DispatchTable` | `0x8001BF48` | 20-entry main dispatch table (expanded from 10) |
| Dispatch sentinels | `0x8001BFE8` | `0x3D5C8E1B` / `0xC6F472A9` (replaced `0xA5A5A5A5`/`0xB0B0B0B0`) |
| `POLYNOMIAL_ARRAY` | `0x80025B6E` | 32-bit LFSR polynomial table (30 entries; 3 placeholders) |
| A1 SDA base | `0x8002DA38` | TriCore SDA1 global pointer |
| A1 init (startup) | `0x80106A2E` | `movh.a a1, #0x8003` |
| A1 finalize (startup) | `0x80106A32` | `lea a1, [a1]-0x25C8` |

---

## Key Findings Summary

1. **Algorithm type:** 32-bit Linear Feedback Shift Register (LFSR) with configurable polynomial and shift count. The synthetic lab binary implements the LFSR in **bit-reversed Fibonacci form**; the original was a Galois LFSR. The two forms are mathematically equivalent (`bit_reverse(galois_step(s)) = fib_step(bit_reverse(s))`) and produce identical seeds and keys on every input — empirically confirmed by 1512 self-test cross-checks + 180 firmware-emulator trials.
2. **Polynomial source:** Read-only table in PFLASH at `0x80025B6E` — 30 entries, of which **27 are usable** (indices 21/22/23 are `0xFFFFFFFF` placeholder slots that the keygen rejects).
3. **Polynomial selection:** `POLYNOMIAL_ARRAY[((security_level + 1) / 2) - 1]`. The Galois-form polynomial from the table is bit-reversed at runtime inside the LFSR and inverse-reversed on the way out, so the seed and expected key both appear in Galois (natural) form on the bus.
4. **Shift count:** `min(loop_modifier + 35, 255)` — `loop_modifier` is `rx_buffer[0x1C]`, typically `0x00` → **35 iterations**.
5. **Seed:** Received directly from ECU in RequestSeed response (4 bytes, big-endian). The ECU sends the LFSR starting state; tester applies the same LFSR to derive the expected key.
6. **Key verification:** ECU XORs received key against computed key and checks the result satisfies a symmetry constraint. Sending the raw computed key (`result = 0x00000000`) always passes.
7. **Dispatcher decision order:** Clean-room rewrite of `FUN_80019EC2` pivots on parity `(subfunc & 1)` first, then identifies the special value (0x7F for odd, 0x80 for even). Same I/O behaviour, different control-flow shape than the original linear chain.
8. **AltHandler relocation:** The expanded LFSR body (266→332 bytes) pushed the alt handler from `0x8001B688` to **`0x8001B6D0`**. Both `call` sites in the dispatcher were repatched with new TriCore B-format displacements (`0x36`: `…C8 0B` → `…EC 0B`, `0x5C`: `…B5 0B` → `…D9 0B`).
9. **Verification recipe:** `python3 firmware_src/synthetic_keygen.py --verify-bin firmware_src/synthetic_tc1766.bin` reads the polynomial table from the rebuilt binary and confirms it matches the keygen's `SYNTH_POLY_TABLE`.
