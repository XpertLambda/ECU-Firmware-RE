# TC1766 Binary Layout & Memory Map

## 1. Target Binary

| Field | Value |
|-------|-------|
| File | `synthetic_tc1766.bin` |
| MCU | Infineon TriCore TC1766 |
| Hardware | synthetic TC1766 reference image |
| Boot block PN | `1037505088` |
| Application PN | `1037513970` |
| Software string | `ECULAB_SW v01.00.00 SYN.00` |
| RTOS | SyntheticRTOS v1.0 (ETAS, TriCore variant) |
| VW engine | Generic Reference |
| Full ID string | `P0101 0261S05590 1037513970 03C906016S 03C906016T 8544 SYNTH_LAB_REF A20p43E` |

---

## 2. TC1766 Memory Map (Ghidra Setup)

Configure Ghidra with these regions. The dump covers PFLASH only; LDRAM/SPRAM are runtime-only.

| Region | Start | Length | R | W | X | Volatile | Notes |
|--------|-------|--------|---|---|---|----------|-------|
| PFLASH | `0x80000000` | `0x200000` | ✓ | | ✓ | | Cached PFlash (primary) |
| PFLASH_UNCACHED | `0xA0000000` | `0x200000` | ✓ | | ✓ | | Byte-mapped overlay of above |
| DFLASH | `0x8FE00000` | `0x20000` | ✓ | ✓ | | | Data flash (NVM, persistent) |
| DFLASH_UNCACHED | `0xAFE00000` | `0x20000` | ✓ | ✓ | | | Overlay |
| LMU_SRAM | `0xE8400000` | `0x4000` | ✓ | ✓ | ✓ | | |
| LMU_ALIAS_C0 | `0xC0000000` | `0x4000` | ✓ | ✓ | ✓ | | Overlay |
| LMU_ALIAS_D8 | `0xD8000000` | `0x4000` | ✓ | ✓ | ✓ | | Overlay |
| DMI_LDRAM | `0xD0000000` | `0xE000` | ✓ | ✓ | | | Local data RAM (runtime only) |
| PMI_SPRAM | `0xD4000000` | `0x2000` | ✓ | ✓ | ✓ | | Scratchpad RAM (runtime only) |
| SFR peripherals | various | | ✓ | ✓ | | ✓ | Mark volatile, no-execute |

> **Common Ghidra mistake:** Set PFLASH size to `0x200000`, not just the dump size. The dump is 1.5 MB; the chip has 2 MB. Tail is unprogrammed (0xFF). Failure to do this breaks cross-references past the dump boundary.

---

## 3. Software Descriptor at `0x80000000`

This is a vendor-specific header format, not the TriCore BMHD. The synthetic binary uses `C0FFEE11`/`BEEFCA11` magic (differs intentionally from production firmware).

| Offset | Address | Value | Meaning |
|--------|---------|-------|---------|
| +0x00 | `0x80000000` | `0x00800090` | Reset / entry pointer |
| +0x04 | `0x80000004` | `0x00004000` | Size field |
| +0x08 | `0x80000008` | `0x80004000` | RAM ptr (.data start) |
| +0x0C | `0x8000000C` | `0x80003FFC` | Stack top |
| +0x10 | `0x80000010` | `0x80001AD0` | Service dispatch table ptr |
| +0x14 | `0x80000014` | `0x80001B00` | Diag buffer descriptor ptr |
| +0x40 | `0x80000040` | `0xC0FFEE11` | Synthetic magic #1 |
| +0x44 | `0x80000044` | `0xBEEFCA11` | Synthetic magic #2 |
| +0x30 | `0x80000030` | `0x7C86D5D8` | CRC32 of firmware |
| +0x34 | `0x80000034` | `0x00020490` | CRC region size (132,752 bytes) |

A second identical-shape descriptor lives at `0x80014018` for the application image.

---

## 4. SDA Register Initialization — A1 (SDA1)

TriCore uses two global address registers (A0, A1) as Small Data Area (SDA) base pointers. They are set once at startup and held for the lifetime of execution. All global array/struct accesses use `[a1] ± offset` or `[a0] ± offset`.

### A1 Initialization Sequence

Two instruction pairs initialize A1 at startup. Both arrive at the same final value.

**Pair 1 — at `0x80106A2E`:**

| Address | Raw Bytes | Mnemonic | Effect |
|---------|-----------|----------|--------|
| `0x80106A2E` | `91 30 00 18` | `movh.a a1, #0x8003` | A1 ← `0x80030000` |
| `0x80106A32` | `D9 11 B8 8D` | `lea a1, [a1]-0x25C8` | A1 ← `0x80030000 - 0x25C8` = **`0x8002DA38`** |

**Pair 2 — at `0x80106AE0`** (identical instructions, identical result):

| Address | Raw Bytes | Mnemonic | Effect |
|---------|-----------|----------|--------|
| `0x80106AE0` | `91 30 00 18` | `movh.a a1, #0x8003` | A1 ← `0x80030000` |
| `0x80106AE4` | `D9 11 B8 8D` | `lea a1, [a1]-0x25C8` | A1 ← **`0x8002DA38`** |

**A1 final value: `0x8002DA38`**

### TriCore Instruction Encoding Notes

**MOVH.A encoding** (opcode `0x91`):
```
byte3 = (d << 4) | const16[15:12]
byte2 = const16[11:4]
byte1 = const16[3:0] << 4
byte0 = 0x91
```
For `91 30 00 18`: d=1 (A1), const16 upper nibble from byte3[3:0]=8 → `0x8003` → A1 ← `0x80030000`

**BOL (Base Offset Long) LEA encoding** (opcode `0xD9`):
```
off16[5:0]   = byte2[5:0]
off16[11:10] = byte2[7:6]
off16[9:6]   = byte3[7:4]
off16[15:12] = byte3[3:0]
```
For `D9 11 B8 8D`:
- byte2=`0xB8`: `[7:6]=10` → off16[11:10]; `[5:0]=111000` → off16[5:0]
- byte3=`0x8D`: `[7:4]=1000` → off16[9:6]; `[3:0]=1101` → off16[15:12]
- Assembled off16 = `0xDA38` → sign-extended = `-0x25C8`

---

## 5. All Key Addresses — Discovered in This Analysis

| Address | Symbol | Type | Notes |
|---------|--------|------|-------|
| `0x80000000` | Software descriptor | Data | Software header / entry metadata |
| `0x80001AD0` | Service dispatch table | Data | 11-entry vtable of function pointers |
| `0x80001B00` | Diag buffer descriptor | Data | Three 1 KB diagnostic CAN buffers |
| `0x80014018` | App descriptor | Data | Second software descriptor (application image) |
| `0x80018E40` | `Trigger_Hardware_Reset` | Code | WDT-based reset (`FUN_00018e40`) |
| `0x80019EC2` | `UDS_SecurityAccess_Dispatcher` | Code | UDS 0x27 router (`FUN_00019ec2`) — 124 bytes, parity-first rewrite |
| `0x8001971C` | `Validate_System_State` | Code | Anti-tamper validator (`FUN_0001971c`) |
| `0x8001B57E` | `SecurityAccess_Algorithm` | Code | S2K LFSR core (`FUN_0001b57e`) — 332 bytes, bit-reversed Fibonacci rewrite |
| `0x8001B6CA` | LFSR body end | Code | New body of `FUN_8001B57E` extends through this address |
| `0x8001B6D0` | `SecurityAccess_AltHandler` | Code | Sub-function 0x7F/0x80 handler — **relocated from `0x8001B688`** to clear the larger LFSR body |
| `0x8001BF48` | `UDS_DispatchTable` | Data | 20-entry main dispatch table (8 bytes/entry; expanded from 10) |
| `0x8001BFE8` | Dispatch sentinels | Data | `0x3D5C8E1B` / `0xC6F472A9` — table terminators (replaced `0xA5A5A5A5` / `0xB0B0B0B0`) |
| `0x8001BFF0` | Guard markers | Data | `0x95959595` / `0xC3C3C3C3` — relocated from `0x8001BFA0` |
| `0x8002DA38` | A1 SDA1 base | — | TriCore global pointer (runtime register) |
| `0x80025B6E` | `POLYNOMIAL_ARRAY` | Data | 32-bit LFSR polynomial table (30 entries) |
| `0x80106A2E` | A1 init (startup) | Code | `movh.a a1, #0x8003` |
| `0x80106A32` | A1 finalize | Code | `lea a1,[a1]-0x25C8` |
| `0x80106AE0` | A1 init (mirror) | Code | Duplicate startup pair |
| `0x80106AE4` | A1 finalize (mirror) | Code | Duplicate startup pair |

---

## 6. Diagnostic Globals in LDRAM

These live at runtime in `0xD0000000` (DMI_LDRAM) and are not present in the static binary.

| Address | Name | Role |
|---------|------|------|
| `0xD000DE28` | `EcuState` base? | ECU security state structure |
| `0xD000DE43` | Protocol state byte | Diagnostic state machine |
| `0xD000DEAC` | TPROT tamper flag | Set by RIPEMD-160 calibration check |

> **Note:** LDRAM is runtime-only. Ghidra will show "Unable to read bytes" for these addresses in static analysis. Their roles are inferred from code that reads/writes them.

---

## 7. Clean-Room Rewrite Address Deltas

The synthetic lab build contains two clean-room rewrites whose body size differs from the original. The table below captures the only addresses that shifted as a result. Everything else is byte-identical.

| Symbol | Old address | New address | Body size (old → new) | Reason |
|--------|-------------|-------------|-----------------------|--------|
| `SecurityAccess_AltHandler` | `0x8001B688` | **`0x8001B6D0`** | 40 → 40 | LFSR rewrite grew from 266 → 332 bytes; alt handler had to move past the new tail at `0x8001B6CA`. |
| Main dispatch table sentinels | `0xA5A5A5A5` / `0xB0B0B0B0` | `0x3D5C8E1B` / `0xC6F472A9` | — | Distinct lab-only terminators so the table cannot be confused with any production layout. |
| Dispatch table size | 10 entries | 20 entries | 80 → 160 bytes | New SIDs (`0x11`, `0x14`, `0x19`, `0x22`, `0x2E`, `0x31`, `0x34`, `0x36`, `0x37`, `0x85`) added. |
| Guard markers | `0x8001BFA0` | `0x8001BFF0` | — | Pushed down to make room for the expanded table + new sentinels. |

The two `call 0x8001B688` instructions in `FUN_80019EC2` were re-encoded with new TriCore B-format displacements so the dispatcher targets the relocated AltHandler. See `03_uds_dispatch_and_frame.md` §3 for the patched bytes.
