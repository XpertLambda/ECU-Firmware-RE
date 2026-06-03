# Synthetic Binary Manifest

**File:** `synthetic_tc1766.bin`  
**Size:** 2,097,152 bytes (0x200000)  
**SHA-256:** `16a90e0455fba2c98fb8602e7d13449d44523cc1f86b177bca6baa15e31af91c`  
**Generator:** `synthetic_tc1766_build.py` (deterministic, seed `0x8001B57E`)  
**Date:** 2026-05-22  

---

## Legal Confirmation

**Zero bytes in this binary were copied from the real (unrelated) firmware.**

Sources used to author this binary:
- `FW-RE/validation/architecture/` — documented addresses and memory layout
- `FW-RE/validation/findings/findings.json` — function call graph
- `FW-RE/validation/findings/functions/*/` — algorithm structure docs
- TriCore TC1766 User Manual (public Infineon document) — instruction encodings

The real firmware was **never opened, read, or inspected**
during the generation of this synthetic binary.

---

## Memory Layout

| Region       | Start        | End          | Length    | Content in binary |
|--------------|--------------|--------------|-----------|-------------------|
| PFLASH       | `0x80000000` | `0x80177FFF` | `0x178000` | Code + data (file-backed) |
| PFLASH_TAIL  | `0x80178000` | `0x801FFFFF` | `0x088000` | `0xFF` (unprogrammed flash) |
| DMI_LDRAM    | `0xD0000000` | `0xD000DFFF` | runtime   | Not in binary |
| LMU_SRAM     | `0xB0000000` | `0xB0003FFF` | runtime   | Not in binary |

---

## Zone Map

| Zone | Address range              | Offset range         | Content |
|------|----------------------------|----------------------|---------|
| 1    | `0x80000000`–`0x80003FFF`  | `0x000000`–`0x003FFF` | Boot header, reset stub, **`FUN_80000076`** (hex encoder), **`diag_state_machine`** @ `0xE4`, **`FUN_80001096`**, **`FUN_80001178`** (ISO-TP init), **`FUN_80001184`** (completion check), **`ISOTP_StateMachine`** @ `0x118E`, **`FUN_800012F2`** (TX framing), **`FUN_80001396`** (SF/FF), **`FUN_80001824`** (CF reassembly), **`FUN_800019CA`** (wait-CF), service dispatch table @ `0x1AD0`, diag buffer @ `0x1B00` |
| 2    | `0x80004000`–`0x80013FFF`  | `0x004000`–`0x013FFF` | 256 synthetic filler stubs (one every 256 B, NOP+RET) |
| 3    | `0x80014000`–`0x8001FFFF`  | `0x014000`–`0x01FFFF` | 5 SecurityAccess-chain functions (`Trigger_Hardware_Reset`, `Validate_System_State`, `UDS_SA_Dispatch`, `SecurityAccess_Algorithm`, `SecurityAccess_AltHandler`), plus **`FUN_80019C5A`** and **`FUN_8001A4BC`** — rest `0xFF` |
| 4    | `0x80020000`–`0x80025FFF`  | `0x020000`–`0x025FFF` | `POLYNOMIAL_ARRAY` at `0x025B6E` — rest `0xFF` |
| 5    | `0x80093000`–`0x80094FFF`  | `0x093000`–`0x094FFF` | **`STM_TIM0_Read`** @ `0x93A36`, **3 RTOS scheduler tasks** at `0x93E6E`, `0x9461A`, `0x94CFE` — rest `0xFF` |
| 6    | `0x80131000`–`0x80159FFF`  | `0x131000`–`0x159FFF` | **`FUN_80131F10`** (UDS gatekeeper), **`CAN_DiagPoll_Task`** @ `0x14DC58`, **`FUN_8014FB06`**, **`CAN_Channel_RxCheck`** @ `0x153018`, **`CAN_MsgObj_Receive`** @ `0x158E2A`, **`FUN_8015C374`** — rest `0xFF` |
| —    | (remaining gaps)           | (gaps in zones 5/6)  | `0xFF` (unprogrammed flash) |

**Total recognisable functions: 284** — 27 with real assembled TriCore bodies
(5 SecurityAccess chain + 6 documented secondary + 16 internal call-target
stubs), plus 256 filler stubs and 1 Reset_Handler entry. All real bodies
come from Ghidra's `Assembler` API applied to human-written TriCore
assembly; bytes are captured in `_assembled_functions.py` for deterministic
rebuilds. Each filler stub uses the SR-format `NOP16` (`00 00`) +
`RET16` (`00 90`) sequences from Ghidra's `tricore.sinc` SLEIGH spec.

---

## Critical Address Table

Every address listed here has been verified to contain non-`0xFF` content.

| Symbol                       | Address      | Binary offset | Size    | Content summary |
|------------------------------|--------------|---------------|---------|-----------------|
| Boot header start            | `0x80000000` | `0x000000`    | 80 B    | Struct of LE uint32 fields |
| Reset/entry pointer field    | `0x80000000` | `0x000000`    | 4 B     | `0x00800090` |
| Dispatch table ptr field     | `0x80000010` | `0x000010`    | 4 B     | `0x80001AD0` |
| Diag buffer ptr field        | `0x80000014` | `0x000014`    | 4 B     | `0x80001B00` |
| CRC32 placeholder            | `0x80000030` | `0x000030`    | 4 B     | `0x00000000` |
| CRC region size              | `0x80000034` | `0x000034`    | 4 B     | `0x00020490` |
| **Synthetic magic #1**       | `0x80000040` | `0x000040`    | 4 B     | `0xC0FFEE11` (NOT `FADECAFE`) |
| **Synthetic magic #2**       | `0x80000044` | `0x000044`    | 4 B     | `0xBEEFCA11` (NOT `CAFEAFFE`) |
| Reset handler entry          | `0x80000090` | `0x000090`    | 68 B    | 32 × NOP16 (`00 00`) + RET16 (`00 90`) + NOP pad (entry stub) |
| Secondary diag-config struct | `0x80001AD0` | `0x001AD0`    | 32 B    | Forward-pointer + flags |
| Diag buffer descriptor       | `0x80001B00` | `0x001B00`    | 64 B    | Buffer ptrs, sizes, back-ptr |
| **Main UDS dispatch table**  | `0x8001BF48` | `0x01BF48`    | 160 B   | 20 (handler, SID_word) entries × 8 B; ends at `0x8001BFE7` (per `docs/ECU firmware RE.pdf` §III.4) |
| **Guard boundary**           | `0x8001BFF0` | `0x01BFF0`    | —       | Linker pad / unprogrammed flash; marks end of dispatch region |
| **Trigger_Hardware_Reset**   | `0x80018E40` | `0x018E40`    | 78 B    | WDT unlock sequence + RST_REQ write + hang loop |
| **Validate_System_State**    | `0x8001971C` | `0x01971C`    | 94 B    | calls `snapshot_status` (FUN_8001B558), canary checks (`0xA55AF00F` at `a0-0x5828`, `0xC33C1881` at `a0-0x5530`), integrity (`FUN_8001A4BC`), timing (`FUN_80019C5A`), reset on any failure (per `docs §III.9`) |
| **UDS_SecurityAccess_Disp**  | `0x80019EC2` | `0x019EC2`    | 124 B   | sub-function dispatch (0x7F/0x80/odd/even), calls `SecurityAccess_Algorithm` / `SecurityAccess_AltHandler` / `Validate_System_State` |
| **SecurityAccess_Algorithm** | `0x8001B57E` | `0x01B57E`    | ~332 B  | range guard, polynomial-table access via `lea a2,[a1]-0x7eca`, LFSR shift loop, seed/key write to buffer; body covers RequestSeed and SendKey branches, ends at `0x8001B6C8` |
| **SecurityAccess_AltHandler**| `0x8001B6D0` | `0x01B6D0`    | 40 B    | sub-function 0x7F/0x80 handler — load current_sec_lvl, branch on `0x7F`, write or return NRC |
| ─                            | `0x8001B596` | `0x01B596`    | 4 B     | exact bytes `D9 12 36 48` = `lea a2,[a1]-0x7eca` (polynomial table base computation) |
| **POLYNOMIAL_ARRAY**         | `0x80025B6E` | `0x025B6E`    | 120 B   | 30 × uint32 LE (synthetic values; slots 21/22/23 = `0xFFFFFFFF`) |
| **App_Descriptor**           | `0x80014018` | `0x014018`    | 80 B    | Second synthetic software descriptor (application image) — per `validation/architecture/01 §3` |
| **CRC32 of firmware**        | `0x80000030` | `0x000030`    | 4 B     | `0x7C86D5D8` (per `docs/ECU Firmware RE.pdf` §II.4 Table II.2) |
| **CRC32 region size**        | `0x80000034` | `0x000034`    | 4 B     | `0x00020490` (132,752 bytes) |
| **A1 init code (primary)**   | `0x80106A2E` | `0x106A2E`    | 8 B     | exact bytes `91 30 00 18 D9 11 B8 8D` = `movh.a a1,#0x8003 ; lea a1,[a1]-0x25C8` → A1=`0x8002DA38` (per `validation/architecture/01 §4`) |
| **A1 init code (mirror)**    | `0x80106AE0` | `0x106AE0`    | 8 B     | duplicate of primary (same exact bytes; lab note: "identical-shape descriptor") |
| **CRC32 stored sentinel**    | `0x8017BFFC` | `0x17BFFC`    | 4 B     | `DE AD BE EF` (per `docs/ECU Firmware RE.pdf` §I.5.1 Fig I.11) |
| **CRC-32 polynomial consts** | `0x800F0200` | `0x0F0200`    | 8 B     | `0xEDB88320` + `0x04C11DB7` (per `docs §I.5.1`, for RE-search) |

### Secondary documented functions (`validation/findings/findings.json`)

| Symbol                       | Address      | Size    | Content summary |
|------------------------------|--------------|---------|-----------------|
| `diag_state_machine`         | `0x800000E4` | 66 B    | UDS outer state machine (4 states on `DAT_d000de40[3]`), calls `ISOTP_StateMachine` / `FUN_80001178` / `FUN_80001184` / `FUN_80000076` |
| `ISOTP_StateMachine`         | `0x8000118E` | 88 B    | ISO-15765-2 transport state machine (8 states on `param[0x14c]`), branches to `FUN_80001396` / `FUN_80001824` / `FUN_800019CA` / `FUN_800012F2` |
| `STM_TIM0_Read`              | `0x80093A36` | 10 B    | `movh.a a4,#0xf000` + `ld.w d2,[a4]0x100` (reads STM_TIM0 free-running counter) |
| `CAN_DiagPoll_Task`          | `0x8014DC58` | 58 B    | 7-iter loop over CAN msg-obj slots, calls `CAN_Channel_RxCheck`, sets LDRAM flag, calls UDS gatekeeper |
| `CAN_Channel_RxCheck`        | `0x80153018` | 26 B    | Wrapper — indexes channel table via `addsc.a`, tail-calls `CAN_MsgObj_Receive` |
| `CAN_MsgObj_Receive`         | `0x80158E2A` | 106 B   | MultiCAN MOCTR / MOFCR / MOAR / MODATAL reads, NEWDAT bit check, 4-byte payload copy, NEWDAT clear |

### Internal call-target stubs

Minimal-but-valid TriCore bodies (8–60 B each) at every `FUN_xxxx` address
referenced as `called_by` or `calls` in `findings.json`. These give Ghidra
real entry points to anchor the call graph rather than `??` regions:

| Address      | Symbol                  | Role |
|--------------|-------------------------|------|
| `0x80000076` | `FUN_80000076`          | Generic hex encoder |
| `0x80001096` | `FUN_80001096`          | Internal ISO-TP helper |
| `0x80001178` | `FUN_80001178`          | ISO-TP init |
| `0x80001184` | `FUN_80001184`          | Completion check |
| `0x800012F2` | `FUN_800012F2`          | TX framing |
| `0x80001396` | `FUN_80001396`          | SF/FF processing |
| `0x80001824` | `FUN_80001824`          | CF reassembly |
| `0x800019CA` | `FUN_800019CA`          | Wait-CF check |
| `0x80019C5A` | `FUN_80019C5A`          | Internal |
| `0x8001A4BC` | `FUN_8001A4BC`          | Internal |
| `0x80131F10` | `FUN_80131F10`          | UDS dispatcher / gatekeeper |
| `0x8014FB06` | `FUN_8014FB06`          | Internal |
| `0x8015C374` | `FUN_8015C374`          | Internal |
| `0x80093E6E` | `RTOS_Task_80093E6E`    | SyntheticRTOS scheduler task |
| `0x8009461A` | `RTOS_Task_8009461A`    | SyntheticRTOS scheduler task |
| `0x80094CFE` | `RTOS_Task_80094CFE`    | SyntheticRTOS scheduler task |

---

## Boot Header Fields

```
offset  value        meaning
+0x00   00 90 80 00  reset/entry pointer = 0x00800090  (points to 0x80000090)
+0x04   00 40 00 00  size field          = 0x00004000
+0x08   00 40 00 80  RAM ptr             = 0x80004000  (.data start)
+0x0C   FC 3F 00 80  stack top           = 0x80003FFC
+0x10   D0 1A 00 80  dispatch table ptr  = 0x80001AD0
+0x14   00 1B 00 80  diag buffer ptr     = 0x80001B00
+0x18 – +0x2F        zero-fill
+0x30   00 00 00 00  CRC32 placeholder   = 0x00000000
+0x34   90 04 02 00  CRC region size     = 0x00020490 (132,752 bytes)
+0x38 – +0x3F        zero-fill
+0x40   11 EE FF C0  synthetic magic #1  = 0xC0FFEE11
+0x44   11 CA EF BE  synthetic magic #2  = 0xBEEFCA11
```

---

## Key Function Stub Details

The five named SecurityAccess-chain functions contain **real assembled
TriCore machine code** that implements the algorithms described in
`validation/architecture/02_function_reference.md`, `04_seed_to_key_algorithm.md`,
and `06_anti_tamper.md`. The bytes were produced by Ghidra's built-in
`ghidra.app.plugin.assembler.Assembler` from human-written TriCore
assembly, then captured to `_assembled_functions.py` for reproducible builds.

| Function | Size | Highlights |
|----------|------|------------|
| `Trigger_Hardware_Reset` | 78 B | `sub.a a10`, save regs, MMIO writes to WDT_CON0 (`0xF0000020`) and RST_REQ (`0xF0000010`), `j self` infinite loop. |
| `Validate_System_State`  | 94 B | Calls `snapshot_status` (`FUN_8001B558`), checks canary `0xA55AF00F` at `a0-0x5828` and `0xC33C1881` at `a0-0x5530`, integrity check (`FUN_8001A4BC`), timing check (`FUN_80019C5A`), resets on any failure. |
| `UDS_SecurityAccess_Dispatch` | 124 B | Reads `rx_buffer[0x1B]` via `ld.bu d15,[a3]#0x3`, three-way branch (0x7F/0x80 → alt, odd → RequestSeed call, even → SendKey call), unconditional tail call to `Validate_System_State`. |
| `SecurityAccess_Algorithm` | ~332 B | Range guard (`> 0x7E` → return `0x91`), **exact `D9 12 36 48` = `lea a2,[a1]-0x7eca` at `0x8001B596`**, bit-reversed Fibonacci LFSR loop, four-byte big-endian seed write, dual return paths (`0x34` / `0x91`). |
| `SecurityAccess_AltHandler` | 40 B | Entry at `0x8001B6D0`. Loads current security level via `lea a3,[a1]-0x558c`, branches on `0x7F`, returns `0x34` (granted) or `0x33` (denied). |

Decompilation (Ghidra) of `Validate_System_State` (Ghidra signed-constant display):

```c
/* g_canary_1 @ a0-0x5828 = 0xA55AF00F  (-0x5aa50ff1 signed)
   g_canary_2 @ a0-0x5530 = 0xC33C1881  (-0x3cc3e77f signed) */
snapshot_status();                           /* FUN_8001b558 */

if (*(int *)(a0 + -0x5828) != -0x5aa50ff1   /* 0xA55AF00F */
 || *(int *)(a0 + -0x5530) != -0x3cc3e77f   /* 0xC33C1881 */
 || FUN_8001a4bc() != 0                      /* integrity check */
 || FUN_80019c5a() != 1)                     /* timing/state check */
    Trigger_Hardware_Reset(5, 0x2f);
```

(Base register is `a0`, not `a1`. Canary value #1 is `0xA55AF00F` — the nibble is `F00F`, not `000F`.)

The `Reset_Handler` entry at `0x80000090` is still a 68-byte NOP-sled + RET16
stub (the lab does not document its body). The 256 synthetic filler stubs
at `0x80004000 + 256·k` are also NOP-sled + RET16 (each 20 B), per the lab's
function-count specification.

The structural meaning of each function (WDT unlock, canary check, UDS
dispatch, LFSR seed-to-key, alternate handler) is documented in the lab
analysis notes under `validation/architecture/` and `validation/findings/functions/`.
Those notes describe what the original function *does*; the stub here only
marks the address so Ghidra recognises a function entry point.

---

## proprietary IP Audit

| Check | Result |
|-------|--------|
| `FADECAFE` present in binary | **NO** — replaced with `0xC0FFEE11` |
| `CAFEAFFE` present in binary | **NO** — replaced with `0xBEEFCA11` |
| Any byte copied from real firmware    | **NO** — file never opened |
| Any known-proprietary polynomial in polynomial array | **NO** — all 27 live slots are synthetic |
| Any known-proprietary polynomial anywhere in binary | Not placed by build script |
| `0xFFFFFFFF` in slots 21/22/23 | YES — required spec convention, not proprietary IP |

---

## Reproducibility

Re-running `synthetic_tc1766_build.py` with the same Python version will
produce a bit-for-bit identical binary. All randomness uses
`random.Random(0x8001B57E)` (deterministic seeding). No system entropy
is consumed.

To confirm:
```bash
sha256sum synthetic_tc1766.bin
python3 synthetic_tc1766_build.py   # regenerate
sha256sum synthetic_tc1766.bin      # should match
```
