# UDS Dispatch & CAN Frame Structure

## 1. UDS Service 0x27 — SecurityAccess Overview

UDS SecurityAccess is a two-step challenge-response protocol:

```
Tester → ECU :  27 <odd_subfunction>  [loop_modifier]
ECU → Tester :  67 <odd_subfunction>  <seed_byte0> <seed_byte1> <seed_byte2> <seed_byte3>

Tester → ECU :  27 <even_subfunction> <key_byte0>  <key_byte1>  <key_byte2>  <key_byte3>
ECU → Tester :  67 <even_subfunction>                   (positive response)
             OR  7F 27 33                               (negative response — 0x33 = SecurityAccessDenied)
```

- Odd sub-function = RequestSeed
- Even sub-function = SendKey (= odd + 1)
- Common pairs observed in dispatcher comments: `0x01/0x02`, `0x09/0x0A`

---

## 2. Main UDS Dispatch Table (`0x8001BF48`)

The dispatch table in the synthetic lab build was expanded from 10 to **20 entries**. Each entry is an `(fn_ptr, SID)` pair (8 bytes); the table is terminated by two sentinel words and followed by guard markers.

```
Address       Bytes                 Meaning
0x8001BF48    <fn_ptr> <SID>        Entry 0
…             …                     …
0x8001BFE0    <fn_ptr> <SID>        Entry 19  (last)
0x8001BFE8    3D 5C 8E 1B           Sentinel A (was 0xA5A5A5A5)
0x8001BFEC    C6 F4 72 A9           Sentinel B (was 0xB0B0B0B0)
0x8001BFF0    95 95 95 95           Guard marker A (relocated from 0x8001BFA0)
0x8001BFF4    C3 C3 C3 C3           Guard marker B
```

**SIDs registered** (the underlined ten are the new lab additions on top of the original ten):

| SID  | Service                                | Notes |
|------|----------------------------------------|-------|
| `0x10` | DiagnosticSessionControl              | original |
| `0x11` | **ECUReset**                          | new |
| `0x14` | **ClearDiagnosticInformation**        | new |
| `0x19` | **ReadDTCInformation**                | new |
| `0x22` | **ReadDataByIdentifier**              | new |
| `0x27` | SecurityAccess                        | original — routes into `FUN_80019EC2` |
| `0x28` | CommunicationControl                  | original |
| `0x2E` | **WriteDataByIdentifier**             | new |
| `0x2F` | InputOutputControlByIdentifier        | original |
| `0x31` | **RoutineControl**                    | new |
| `0x34` | **RequestDownload**                   | new |
| `0x35` | RequestUpload                         | original |
| `0x36` | **TransferData**                      | new |
| `0x37` | **RequestTransferExit**               | new |
| `0x3D` | WriteMemoryByAddress                  | original |
| `0x3E` | TesterPresent                         | original |
| `0x83` | AccessTimingParameter                 | original |
| `0x85` | **ControlDTCSetting**                 | new |
| `0x86` | ResponseOnEvent                       | original |
| `0x87` | LinkControl                           | original |

> The dispatch-table-traversal loop in `FUN_80131F10` walks until it sees the two sentinels; the new sentinels were chosen to be 32-bit values that cannot occur in any valid `(fn_ptr, SID)` pair in this image.

---

## 3. CAN Frame / Buffer Layout

The ECU firmware uses an internal buffer structure for all UDS messages. The buffer is addressed relative to a base pointer. Relevant offsets:

| Buffer Offset | Field | Notes |
|---------------|-------|-------|
| `+0x18` | Payload base | `lea a3, [a4]0x18` in the dispatcher |
| `+0x19` | Response length / tag | Set by dispatcher before returning (`0x02`, `0x06`, `0x0C`) |
| `+0x1B` | Sub-function byte | `rx_buffer[0x1B]` = UDS sub-function (e.g., 0x09) |
| `+0x1C` | Loop modifier byte | `rx_buffer[0x1C]` = first data byte after sub-function |
| `+0x1C` | Seed (tx, 4 bytes) | Written to tx_buffer in RequestSeed response (Galois form) |
| `+0x1C` | Key (rx, 4 bytes) | Read from rx_buffer in SendKey |
| `+0x20` | Response code (RequestSeed) | Written by dispatcher |
| `+0x26` | Response code (alt handler 0x7F path) | Used only for sub-function 0x7F |

**UDS frame byte positions relative to a standard CAN diagnostic frame:**
```
CAN payload:  [SID=0x27] [sub-function] [data_byte_0] [data_byte_1] ...
Buffer map:   [0x1A]     [0x1B]         [0x1C]        [0x1D]
```

---

## 4. The Loop Modifier (rx_buffer[0x1C])

This byte is the first data byte in the RequestSeed frame after the sub-function. It is passed directly into the S2K algorithm as `loop_modifier` (param_3) and controls the LFSR iteration count:

```c
shifts = loop_modifier + 35;   // 0x23 = 35 decimal
if (shifts > 255) shifts = 255;
```

The Fibonacci LFSR in the rewritten body uses the *same* iteration count — only the per-iteration update changes (see `04_seed_to_key_algorithm.md`). The wire-level seed/key behaviour is unchanged.

**Standard tester behavior:**
- A standard `27 09` request sends only two bytes: service ID and sub-function.
- The byte at offset `0x1C` is either zero-padded or absent → `loop_modifier = 0x00`.
- Therefore: **standard shift count = 35 iterations**.

**Non-standard tester:**
- If a tester sends `27 09 XX` where `XX != 0`, the LFSR runs `XX + 35` iterations (max 255).
- The ECU does **not** communicate which loop count it used. The tester and KeyGen must agree in advance.
- For standalone KeyGen, always use `loop_modifier = 0` unless a packet capture shows otherwise.

---

## 5. Dispatcher Assembly — Parity-First Flow

The clean-room rewrite of `FUN_80019EC2` pivots on the parity bit `(subfunc & 1)` first, then identifies the special value (0x7F or 0x80) inside each parity branch. Observable behaviour is identical to the original linear chain — only the internal decision order changed.

```asm
; --- Entry ---
80019ec2:  lea     a3, [a4]0x18         ; a3 = req + 0x18
80019ec6:  mov.aa  a2, a4               ; a2 = req (saved)
80019ec8:  lea     a15, [a5]0x18        ; a15 = resp + 0x18 (status base)
80019ecc:  ld.bu   d15, [a3]#0x3        ; d15 = req[0x1B] = subfunc
80019ece:  extr.u  d9,  d15, #0x0, #0x8 ; d9  = subfunc & 0xFF
80019ed2:  jz.t    d15, #0x0, even_path ; outermost branch on parity

odd_path:
80019ed8:  jeq     d9,  #0x7F, alt_7F   ; identify special odd value
80019ede:  ld.bu   d5,  [a3]#0x4        ; d5 = req[0x1C] = loop_modifier
80019ee0:  mov     d4,  d15             ; d4 = subfunc
80019ee2:  call    0x8001b57e           ; SecurityAccess_Algorithm(resp.payload, subfunc, loop_modifier)
80019ee6:  ; status tag 0x06 → resp[0x19], rc → resp[0x20]

alt_7F:
80019ef0:  mov     d4,  #0x7F
80019ef2:  call    0x8001b6d0           ; alt handler (relocated)
80019ef6:  ; status tag 0x0C → resp[0x19], rc → resp[0x26]

even_path:
80019f0a:  jeq     d9,  #0x80, alt_80   ; identify special even value
80019f10:  mov     d5,  #0x0            ; loop_modifier = 0 for SendKey
80019f12:  mov     d4,  d15
80019f14:  call    0x8001b57e           ; SendKey path
80019f18:  ; status tag 0x02 → resp[0x19], rc → resp[0x1C]

alt_80:
80019f28:  mov     d4,  #0x80
80019f2a:  call    0x8001b6d0           ; alt handler (relocated)
80019f2e:  ; status tag 0x02 → resp[0x19], rc → resp[0x1C]
```

### Patched CALL bytes (AltHandler relocation)

The TriCore B-format `call` displacement was re-encoded in both call sites so the dispatcher targets `0x8001B6D0` instead of `0x8001B688`:

| Site | Offset in FUN | Old bytes | New bytes | Old disp24 | New disp24 |
|------|---------------|-----------|-----------|------------|------------|
| odd  | `+0x36`       | `6D 00 C8 0B` | `6D 00 EC 0B` | `0x0BC8` | `0x0BEC` |
| even | `+0x5C`       | `6D 00 B5 0B` | `6D 00 D9 0B` | `0x0BB5` | `0x0BD9` |

A 0x24 displacement bump in both rows is exactly the 0x48-byte AltHandler shift (`0x8001B6D0 − 0x8001B688 = 0x48`, displacements are word-scaled by 2 in this encoding).

The function always tail-calls `FUN_8001971C` (anti-tamper validator) before returning, regardless of which path was taken.

---

## 6. Routing table (per-branch outcomes)

| Branch | Condition | Callee | Args | Status tag (at `resp+0x19`) | Response code at |
|--------|-----------|--------|------|----------------------------|------------------|
| Odd RequestSeed | `(sf & 1) && sf != 0x7F` | `0x8001B57E` | `(&resp.payload, sf, req[0x1C])` | `0x06` | `resp+0x20` |
| Odd special     | `sf == 0x7F`             | `0x8001B6D0` | `(&resp.payload, 0x7F)`          | `0x0C` | `resp+0x26` |
| Even SendKey    | `(sf & 1) == 0 && sf != 0x80` | `0x8001B57E` | `(&req.payload, sf, 0)`      | `0x02` | `resp+0x1C` |
| Even special    | `sf == 0x80`             | `0x8001B6D0` | `(&req.payload, 0x80)`           | `0x02` | `resp+0x1C` |

---

## 7. Response Code Constants

| Value | Constant | Meaning |
|-------|----------|---------|
| `0x34` | `UDS_SUCCESS` | Internal success marker (cleared to 0 in response) |
| `0x33` | `UDS_NRC_SECURITY_ACCESS_DENIED` | Tester key didn't match |
| `0x91` | (internal) | Security level out of range (≥ 0x7F) or length error |
| `0x7F 0x27 0x33` | Negative response | Sent on wire for AccessDenied |
| `0x7F 0x27 0x35` | Negative response | InvalidKey (depending on implementation) |

---

## 8. Security Level Constraints

The S2K algorithm rejects security levels ≥ 0x7F:

```c
if (security_level > 0x7E) {
    state->seed_active_flag &= ~2;
    return 0x91;
}
```

Valid odd levels: `0x01` through `0x7D`.  
The polynomial table has 30 entries, of which **27 are usable** (indices 0–20 and 24–29). Indices 21/22/23 (sub-functions `0x2B`, `0x2D`, `0x2F`) are intentional `0xFFFFFFFF` placeholder slots that the keygen rejects — see `05_polynomial_table.md`.

For levels beyond `0x3D`, `POLYNOMIAL_ARRAY[((level+1)/2)-1]` would read index ≥ 30 which falls in the `0xFFFFFFFF` unprogrammed flash region. Whether the ECU supports these levels in practice is determined by what the CAN diagnostic session allows — not enforced in the S2K function itself.
