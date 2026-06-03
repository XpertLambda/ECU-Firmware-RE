# Polynomial Table — Synthetic Lab Values

**Array name:** `POLYNOMIAL_ARRAY`
**Address in firmware:** `0x80025B6E` (PFLASH — read-only)
**Derivation:** `A1 - 0x7ECA` = `0x8002DA38 - 0x7ECA`
**Entry size:** 4 bytes (uint32_t, little-endian)
**Valid entries:** 30 (indices 0–29); indices 30+ are `0xFFFFFFFF` (unprogrammed flash)
**Placeholder slots (intentional `0xFFFFFFFF`):** indices 21, 22, 23 — sub-functions `0x2B`, `0x2D`, `0x2F` have no polynomial assigned and are rejected by `synthetic_keygen.py`.

> **LAB binary values.** The table below holds the *synthetic* polynomials
> baked into `synthetic_tc1766.bin`. They are produced by the build script
> in `firmware_src/` and **do not match any production ECU**. The single
> source of truth is the `SYNTH_POLYS` tuple in `synthetic_tc1766_build.py`.

---

## How the Table Is Used

The table serves two distinct purposes in the S2K algorithm:

### Purpose 1 — Seed Randomization (per-call, ECU-internal)
```c
seed = g_lfsr_state ^ POLYNOMIAL_ARRAY[STM_TIM0 & 0x3F];
```
- Index: `STM_TIM0 & 0x3F` (0–63)
- Used internally to generate the random seed sent to the tester
- **Not needed for KeyGen** — the tester receives the seed output directly

### Purpose 2 — LFSR Polynomial (per security level)
```c
poly = POLYNOMIAL_ARRAY[((security_level + 1) / 2) - 1];
```
- Index: `((level + 1) / 2) - 1`
- This value drives the LFSR's feedback step (bit-reversed at runtime; see
  `04_seed_to_key_algorithm.md` §3)
- **Required for KeyGen** — must be extracted per security level

---

## Full Table — Raw Memory at `0x80025B6E`

Bytes as they appear in PFLASH, four bytes per entry, little-endian:

```
Offset  Raw bytes (hex)     LE uint32      Index   Sub-function
------  ----------------    -----------    -----   ------------
+0x00   00 b9 18 a2         0xA218B900     [ 0]    0x01
+0x04   9d fb 04 8f         0x8F04FB9D     [ 1]    0x03
+0x08   fb 9c 52 f0         0xF0529CFB     [ 2]    0x05
+0x0C   f7 b3 83 af         0xAF83B3F7     [ 3]    0x07
+0x10   af 2c c0 98         0x98C02CAF     [ 4]    0x09
+0x14   4a b0 e0 e0         0xE0E0B04A     [ 5]    0x0B
+0x18   28 76 b4 a2         0xA2B47628     [ 6]    0x0D
+0x1C   cd 30 76 fe         0xFE7630CD     [ 7]    0x0F
+0x20   cb 04 b4 be         0xBEB404CB     [ 8]    0x11
+0x24   96 c5 79 ce         0xCE79C596     [ 9]    0x13
+0x28   1c 1f 4c d9         0xD94C1F1C     [10]    0x15
+0x2C   5e 91 82 f8         0xF882915E     [11]    0x17
+0x30   48 be df d4         0xD4DFBE48     [12]    0x19
+0x34   36 3d 8a f9         0xF98A3D36     [13]    0x1B
+0x38   ca 41 19 fc         0xFC1941CA     [14]    0x1D
+0x3C   c4 fe ed f6         0xF6EDFEC4     [15]    0x1F
+0x40   30 bf 8a a6         0xA68ABF30     [16]    0x21
+0x44   d9 ac 80 c4         0xC480ACD9     [17]    0x23
+0x48   c2 39 01 a9         0xA90139C2     [18]    0x25
+0x4C   7c a4 00 ef         0xEF00A47C     [19]    0x27
+0x50   9c 4b b4 d2         0xD2B44B9C     [20]    0x29
+0x54   ff ff ff ff         0xFFFFFFFF     [21]    0x2B    placeholder
+0x58   ff ff ff ff         0xFFFFFFFF     [22]    0x2D    placeholder
+0x5C   ff ff ff ff         0xFFFFFFFF     [23]    0x2F    placeholder
+0x60   ae a6 ff 9f         0x9FFFA6AE     [24]    0x31
+0x64   f6 a4 eb e5         0xE5EBA4F6     [25]    0x33
+0x68   ab e3 e8 c4         0xC4E8E3AB     [26]    0x35
+0x6C   d0 29 c6 be         0xBEC629D0     [27]    0x37
+0x70   ff 5b 5e 9c         0x9C5E5BFF     [28]    0x39
+0x74   1d 37 7c e6         0xE67C371D     [29]    0x3B
+0x78   ff ff ff ff ...     (unprogrammed) [30+]
```

You can confirm these bytes in your dump by running:

```
python3 firmware_src/synthetic_keygen.py --verify-bin firmware_src/synthetic_tc1766.bin
```

which reads the 30 uint32 values from PFLASH offset `0x025B6E` and
compares against `SYNTH_POLY_TABLE` in the keygen.

---

## LFSR Polynomials per Security Level

For KeyGen use, look up the polynomial by security level (the odd sub-function value):

| Odd Level | Even Level | Poly Index | Polynomial |
|-----------|------------|-----------|------------|
| `0x01`    | `0x02`     | 0         | `0xA218B900` |
| `0x03`    | `0x04`     | 1         | `0x8F04FB9D` |
| `0x05`    | `0x06`     | 2         | `0xF0529CFB` |
| `0x07`    | `0x08`     | 3         | `0xAF83B3F7` |
| `0x09`    | `0x0A`     | 4         | `0x98C02CAF` |
| `0x0B`    | `0x0C`     | 5         | `0xE0E0B04A` |
| `0x0D`    | `0x0E`     | 6         | `0xA2B47628` |
| `0x0F`    | `0x10`     | 7         | `0xFE7630CD` |
| `0x11`    | `0x12`     | 8         | `0xBEB404CB` |
| `0x13`    | `0x14`     | 9         | `0xCE79C596` |
| `0x15`    | `0x16`     | 10        | `0xD94C1F1C` |
| `0x17`    | `0x18`     | 11        | `0xF882915E` |
| `0x19`    | `0x1A`     | 12        | `0xD4DFBE48` |
| `0x1B`    | `0x1C`     | 13        | `0xF98A3D36` |
| `0x1D`    | `0x1E`     | 14        | `0xFC1941CA` |
| `0x1F`    | `0x20`     | 15        | `0xF6EDFEC4` |
| `0x21`    | `0x22`     | 16        | `0xA68ABF30` |
| `0x23`    | `0x24`     | 17        | `0xC480ACD9` |
| `0x25`    | `0x26`     | 18        | `0xA90139C2` |
| `0x27`    | `0x28`     | 19        | `0xEF00A47C` |
| `0x29`    | `0x2A`     | 20        | `0xD2B44B9C` |
| `0x2B`    | `0x2C`     | 21        | `0xFFFFFFFF` *(placeholder — rejected)* |
| `0x2D`    | `0x2E`     | 22        | `0xFFFFFFFF` *(placeholder — rejected)* |
| `0x2F`    | `0x30`     | 23        | `0xFFFFFFFF` *(placeholder — rejected)* |
| `0x31`    | `0x32`     | 24        | `0x9FFFA6AE` |
| `0x33`    | `0x34`     | 25        | `0xE5EBA4F6` |
| `0x35`    | `0x36`     | 26        | `0xC4E8E3AB` |
| `0x37`    | `0x38`     | 27        | `0xBEC629D0` |
| `0x39`    | `0x3A`     | 28        | `0x9C5E5BFF` |
| `0x3B`    | `0x3C`     | 29        | `0xE67C371D` |

`synthetic_keygen.py` rejects the three placeholder slots with a clear
error — `bit_reverse_32(0xFFFFFFFF)` is itself `0xFFFFFFFF` and a Fibonacci
LFSR seeded with that polynomial degenerates immediately, so these slots
are not safe to use.

---

## Python Array (copy-paste ready)

```python
POLYNOMIAL_ARRAY = [
    0xA218B900,  # [ 0]  level 0x01
    0x8F04FB9D,  # [ 1]  level 0x03
    0xF0529CFB,  # [ 2]  level 0x05
    0xAF83B3F7,  # [ 3]  level 0x07
    0x98C02CAF,  # [ 4]  level 0x09
    0xE0E0B04A,  # [ 5]  level 0x0B
    0xA2B47628,  # [ 6]  level 0x0D
    0xFE7630CD,  # [ 7]  level 0x0F
    0xBEB404CB,  # [ 8]  level 0x11
    0xCE79C596,  # [ 9]  level 0x13
    0xD94C1F1C,  # [10]  level 0x15
    0xF882915E,  # [11]  level 0x17
    0xD4DFBE48,  # [12]  level 0x19
    0xF98A3D36,  # [13]  level 0x1B
    0xFC1941CA,  # [14]  level 0x1D
    0xF6EDFEC4,  # [15]  level 0x1F
    0xA68ABF30,  # [16]  level 0x21
    0xC480ACD9,  # [17]  level 0x23
    0xA90139C2,  # [18]  level 0x25
    0xEF00A47C,  # [19]  level 0x27
    0xD2B44B9C,  # [20]  level 0x29
    0xFFFFFFFF,  # [21]  level 0x2B   placeholder — rejected
    0xFFFFFFFF,  # [22]  level 0x2D   placeholder — rejected
    0xFFFFFFFF,  # [23]  level 0x2F   placeholder — rejected
    0x9FFFA6AE,  # [24]  level 0x31
    0xE5EBA4F6,  # [25]  level 0x33
    0xC4E8E3AB,  # [26]  level 0x35
    0xBEC629D0,  # [27]  level 0x37
    0x9C5E5BFF,  # [28]  level 0x39
    0xE67C371D,  # [29]  level 0x3B
]
```
