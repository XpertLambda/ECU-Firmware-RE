# Synthetic Polynomial Table — Documentation

**File:** `synthetic_poly_table.md`  
**Binary:** `synthetic_tc1766.bin`  
**Address:** `0x80025B6E` (PFLASH offset `0x025B6E`)  
**Format:** 30 × `uint32`, little-endian  
**Generator seed:** `0x8001B57E` (the lab's key function address)

---

## Why This Table Exists

The real synthetic TC1766 reference image firmware contains a 30-entry polynomial table at
`0x80025B6E` used by the LFSR seed-to-key algorithm (`FUN_8001B57E`).
Those values are proprietary data and **must not appear** in any
legally redistributable binary.

This synthetic table was produced **once, offline**, by the following
procedure. The published build script does not re-run this procedure — it
stores the frozen result (see "How the build script uses the table" below).

```python
import random
rng = random.Random(0x8001B57E)   # deterministic, reproducible

SYNTH_POLYS = []
for i in range(30):
    if i in (21, 22, 23):
        SYNTH_POLYS.append(0xFFFFFFFF)   # spec-required placeholder
    else:
        while True:
            v = rng.getrandbits(32) | 0x80000000   # high bit set (valid LFSR poly)
            if v not in PROPRIETARY_POLYS and v != 0xFFFFFFFF:
                SYNTH_POLYS.append(v)
                break
```

The `| 0x80000000` mask ensures each value has its highest bit set, which
is the characteristic of a maximal-length LFSR polynomial in this Galois
structure. The `PROPRIETARY_POLYS` set used in the loop above existed only
in the one-time generation environment; it is **not** part of this lab.

### How the build script uses the table

`synthetic_tc1766_build.py` hardcodes the frozen synthetic set as the
`SYNTH_POLYS` tuple and writes it to `0x80025B6E`. It does not regenerate the
values, and it carries no copy of the proprietary set. The only check it
performs is a **readback assertion**: after writing the table it reads it back
from the assembled binary and asserts it matches `SYNTH_POLYS` exactly.

---

## Confirmation: No Proprietary Values Appear

During the one-time offline generation described above, each synthetic value was checked against the set of known proprietary polynomial values from the original research and discarded on any collision. Those proprietary values are **not stored anywhere in this lab** — only the resulting synthetic set is. The published `synthetic_tc1766_build.py` simply hardcodes that frozen synthetic set; it does not contain the proprietary values, a blocklist, or any runtime hash check.

| Real index | Real value     | Status                       |
|------------|----------------|------------------------------|
| 0          | [REDACTED]     | Excluded (value redacted)    |
| 1          | [REDACTED]     | Excluded (value redacted)    |
| 2          | [REDACTED]     | Excluded (value redacted)    |
| 3          | [REDACTED]     | Excluded (value redacted)    |
| 4          | [REDACTED]     | Excluded (value redacted)    |
| 5          | [REDACTED]     | Excluded (value redacted)    |
| 6          | [REDACTED]     | Excluded (value redacted)    |
| 7          | [REDACTED]     | Excluded (value redacted)    |
| 8          | [REDACTED]     | Excluded (value redacted)    |
| 9          | [REDACTED]     | Excluded (value redacted)    |
| 10         | [REDACTED]     | Excluded (value redacted)    |
| 11         | [REDACTED]     | Excluded (value redacted)    |
| 12         | [REDACTED]     | Excluded (value redacted)    |
| 13         | [REDACTED]     | Excluded (value redacted)    |
| 14         | [REDACTED]     | Excluded (value redacted)    |
| 15         | [REDACTED]     | Excluded (value redacted)    |
| 16         | [REDACTED]     | Excluded (value redacted)    |
| 17         | [REDACTED]     | Excluded (value redacted)    |
| 18         | [REDACTED]     | Excluded (value redacted)    |
| 19         | [REDACTED]     | Excluded (value redacted)    |
| 20         | [REDACTED]     | Excluded (value redacted)    |
| 21–23      | `0xFFFFFFFF`   | YES — `0xFFFFFFFF` is a mathematical convention (unprogrammed flash / placeholder), not proprietary IP |
| 24         | [REDACTED]     | Excluded (value redacted)    |
| 25         | [REDACTED]     | Excluded (value redacted)    |
| 26         | [REDACTED]     | Excluded (value redacted)    |
| 27         | [REDACTED]     | Excluded (value redacted)    |
| 28         | [REDACTED]     | Excluded (value redacted)    |
| 29         | [REDACTED]     | Excluded (value redacted)    |

> `0xFFFFFFFF` in slots 21/22/23 is not proprietary IP — it is the value of
> unprogrammed NOR flash (all bits erased). Its presence as a "no algorithm"
> marker is a mathematical convention documented in the TriCore flash spec
> and reproduced here per the lab requirements.

---

## Full Synthetic Table

| Index | Synthetic value | Odd level | Security level pair |
|-------|-----------------|-----------|---------------------|
| 0     | `0xA218B900`    | `0x01`    | 0x01 / 0x02         |
| 1     | `0x8F04FB9D`    | `0x03`    | 0x03 / 0x04         |
| 2     | `0xF0529CFB`    | `0x05`    | 0x05 / 0x06         |
| 3     | `0xAF83B3F7`    | `0x07`    | 0x07 / 0x08         |
| 4     | `0x98C02CAF`    | `0x09`    | 0x09 / 0x0A         |
| 5     | `0xE0E0B04A`    | `0x0B`    | 0x0B / 0x0C         |
| 6     | `0xA2B47628`    | `0x0D`    | 0x0D / 0x0E         |
| 7     | `0xFE7630CD`    | `0x0F`    | 0x0F / 0x10         |
| 8     | `0xBEB404CB`    | `0x11`    | 0x11 / 0x12         |
| 9     | `0xCE79C596`    | `0x13`    | 0x13 / 0x14         |
| 10    | `0xD94C1F1C`    | `0x15`    | 0x15 / 0x16         |
| 11    | `0xF882915E`    | `0x17`    | 0x17 / 0x18         |
| 12    | `0xD4DFBE48`    | `0x19`    | 0x19 / 0x1A         |
| 13    | `0xF98A3D36`    | `0x1B`    | 0x1B / 0x1C         |
| 14    | `0xFC1941CA`    | `0x1D`    | 0x1D / 0x1E         |
| 15    | `0xF6EDFEC4`    | `0x1F`    | 0x1F / 0x20         |
| 16    | `0xA68ABF30`    | `0x21`    | 0x21 / 0x22         |
| 17    | `0xC480ACD9`    | `0x23`    | 0x23 / 0x24         |
| 18    | `0xA90139C2`    | `0x25`    | 0x25 / 0x26         |
| 19    | `0xEF00A47C`    | `0x27`    | 0x27 / 0x28         |
| 20    | `0xD2B44B9C`    | `0x29`    | 0x29 / 0x2A         |
| 21    | `0xFFFFFFFF`    | `0x2B`    | placeholder         |
| 22    | `0xFFFFFFFF`    | `0x2D`    | placeholder         |
| 23    | `0xFFFFFFFF`    | `0x2F`    | placeholder         |
| 24    | `0x9FFFA6AE`    | `0x31`    | 0x31 / 0x32         |
| 25    | `0xE5EBA4F6`    | `0x33`    | 0x33 / 0x34         |
| 26    | `0xC4E8E3AB`    | `0x35`    | 0x35 / 0x36         |
| 27    | `0xBEC629D0`    | `0x37`    | 0x37 / 0x38         |
| 28    | `0x9C5E5BFF`    | `0x39`    | 0x39 / 0x3A         |
| 29    | `0xE67C371D`    | `0x3B`    | 0x3B / 0x3C         |

---

## Verification Command

```bash
# Verify the table in the binary matches this file:
python3 synthetic_keygen.py --verify-bin synthetic_tc1766.bin

# Run the self-test:
python3 synthetic_keygen.py --self-test

# Compute a key (level 0x01, seed A1B2C3D4):
python3 synthetic_keygen.py A1B2C3D4 01
```

---

## Legal Statement

The values in this table were generated algorithmically from a seeded PRNG.
They have no mathematical relationship to the proprietary polynomial values.
No proprietary firmware bytes were read, disassembled, or referenced during
generation. The `0xFFFFFFFF` entries in slots 21–23 are not proprietary data;
they are the standard NOR flash erased state used as a placeholder marker.
