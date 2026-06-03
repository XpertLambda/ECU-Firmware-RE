# Seed-to-Key Algorithm — Complete Analysis

**Function:** `SecurityAccess_Algorithm`
**Address:** `0x8001B57E`
**Ghidra name:** `FUN_0001b57e`
**Algorithm type:** 32-bit LFSR — bit-reversed Fibonacci formulation (clean-room rewrite of the original Galois LFSR; mathematically equivalent, bit-identical outputs)

---

## 1. Full Annotated Source

```c
#define UDS_NRC_SECURITY_ACCESS_DENIED  0x33
#define UDS_INVALID_LENGTH              0x91
#define UDS_SUCCESS                     0x34
#define SEED_AWAITING_KEY               0x02
#define MAX_LFSR_ROUNDS                 0xFF   // 255

// Globals (a0-relative small-data) — not function args:
//   g_sec_state_flags  @ a0 - 0x55C0   (bit 1 = seed_pending)
//   g_current_sec_lvl  @ a0 - 0x558C
//   g_lfsr_state       @ a0 - 0x56FC   (rolling seed accumulator, Galois form)
//   g_expected_key     @ a0 - 0x581C   (Galois-form key for SendKey compare)
//
// Const table (a1-relative):
//   g_lfsr_poly_tbl[]  @ a1 - 0x7ECA   (30 uint32 polynomials, Galois form)
//                                      Base = A1 - 0x7ECA = 0x80025B6E.

// Helper: 32-bit bit reversal. The TriCore body emits this as a 32-iteration
// `loop a15, BODY` over `r = (r << 1) | (x & 1); x >>= 1;`.
static inline uint32_t bit_reverse_32(uint32_t x) {
    uint32_t r = 0;
    for (int i = 0; i < 32; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}

uint8_t SecurityAccess_Algorithm(
    uint8_t* buffer,
    uint8_t  security_level,
    uint8_t  loop_modifier)
{
    // ----------------------------------------------------------------
    // Guard: reject sub-functions outside [0x01, 0x7F]
    // ----------------------------------------------------------------
    if ((unsigned)(security_level - 1) > 0x7E) {
        g_sec_state_flags &= ~SEED_AWAITING_KEY;
        return UDS_INVALID_LENGTH;
    }

    // ================================================================
    // EVEN LEVEL PATH — SendKey (Key Verification)
    // ================================================================
    if ((security_level & 1) == 0) {

        // Reject if no seed was requested first (prevents replay attacks)
        if ((g_sec_state_flags & SEED_AWAITING_KEY) == 0) {
            return UDS_NRC_SECURITY_ACCESS_DENIED;
        }

        // Clear seed-pending flag and revoke current access
        g_sec_state_flags &= ~SEED_AWAITING_KEY;
        g_current_sec_lvl  = 0;

        // Read the 4-byte tester-supplied key (big-endian over CAN)
        uint32_t tester_key = ((uint32_t)buffer[0] << 24)
                            | ((uint32_t)buffer[1] << 16)
                            | ((uint32_t)buffer[2] <<  8)
                            |  (uint32_t)buffer[3];

        // XOR against the pre-computed expected key
        uint32_t result = tester_key ^ g_expected_key;

        // Accept iff all four bytes of result are equal and <= 0x7F
        if (((result & 0xFF) != ((result >>  8) & 0xFF)) ||
            ((result & 0xFF) != ((result >> 16) & 0xFF)) ||
            ((result & 0xFF) != ((result >> 24) & 0xFF)) ||
            ((result & 0xFF) >   0x7F)) {
            return UDS_NRC_SECURITY_ACCESS_DENIED;
        }
        g_current_sec_lvl = (uint8_t)result + 1;
        return UDS_SUCCESS;
    }

    // ================================================================
    // ODD LEVEL PATH — RequestSeed (Bit-Reversed Fibonacci LFSR)
    // ================================================================

    // 1. Timer-nonce scramble — perturb the rolling seed with a poly-table
    //    word selected by the low 6 bits of STM_TIM0.
    uint32_t timer_nonce = STM_TIM0 & 0x3F;
    uint32_t poly_galois = g_lfsr_poly_tbl[((security_level + 1) >> 1) - 1];

    uint32_t s = g_lfsr_state ^ g_lfsr_poly_tbl[timer_nonce];
    g_lfsr_state = s;

    // 2. Emit seed BIG-ENDIAN to the response buffer (Galois form — the
    //    tester sees the seed in its natural orientation, unaware of the
    //    internal bit-reversed computation).
    buffer[0] = (uint8_t)(s >> 24);
    buffer[1] = (uint8_t)(s >> 16);
    buffer[2] = (uint8_t)(s >>  8);
    buffer[3] = (uint8_t) s;

    // 3. Compute rounds = min(loop_modifier + 0x23, 0xFF)
    uint32_t rounds = (uint32_t)loop_modifier + 0x23;
    if (rounds > MAX_LFSR_ROUNDS) rounds = MAX_LFSR_ROUNDS;

    // 4. Move into Fibonacci coordinates.
    uint32_t poly_rev  = bit_reverse_32(poly_galois);
    uint32_t state_rev = bit_reverse_32(s);

    // 5. Right-shift Fibonacci LFSR loop with branchless mask XOR.
    //    `-fb` evaluates to 0 or 0xFFFFFFFF — the TriCore body uses
    //    `rsub d15, d15, #0x0` (bytes 8F 14 00 F1) to build the mask.
    while (rounds--) {
        uint32_t fb = state_rev & 1u;
        state_rev = (state_rev >> 1) ^ ((uint32_t)(-(int32_t)fb) & poly_rev);
    }

    // 6. Move back to Galois coordinates for storage / SendKey compare.
    uint32_t key = bit_reverse_32(state_rev);

    g_expected_key      = key;
    g_sec_state_flags  |= SEED_AWAITING_KEY;
    return UDS_SUCCESS;
}
```

---

## 2. Algorithm Step-by-Step (KeyGen Perspective)

From the tester's point of view, the KeyGen only needs the **odd
(RequestSeed) path** plus the LFSR. The even path runs on the ECU
internally.

### Step 1 — Request a Seed

Send: `27 <odd_level>` (e.g. `27 09`)

Receive: `67 09 <b0> <b1> <b2> <b3>`

The four bytes `b0..b3` are the seed in **big-endian** order. This is the
ECU's LFSR starting state, in *Galois* (natural) form. The internal
bit-reversed computation is invisible to the tester.

> **Key insight:** The seed is written to the response buffer *before* the
> LFSR runs. The tester receives the exact value the LFSR will start from.
> You do not need to know the internal timer value or rolling-state
> evolution — the ECU hands you the starting state directly.

### Step 2 — Select Polynomial

```
index = ((security_level + 1) / 2) - 1
poly  = POLYNOMIAL_ARRAY[index]
```

See `05_polynomial_table.md` for the synthetic-lab values.

### Step 3 — Apply the LFSR

The cleanest tester-side implementation is the *Galois* LFSR — it produces
the same output as the firmware's Fibonacci form and is one shift per
round with no bit-reversal bookkeeping. Both forms are accepted by
`synthetic_keygen.py`; the canonical script ships with the Fibonacci form
(matching the firmware exactly) and a Galois reference used by the
self-test.

**Galois reference (simpler, sufficient for tester-side keygen):**
```python
seed_int = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
rounds   = min(loop_modifier + 35, 255)  # loop_modifier=0 → 35 rounds default
for _ in range(rounds):
    if seed_int & 0x80000000:
        seed_int = ((seed_int << 1) & 0xFFFFFFFF) ^ poly
    else:
        seed_int = (seed_int << 1) & 0xFFFFFFFF
```

**Fibonacci form (matches the firmware byte-for-byte):**
```python
def bit_reverse_32(x):
    x = ((x & 0x55555555) << 1) | ((x >> 1) & 0x55555555)
    x = ((x & 0x33333333) << 2) | ((x >> 2) & 0x33333333)
    x = ((x & 0x0F0F0F0F) << 4) | ((x >> 4) & 0x0F0F0F0F)
    x = ((x & 0x00FF00FF) << 8) | ((x >> 8) & 0x00FF00FF)
    return ((x << 16) | (x >> 16)) & 0xFFFFFFFF

poly_rev  = bit_reverse_32(poly)
state_rev = bit_reverse_32((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
for _ in range(rounds):
    fb = state_rev & 1
    state_rev >>= 1
    if fb:
        state_rev ^= poly_rev
key_int = bit_reverse_32(state_rev)
```

The two forms agree on every input — verified by 1512 cross-equivalence
checks (`synthetic_keygen.py --self-test`).

### Step 4 — Send Key

The result of Step 3 is `expected_key`. Send it as four big-endian bytes:

`27 <even_level> <key>>24 & 0xFF> <key>>16 & 0xFF> <key>>8 & 0xFF> <key & 0xFF>`

e.g. for level 0x09/0x0A: `27 0A K0 K1 K2 K3`

### Step 5 — Verification Logic (on ECU side, for reference)

```c
result = tester_key ^ expected_key

pass if:
    (result & 0xFFFF) == (result >> 16)   // all 4 bytes are the same value
    (result & 0xFF)   == (result >> 24)
    (result & 0xFF)   <= 0x7F
```

Sending `expected_key` directly gives `result = 0x00000000`, which
satisfies all three conditions. This is the correct and simplest approach.

---

## 3. LFSR Properties

| Property              | Value (lab firmware)                                   |
|-----------------------|--------------------------------------------------------|
| Register width        | 32 bits                                                |
| Implementation form   | Bit-reversed Fibonacci (right-shift)                   |
| Equivalent abstract form | 32-bit Galois LFSR                                  |
| Feedback              | XOR with bit-reversed polynomial, gated on LSB         |
| Default rounds        | 35 (loop_modifier = 0; base = 0x23)                    |
| Max rounds            | 255                                                    |
| Round-count register  | `min(loop_modifier + 0x23, 0xFF)`                      |
| Overflow handling     | Right-shift is non-overflowing; the 32-bit register is preserved by the shift-and-XOR pattern. |

### Why Fibonacci instead of Galois?

The clean-room rewrite swaps representation only — never math. Working in
bit-reversed coordinates lets the binary express the same primitive with
a structurally distinct inner loop:

| Aspect                   | Galois (original)             | Fibonacci (new)               |
|--------------------------|-------------------------------|-------------------------------|
| Shift direction          | Left (`state << 1`)           | Right (`state >> 1`)          |
| Bit tested for feedback  | MSB (`state & 0x80000000`)    | LSB (`state & 1`)             |
| Polynomial constant      | as stored in the table        | bit-reversed at runtime       |
| Branchless mask          | none / multiply form          | `rsub d15, d15, #0` (`-fb`)   |
| Boundary conversion      | none                          | 3× `bit_reverse_32`           |

---

## 4. POLYNOMIAL_ARRAY Address Derivation

The polynomial table address is resolved at runtime from the A1 SDA1
register:

```
POLYNOMIAL_ARRAY = A1 - 0x7ECA
A1               = 0x8002DA38   (set at startup — see 01_binary_and_memory_map.md)
POLYNOMIAL_ARRAY = 0x8002DA38 - 0x7ECA = 0x80025B6E
```

The LEA instruction performing the offset is at `0x8001B59A` (offset 0x1C
inside the function body, *unchanged* by the rewrite):
```
Bytes:    D9 12 36 48
Mnemonic: lea a2, [a1]-0x7ECA
Result:   a2 = 0x80025B6E
```

This address is in PFLASH (read-only). The table is a compile-time
constant embedded in firmware.

---

## 5. Seed Entropy — Why Seeds Vary

Even though the polynomial table and LFSR are deterministic, every
RequestSeed produces a different seed because:

1. `raw_timer = STM_TIM0` — hardware free-running counter, different every millisecond
2. `seed = g_lfsr_state ^ POLYNOMIAL_ARRAY[raw_timer & 0x3F]` — XOR with rolling state
3. `g_lfsr_state = seed` — the rolling state updates on every call

This makes seed prediction from outside the ECU computationally
infeasible. However, it does **not** affect the KeyGen — the seed is sent
to the tester directly. The tester doesn't need to predict or reconstruct
it.

---

## 6. Empirical Verification

Two independent validation harnesses confirm that the rewritten LFSR
produces bit-identical output to a textbook Galois LFSR:

| Harness                                          | Trials | Pass | Fail |
|--------------------------------------------------|-------:|-----:|-----:|
| `synthetic_keygen.py --self-test` (cross-form)   |   1512 | 1512 |    0 |
| `KeygenOracle.java` → `run_validation.py` (emu)  |    180 |  180 |    0 |

The first sweeps every valid sub-function across hand-picked seeds and
round modifiers, comparing the Fibonacci form against a pure-Galois
reference at the Python level. The second runs Ghidra's TriCore emulator
on the rebuilt binary to capture the firmware's `g_expected_key` for each
seed, then runs `synthetic_keygen.py` on that captured seed and checks
the keys match.
