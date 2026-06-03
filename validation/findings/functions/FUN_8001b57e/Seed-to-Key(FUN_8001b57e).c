/*
 * SYNTHETIC LAB VERSION
 * ---------------------
 * This file documents the algorithm structure reverse-engineered from the
 * synthetic lab binary at address 0x8001B57E. It is the researcher's
 * own analysis and annotation; it does not contain executable proprietary
 * code.
 *
 * Implementation note (clean-room rewrite):
 *   The LFSR was reformulated from a textbook Galois LFSR (left-shift +
 *   MSB-test + conditional XOR with poly) into its Fibonacci dual operating
 *   in bit-reversed coordinates (right-shift + LSB-test + conditional XOR
 *   with bit-reversed poly, with bit-reversal at the I/O boundaries).
 *
 *   The two formulations are mathematically equivalent. For any (seed,
 *   poly, rounds) triple they produce bit-identical output. The proof is
 *   the pair of identities
 *       bit_reverse((s << 1) & 0xFFFFFFFF)  ==  bit_reverse(s) >> 1
 *       bit_reverse(msb(s) ? P : 0)         ==  lsb(bit_reverse(s)) ? bit_reverse(P) : 0
 *   applied to each step of the Galois recursion.
 */
// State globals (zero/small data, relative to a0):
//   g_sec_state_flags  @ a0 - 0x55c0   (bit1 = seed_sent_awaiting_key)
//   g_current_sec_lvl  @ a0 - 0x558c
//   g_lfsr_state       @ a0 - 0x56fc   (rolling seed accumulator, Galois form)
//   g_expected_key     @ a0 - 0x581c   (Galois-form key for SendKey compare)
// Const table:
//   g_lfsr_poly_tbl[]  @ a1 - 0x7eca   (one uint32 polynomial per sec level,
//                                       stored in Galois form, bit-reversed
//                                       on the fly inside this function)

#define NRC_OK_INTERNAL       0x34
#define NRC_DENIED            0x33
#define NRC_INVALID_LEN       0x91
#define SEED_AWAITING_KEY     0x02

static inline uint32_t bit_reverse_32(uint32_t x)
{
    // 32-iteration bit-by-bit reversal — matches the loop emitted in the
    // TriCore body (the assembler script unrolls a `loop a15, BODY` over
    // 32 iterations of `r = (r << 1) | (x & 1); x >>= 1;`).
    uint32_t r = 0;
    for (int i = 0; i < 32; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}

uint32_t uds_security_access_handler(uint8_t *buf, uint32_t subfunc, uint32_t session_byte)
{
    // UDS 0x27 sub-function must be 1..0x7F
    if ((subfunc - 1) > 0x7E) {
        g_sec_state_flags &= ~SEED_AWAITING_KEY;
        return NRC_INVALID_LEN;
    }

    if ((subfunc & 1) == 0) {
        /* ---------- sendKey (even sub-function) ---------- */
        if ((g_sec_state_flags & SEED_AWAITING_KEY) == 0)
            return NRC_DENIED;                       // no seed pending

        g_sec_state_flags &= ~SEED_AWAITING_KEY;     // one-shot
        g_current_sec_lvl  = 0;

        uint32_t received = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
        uint32_t diff     = received ^ g_expected_key;

        // diff must be a single byte replicated 4 times, < 0x80
        uint8_t b0 =  diff        & 0xFF;
        uint8_t b1 = (diff >>  8) & 0xFF;
        uint8_t b2 = (diff >> 16) & 0xFF;
        uint8_t b3 = (diff >> 24) & 0xFF;
        if (b0 != b1 || b0 != b2 || b0 != b3 || b0 >= 0x80)
            return NRC_DENIED;

        g_current_sec_lvl = b0 + 1;                  // granted level
        return NRC_OK_INTERNAL;
    }

    /* ---------- requestSeed (odd sub-function) — Fibonacci LFSR -------- */

    // 1) timer-nonce scramble (spec-unchanged): perturb the rolling seed
    //    with a poly-table word selected by the low 6 bits of STM_TIM0.
    uint32_t timer_nonce = STM_TIM0 & 0x3F;
    uint32_t poly_galois = g_lfsr_poly_tbl[((subfunc + 1) >> 1) - 1];

    uint32_t s = g_lfsr_state ^ g_lfsr_poly_tbl[timer_nonce];
    g_lfsr_state = s;

    // 2) Emit seed BIG-ENDIAN to the response buffer (still Galois form;
    //    the tester sees the seed in its natural orientation).
    buf[0] = (uint8_t)(s >> 24);
    buf[1] = (uint8_t)(s >> 16);
    buf[2] = (uint8_t)(s >>  8);
    buf[3] = (uint8_t) s;

    // 3) Compute rounds = min(session_byte + 0x23, 0xFF)
    uint32_t rounds = session_byte + 0x23;
    if (rounds > 0xFF) rounds = 0xFF;

    // 4) Convert into Fibonacci coordinates: bit-reverse the polynomial,
    //    bit-reverse the LFSR state.
    uint32_t poly_rev  = bit_reverse_32(poly_galois);
    uint32_t state_rev = bit_reverse_32(s);

    // 5) Right-shift Fibonacci LFSR. The branchless formulation
    //         state_rev = (state_rev >> 1) ^ (-fb & poly_rev)
    //    matches the TriCore body (`rsub d15, d15, #0` builds the
    //    0/0xFFFFFFFF mask from the LSB).
    while (rounds--) {
        uint32_t fb = state_rev & 1u;
        state_rev = (state_rev >> 1) ^ ((uint32_t)(-(int32_t)fb) & poly_rev);
    }

    // 6) Convert back to Galois coordinates for storage / SendKey compare.
    uint32_t key = bit_reverse_32(state_rev);

    g_expected_key      = key;
    g_sec_state_flags  |= SEED_AWAITING_KEY;
    return NRC_OK_INTERNAL;
}
