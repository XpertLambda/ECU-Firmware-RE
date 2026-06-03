/*
 * SYNTHETIC LAB VERSION
 * ---------------------
 * This file documents the algorithm structure reverse-engineered during the
 * original research phase. It represents the researcher's own analysis and
 * annotation work. The lab binary (synthetic_tc1766.bin) implements an
 * equivalent algorithm at the same addresses; students should arrive at a
 * similar understanding through their own RE work.
 *
 * This file does not contain executable proprietary code.
 */
#define CANARY_1  0xA55AF00Fu     // -0x5aa50ff1
#define CANARY_2  0xC33C1881u     // -0x3cc3e77f

// Sentinels (relative to a0):
//   g_canary_1     @ a0 - 0x5828
//   g_canary_2     @ a0 - 0x5530

void check_security_state_integrity(void)
{
    refresh_security_shadow();                       // FUN_8001b558

    if (g_canary_1 != CANARY_1 ||
        g_canary_2 != CANARY_2 ||
        verify_security_struct_crc() != 0)           // FUN_8001a4bc
    {
        panic_reset_with_diag(5, 0x2F, 1);           // reason code 0x2F / 1
        // does not return
    }

    if (verify_runtime_security_invariant() != 1) {  // FUN_80019c5a
        panic_reset_with_diag(5, 0x2F, 0);
        return;
    }
}