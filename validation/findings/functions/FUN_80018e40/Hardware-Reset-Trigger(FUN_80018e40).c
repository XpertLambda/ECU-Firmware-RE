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
// Post-mortem crash record at 0xD000DF30..0xD000DF4F
typedef struct {
    uint64_t timer_caps;     // +0x00  STM_TIM0*k, STM_CAP*k where k = (STM_CLC>>8)&7
    uint32_t saved_param3;   // +0x10
    uint32_t return_addr;    // +0x14
    uint16_t reason_code;    // +0x18
    uint16_t reason_inverted;// +0x1a  ~reason_code, integrity check
    uint8_t  sub_reason;     // +0x1c
    uint8_t  pad1;           // +0x1d
    uint8_t  pad2;           // +0x1e
    uint8_t  subsystem_id;   // +0x1f
} panic_record_t;
#define PANIC_REC  (*(volatile panic_record_t*)0xD000DF30)

__attribute__((noreturn))
void panic_reset_with_diag(uint8_t subsystem, uint16_t reason, uint32_t sub_reason)
{
    uint32_t t0 = STM_TIM0;
    uint32_t tc = STM_CAP;
    uint32_t k  = (STM_CLC >> 8) & 7;                // STM prescaler bits

    PANIC_REC.timer_caps      = ((uint64_t)(tc * k) << 32) | (t0 * k);
    PANIC_REC.saved_param3    = sub_reason;
    PANIC_REC.return_addr     = (uint32_t)__builtin_return_address(0);
    PANIC_REC.reason_code     = reason;
    PANIC_REC.reason_inverted = ~reason;
    PANIC_REC.sub_reason      = 0;
    PANIC_REC.pad1            = 0;
    PANIC_REC.pad2            = 0;
    PANIC_REC.subsystem_id    = subsystem;

    if (DBGSR & 1) debug();                          // halt to OCDS if attached

    // Unlock + arm watchdog, then request reset
    uint32_t c = (WDT_CON0 & 0xFFFFFFF3) | 0xF0 | (WDT_CON1 & 0x0C);
    WDT_CON0 = c ^ 2;                                // password unlock pattern
    WDT_CON0 = (c & 0xFFFFFFF0) | 2;                 // lock with new config
    (void)WDT_CON0;
    RST_REQ  = 4;
    (void)RST_REQ;

    for (;;) { /* wait for reset */ }
}