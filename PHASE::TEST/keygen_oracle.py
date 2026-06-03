# -*- coding: utf-8 -*-
# @category Validation
# @runtime Jython
#
# Live emulation harness for synthetic_keygen.py validation.
# Loads synthetic_tc1766.bin in Ghidra. Uses SYNTHETIC polynomial table.
# Drives FUN_8001b57e (the LFSR seed/key primitive at 0x8001b57e) for several
# (subfunc, STM_TIM0) combinations. For each trial it captures:
#   - the firmware-generated seed (bytes the dispatcher would put at tx_buf+0x1C)
#   - the firmware-computed expected_key (stored to *(a0 - 0x581c))
# Output is JSON, written to /tmp/keygen_oracle_trials.json, so an external
# step can feed each seed into synthetic_keygen.py and compare with expected_key.
#
# Nothing is mocked, simulated by hand, or symbolic. The firmware bytes are
# executed; the function's own outputs are what we record.

from ghidra.app.emulator import EmulatorHelper
from java.math import BigInteger
import json

# -- target & calling convention --
FUN_LFSR     = 0x8001b57e
SENTINEL     = 0xDEADBEEE         # even -> valid TriCore PC, used as halt PC

# a1 is the small-data base used to index the polynomial table:
#   poly_base = a1 - 0x7eca = 0x80025B6E   =>   a1 = 0x8002DA38
A1_VAL       = 0x8002DA38

# a0 is the LDRAM small-data base. We pick a value such that every a0+disp
# referenced by FUN_8001b57e lands in mapped LDRAM (0xD0000000..0xD000DFFF).
# Offsets used by the function: -0x55c0, -0x55e0, -0x558c, -0x56fc, -0x581c.
# Setting a0 = 0xD000C000 puts every reference into 0xD00067E4..0xD0006A74.
A0_VAL          = 0xD000C000
EXPECTED_KEY_AD = A0_VAL - 0x581c   # 0xD00067E4
SAVED_STATE_AD  = A0_VAL - 0x56fc   # 0xD0006904
UNLOCK_BASE     = A0_VAL - 0x55e0   # 0xD0006A20  (level byte stored at +0x54)
STATE_FLAG_AD   = A0_VAL - 0x55c0   # 0xD0006A40

SEED_BUF        = 0xD0008000        # passed as param_1 (a4): seed written here
STACK_TOP       = 0xD000B000
STM_TIM0        = 0xF0000210

space = currentProgram.getAddressFactory().getDefaultAddressSpace()

def A(off):
    return space.getAddress(off & 0xFFFFFFFF)

def bi(v):
    return BigInteger.valueOf(v & 0xFFFFFFFF)

def write_u32_le(emu, off, value):
    b = bytearray(4)
    b[0] = (value      ) & 0xFF
    b[1] = (value >>  8) & 0xFF
    b[2] = (value >> 16) & 0xFF
    b[3] = (value >> 24) & 0xFF
    emu.writeMemory(A(off), bytes(b))

def read_u32_le(emu, off):
    raw = emu.readMemory(A(off), 4)
    return (raw[0] & 0xFF) | ((raw[1] & 0xFF) << 8) | ((raw[2] & 0xFF) << 16) | ((raw[3] & 0xFF) << 24)

def read_bytes(emu, off, n):
    raw = emu.readMemory(A(off), n)
    return bytearray([(raw[i] & 0xFF) for i in range(n)])

def to_uint(v):
    # Jython auto-unwraps BigInteger to a Python long; handle both cases.
    if hasattr(v, "longValue"):
        return v.longValue() & 0xFFFFFFFF
    return int(v) & 0xFFFFFFFF

def run_trial(emu, subfunc, timer_val, saved_state=0, loop_modifier=0):
    # Reset relevant globals and registers
    emu.writeRegister("a0",  bi(A0_VAL))
    emu.writeRegister("a1",  bi(A1_VAL))
    emu.writeRegister("a4",  bi(SEED_BUF))
    emu.writeRegister("a10", bi(STACK_TOP))
    emu.writeRegister("a11", bi(SENTINEL))
    emu.writeRegister("d4",  bi(subfunc))
    emu.writeRegister("d5",  bi(loop_modifier))
    emu.writeRegister("pc",  bi(FUN_LFSR))

    write_u32_le(emu, SAVED_STATE_AD,  saved_state)
    write_u32_le(emu, EXPECTED_KEY_AD, 0)
    write_u32_le(emu, STATE_FLAG_AD,   0)
    write_u32_le(emu, SEED_BUF,        0)
    write_u32_le(emu, STM_TIM0,        timer_val)

    err = ""
    steps = 0
    MAX_STEPS = 200000
    while steps < MAX_STEPS:
        pc = to_uint(emu.readRegister("pc"))
        if pc == (SENTINEL & 0xFFFFFFFF):
            break
        if not emu.step(monitor):
            err = "step fault @ 0x%08x: %s" % (pc, emu.getLastError() or "?")
            break
        steps += 1
    else:
        err = "max steps exhausted"

    ret_code = to_uint(emu.readRegister("d2")) & 0xFF
    seed_b   = read_bytes(emu, SEED_BUF, 4)
    seed_be  = (seed_b[0] << 24) | (seed_b[1] << 16) | (seed_b[2] << 8) | seed_b[3]
    exp_key  = read_u32_le(emu, EXPECTED_KEY_AD)
    state_fl = read_u32_le(emu, STATE_FLAG_AD)

    return {
        "subfunc":      "0x%02X" % subfunc,
        "subfunc_int":  subfunc,
        "loop_modifier": loop_modifier,
        "timer":        "0x%08X" % timer_val,
        "saved_state":  "0x%08X" % saved_state,
        "ret_code":     "0x%02X" % ret_code,
        "seed_hex":     "%02X%02X%02X%02X" % (seed_b[0], seed_b[1], seed_b[2], seed_b[3]),
        "seed_be_u32":  "0x%08X" % seed_be,
        "expected_key": "0x%08X" % exp_key,
        "state_flag":   "0x%08X" % state_fl,
        "steps":        steps,
        "error":        err,
    }

# ---- trials ----
emu = EmulatorHelper(currentProgram)
trials = []
try:
    subfuncs = [0x01, 0x03, 0x05, 0x07, 0x09, 0x0B]
    # By varying saved_state we control the seed directly:
    #   seed = saved_state XOR poly_table[timer & 0x3F]
    # Timer fixed at 0 (=> XOR with poly[0]=0xA218B900 (synthetic) — predictable & valid).
    # The set below covers edge cases (all-zero, all-one, single-bit, mixed)
    # plus diverse arbitrary patterns.
    timer_val = 0
    seeds_via_saved_state = [
        0x00000000, 0x00000001, 0xFFFFFFFF, 0x80000000,
        0x12345678, 0xDEADBEEF, 0xCAFEBABE, 0xA5A5A5A5,
        0x5A5A5A5A, 0xAAAAAAAA, 0x55555555, 0x01010101,
        0x10101010, 0x7FFFFFFF, 0x00000002, 0x00000003,
        0xA218B900, 0x8F04FB9D, 0xF0529CFB, 0xAF83B3F7,
        0x98C02CAF, 0xE0E0B04A, 0xFF00FF00, 0x00FF00FF,
        0x0F0F0F0F, 0xF0F0F0F0, 0xDEADC0DE, 0xFACEFEED,
        0xBADC0FFE, 0x8BADF00D,
    ]
    POLY0 = 0xA218B900  # synthetic poly_table[0], XORed with saved_state when timer=0
    for sf in subfuncs:
        for s in seeds_via_saved_state:
            # We want the firmware to produce 'seed = s'.
            # seed = saved_state XOR poly[0], so saved_state = s XOR poly[0].
            ss = (s ^ POLY0) & 0xFFFFFFFF
            trials.append(run_trial(emu, sf, timer_val, saved_state=ss))
finally:
    emu.dispose()

out_path = "/tmp/keygen_oracle_trials.json"
f = open(out_path, "w")
f.write(json.dumps(trials, indent=2))
f.close()

print "wrote %d trials -> %s" % (len(trials), out_path)
for t in trials:
    print "[%s tim=%s] ret=%s seed=%s exp_key=%s err=%s" % (
        t["subfunc"], t["timer"], t["ret_code"], t["seed_hex"],
        t["expected_key"], t["error"] or "-")
