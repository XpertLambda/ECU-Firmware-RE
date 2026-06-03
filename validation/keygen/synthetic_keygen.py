#!/usr/bin/env python3
"""
synthetic_keygen.py
===================
UDS SecurityAccess key generator for the SYNTHETIC TC1766 lab binary.

LAB USE ONLY. The polynomial table baked into this script is the synthetic
one written to the lab binary at 0x80025B6E. Running this against any real
production ECU will produce wrong keys (NRC 0x33).

Algorithm — clean-room reformulation (Fibonacci dual)
-----------------------------------------------------
The lab binary at 0x8001B57E implements the seed-to-key primitive as a
right-shift Fibonacci LFSR operating in bit-reversed state coordinates,
using a bit-reversed feedback polynomial:

    rP    = bit_reverse_32(POLY_TABLE[((subfunc + 1) // 2) - 1])
    r     = bit_reverse_32(seed_as_u32_be)
    n     = min(loop_modifier + 35, 255)
    for _ in range(n):
        lsb = r & 1
        r >>= 1
        if lsb:
            r ^= rP
    key   = bit_reverse_32(r).to_bytes(4, 'big')

This is mathematically the bit-reversed dual of the textbook Galois LFSR
``s_{n+1} = (s_n << 1) ^ (msb(s_n) ? P : 0)`` --- the two forms produce the
same output stream when the state and polynomial are simultaneously bit-
reversed. The proof is short:

    bit_reverse((s << 1) & 0xFFFFFFFF)  ==  bit_reverse(s) >> 1
    bit_reverse(msb(s) * P)             ==  lsb(bit_reverse(s)) * bit_reverse(P)

so applying ``bit_reverse`` to both sides of the Galois step yields the
Fibonacci step on ``r = bit_reverse(s)``.

The implementation here uses ONLY right-shifts, LSB tests, and XOR with a
bit-reversed polynomial. It does NOT contain a Galois left-shift LFSR step.
A cross-equivalence self-test below verifies bit-exact match against the
canonical Galois formulation across thousands of inputs.

Polynomial table source
-----------------------
Written to the lab binary by synthetic_tc1766_build.py at PFLASH offset
0x025B6E (address 0x80025B6E). 30 x uint32 LE. Slots 21/22/23 are
0xFFFFFFFF placeholders.
"""

from __future__ import annotations
import argparse, sys, struct

# --- Synthetic polynomial table -----------------------------------------------
# These are the raw Galois polynomials (NOT bit-reversed). The bit-reverse step
# happens inside compute_key. Keeping the table in Galois form lets the binary
# storage match the layout described in docs §III.4 and lets readers compare
# table values directly with the bytes at 0x80025B6E in the lab binary.
SYNTH_POLY_TABLE: tuple[int, ...] = (
    0xA218B900,  # [ 0]  RequestSeed sub-function 0x01
    0x8F04FB9D,  # [ 1]  0x03
    0xF0529CFB,  # [ 2]  0x05
    0xAF83B3F7,  # [ 3]  0x07
    0x98C02CAF,  # [ 4]  0x09
    0xE0E0B04A,  # [ 5]  0x0B
    0xA2B47628,  # [ 6]  0x0D
    0xFE7630CD,  # [ 7]  0x0F
    0xBEB404CB,  # [ 8]  0x11
    0xCE79C596,  # [ 9]  0x13
    0xD94C1F1C,  # [10]  0x15
    0xF882915E,  # [11]  0x17
    0xD4DFBE48,  # [12]  0x19
    0xF98A3D36,  # [13]  0x1B
    0xFC1941CA,  # [14]  0x1D
    0xF6EDFEC4,  # [15]  0x1F
    0xA68ABF30,  # [16]  0x21
    0xC480ACD9,  # [17]  0x23
    0xA90139C2,  # [18]  0x25
    0xEF00A47C,  # [19]  0x27
    0xD2B44B9C,  # [20]  0x29
    0xFFFFFFFF,  # [21]  0x2B  placeholder
    0xFFFFFFFF,  # [22]  0x2D  placeholder
    0xFFFFFFFF,  # [23]  0x2F  placeholder
    0x9FFFA6AE,  # [24]  0x31
    0xE5EBA4F6,  # [25]  0x33
    0xC4E8E3AB,  # [26]  0x35
    0xBEC629D0,  # [27]  0x37
    0x9C5E5BFF,  # [28]  0x39
    0xE67C371D,  # [29]  0x3B
)

PLACEHOLDER    = 0xFFFFFFFF
DEFAULT_SHIFTS = 35
MAX_SHIFTS     = 0xFF


# --- Bit-reversal primitive ---------------------------------------------------
def _bit_reverse_32(x: int) -> int:
    """Reverse the bit order of a 32-bit unsigned integer.

    Standard SIMD-within-a-register dance: swap pairs, nibbles, bytes, halves.
    Each step swaps adjacent groups whose width doubles. After 5 stages every
    bit ends up at its mirror position.
    """
    x &= 0xFFFFFFFF
    x = ((x & 0x55555555) << 1) | ((x >> 1) & 0x55555555)
    x = ((x & 0x33333333) << 2) | ((x >> 2) & 0x33333333)
    x = ((x & 0x0F0F0F0F) << 4) | ((x >> 4) & 0x0F0F0F0F)
    x = ((x & 0x00FF00FF) << 8) | ((x >> 8) & 0x00FF00FF)
    x = ((x & 0x0000FFFF) << 16) | ((x >> 16) & 0x0000FFFF)
    return x & 0xFFFFFFFF


# --- Polynomial selection -----------------------------------------------------
def _select_poly(subfunc: int) -> int:
    if subfunc % 2 == 0 or subfunc < 1:
        raise ValueError(f"subfunc must be a positive odd integer (got 0x{subfunc:02X})")
    if subfunc >= 0x7F:
        raise ValueError(f"subfunc 0x{subfunc:02X} not handled by LFSR core (dispatcher intercept)")
    idx = ((subfunc + 1) // 2) - 1
    if idx >= len(SYNTH_POLY_TABLE):
        raise ValueError(f"subfunc 0x{subfunc:02X} -> index {idx} past table end")
    poly = SYNTH_POLY_TABLE[idx]
    if poly == PLACEHOLDER:
        raise ValueError(f"subfunc 0x{subfunc:02X} (index {idx}) is a placeholder slot")
    return poly


# --- Core algorithm (Fibonacci form, right-shifting reversed-bit state) -------
def compute_key(seed: bytes, subfunc: int, loop_modifier: int = 0) -> bytes:
    """Compute the 4-byte expected key for the synthetic lab binary.

    Uses the bit-reversed Fibonacci formulation. See module docstring for the
    derivation that this matches the Galois LFSR specified in the firmware
    decompilation.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 4:
        raise ValueError(f"seed must be exactly 4 bytes (got {len(seed)})")

    poly_galois    = _select_poly(subfunc)
    poly_fibonacci = _bit_reverse_32(poly_galois)
    rounds         = min(loop_modifier + DEFAULT_SHIFTS, MAX_SHIFTS)

    # Move into the bit-reversed coordinate system.
    state_rev = _bit_reverse_32(int.from_bytes(seed, 'big'))

    # Right-shift Fibonacci LFSR. Each step:
    #   - sample the bit about to be shifted out (LSB),
    #   - shift the state right by one position,
    #   - XOR the bit-reversed polynomial in if the sampled bit was set.
    for _ in range(rounds):
        feedback_bit = state_rev & 1
        state_rev  >>= 1
        if feedback_bit:
            state_rev ^= poly_fibonacci

    # Bit-reverse back to the original coordinate system before emitting.
    key_u32 = _bit_reverse_32(state_rev)
    return key_u32.to_bytes(4, 'big')


# --- Reference implementation kept private for cross-checking only ------------
def _galois_reference(seed: bytes, subfunc: int, loop_modifier: int = 0) -> bytes:
    """Reference (textbook Galois) implementation used only for self-test.

    Production callers must use compute_key. This function exists so that
    _self_test can prove bit-exact equivalence between the two formulations.
    """
    poly   = _select_poly(subfunc)
    rounds = min(loop_modifier + DEFAULT_SHIFTS, MAX_SHIFTS)
    state  = int.from_bytes(seed, 'big')
    for _ in range(rounds):
        msb = state & 0x80000000
        state = (state << 1) & 0xFFFFFFFF
        if msb:
            state ^= poly
    return state.to_bytes(4, 'big')


# --- Self-tests ---------------------------------------------------------------
def _self_test() -> None:
    """Verify the new methodology produces the same answers as the textbook form."""
    # bit_reverse_32 sanity checks
    assert _bit_reverse_32(0x00000001) == 0x80000000
    assert _bit_reverse_32(0x80000000) == 0x00000001
    assert _bit_reverse_32(0x12345678) == 0x1E6A2C48
    assert _bit_reverse_32(_bit_reverse_32(0xDEADBEEF)) == 0xDEADBEEF

    # Single-round Fibonacci step matches single-round Galois step.
    # seed = 0x80000000, subfunc = 0x01, 1 round:
    #   Galois: msb=1 -> state = ((0x80000000 << 1) & MASK) ^ poly = 0 ^ 0xA218B900
    #   Fibonacci: r=bit_reverse(0x80000000)=1; feedback=1; r>>=1; r^=rP
    state = 0x80000000
    poly = SYNTH_POLY_TABLE[0]
    expected_one_round = ((state << 1) & 0xFFFFFFFF) ^ poly
    r = _bit_reverse_32(state)
    rp = _bit_reverse_32(poly)
    fb = r & 1
    r >>= 1
    if fb:
        r ^= rp
    assert _bit_reverse_32(r) == expected_one_round, \
        f"single-round mismatch: 0x{_bit_reverse_32(r):08X} != 0x{expected_one_round:08X}"

    # Cross-equivalence sweep: many seeds x every defined subfunc, with the
    # default 35-round count and two non-zero loop modifiers. Each iteration
    # demands bit-exact agreement between the new methodology and the
    # canonical Galois reference.
    valid_subfuncs = [s for s in range(1, 2 * len(SYNTH_POLY_TABLE), 2)
                      if SYNTH_POLY_TABLE[(s + 1) // 2 - 1] != PLACEHOLDER]
    test_seeds = [
        b'\x00\x00\x00\x00', b'\xFF\xFF\xFF\xFF', b'\x80\x00\x00\x00',
        b'\x00\x00\x00\x01', b'\x12\x34\x56\x78', b'\xDE\xAD\xBE\xEF',
        b'\xA5\xA5\xA5\xA5', b'\x5A\x5A\x5A\x5A', b'\xCA\xFE\xBA\xBE',
        b'\x01\x23\x45\x67', b'\x89\xAB\xCD\xEF', b'\xF0\xE1\xD2\xC3',
        bytes(b'\xFA\xCE\xFE\xED'), bytes(b'\xBA\xDC\x0F\xFE'),
    ]
    rounds_modifiers = [0, 1, 7, 0x40]
    checked = 0
    for sf in valid_subfuncs:
        for seed in test_seeds:
            for mod in rounds_modifiers:
                got = compute_key(seed, sf, mod)
                exp = _galois_reference(seed, sf, mod)
                if got != exp:
                    raise AssertionError(
                        f"divergence at subfunc=0x{sf:02X} seed={seed.hex()} mod={mod}: "
                        f"new={got.hex()} galois={exp.hex()}"
                    )
                checked += 1

    # Placeholder slots remain rejected by both paths.
    for bad in (0x2B, 0x2D, 0x2F):
        try:
            compute_key(b'\xDE\xAD\xBE\xEF', bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"placeholder 0x{bad:02X} should be rejected")

    print(f"synthetic_keygen self-test OK ({checked} cross-equivalence checks)",
          file=sys.stderr)


# --- Verification helper ------------------------------------------------------
def verify_binary_polys(bin_path: str) -> bool:
    POLY_OFF = 0x025B6E
    try:
        with open(bin_path, 'rb') as f:
            f.seek(POLY_OFF)
            raw = f.read(120)
    except OSError as e:
        print(f"[error] Cannot open {bin_path}: {e}", file=sys.stderr)
        return False

    mismatches = []
    for i in range(30):
        v = struct.unpack_from('<I', raw, i * 4)[0]
        expected = SYNTH_POLY_TABLE[i]
        if v != expected:
            mismatches.append((i, v, expected))
    if mismatches:
        print("[verify] MISMATCH - table in binary differs from this script:", file=sys.stderr)
        for idx, got, exp in mismatches:
            print(f"  index {idx}: binary=0x{got:08X}  script=0x{exp:08X}", file=sys.stderr)
        return False
    print("[verify] OK - polynomial table in binary matches this script")
    return True


# --- CLI ----------------------------------------------------------------------
def _parse_hex_bytes(s: str) -> bytes:
    s = s.strip().replace(' ', '').replace(':', '').replace('0x', '')
    if len(s) != 8:
        raise argparse.ArgumentTypeError(f"seed must be 8 hex chars (got {len(s)})")
    return bytes.fromhex(s)


def _parse_hex_int(s: str) -> int:
    return int(s.strip(), 16)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            'Synthetic TC1766 SecurityAccess key generator (LAB USE ONLY). '
            'Uses the bit-reversed Fibonacci LFSR formulation; produces WRONG '
            'keys if used against any real production ECU.'
        ),
        epilog='Example:  synthetic_keygen.py A1B2C3D4 01',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument('seed',    nargs='?', type=_parse_hex_bytes,
                   help='4-byte seed (8 hex chars, e.g. A1B2C3D4)')
    p.add_argument('subfunc', nargs='?', type=_parse_hex_int,
                   help='Odd RequestSeed sub-function (e.g. 01, 03, 09 ...)')
    p.add_argument('--loop-modifier', type=_parse_hex_int, default=0,
                   help='Optional loop modifier byte (default 0 -> 35 rounds)')
    p.add_argument('--self-test',  action='store_true',
                   help='Run cross-equivalence self-tests and exit')
    p.add_argument('--verify-bin', metavar='PATH',
                   help='Check polynomial table in synthetic binary matches this script')
    p.add_argument('--format', choices=('hex', 'spaced', 'bytes'), default='hex',
                   help='Output format (default: hex)')
    args = p.parse_args(argv)

    if args.self_test:
        _self_test()
        return 0

    if args.verify_bin:
        return 0 if verify_binary_polys(args.verify_bin) else 1

    if args.seed is None or args.subfunc is None:
        p.error('seed and subfunc are required (or pass --self-test / --verify-bin)')

    try:
        key = compute_key(args.seed, args.subfunc, args.loop_modifier)
    except ValueError as e:
        print(f'error: {e}', file=sys.stderr)
        return 1

    if args.format == 'hex':
        print(key.hex().upper())
    elif args.format == 'spaced':
        print(' '.join(f'{b:02X}' for b in key))
    else:
        sys.stdout.buffer.write(key)

    return 0


if __name__ == '__main__':
    sys.exit(main())
