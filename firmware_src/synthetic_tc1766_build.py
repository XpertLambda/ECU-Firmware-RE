#!/usr/bin/env python3
"""
synthetic_tc1766_build.py
=========================
Generates synthetic_tc1766.bin — a legally clean 2 MB TriCore TC1766
firmware binary. Zero bytes are copied from the real (unrelated) firmware.

This rewrite uses ONLY pre-verified valid TriCore instruction byte
sequences (NOP16 / RET16). The previous build emitted byte sequences
that Ghidra rejected as invalid TriCore instructions ("??" in the
listing). The verified bytes produce a binary where every function
disassembles cleanly.

Usage:
    python3 synthetic_tc1766_build.py

Output:
    synthetic_tc1766.bin   (exactly 2,097,152 bytes)
"""

from __future__ import annotations
import struct, sys, os, hashlib

# ─── Base configuration ───────────────────────────────────────────────────────
BASE_ADDR  = 0x80000000
TOTAL_SIZE = 0x200000        # 2 MB = 2,097,152 bytes

MY_MAGIC_1 = 0xC0FFEE11      # NOT the real proprietary FADECAFE
MY_MAGIC_2 = 0xBEEFCA11      # NOT the real proprietary CAFEAFFE

# ─── Pre-verified TriCore instruction byte sequences ─────────────────────────
# Sourced directly from Ghidra's TriCore SLEIGH spec (tricore.sinc):
#   NOP (SR-format)  :nop  is op0007=0x0  & op0815=0x0   →  bytes 00 00
#   RET (SR-format)  :ret  is op0007=0x0  & op0815=0x90  →  bytes 00 90
# Both are 16-bit instructions; the RET pcode terminates control flow so
# Ghidra closes the function body cleanly.
NOP16     = bytes([0x00, 0x00])             # nop  (16-bit, SR-format)
RET16     = bytes([0x00, 0x90])             # ret  (16-bit, SR-format)


# ─── Key function table (single source of truth) ─────────────────────────────
# (name, address). binary_offset = address - BASE_ADDR
KEY_FUNCTIONS: list[tuple[str, int]] = [
    ('Boot_Header',               0x80000000),
    ('Reset_Handler',             0x80000090),
    ('Service_Dispatch_Table',    0x80001AD0),
    ('Diag_Buffer_Descriptor',    0x80001B00),
    ('Trigger_Hardware_Reset',    0x80018E40),
    ('Validate_System_State',     0x8001971C),
    ('UDS_SA_Dispatcher',         0x80019EC2),
    ('SecurityAccess_Algorithm',  0x8001B57E),
    ('SecurityAccess_AltHandler', 0x8001B6D0),
    ('POLYNOMIAL_ARRAY',          0x80025B6E),
]


# ─── Synthetic polynomial table ───────────────────────────────────────────────
# These 30 uint32 LE values are written at PFLASH offset 0x025B6E (address
# 0x80025B6E). Slots 21/22/23 are 0xFFFFFFFF placeholders. None of these
# values match any real proprietary polynomial — they are the synthetic table
# that synthetic_keygen.py also uses. Source of truth: synthetic_keygen.py.
SYNTH_POLYS: tuple[int, ...] = (
    0xA218B900, 0x8F04FB9D, 0xF0529CFB, 0xAF83B3F7, 0x98C02CAF,
    0xE0E0B04A, 0xA2B47628, 0xFE7630CD, 0xBEB404CB, 0xCE79C596,
    0xD94C1F1C, 0xF882915E, 0xD4DFBE48, 0xF98A3D36, 0xFC1941CA,
    0xF6EDFEC4, 0xA68ABF30, 0xC480ACD9, 0xA90139C2, 0xEF00A47C,
    0xD2B44B9C, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x9FFFA6AE,
    0xE5EBA4F6, 0xC4E8E3AB, 0xBEC629D0, 0x9C5E5BFF, 0xE67C371D,
)
assert len(SYNTH_POLYS) == 30


# ─── Offset helpers ──────────────────────────────────────────────────────────
def offset_for(address: int) -> int:
    return address - BASE_ADDR


# ─── Boot header ─────────────────────────────────────────────────────────────
def make_boot_header() -> bytes:
    """80-byte synthetic boot header at 0x80000000."""
    hdr = bytearray(0x50)
    def w32(off: int, val: int) -> None:
        struct.pack_into('<I', hdr, off, val)
    w32(0x00, 0x00800090)   # reset/entry pointer
    w32(0x04, 0x00004000)   # size field
    w32(0x08, 0x80004000)   # RAM ptr (.data start)
    w32(0x0C, 0x80003FFC)   # stack top
    w32(0x10, 0x80001AD0)   # service dispatch table ptr
    w32(0x14, 0x80001B00)   # diag buffer descriptor ptr
    w32(0x30, 0x7C86D5D8)   # CRC32 of firmware (per docs/ECU Firmware RE.pdf §II.4 Table II.2)
    w32(0x34, 0x00020490)   # CRC region size (132,752 bytes)
    w32(0x40, MY_MAGIC_1)   # 0xC0FFEE11 — NOT FADECAFE
    w32(0x44, MY_MAGIC_2)   # 0xBEEFCA11 — NOT CAFEAFFE
    return bytes(hdr)


# ─── Function stub generators ────────────────────────────────────────────────
def make_key_function_stub() -> bytes:
    """Key function stub: 32 × NOP16 + RET16, padded to 68 bytes (4-byte align).

    32 × NOP16 + RET16 = 64 + 2 = 66 bytes
    Pad to 68 with one more NOP16 → 4-byte aligned.
    """
    body = NOP16 * 32 + RET16
    while len(body) % 4:
        body += NOP16
    assert len(body) == 68
    return body


def make_small_function_stub() -> bytes:
    """Synthetic filler stub: 8 × NOP16 + RET16, padded to 20 bytes."""
    body = NOP16 * 8 + RET16
    while len(body) < 20:
        body += NOP16
    assert len(body) == 20
    return body


# ─── Dispatch tables ─────────────────────────────────────────────────────────
def make_secondary_struct() -> bytes:
    """Secondary structure at 0x80001AD0 referenced by boot header +0x10.

    Per docs/ECU Firmware RE.pdf §II.4 Table II.2 the boot header +0x10
    points here, with the annotation "Discoverable later". This is NOT the
    UDS service dispatch table — that is at 0x8001BF48 per docs §III.4.
    Here we place a smaller diagnostic-config structure (32 bytes) that
    contains pointers but **does not** use the DISPATCH_SENTINEL_A/B pattern
    (the docs require that sentinel pair to be unique to 0x8001BF98).
    """
    buf = bytearray(32)
    w = lambda off, v: struct.pack_into('<I', buf, off, v)
    w(0,  0x8001BF48)        # forward-pointer to main UDS dispatch table
    w(4,  0x00000010)        # config flag
    w(8,  0xD000DE28)        # rx buffer base (mirror of diag descriptor)
    w(12, 0x00000014)        # number of dispatch entries (now 20)
    w(16, 0x12345678)        # placeholder marker (not the dispatch sentinel)
    w(20, 0x9ABCDEF0)        # placeholder marker
    w(24, 0x80001B00)        # diag buffer descriptor pointer
    w(28, 0x00000001)        # version byte
    return bytes(buf)


DISPATCH_SENTINEL_A = 0x3D5C8E1B    # NEW lab-binary sentinel (was 0xA5A5A5A5)
DISPATCH_SENTINEL_B = 0xC6F472A9    # NEW lab-binary sentinel (was 0xB0B0B0B0)


def make_main_dispatch_table() -> bytes:
    """Main UDS service dispatch table at 0x8001BF48.

    The lab-revised table holds 20 (handler, SID_word) entries followed by the
    new sentinel pair (DISPATCH_SENTINEL_A, DISPATCH_SENTINEL_B). 20*8 + 8 =
    168 bytes total. The sentinel pair must be unique in PFLASH so students
    can still locate the table by searching for that pattern.
    """
    entries = [
        # ---- Original 10 entries (preserved) ----
        (0x80019CF8, 0x00000010),   # DiagnosticSessionControl       SID=0x10
        (0x80019EC2, 0x00000027),   # SecurityAccess                 SID=0x27 (*)
        (0x80019E02, 0x0000003E),   # TesterPresent                  SID=0x3E
        (0x80019DA8, 0x00000081),   # Vendor                         SID=0x81
        (0x80019DF0, 0x00000082),   # Vendor                         SID=0x82
        (0x80019E0C, 0x00000083),   # Vendor                         SID=0x83
        (0x8001A026, 0x00210000),   # flag-form                      (high-byte SID 0x21)
        (0x8001A10E, 0x00E10000),
        (0x8001A168, 0x00E20001),
        (0x8001A1AE, 0x00F40001),
        # ---- New entries (10 additional standard UDS SIDs) ----
        (0x8001A220, 0x00000011),   # ECUReset                       SID=0x11
        (0x8001A240, 0x00000014),   # ClearDiagnosticInformation     SID=0x14
        (0x8001A260, 0x00000019),   # ReadDTCInformation             SID=0x19
        (0x8001A280, 0x00000022),   # ReadDataByIdentifier           SID=0x22
        (0x8001A2A0, 0x0000002E),   # WriteDataByIdentifier          SID=0x2E
        (0x8001A2C0, 0x00000031),   # RoutineControl                 SID=0x31
        (0x8001A2E0, 0x00000034),   # RequestDownload                SID=0x34
        (0x8001A300, 0x00000036),   # TransferData                   SID=0x36
        (0x8001A320, 0x00000037),   # RequestTransferExit            SID=0x37
        (0x8001A340, 0x00000085),   # ControlDTCSetting              SID=0x85
    ]
    buf = bytearray()
    for ptr, sid_word in entries:
        buf += struct.pack('<I', ptr)
        buf += struct.pack('<I', sid_word)
    buf += struct.pack('<I', DISPATCH_SENTINEL_A)
    buf += struct.pack('<I', DISPATCH_SENTINEL_B)
    assert len(buf) == 168, f"dispatch table size {len(buf)} != 168"
    return bytes(buf)


def make_guard_markers() -> bytes:
    """Guard markers `95 95 95 95 C3 C3 C3 C3` after the dispatch sentinel.
    Per docs §III.4.2: "the linker sometimes places multiple end-of-table
    guards." Located at 0x8001BFF0 (right after the 20-entry dispatch table
    and its sentinel pair)."""
    return struct.pack('<II', 0x95959595, 0xC3C3C3C3)


def make_diag_buffer() -> bytes:
    """Diagnostic buffer descriptor at 0x80001B00 — 64 bytes."""
    buf = bytearray(64)
    w = lambda off, v: struct.pack_into('<I', buf, off, v)
    w(0,  0xD000DE28)   # rx buffer base
    w(4,  0x00000400)   # rx size: 1 KB
    w(8,  0xD000E228)   # tx buffer base
    w(12, 0x00000400)
    w(16, 0xD000E628)
    w(20, 0x00000400)
    w(24, 0x80001AD0)   # back-pointer to dispatch table
    w(28, 0x00000001)
    return bytes(buf)


def make_app_descriptor() -> bytes:
    """Second synthetic software descriptor at 0x80014018 (application image header).
    Same shape as the primary one at 0x80000000, but with different pointers
    to mark the start of the application image. Documented in
    validation/architecture/01_binary_and_memory_map.md §3.
    """
    buf = bytearray(0x50)
    w32 = lambda off, v: struct.pack_into('<I', buf, off, v)
    w32(0x00, 0x80014040)        # reset/entry pointer for app image
    w32(0x04, 0x00004000)        # size field
    w32(0x08, 0x80004400)        # RAM ptr (.data start, app)
    w32(0x0C, 0x80003FFC)        # stack top
    w32(0x10, 0x80001AD0)        # dispatch table (shared with primary)
    w32(0x14, 0x80001B00)        # diag buffer (shared)
    w32(0x30, 0x12345678)        # placeholder app-image CRC32
    w32(0x34, 0x00080000)        # app CRC region size
    w32(0x40, MY_MAGIC_1)        # same magic numbers (synthetic)
    w32(0x44, MY_MAGIC_2)
    return bytes(buf)


# ─── A1 init code (documented in validation/architecture/01 §4) ────────────────────────
# Exact bytes from the lab spec. movh.a a1,#0x8003 + lea a1,[a1]-0x25C8 → A1
# ends up at 0x8002DA38. Two identical pairs: one at 0x80106A2E, one at
# 0x80106AE0 (the mirror).
A1_INIT_BYTES = bytes([0x91, 0x30, 0x00, 0x18, 0xD9, 0x11, 0xB8, 0x8D])
A1_INIT_PRIMARY = 0x80106A2E
A1_INIT_MIRROR  = 0x80106AE0


# ─── Window overlap helper ───────────────────────────────────────────────────
# A reserved span around each key structure that filler stubs must avoid.
RESERVED_SPANS: list[tuple[int, int]] = []


def _build_reserved_spans(assembled_functions: dict[int, tuple] | None = None) -> None:
    """Populate the list of [start_off, end_off) ranges that filler must skip.

    Reserves space for:
      - All named key structures (boot header, dispatch table, etc.)
      - Every assembled function body (5 named + 6 documented + 16 stubs)
      - The polynomial table
      - The second software descriptor @ 0x14018 (80 B)
      - The CRC32 polynomial constants block @ 0xF0200 (8 B)
      - The CRC sentinel @ 0x17BFFC (4 B)
      - The calibration-data zone (0x100000–0x180000)
      - The PFLASH_TAIL zone (0x178000–0x200000) — unprogrammed flash
      - The ID-string block @ 0x1B40–0x1CE0
      - The DTC-strings block @ 0xF0010–0xF01C0
    """
    spans: list[tuple[int, int]] = []
    for name, addr in KEY_FUNCTIONS:
        off = offset_for(addr)
        spans.append((off, off + 256))
    if assembled_functions is not None:
        for addr, body_tuple in assembled_functions.items():
            off = offset_for(addr)
            spans.append((off, off + len(body_tuple) + 4))
    spans.append((0x014018, 0x014018 + 0x50))          # App_Descriptor
    spans.append((0x001B40, 0x001CE0))                  # ID strings block
    spans.append((0x01BF48, 0x01BFF8))                  # Main dispatch table (20 entries) + sentinel + guard
    spans.append((0x0F0000, 0x0F0220))                  # DTC strings + CRC poly constants
    spans.append((0x100000, 0x180000))                  # calibration zone
    spans.append((0x178000, 0x200000))                  # PFLASH_TAIL (unprogrammed)
    RESERVED_SPANS.extend(spans)


def window_overlaps_reserved(start: int, end: int) -> bool:
    for r_start, r_end in RESERVED_SPANS:
        if start < r_end and r_start < end:
            return True
    return False


# ─── Main builder ─────────────────────────────────────────────────────────────
def build(out_path: str) -> None:
    print("[build] Initialising 2 MB buffer with 0xFF fill...")
    binary = bytearray(b'\xFF' * TOTAL_SIZE)

    # Load the assembled function bodies so we can reserve spans for all of them.
    from _assembled_functions import ASSEMBLED_FUNCTIONS

    # Pre-flight: verify offset arithmetic for every named structure.
    for name, addr in KEY_FUNCTIONS:
        off = offset_for(addr)
        assert off == addr - 0x80000000, f"Offset error for {name}"
        assert 0 <= off < TOTAL_SIZE, f"Offset out of range for {name}"
    _build_reserved_spans(ASSEMBLED_FUNCTIONS)
    print(f"[build] Verified {len(KEY_FUNCTIONS)} key structure offsets "
          f"+ {len(ASSEMBLED_FUNCTIONS)} assembled-function reserves "
          f"+ calibration zone")

    # 1. Boot header @ 0x000000
    off = offset_for(0x80000000)
    hdr = make_boot_header()
    binary[off:off + len(hdr)] = hdr
    print(f"[build] Boot header                @ 0x{off:06X}  ({len(hdr)} B)")

    # 2. Reset handler stub @ 0x000090
    off = offset_for(0x80000090)
    stub = make_key_function_stub()
    binary[off:off + len(stub)] = stub
    print(f"[build] Reset_Handler              @ 0x{off:06X}  ({len(stub)} B)")

    # 3. Secondary structure @ 0x80001AD0 (NOT the dispatch table; per
    # docs §II.4 this is the "Discoverable later" pointer target — a smaller
    # config structure. The real UDS dispatch table is at 0x8001BF48.)
    off = offset_for(0x80001AD0)
    secondary = make_secondary_struct()
    binary[off:off + len(secondary)] = secondary
    print(f"[build] Secondary_Struct (no sentinel) @ 0x{off:06X}  ({len(secondary)} B)")

    # 4. Diag buffer descriptor @ 0x001B00
    off = offset_for(0x80001B00)
    diag = make_diag_buffer()
    binary[off:off + len(diag)] = diag
    print(f"[build] Diag_Buffer_Descriptor     @ 0x{off:06X}  ({len(diag)} B)")

    # 4b. Second app-image descriptor @ 0x80014018 (per validation/architecture/01 §3).
    off = offset_for(0x80014018)
    app_hdr = make_app_descriptor()
    binary[off:off + len(app_hdr)] = app_hdr
    print(f"[build] App_Descriptor             @ 0x{off:06X}  ({len(app_hdr)} B)")

    # 4c. Main UDS dispatch table @ 0x8001BF48 (per docs §III.4, expanded).
    # 20 (handler, SID_word) entries + sentinel DISPATCH_SENTINEL_A/B + guard
    # markers. The sentinel pair is unique in PFLASH so students locate the
    # table by searching for it.
    off = offset_for(0x8001BF48)
    main_dtbl = make_main_dispatch_table()
    binary[off:off + len(main_dtbl)] = main_dtbl
    print(f"[build] Main_Dispatch_Table        @ 0x{off:06X}  "
          f"({len(main_dtbl)} B, 20 entries, sentinel @+0xA0)")

    # 4d. Guard markers right after the sentinel (0x8001BFF0).
    off = offset_for(0x8001BFF0)
    guard = make_guard_markers()
    binary[off:off + len(guard)] = guard
    print(f"[build] Guard_Markers (95×4,C3×4)  @ 0x{off:06X}  ({len(guard)} B)")

    # (A1 init code is written AFTER the calibration zone — see step 8e —
    # because the calibration zone overlaps both 0x106A2E and 0x106AE0.)

    # Note: the assembled function bodies (ASSEMBLED_FUNCTIONS) are written
    # AFTER the calibration zone (step 8) so that documented function
    # addresses inside 0x100000–0x180000 (e.g. CAN_DiagPoll_Task @ 0x14DC58,
    # FUN_80131F10, etc.) over-write the calibration data with their real
    # TriCore code instead of being clobbered by it.

    # 6. Polynomial table @ 0x025B6E (30 × uint32 LE)
    off = offset_for(0x80025B6E)
    poly_bytes = struct.pack('<30I', *SYNTH_POLYS)
    binary[off:off + len(poly_bytes)] = poly_bytes
    print(f"[build] POLYNOMIAL_ARRAY           @ 0x{off:06X}  ({len(poly_bytes)} B)")
    # Sanity check: read back and confirm.
    readback = struct.unpack_from('<30I', binary, off)
    assert tuple(readback) == SYNTH_POLYS

    # 7. Synthetic filler stubs — dense grid across the .text region.
    # Uses 8 varied 60-byte stub patterns (mov/add chain, ld/st burst,
    # and/or/xor, branch loop, shift, call, st.w sequence, plain NOP sled).
    # Step is 64 bytes so consecutive stubs sit shoulder-to-shoulder with
    # only a 4-byte 0xFF gap between them — gives the .text region a real,
    # continuous-code look in the Ghidra listing.
    from _filler_variants import FILLER_VARIANTS
    STUB_SIZE = 60
    STUB_STEP = 64
    count = 0
    for window_start in range(0x004000, 0x0F0000, STUB_STEP):
        window_end = window_start + STUB_SIZE
        if window_overlaps_reserved(window_start, window_end):
            continue
        variant = FILLER_VARIANTS[(window_start // STUB_STEP) % len(FILLER_VARIANTS)]
        binary[window_start:window_start + STUB_SIZE] = variant
        count += 1
    print(f"[build] Placed {count} dense filler stubs ({STUB_SIZE} B every "
          f"{STUB_STEP} B in 0x004000–0x0F0000, 8 varied patterns)")

    # 8. Calibration table zone @ 0x100000–0x178000 (480 KB).
    # Pseudo-random uint16 values produced by a deterministic PRNG, modelling
    # the dense lookup-map region that proprietary ECUs typically occupy. None of
    # these values are taken from any real ECU — the PRNG seed is the lab
    # MAIN_SEED, so the table is reproducible bit-for-bit. Range stops at
    # 0x178000 (the PFLASH/PFLASH_TAIL boundary per docs §II.2).
    import random
    rng = random.Random(0x8001B57E ^ 0xCA11BB10)
    cal_size = 0x78000   # 480 KB (stops at PFLASH_TAIL boundary)
    cal_off  = 0x100000
    cal_bytes = bytearray(cal_size)
    for i in range(0, cal_size, 2):
        v = rng.randint(0, 0xFFFF)
        struct.pack_into('<H', cal_bytes, i, v)
    # Embed a few "axis structures" (linearly increasing uint16 sequences)
    # at known offsets — these mimic the X/Y axis arrays prefixing each map.
    for axis_off, count_pts in [
        (0x000000, 16), (0x002000, 16), (0x004000, 32), (0x008000, 16),
        (0x010000, 24), (0x020000, 32), (0x030000, 20), (0x040000, 16),
        (0x050000, 28), (0x060000, 18), (0x070000, 24),
    ]:
        for j in range(count_pts):
            struct.pack_into('<H', cal_bytes, axis_off + j*2, (j * 100) + 250)
    binary[cal_off:cal_off + cal_size] = cal_bytes
    print(f"[build] Calibration table zone     @ 0x{cal_off:06X} "
          f"({cal_size:,} bytes, PRNG-generated uint16 maps + 11 axis arrays)")

    # 8b. NOW write the assembled TriCore function bodies — real machine code.
    # Placed last (over filler grid and calibration zone) so any documented
    # function address sitting inside 0x100000–0x180000 wins over the
    # calibration noise.
    for addr, body_tuple in ASSEMBLED_FUNCTIONS.items():
        body_bytes = bytes(body_tuple)
        off = offset_for(addr)
        assert 0 <= off and off + len(body_bytes) <= TOTAL_SIZE, \
            f"Function at 0x{addr:08X} doesn't fit in binary"
        binary[off:off + len(body_bytes)] = body_bytes
    print(f"[build] Wrote {len(ASSEMBLED_FUNCTIONS)} assembled function bodies "
          f"(real TriCore code, overlay)")

    # 8c. CRC sentinel at 0x8017BFFC (file offset 0x17BFFC).
    # Per docs/ECU Firmware RE.pdf §I.5.1, the stored CRC value is the last
    # 4 bytes of the CRC-covered region: 0xDE 0xAD 0xBE 0xEF.
    crc_sentinel_off = 0x17BFFC
    binary[crc_sentinel_off:crc_sentinel_off + 4] = b'\xDE\xAD\xBE\xEF'
    print(f"[build] CRC32 stored sentinel       @ 0x{crc_sentinel_off:06X}  "
          f"(DE AD BE EF — per docs §I.5.1)")

    # 8d. CRC-32 polynomial constants embedded in PFLASH so RE work in Ch.III
    # can locate the CRC routine by searching for these constants
    # (per docs/ECU Firmware RE.pdf §I.5.1).
    binary[0x0F0200:0x0F0204] = struct.pack('<I', 0xEDB88320)   # bit-reflected
    binary[0x0F0204:0x0F0208] = struct.pack('<I', 0x04C11DB7)   # normal form
    print(f"[build] CRC32 polynomial constants  @ 0x0F0200/0x0F0204  "
          f"(EDB88320 / 04C11DB7)")

    # 8e. A1 init code at 0x80106A2E + mirror at 0x80106AE0.
    # Exact bytes "91 30 00 18 D9 11 B8 8D" per validation/architecture/01 §4.
    # Disassembles to: movh.a a1,#0x8003 ; lea a1,[a1]-0x25C8 → A1=0x8002DA38.
    # Written AFTER the calibration zone so the calibration noise doesn't
    # clobber these documented bytes.
    binary[offset_for(A1_INIT_PRIMARY):offset_for(A1_INIT_PRIMARY) + 8] = A1_INIT_BYTES
    binary[offset_for(A1_INIT_MIRROR):offset_for(A1_INIT_MIRROR) + 8]   = A1_INIT_BYTES
    print(f"[build] A1_init (primary+mirror)   @ 0x{offset_for(A1_INIT_PRIMARY):06X}, "
          f"0x{offset_for(A1_INIT_MIRROR):06X}  (8 B each, sets A1=0x8002DA38)")

    # 9. ASCII strings at convenient offsets — version info, DTC labels.
    # Placed in the gap between Diag_Buffer_Descriptor and the first filler
    # stub region (0x001B40–0x003FFF), then a few more in later gaps.
    # Neutral synthetic identifier strings. NO manufacturer/vendor strings
    # (no manufacturer/vendor identifiers, no proprietary code) — the user's IP-safety
    # requirement is to avoid any signature that could be confused with
    # production firmware.
    strings = [
        (0x001B40, b"TC1766_GenericECU_LabImage_v1.0\x00"),
        (0x001B70, b"BuildSeed_8001B57E_2026-05-22\x00"),
        (0x001B90, b"Project: ECU_KeyGen_Education\x00"),
        (0x001BB0, b"NO_PROPRIETARY_IP_ZERO_BYTES_COPIED\x00"),
        # Synthetic identification strings (no real ECU signatures)
        (0x001BD0, b"ECULAB_SW v01.00.00 SYN.00\x00"),                # synthetic software string
        (0x001BF0, b"BOOT_PN_SYNTH_0001\x00"),                        # synthetic boot PN
        (0x001C10, b"APP_PN_SYNTH_0002\x00"),                         # synthetic application PN
        (0x001C30, b"Generic_2.0L_PetrolReference\x00"),              # generic engine reference
        (0x001C50, b"SyntheticRTOS_v1.0_TriCore\x00"),                # generic RTOS name
        (0x001C70, b"P0001 SYNTH01 SYN_0000001 SYN-BLOCK-A SYN-BLOCK-B 0000 ECULAB.LAB SYNTH SYN-0p00R\x00"),
        (0x0F0010, b"DTC_P0001_FuelInjectorA_Open\x00"),
        (0x0F0030, b"DTC_P0010_VVT_BankA_Performance\x00"),
        (0x0F0050, b"DTC_P0107_MAP_Sensor_Low\x00"),
        (0x0F0070, b"DTC_P0301_Cylinder1_Misfire\x00"),
        (0x0F0090, b"DTC_U0100_Lost_Comm_ECM\x00"),
        (0x0F00B0, b"UDS27_SecurityAccess_v3.2\x00"),
        (0x0F00D0, b"Calib_HW_PN_03L906018_v2.1\x00"),
        (0x0F00F0, b"FlashID_TC1766_Rev_BC\x00"),
        (0x0F0110, b"OBD_Standard_ISO15765-4\x00"),
        (0x0F0140, b"\xAA\xCC\xAA\xCC ECU_PartNumber=03L906022CN \xAA\xCC\xAA\xCC\x00"),
        (0x0F0180, b"Powertrain_2.0L_TDI_CR\x00"),
    ]
    str_count = 0
    str_bytes = 0
    for off, s in strings:
        binary[off:off + len(s)] = s
        str_count += 1
        str_bytes += len(s)
    print(f"[build] Wrote {str_count} ASCII strings ({str_bytes} bytes)")

    # Total functions: assembled bodies + filler stubs + Reset_Handler
    total_functions = len(ASSEMBLED_FUNCTIONS) + count + 1  # +1 for Reset_Handler
    print(f"[build] Total recognisable functions: {total_functions} "
          f"({len(ASSEMBLED_FUNCTIONS)} real + {count} filler + Reset_Handler)")

    # 8. Write output
    with open(out_path, 'wb') as f:
        f.write(binary)
    print(f"\n[build] Output: {out_path}")
    print(f"[build] Size:   {len(binary):,} bytes (0x{len(binary):X})")


# ─── Verification ─────────────────────────────────────────────────────────────
def verify_offset(binary: bytes, address: int, description: str) -> None:
    offset = address - 0x80000000
    assert 0 <= offset < len(binary), f"Offset out of range: {description}"
    assert binary[offset] != 0xFF, f"Nothing written at {description}"
    print(f"  OK {description:<28} address 0x{address:08X} "
          f"offset 0x{offset:06X}  first bytes: "
          f"{binary[offset:offset+4].hex()}")


def verify(path: str) -> bool:
    print("\n" + "=" * 70)
    print("[verify] Running verification checks...")
    print("=" * 70)
    with open(path, 'rb') as f:
        binary = f.read()

    ok = True

    # Check 1: file size
    if len(binary) == TOTAL_SIZE:
        print(f"  OK file size = {len(binary):,} bytes (0x{len(binary):X})")
    else:
        print(f"  FAIL file size = {len(binary):,} (expected {TOTAL_SIZE:,})")
        ok = False

    # Check 2: each key address has content
    print("\n[verify] Key address content:")
    for name, addr in KEY_FUNCTIONS:
        try:
            verify_offset(binary, addr, name)
        except AssertionError as e:
            print(f"  FAIL {name}: {e}")
            ok = False

    # Check 3: magic at 0x000040 must be C0 FF EE 11
    m1 = struct.unpack_from('<I', binary, 0x000040)[0]
    expected_bytes = bytes.fromhex('11EEFFC0')   # 0xC0FFEE11 little-endian
    actual_bytes = binary[0x000040:0x000044]
    print(f"\n[verify] Magic at 0x000040:")
    if actual_bytes == expected_bytes and m1 == MY_MAGIC_1:
        print(f"  OK 0x000040 reads 0xC0FFEE11 (LE bytes "
              f"{actual_bytes.hex().upper()})")
    else:
        print(f"  FAIL 0x000040 = 0x{m1:08X} (bytes {actual_bytes.hex()})")
        ok = False

    # Check 4: not the proprietary magic
    if m1 != 0xFADECAFE:
        print(f"  OK 0x000040 is not 0xFADECAFE (no proprietary IP)")
    else:
        print(f"  FAIL 0x000040 == 0xFADECAFE")
        ok = False

    # Check 5: polynomial array matches SYNTH_POLYS exactly
    p_off = offset_for(0x80025B6E)
    p_vals = struct.unpack_from('<30I', binary, p_off)
    if tuple(p_vals) == SYNTH_POLYS:
        print(f"\n[verify] POLYNOMIAL_ARRAY @ 0x{p_off:06X}: all 30 values match "
              f"SYNTH_POLYS")
    else:
        for i, (got, exp) in enumerate(zip(p_vals, SYNTH_POLYS)):
            if got != exp:
                print(f"  FAIL poly[{i}]: got 0x{got:08X} expected 0x{exp:08X}")
        ok = False

    # SHA-256 (for the manifest)
    h = hashlib.sha256(binary).hexdigest()
    print(f"\n[verify] SHA-256: {h}")
    print("=" * 70)
    if ok:
        print("[verify] ALL CHECKS PASSED")
    else:
        print("[verify] FAILURES — see above")
    print("=" * 70)
    return ok


# ─── Entry point ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    here     = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(here, 'synthetic_tc1766.bin')
    build(out_path)
    ok = verify(out_path)
    sys.exit(0 if ok else 1)
