#!/usr/bin/env python3
"""Cross-check synthetic_keygen.py output against firmware-emulated oracle trials.

Reads /tmp/keygen_oracle_trials.json (produced by keygen_oracle.py running
inside Ghidra's emulator). For each trial:
  - takes the firmware-generated seed
  - invokes synthetic_keygen.py with that seed and the trial's sub-function
  - compares the returned key with the firmware's expected_key
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TRIALS  = Path("/tmp/keygen_oracle_trials.json")
KEYGEN  = Path(__file__).with_name("synthetic_keygen.py")

def run_keygen(seed_hex: str, subfunc_int: int) -> str:
    out = subprocess.check_output(
        [sys.executable, str(KEYGEN), seed_hex, "%02X" % subfunc_int,
         "--format", "hex"],
        stderr=subprocess.PIPE,
    )
    return out.decode().strip()

def main() -> int:
    trials = json.loads(TRIALS.read_text())
    if not trials:
        print("no trials in", TRIALS); return 2

    pass_n = fail_n = err_n = 0
    failures = []
    for t in trials:
        seed_hex = t["seed_hex"]
        expected = t["expected_key"][2:]   # strip 0x
        try:
            got = run_keygen(seed_hex, t["subfunc_int"])
        except subprocess.CalledProcessError as e:
            err_n += 1
            print("ERR  sf=%s tim=%s seed=%s : %s" %
                  (t["subfunc"], t["timer"], seed_hex, e.stderr.decode().strip()))
            continue

        ok = got.upper() == expected.upper()
        tag = "PASS" if ok else "FAIL"
        if ok: pass_n += 1
        else:
            fail_n += 1
            failures.append((t, got))
        print("%s sf=%s tim=%s seed=%s  fw_key=%s  keygen=%s" %
              (tag, t["subfunc"], t["timer"], seed_hex, expected, got))

    print()
    print("summary: %d PASS  %d FAIL  %d ERROR  (of %d trials)" %
          (pass_n, fail_n, err_n, len(trials)))
    if failures:
        print("\nfailures:")
        for t, got in failures:
            print("  sf=%s tim=%s seed=%s  fw=%s  keygen=%s" %
                  (t["subfunc"], t["timer"], t["seed_hex"],
                   t["expected_key"], got))
    return 0 if (fail_n == 0 and err_n == 0) else 1

if __name__ == "__main__":
    sys.exit(main())
