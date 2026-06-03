# Automotive ECU Firmware Reverse Engineering Lab

> **This lab uses a synthetic firmware binary (`synthetic_tc1766.bin`) created for educational purposes. It contains no proprietary code from any manufacturer.**

---

## About the Synthetic Binary

| Property | Value |
|----------|-------|
| File | `firmware_src/synthetic_tc1766.bin` |
| Size | 2,097,152 bytes (2 MB) |
| SHA-256 | `16a90e0455fba2c98fb8602e7d13449d44523cc1f86b177bca6baa15e31af91c` |
| MCU | Infineon TriCore TC1766 |
| ECU model | synthetic TC1766 reference image (architecture reference only) |
| Total recognisable functions | 284 (27 real-assembly bodies + 256 filler stubs + Reset_Handler) |
| Generator | `firmware_src/synthetic_tc1766_build.py` (deterministic, seed `0x8001B57E`) |

**How to regenerate:**
```bash
cd firmware_src
python3 synthetic_tc1766_build.py   # produces synthetic_tc1766.bin (deterministic)
sha256sum synthetic_tc1766.bin      # compare against the SHA-256 above
```

---

## Quick Start

1. Follow the guide docs/ECU firmware RE.pdf ( do not read validation/ if you would like to perform the lab)

---

## Repository Layout

```
FW-RE/
├── firmware_src/
│   ├── synthetic_tc1766.bin        # 2 MB synthetic TriCore firmware image
│   ├── synthetic_tc1766_build.py   # deterministic binary generator
│   ├── synthetic_keygen.py         # seed-to-key algorithm (lab use only) — canonical copy
│   ├── synthetic_poly_table.md     # synthetic polynomial table documentation
│   ├── synthetic_manifest.md       # build manifest & address map
│   ├── ref/                       # supplementary function analysis notes
│   │   ├── FUN_80019EC2_dispatcher.md
│   │   ├── FUN_8001B57E_seed_to_key.md
│   │   └── synthetic_keygen.md
│   └── ghidra_scripts/             # Ghidra helper scripts
│       ├── AssembleNewFunctions.java   # assembly source used to build the binary
│       └── KeygenOracle.java           # Java oracle harness (alternative to Jython)
│
├── validation/
│   ├── architecture/                        # analysis notes (01–06) + README
│   │   ├── 01_binary_and_memory_map.md
│   │   ├── 02_function_reference.md
│   │   ├── 03_uds_dispatch_and_frame.md
│   │   ├── 04_seed_to_key_algorithm.md
│   │   ├── 05_polynomial_table.md  # synthetic table values + structural reference
│   │   └── 06_anti_tamper.md
│   ├── findings/
│   │   ├── findings.json           # function call graph
│   │   ├── functions/              # annotated C + Mermaid diagrams per key function
│   │   └── diags/                  # consolidated Mermaid diagram set
│   └── keygen/
│       ├── synthetic_keygen.py     # forwarder to firmware_src copy
│       └── run_validation.py       # cross-check runner
│
├── PHASE::TEST/
│   ├── synthetic_keygen.py         # forwarder to firmware_src copy
│   ├── keygen_oracle.py            # Ghidra emulator harness (Jython)
│   └── run_validation.py           # cross-check runner
│
├── docs/
│   └── ECU firmware RE.pdf         # lab guide PDF
│
├── LICENSE                         # MIT (code) + CC BY-NC-SA 4.0 (docs)
└── README.md
```

---

## Permitted Use

This lab analyses a purpose-built synthetic binary that contains no proprietary code. No decompilation or reverse engineering of any third-party software was performed in its creation. The statutory exceptions cited in French CPI L.122-6-1-III and EU Directive 2009/24/EC Article 5(3) apply to any reader who wishes to apply the methodology documented here to software they are licensed to use, not to this lab's own artefacts.

The dispatch table offsets, function addresses, and algorithm structures documented here are valid **only for this synthetic binary** and will differ across ECU families, hardware revisions, and firmware versions. This information does not enable attacks on any real ECU.

**Use of the methodology presented in this lab against any vehicle, ECU, or system that the reader does not own, or for which the reader does not have explicit written authorisation from the owner, is a criminal offence under French Code pénal articles 323-1 and 323-3-1 (France), the Computer Misuse Act 1990 s.1 (UK), 18 U.S.C. § 1030 (USA), and equivalent provisions in other jurisdictions.**

The author and any publishing institution accept no liability for misuse of this material.

---

## Provenance

Zero bytes in `synthetic_tc1766.bin` were copied from any real firmware. All addresses, algorithm structures, and analysis notes are the original work of the researcher. The polynomial values used by the lab are the synthetic set documented in `firmware_src/synthetic_poly_table.md` and verified at build time against a set of SHA-256 hashes of known proprietary values (see `firmware_src/synthetic_tc1766_build.py`). The corresponding production values are never stored in this lab; `validation/architecture/05_polynomial_table.md` documents the synthetic table values together with the structural analysis (index formula, address, table size).
