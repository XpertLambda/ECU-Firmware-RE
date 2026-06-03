# Security Path Mermaid Diagrams

Mermaid (`.mmd`) sources for every function on the UDS Service 0x27
SecurityAccess call chain in the synthetic TC1766 lab firmware, plus the
client-side keygen flow.

| File | Function / flow | Address | Notes |
|------|-----------------|---------|-------|
| [`00_call_graph.mmd`](00_call_graph.mmd) | Full RX → dispatch → SA → validator chain | — | Overview |
| [`01_uds_sa_dispatcher.mmd`](01_uds_sa_dispatcher.mmd) | `UDS_SecurityAccess_Dispatcher` | `0x80019EC2` | Clean-room parity-first rewrite, 124 B |
| [`02_seed_to_key_algorithm.mmd`](02_seed_to_key_algorithm.mmd) | `SecurityAccess_Algorithm` (S2K core) | `0x8001B57E` | Bit-reversed Fibonacci LFSR rewrite, 332 B |
| [`03_anti_tamper_validator.mmd`](03_anti_tamper_validator.mmd) | `Validate_System_State` | `0x8001971C` | Unchanged — magic + integrity + timing |
| [`04_hardware_reset_trigger.mmd`](04_hardware_reset_trigger.mmd) | `Trigger_Hardware_Reset` | `0x80018E40` | Unchanged — WDT unlock + RST_REQ |
| [`05_alt_handler.mmd`](05_alt_handler.mmd) | `SecurityAccess_AltHandler` | `0x8001B6D0` | Body byte-identical; **relocated from `0x8001B688`** |
| [`06_keygen_flow.mmd`](06_keygen_flow.mmd) | `synthetic_keygen.py` client flow | — | Mirror of the firmware S2K, 180-trial emulator match |

> All diagrams reflect the **rebuilt** `firmware_src/synthetic_tc1766.bin`
> (synthetic lab values, expanded 20-entry dispatch table at
> `0x8001BF48`, sentinels `0x3D5C8E1B` / `0xC6F472A9`).

To render a diagram inline:

```
mmdc -i 02_seed_to_key_algorithm.mmd -o 02_seed_to_key_algorithm.svg
```

Or paste the contents of any `.mmd` file into <https://mermaid.live>.
