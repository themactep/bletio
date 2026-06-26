# bletio — Handoff File

## Project State (2026-06-25)

**951 tests, 0 failures.** The stack implements a complete BLE host from HCI to GATT to SMP.

## Quick Start After Reboot

```bash
cd /home/paul/src/bletio

# Build and run all tests
cargo test                    # 951 pass, 0 fail

# Run the full-stack demo
cargo run --example full_stack_demo

# Run examples
cargo run --example gatt_server_demo
cargo run --example gatt_client_demo
cargo run --example smp_pairing_demo

# CLI scanner (needs bluetooth service stopped first)
sudo systemctl stop bluetooth
cd cli && cargo build --release
sudo ./target/release/bletio-cli scan --duration 5
sudo systemctl start bluetooth
```

## What's Fully Done ✅

### Phase 1 — Hardening (8/8)
- ACL data panic fixes, log support, event capacity (4→8), reset timeout (5s)
- API docs on key types, enum size documented
- File: `bletio-hci/src/hci.rs`, `bletio-hci/src/event/mod.rs`

### Phase 2 — Data Plane (5/5)  
- ACL send/receive, credit-based flow control, connection registry
- File: `bletio-hci/src/hci.rs` (write_acl_data, le_acl_credits)
- File: `bletio-host/src/connection_registry.rs`

### Phase 3 — ATT/GATT (6/6)
- ATT PDU encoding/decoding (16 types), ATT client state machine
- GATT client (discovery + read/write), GATT server (attribute table + builders)
- Standard profiles (DIS, BAS, GAP, GATT, HRS)
- File: `bletio-host/src/att/`

### Phase 4 — Security (3/4)
- SMP PDU encoding/decoding (11 types)
- LE Legacy Pairing: Just Works + Passkey Entry
- Bonding: BondStore trait + MemoryBondStore
- File: `bletio-host/src/smp/`, `bletio-host/src/bond_store.rs`

### Phase 5 — Features (7/10)
- LE Coded PHY commands, connection profiles, vendor commands
- Hardware error / data buffer overflow events
- CCCD subscription tracking, MTU negotiation, power profiling
- File: `bletio-host/src/power.rs`, `bletio-host/src/connection_update_parameters.rs`

### Phase 6 — Developer Experience (4/7)
- 4 examples, platform support matrix, structured event tracing (bletio_* macros)
- File: `bletio-host/examples/`

## What's Scaffolding / Partial ⚠️

| Item | File | What's needed |
|------|------|---------------|
| 4.3 LE Secure Connections | `bletio-host/src/smp/pairing.rs` | P-256 implementation behind SmpCrypto trait (PDU types + hooks exist) |
| 5.1 Extended Advertising | `bletio-hci/src/event/le_extended_advertising_report.rs` | Full command encoding for SetExtendedAdvertisingParameters/Data/Enable |
| 5.3 Isochronous Channels | `bletio-hci/src/iso.rs` | Command/event encoding, ISO data path handling |
| 5.4 PAwR | `bletio-hci/src/event/le_meta.rs` | Command/event encoding for subevent 0x26 |
| 6.1 Integration tests | `bletio-hci/src/test/e2e_tests.rs` | More E2E scenarios (pairing, GATT services) |
| 6.2 CLI tool | `cli/src/main.rs` | Add connect/advertise/read commands |
| 6.5 Conformance tests | `bletio-host/src/conformance.rs` | Need PTS software + hardware |

## Key Files by Layer

```
bletio-hci/src/
  hci.rs           — Main HCI struct, all commands, flow control
  command.rs       — Command enum, opcodes, encoding, nom parser
  event/mod.rs     — Event enum, all event types, parser dispatch
  event/*.rs       — Individual event type definitions + parsers
  acl_data.rs      — ACL data packet type, encode/decode
  traits.rs        — HciDriver + WithTimeout traits
  iso.rs           — Isochronous types (scaffolding)
  test/e2e_tests.rs — End-to-end integration tests

bletio-host/src/
  att/
    att_pdu.rs         — ATT PDU types (16 variants), encode/decode/nom parser
    att_client.rs      — ATT client state machine (request-response)
    gatt.rs            — GATT client (discovery + read/write)
    gatt_server.rs     — GATT server (attribute table, request handling, CCCD)
    profiles.rs        — Standard profile builders (DIS, BAS, GAP, GATT, HRS)
  smp/
    smp_pdu.rs         — SMP PDU types (11 variants), encode/decode
    pairing.rs         — SmpPairing state machine (Just Works + Passkey Entry + SC hooks)
  bond_store.rs        — BondStore trait + MemoryBondStore
  connection_registry.rs — Connection tracking (add/find/remove/update)
  connection_update_parameters.rs — ConnectionProfile presets
  power.rs             — PowerEstimator, battery life calculations
  conformance.rs       — PTS test case matrix
  ble_device.rs        — Top-level BleDevice runner + observer pattern
  ble_host.rs          — BleHost state machine (7 states)

bletio-host/examples/
  full_stack_demo.rs   — All 7 features demonstrated in one program
  gatt_server_demo.rs  — GATT server with profiles
  gatt_client_demo.rs  — GATT client discovery + read/write
  smp_pairing_demo.rs  — Full pairing flow

cli/src/main.rs        — Raw HCI scanner (sync, no async runtime)
```

## Test Counts

| Crate | Tests |
|-------|-------|
| bletio-hci | 497 (incl. 3 E2E + 494 unit + 10 doc) |
| bletio-host | 409 |
| bletio-utils | 28 |
| **Total** | **951** |

## Hardware

- Intel BLE 5.4 controller on hci0 (BD_ADDR: BC:CD:99:F8:4E:EE)
- CLI scan works: `sudo systemctl stop bluetooth && cli scan && sudo systemctl start bluetooth`

## Commit History (on themactep/bletio fork)

Recent commits are structured as:
- `feat(phaseX): ...` — new features
- `fix(phaseX): ...` — bug fixes  
- `docs: ...` — documentation updates
- `test(phaseX): ...` — test additions

Upstream is `ghismary/bletio` (original author). Fork is `themactep/bletio`.

## Next Steps If Continuing

1. **Priority**: End-to-end pairing test (SMP Just Works over mock controller)
2. **Priority**: GATT server end-to-end test (register services, handle requests)
3. **Nice-to-have**: CLI connect/advertise commands
4. **Nice-to-have**: P-256 crypto for LE Secure Connections
5. **Nice-to-have**: Extended Advertising command encoding
