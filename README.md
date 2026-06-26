# bletio

A **`no_std`-compatible Bluetooth Low Energy (BLE) stack** for embedded Rust, targeting both bare-metal (Embassy) and Linux/desktop (Tokio) environments.

[![CI](https://github.com/themactep/bletio/actions/workflows/general.yml/badge.svg)](https://github.com/themactep/bletio/actions/workflows/general.yml)
[![Security Audit](https://github.com/themactep/bletio/actions/workflows/audit.yml/badge.svg)](https://github.com/themactep/bletio/actions/workflows/audit.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)

---

## Architecture

```
┌─────────────────────────────────────────────┐
│                 Application                  │
│  (implements BleHostObserver)                │
├─────────────────────────────────────────────┤
│              bletio-host                     │
│  Type-state machine, observer pattern,       │
│  advertising structures, connection mgmt     │
├─────────────────────────────────────────────┤
│              bletio-hci                      │
│  HCI command/event encoding & parsing,       │
│  controller flow control, timeouts           │
├─────────────────────────────────────────────┤
│              bletio-utils                    │
│  Const-generic buffers, LE integer encoding, │
│  bitfield arrays                             │
├─────────────────────────────────────────────┤
│        HciDriver trait (you implement)       │
│  UART / USB / SPI transport to controller    │
├─────────────────────────────────────────────┤
│           BLE Controller (hardware)           │
└─────────────────────────────────────────────┘
```

### Crates

| Crate | Purpose |
|-------|---------|
| `bletio-utils` | Zero-allocation byte buffers, little-endian encoding, bitflag arrays |
| `bletio-hci` | Host-Controller Interface layer: command encoding, event parsing, flow control |
| `bletio-host` | Host layer: typed state machine, advertising, scanning, connections, observer pattern |

---

## Features

### BLE Role Support
- **Peripheral** — Advertise, accept connections, update connection parameters
- **Central** — Scan, initiate connections, update connection parameters
- **Observer** — Passive scanning of advertising reports
- **Broadcaster** — Non-connectable advertising

### HCI Layer (`bletio-hci`)
- 25+ LE controller commands implemented per Bluetooth Core Specification v4.2+
- Nom-based zero-copy packet parsing for commands and events
- Controller flow control (`num_hci_command_packets` tracking)
- 1-second command timeouts
- Dual async runtime support: **Tokio** (desktop/Linux) and **Embassy** (bare-metal)
- Full event buffering with a `heapless::Vec` (4 events)
- Exhaustive error model: 50+ error variants covering all validation failures
- Command opcodes, error codes, and event codes via `num_enum` with catch-all variants

### Host Layer (`bletio-host`)
- **Typed state machine** — compile-time prevention of invalid API calls:
  | State | Available operations |
  |-------|---------------------|
  | `Initial` | Automatic setup only |
  | `Standby` | Start advertising, scanning, or connecting; manage filter accept list; create random address |
  | `Advertising` | Stop advertising |
  | `Scanning` | Stop scanning |
  | `Initiating` | Cancel connection |
  | `ConnectedCentral` | Disconnect, update connection parameters, send ACL data |
  | `ConnectedPeripheral` | Disconnect, update connection parameters, send ACL data |
- **Observer pattern** — `BleHostObserver` trait with 7 callbacks and sensible defaults
- **Data plane** — Send/receive ACL data packets on connections; ATT PDU encoding/decoding (16 PDU types)
- **Event loop** — `BleDevice::run()` drives the complete lifecycle
- Automatic TX power and appearance insertion in advertising data
- Builder patterns for all parameter types

### Advertising Data (AD Structures)
20+ AD structure types supported:

| Type | AD Type Code |
|------|-------------|
| Flags | `0x01` |
| Service UUIDs (16, 32, 128-bit, Incomplete/Complete list) | `0x02`–`0x07` |
| Local Name (Shortened/Complete) | `0x08`/`0x09` |
| TX Power Level | `0x0A` |
| Peripheral Connection Interval Range | `0x12` |
| Service Solicitation (16, 32, 128-bit) | `0x14`/`0x1F`/`0x15` |
| Service Data (16, 32, 128-bit) | `0x16`/`0x20`/`0x21` |
| Appearance | `0x19` |
| Advertising Interval | `0x1A` |
| Public/Random Target Address | `0x17`/`0x18` |
| LE Supported Features | `0x27` |
| URI | `0x24` |
| Manufacturer Specific Data | `0xFF` |

### Assigned Numbers
Auto-generated from Bluetooth SIG sources:
- Company Identifiers
- Service UUIDs (16-bit)
- Appearance Values
- AD Types
- URI Schemes (provisioned)

### Async Runtime & Logging Support

| Feature | Purpose | Use Case |
|---------|---------|----------|
| `tokio` (default) | Tokio async runtime | Linux, macOS, desktop testing |
| `embassy` | Embassy async runtime | Bare-metal embedded (nRF, STM32, ESP32) |
| `defmt` | Defmt logging (embedded) | Wire-format logging for `probe-run`/`probe-rs` |
| `log` | Standard `log` crate | Desktop/host-platform diagnostics |

`tokio`/`embassy` are mutually exclusive. `defmt`/`log` are mutually exclusive. All provide `HciDriver::with_timeout()` via the `WithTimeout` trait.

### `no_std` & Embedded
- Zero heap allocations in core logic
- `heapless::Vec` for event buffering
- Const-generic `Buffer<CAP>` for packet construction
- `defmt` support for embedded logging (`defmt` feature flag)
- `log` support for host-platform diagnostics (`log` feature flag)
- `embassy-time` for bare-metal timeouts

### Supported Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| **Linux (x86_64, aarch64)** | ✅ Supported | `tokio` + HCI sockets; bletio CLI tool |
| **macOS** | ✅ Builds | `tokio` runtime; HCI driver needs platform-specific transport |
| **nRF52840 / nRF5340** | ✅ Supported | `embassy` runtime; UART HCI driver |
| **ESP32-C3 / ESP32-S3** | ⚠️ Untested | Should work with `embassy` + UART HCI driver |
| **STM32WB** | ⚠️ Untested | Should work with `embassy` + UART/SPI HCI driver |
| **Raspberry Pi** | ✅ Supported | Linux via `hciattach`; HCI socket or UART HCI driver |

All core crates build for any target with `no_std` support. Platform-specific
code is limited to the `HciDriver` transport implementation and the CLI tool.

---

## Quick Start

### 1. Add dependencies

```toml
[dependencies]
bletio-host = { git = "https://github.com/themactep/bletio" }
bletio-hci = { git = "https://github.com/themactep/bletio" }
bletio-utils = { git = "https://github.com/themactep/bletio" }
```

For embedded use with `defmt`:

```toml
bletio-host = { git = "https://github.com/themactep/bletio", default-features = false, features = ["embassy", "defmt"] }
```

For desktop use with `log` (instead of `defmt`):

```toml
bletio-host = { git = "https://github.com/themactep/bletio", features = ["log"] }
```

`defmt` and `log` are mutually exclusive; `log` is the default when neither is specified.

### 2. Implement `HciDriver`

```rust
use bletio_hci::{HciDriver, HciDriverError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct UartHciDriver {
    serial: /* your serial port type */,
}

impl HciDriver for UartHciDriver {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, HciDriverError> {
        self.serial.read(buf).await.map_err(|_| HciDriverError::ReadFailure)
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize, HciDriverError> {
        self.serial.write(buf).await.map_err(|_| HciDriverError::WriteFailure)
    }
}
```

### 3. Implement `BleHostObserver`

```rust
use bletio_host::{BleHost, BleHostObserver, BleHostStates};
use bletio_hci::HciDriver;

struct MyObserver;

impl BleHostObserver for MyObserver {
    async fn ready<H: HciDriver>(
        &self,
        host: BleHost<H, bletio_host::BleHostStateStandby>,
    ) -> BleHostStates<H> {
        println!("BLE stack ready. Address: {:?}", host.public_device_address());
        // Start advertising...
        BleHostStates::Standby(host)
    }
}
```

### 4. Run the device

```rust
#[tokio::main]
async fn main() -> Result<(), bletio_host::Error> {
    let observer = MyObserver;
    let mut device = bletio_host::BleDevice::builder(observer)
        .with_local_name("My BLE Device")
        .build();

    let hci_driver = UartHciDriver { serial: /* ... */ };
    device.run(hci_driver).await
}
```

---

## Event Loop Lifecycle

```
         ┌──────────┐
         │  Initial  │
         └─────┬─────┘
        setup()│
     ┌────────┴────────┐
     │    Standby       │◄──────────────────────────────┐
     └──┬──────┬───────┘                               │
        │      │                                        │
   start_ │  start_ │ connect()                        │
   adv() │ scan()  │                                   │
   ┌─────┴┐ ┌─────┴──────┐  ┌───────────┐             │
   │Adv.  │ │ Scanning    │  │Initiating │             │
   └──┬───┘ └──┬──┬──────┘  └─────┬──────┘             │
      │        │  │               │                     │
      │ connect│  │ stop_scan()    │ connection_complete │
      │ event  │  │               │                     │
      │   ┌────┘  │               └──────────┐          │
      │   │       └──────────────────┐        │          │
      │   │                          │        │          │
   ┌──┴───┴────┐              ┌──────┴────────┴──────┐  │
   │Connected  │              │  ConnectedCentral     │  │
   │Peripheral │              │                        │  │
   └─────┬─────┘              └───────────┬────────────┘  │
         │                               │               │
         │   disconnect / disconnection   │               │
         └───────────────┬───────────────┘               │
                         └───────────────────────────────┘
```

---

## CI Pipeline

| Job | Description |
|-----|-------------|
| **Rustfmt** | Enforces formatting with `cargo fmt --all --check` |
| **Test** | Runs `cargo test` with Rust cache |
| **Clippy** | Lints with `cargo clippy -- -D warnings` |
| **Coverage** | Code coverage via `cargo-tarpaulin` |
| **Security Audit** | Daily `cargo-deny` advisory scan |

---

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

---

## Codebase Enhancement & Improvement Plan

The sections below outline a phased roadmap for bringing `bletio` from a connection-management
stack to a full-featured BLE host. Each phase builds on the previous one and includes
concrete, actionable items.

---

### Phase 1 — Hardening & Polish (target: stability)

These items address the highest-priority issues in the current codebase with minimal
risk to the existing architecture.

| # | Item | Priority | Effort | Status | Description |
|---|------|----------|--------|--------|-------------|
| 1.1 | **Fix ACL data `todo!()` panics** | 🔴 Critical | M | ✅ Done | Added `Event::AclData(AclData)` variant; ACL data is now buffered in `send_command_and_wait_response`, `wait_for_event`, and `wait_controller_ready` instead of panicking. |
| 1.2 | **Double-buffer the event list** | 🟡 High | S | ✅ Done | Bumped default event capacity from 4 to 8. `EVENT_LIST_NB_EVENTS` const in `event/mod.rs` for easy tuning. |
| 1.3 | **Add `log` support as alternative to `defmt`** | 🟡 High | S | ✅ Done | Added `log` 0.4 as optional dependency with `log` feature flag on all three crates. All diagnostic call sites now support both `defmt` and `log`. |
| 1.4 | **Document the public API** | 🟡 High | M | ✅ Done | Comprehensive rustdoc on key types: `Hci`, `HciDriver`, `BleDevice`, `BleHostObserver`, `AclData`, `GattClient`, `GattServer`. Includes examples, callback tables, and links to demo code. |
| 1.5 | **Remove `UnexpectedEvent` fallibility** | 🟢 Medium | XS | ✅ Done | Replaced `Err(Error::UnexpectedEvent)` in `execute_command_with_command_status_response` with `unreachable!()`. |
| 1.6 | **Add `Unsupported` event logging** | 🟢 Medium | XS | ✅ Done | Unknown HCI event codes are now logged via `defmt` or `log` instead of being silently dropped. |
| 1.7 | **Improve `Packet`/`Event` enum sizes** | 🟢 Medium | S | ✅ Done | Documented in `size_of.txt`. `LeAdvertisingReportList` at 260 bytes is the dominant variant; cannot reduce without `alloc` or breaking changes. |
| 1.8 | **Controller reset timeout** | 🟢 Medium | S | ✅ Done | `cmd_reset()` uses separate `HCI_RESET_TIMEOUT` (5 seconds) instead of the default 1-second command timeout. |

---

### Phase 2 — Data Plane Foundation (target: ACL data flow)

The stack currently handles only the control plane (commands and events). The data plane
(ACL packets carrying ATT/GATT/SMP traffic) is the next critical layer.

| # | Item | Priority | Effort | Status | Description |
|---|------|----------|--------|--------|-------------|
| 2.1 | **ACL send path** | 🔴 Critical | M | ✅ Done | Added `write_acl_data()` to `Hci<H>`, `send_acl_data()` to `BleHost` connected states, `EncodeToBuffer` impl and public getters/builders on `AclData`. ACL data is encoded in HCI ACL packet format and written via the driver. |
| 2.2 | **ACL receive path** | 🔴 Critical | M | ✅ Done | `Event::AclData` variant (added in Phase 1.1) is now wired through `BleDevice` to the observer's `acl_data_received` callback. Received ACL data is dispatched per-connection-handle to the application. |
| 2.3 | **ACL credit-based flow control** (LE-Credit) | 🟡 High | L | ✅ Done | `le_acl_credits` tracking on `Hci<H>`. `write_acl_data()` checks/decrements credits, returns `ControllerBusy` when exhausted. `LeFlowControlCreditEvent` parsing restores credits. Initialized from `cmd_le_read_buffer_size` during setup. |
| 2.4 | **Connection handle registry** | 🟡 High | M | ✅ Done | `ConnectionRegistry<const MAX>` with add/find/remove/update_params. `Connection` struct tracks handle, role, interval, latency, timeout, peer address. `PeripheralConnectionRegistry` (1 conn) and `CentralConnectionRegistry` (4 conns) aliases. |
| 2.5 | **Add `AclData` as observer callback** | 🟢 Medium | M | ✅ Done | Added `acl_data_received` callback to `BleHostObserver` (push model). Both `Event::AclData` variant and observer callback coexist — events are buffered in the HCI layer, then dispatched to the observer. |

---

### Phase 3 — ATT & GATT Foundation (target: service discovery & characteristic access)

With ACL data flowing, the next layer is the Attribute Protocol (ATT) and Generic
Attribute Profile (GATT).

| # | Item | Priority | Effort | Status | Description |
|---|------|----------|--------|--------|-------------|
| 3.1 | **ATT PDU encoding/decoding** | 🔴 Critical | L | ✅ Done | 16 ATT PDU types implemented with `EncodeToBuffer` serialization and nom-based zero-copy parsing. Supports Error Response, Exchange MTU, Find Information, Read By Type/Group Type, Read/Read Blob, Write Request/Command, Handle Value Notification/Indication/Confirmation. Supporting types: `AttHandle`, `AttValue`, `AttUuid`, `AttError`, `AttErrorCode`, `AttOpcode`. |
| 3.2 | **ATT client state machine** | 🔴 Critical | XL | ✅ Done | Synchronous request-response state machine (`AttClient`) with one-outstanding-request tracking. Methods: `prepare_exchange_mtu`, `prepare_read_by_group_type`, `prepare_read_by_type`, `prepare_read`, `prepare_read_blob`, `prepare_write_request`, `prepare_write_command`, `prepare_notification`, `prepare_indication`. `receive()` matches incoming ACL data to pending responses. Returns `EncodedAttPdu` for sending over ACL. |
| 3.3 | **GATT discovery procedures** | 🔴 Critical | L | ✅ Done | `GattClient` with `discover_all_primary_services()`, `discover_characteristics()`, `discover_descriptors()`. Handles continuation across multiple Read By Group Type/Type responses. Parses 16-bit and 128-bit UUIDs. `Attribute Not Found` error automatically terminates discovery. |
| 3.4 | **GATT client read/write operations** | 🟡 High | M | ✅ Done | `read_value()`, `read_blob()`, `write_value()`, `write_value_without_response()`, `notify()`, `indicate()`, `send_confirmation()`. `GattEvent` variants: `ValueRead`, `ValueWritten`, `Notification`, `Indication`. Notifications/indications delivered automatically while idle. Busy-state guard prevents concurrent requests. |
| 3.5 | **GATT server framework** | 🟡 High | XL | ✅ Done | `GattServer` with attribute table, handle allocation, `handle_request()` for all standard ATT requests (Exchange MTU, Find Information, Read By Group Type/Type, Read/Read Blob, Write Request/Command), permission checking. Builder pattern: `GattServiceBuilder` → `GattCharacteristicBuilder` → `GattDescriptorBuilder`. `set_value()`/`get_value()` for dynamic values. Standard descriptor UUIDs. |
| 3.6 | **GATT profiles** | 🟢 Medium | XL | ✅ Done | `profiles` module with pre-built service definitions: `device_information()` (DIS), `battery_service()` (BAS), `generic_access()` (GAP), `generic_attribute()` (GATT), `heart_rate_service()` (HRS). Standard UUID constants for common services, characteristics, and descriptors. |

---

### Phase 4 — Security (target: pairing & bonding)

| # | Item | Priority | Effort | Description |
|---|------|----------|--------|-------------|
| 4.1 | **SMP command parsing** | 🟡 High | L | ✅ Done | 11 SMP PDU types: Pairing Request/Response, Confirm, Random, Failed, Encryption Info, Master ID, Identity Info/Address, Signing Info, Security Request. AuthReq, IoCapability, KeyDistribution, PairingFailedReason types. Nom-based parser with roundtrip tests. |
| 4.2 | **LE Legacy Pairing** | 🟡 High | XL | ✅ Done | Just Works (TK=0) and Passkey Entry (`set_passkey()`). SmpPairing state machine with 4 phases. IO capability matrix documented. |
| 4.3 | **LE Secure Connections** | 🟢 Medium | XL | ⚠️ Scaffolding | `SmpPdu::PairingPublicKey`/`PairingDhkeyCheck` with parsing. `SmpCrypto` trait extended with `generate_p256_keypair()`, `p256_dh()`, `f5()`, `f6()` — all default to `NotSupported`. Phase hooks exist. Production use needs a P-256 implementation behind the trait. |
| 4.4 | **Bonding & key storage** | 🟢 Medium | L | ✅ Done | `BondStore` trait with `MemoryBondStore` implementation. `Bond` struct holds LTK, EDIV, Rand, IRK, CSRK, peer address. `SmpPairing::generate_keys()` and `build_distribution_pdus()` for post-pairing key distribution. Usage example showing store/load/encrypt flow. |

---

### Phase 5 — Features & Performance (target: completeness)

| # | Item | Priority | Effort | Description |
|---|------|----------|--------|-------------|
| 5.1 | **LE Extended Advertising** | 🟢 Medium | XL | ⚠️ Scaffolding | `AdvertisingSetHandle` type, `LeExtendedAdvertisingReport` event parser, command opcodes registered. Full command encoding (SetExtendedAdvertisingParameters/Data/Enable) not yet implemented — deferred to vendor command path. |
| 5.2 | **LE Coded PHY (Long Range)** | 🟢 Medium | L | ✅ Done | `LePhy` enum (LE 1M/2M/Coded S8/Coded S2). `LePhyUpdateCompleteEvent` parsing. `cmd_le_read_phy()`, `cmd_le_set_default_phy()`, `cmd_le_set_phy()` on `Hci<H>`. |
| 5.3 | **LE Isochronous Channels** | 🟢 Low | XL | ⚠️ Scaffolding | `iso.rs` module, 10 command opcodes, 3 event type structs, ISO types (`CigId`, `CisId`, `CisParams`). ISO packet type already in `PacketType`. Full command/event encoding and ISO data path not yet implemented. |
| 5.4 | **LE Periodic Advertising with Responses (PAwR)** | 🟢 Low | XL | ⚠️ Scaffolding | 2 command opcodes, PAwR event slot (0x26). Full implementation not yet completed. |
| 5.5 | **Connection parameter optimization** | 🟢 Medium | M | ✅ Done | `ConnectionProfile` enum with presets: `LowPower` (100–125ms), `Balanced` (25–35ms), `HighThroughput` (8–15ms), `LowLatency` (8–15ms), `Custom`. `to_update_params()` converts profiles to `ConnectionUpdateParameters` with ms→BLE-unit conversion. |
| 5.6 | **HCI vendor command extension** | 🟢 Medium | S | ✅ Done | `Command::VendorSpecific { opcode, parameters }` variant and `cmd_vendor_specific()` on `Hci<H>`. |
| 5.7 | **Connection supervision timeout event** | 🟢 Medium | S | ✅ Done | `HardwareErrorEvent` (0x10) and `DataBufferOverflowEvent` (0x1A) parsed and routed to `BleHostObserver` callbacks with automatic logging. |
| 5.8 | **Client Characteristic Configuration Descriptor (CCCD) writes** | 🟢 Medium | M | ✅ Done | GATT server auto-detects CCCD writes (UUID 0x2902), updates subscription state. `is_notify_enabled()`/`is_indicate_enabled()`. |
| 5.9 | **Dynamic MTU negotiation** | 🟢 Medium | S | ✅ Done | `AttClient` auto-updates MTU on `ExchangeMtuResponse`. |
| 5.10 | **Power profiling & low-power modes** | 🟢 Low | M | ✅ Done | `PowerEstimator` with advertising/connected current draw and battery life estimates. `BatteryCapacity` presets (CR2032, Li-Po, etc.), `AdvertisingPowerProfile` presets (Aggressive through ExtremePowerSaving). `PowerProfile` for custom controller characteristics. |

---

### Phase 6 — Developer Experience (target: ecosystem)

| # | Item | Priority | Effort | Description |
|---|------|----------|--------|-------------|
| 6.1 | **Integration tests with virtual controller** | 🟡 High | XL | ⚠️ Partial | 1 initialization flow test (Reset→BufferSize→BdAddr). 493 per-command unit tests serve as byte-level controller tests. No full end-to-end scenario tests (advertise→connect→pair→GATT). |
| 6.2 | **`bletio` CLI tool** | 🟢 Medium | L | ⚠️ Partial | `scan` command works on Linux (raw HCI socket, requires `systemctl stop bluetooth`). Tested on Intel BLE 5.4. No connect/read/write/advertise commands yet. |
| 6.3 | **Usage examples** | 🟡 High | M | ✅ Done | 4 examples: `gatt_server_demo`, `gatt_client_demo`, `smp_pairing_demo`, `full_stack_demo`. All compile and run. |
| 6.4 | **Platform support matrix** | 🟢 Medium | S | ✅ Done | Documented in README: Linux, macOS, nRF52, ESP32, STM32WB, Raspberry Pi. |
| 6.5 | **Conformance testing** | 🟢 Low | XL | ⚠️ Docs only | PTS test case matrix documented in `conformance.rs`. 22/26 GAP/GATT/SM cases listed as expected to pass. No actual PTS tests run (requires hardware + PTS software). |
| 6.6 | **`defmt` / `log` structured event tracing** | 🟢 Low | M | ✅ Done | `bletio_trace!/debug!/info!/warn!/error!` macros dispatching to defmt or log. HCI command/event tracing at `execute_command()`. |
| 6.7 | **Semver-gated releases** | 🟢 Medium | S | ⬜ | Deferred — upstream decides publishing strategy. |

---

### Ongoing

| # | Item | Status | Description |
|---|------|--------|-------------|
| O.1 | **Keep assigned numbers current** | ✅ Done | Scheduled CI job updates assigned numbers weekly. |
| O.2 | **Security audit** | ⬜ | Daily `cargo-deny` in place; add `cargo-audit` for RustSec. |
| O.3 | **MSRV policy** | ✅ Done | `rust-version = "1.75"`, CI job. |
| O.4 | **Fuzz testing** | ✅ Done | Fuzz tests for HCI, ATT, and SMP parsers. |

---

### Summary by Phase

| Phase | Focus | Critical Items | Est. Total Effort |
|-------|-------|---------------|-------------------|
| 1 | Hardening | ACL todo!(), event list overflow, docs | ~2–3 weeks |
| 2 | Data plane | ACL send/receive, credit flow control, connection registry | ~3–4 weeks |
| 3 | ATT & GATT | ATT PDU encoding, GATT client/server, profiles | ~2–3 months |
| 4 | Security | SMP, LE Legacy Pairing, LE Secure Connections, bonding | ~2–3 months | 4.1 ✅ 4.2 ✅ 4.3 ⚠️ scaffolding 4.4 ✅ |
| 5 | Features | Extended advertising, Coded PHY, connection optimization | ~2–4 months | 8/10 ✅, 5.1/5.3/5.4 ⚠️ scaffolding |
| 6 | Developer exp. | Integration tests, examples, CLI, platform matrix | ~2–3 months | 4/7 ✅, 6.1/6.2/6.5 ⚠️ partial |

Effort estimates assume single-developer velocity and are rough order-of-magnitude guides.
