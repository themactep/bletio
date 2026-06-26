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
| 1.2 | **Double-buffer the event list** | 🟡 High | S | ⬜ | Existing 4-event `heapless::Vec` now also carries ACL data; capacity increase deferred until GATT traffic volume demands it. |
| 1.3 | **Add `log` support as alternative to `defmt`** | 🟡 High | S | ✅ Done | Added `log` 0.4 as optional dependency with `log` feature flag on all three crates. All 5 diagnostic call sites now support both `defmt` and `log`. |
| 1.4 | **Document the public API** | 🟡 High | M | ⬜ | README covers quick start and architecture; per-item rustdoc to follow in a dedicated pass. |
| 1.5 | **Remove `UnexpectedEvent` fallibility** | 🟢 Medium | XS | ✅ Done | Replaced `Err(Error::UnexpectedEvent)` in `execute_command_with_command_status_response` with `unreachable!()`. |
| 1.6 | **Add `Unsupported` event logging** | 🟢 Medium | XS | ✅ Done | Unknown HCI event codes are now logged via `defmt` or `log` instead of being silently dropped. |
| 1.7 | **Improve `Packet`/`Event` enum sizes** | 🟢 Medium | S | ⬜ | Adding `AclData` (~35 bytes) does not increase max variant size; `LeAdvertisingReportList` (260 bytes) remains the dominant variant. Deferred until memory profiling on target. |
| 1.8 | **Controller reset timeout** | 🟢 Medium | S | ⬜ | Not yet observed as a problem; can be addressed when a concrete controller exhibits slow reset. |

---

### Phase 2 — Data Plane Foundation (target: ACL data flow)

The stack currently handles only the control plane (commands and events). The data plane
(ACL packets carrying ATT/GATT/SMP traffic) is the next critical layer.

| # | Item | Priority | Effort | Status | Description |
|---|------|----------|--------|--------|-------------|
| 2.1 | **ACL send path** | 🔴 Critical | M | ✅ Done | Added `write_acl_data()` to `Hci<H>`, `send_acl_data()` to `BleHost` connected states, `EncodeToBuffer` impl and public getters/builders on `AclData`. ACL data is encoded in HCI ACL packet format and written via the driver. |
| 2.2 | **ACL receive path** | 🔴 Critical | M | ✅ Done | `Event::AclData` variant (added in Phase 1.1) is now wired through `BleDevice` to the observer's `acl_data_received` callback. Received ACL data is dispatched per-connection-handle to the application. |
| 2.3 | **ACL credit-based flow control** (LE-Credit) | 🟡 High | L | ⬜ | Only needed for BLE 4.2+ controllers with LE Data Length Extension. Deferred until required by a target controller. |
| 2.4 | **Connection handle registry** | 🟡 High | M | ⬜ | Application tracks handles via `connection_complete` callback. A dedicated registry will be more valuable once Phase 3 (GATT) requires per-connection transaction state. |
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
| 4.2 | **LE Legacy Pairing** | 🟡 High | XL | Just Works, Passkey Entry, Out of Band, Numeric Comparison pairing methods. Implement the full SMP state machine per Core Spec v4.2, Vol. 3, Part H. |
| 4.3 | **LE Secure Connections** | 🟢 Medium | XL | FIPS-approved ECDH key exchange (P-256 curve) with AES-CCM encryption and HMAC-SHA256 for LE Secure Connections pairing. |
| 4.4 | **Bonding & key storage** | 🟢 Medium | L | Define a `KeyStore` trait that applications implement for persistent storage of bonded device keys (LTK, EDIV/Rand, IRK, CSRK). Provide an in-memory implementation for testing. |

---

### Phase 5 — Features & Performance (target: completeness)

| # | Item | Priority | Effort | Description |
|---|------|----------|--------|-------------|
| 5.1 | **LE Extended Advertising** | 🟢 Medium | XL | BLE 5.0 extended advertising: larger payloads (up to 1650 bytes), periodic advertising, advertising on secondary channels, multiple advertising sets, advertising data fragmentation over AUX_CHAIN_IND. |
| 5.2 | **LE Coded PHY (Long Range)** | 🟢 Medium | L | Support for LE 1M, LE 2M, and LE Coded (S=2, S=8) PHY selection via `LE Set PHY` command. Parse `LE PHY Update Complete` event. |
| 5.3 | **LE Isochronous Channels** | 🟢 Low | XL | BLE 5.2 LE Audio support: Connected Isochronous Streams (CIS), Broadcast Isochronous Streams (BIS), isochronous channel commands and events. |
| 5.4 | **LE Periodic Advertising with Responses (PAwR)** | 🟢 Low | XL | BLE 5.4 feature for bidirectional periodic advertising. |
| 5.5 | **Connection parameter optimization** | 🟢 Medium | M | Implement the connection parameter update request procedure per Core Spec. Add heuristics for automatic parameter optimization based on use case (high throughput, low latency, low power). |
| 5.6 | **HCI vendor command extension** | 🟢 Medium | S | ✅ Done | `Command::VendorSpecific { opcode, parameters }` variant and `cmd_vendor_specific()` on `Hci<H>`. |
| 5.7 | **Connection supervision timeout event** | 🟢 Medium | S | ⬜ | |
| 5.8 | **Client Characteristic Configuration Descriptor (CCCD) writes** | 🟢 Medium | M | ✅ Done | GATT server auto-detects CCCD writes (UUID 0x2902), updates subscription state. `is_notify_enabled()`/`is_indicate_enabled()`. |
| 5.9 | **Dynamic MTU negotiation** | 🟢 Medium | S | ✅ Done | `AttClient` auto-updates MTU on `ExchangeMtuResponse`. |
| 5.10 | **Power profiling & low-power modes** | 🟢 Low | M | Document power consumption characteristics. Add support for controller sleep modes. Provide examples of duty-cycled advertising and connection intervals for battery-powered peripherals. |

---

### Phase 6 — Developer Experience (target: ecosystem)

| # | Item | Priority | Effort | Description |
|---|------|----------|--------|-------------|
| 6.1 | **Integration tests with virtual controller** | 🟡 High | XL | Write integration tests using a BLE controller simulator (or a mock HCI that implements the controller side of HCI). This tests the full stack end-to-end: advertising, scanning, connection, pairing, GATT operations. |
| 6.2 | **`bletio` CLI tool** | 🟢 Medium | L | A command-line tool for interacting with BLE devices using a local HCI controller. Useful for debugging, testing, and as a reference application. |
| 6.3 | **Usage examples** | 🟡 High | M | Standalone examples in `examples/`: temperature peripheral, heart rate peripheral, central scanner, battery service, LED control. Each example should target both Tokio (for CI) and a real embedded board. |
| 6.4 | **Platform support matrix** | 🟢 Medium | S | Document and CI-test against: nRF52840, nRF5340, ESP32-C3, STM32WB, Raspberry Pi (via `hciattach`), and Linux HCI sockets. |
| 6.5 | **Conformance testing** | 🟢 Low | XL | Run against Bluetooth SIG qualification test suite (PTS) where feasible. Document PTS test results for qualification. |
| 6.6 | **`defmt` / `log` structured event tracing** | 🟢 Low | M | Emit structured events (not just free-text) for all state transitions, HCI command/event exchanges, and GATT operations. Enable post-mortem analysis of BLE interactions. |
| 6.7 | **Semver-gated releases** | 🟢 Medium | S | Publish to crates.io with proper semver. Set up CI for automated release publishing on tag. |

---

### Ongoing

| # | Item | Description |
|---|------|-------------|
| O.1 | **Keep assigned numbers current** | Run `update-assigned-numbers` periodically (or via CI scheduled job) to sync with Bluetooth SIG updates for company IDs, service UUIDs, and appearance values. |
| O.2 | **Security audit** | The daily `cargo-deny` audit is already in place. Add `cargo-audit` for RustSec advisory database checks. |
| O.3 | **MSRV policy** | Document and CI-test a Minimum Supported Rust Version. The project uses edition 2021 and stable features only. |
| O.4 | **Fuzz testing** | Add fuzz targets for the nom parsers (HCI packets, advertising data, ATT PDUs) using `cargo-fuzz` or `afl.rs`. Parsers are the primary attack surface. |

---

### Summary by Phase

| Phase | Focus | Critical Items | Est. Total Effort |
|-------|-------|---------------|-------------------|
| 1 | Hardening | ACL todo!(), event list overflow, docs | ~2–3 weeks |
| 2 | Data plane | ACL send/receive, credit flow control, connection registry | ~3–4 weeks |
| 3 | ATT & GATT | ATT PDU encoding, GATT client/server, profiles | ~2–3 months |
| 4 | Security | SMP, LE Legacy Pairing, LE Secure Connections, bonding | ~2–3 months |
| 5 | Features | Extended advertising, Coded PHY, connection optimization | ~2–4 months |
| 6 | Developer exp. | Integration tests, examples, CLI, platform matrix | ~2–3 months |

Effort estimates assume single-developer velocity and are rough order-of-magnitude guides.
