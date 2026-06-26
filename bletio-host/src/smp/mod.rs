//! Security Manager Protocol (SMP) layer.
//!
//! Implements SMP PDU encoding/decoding and LE Legacy Pairing per
//! [Core Specification 6.0, Vol. 3, Part H](https://www.bluetooth.com/specifications/specs/core-specification-6-0/).

mod pairing;
mod smp_pdu;

pub use pairing::{
    MockCrypto, SmpCrypto, SmpKeys, SmpPairing, SmpPairingConfig, SmpPairingPhase,
    SmpPairingResult,
};
pub use smp_pdu::{
    AuthReq, IoCapability, KeyDistribution, PairingFailedReason, SmpError, SmpOpcode, SmpPdu,
};
