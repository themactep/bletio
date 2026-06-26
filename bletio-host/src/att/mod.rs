//! Attribute Protocol (ATT) layer.
//!
//! Implements ATT PDU encoding/decoding per
//! [Core Specification 6.0, Vol. 3, Part F](https://www.bluetooth.com/specifications/specs/core-specification-6-0/).

mod att_pdu;

pub use att_pdu::{
    AttError, AttErrorCode, AttHandle, AttHandleValue, AttOpcode, AttPdu, AttUuid, AttValue,
};
