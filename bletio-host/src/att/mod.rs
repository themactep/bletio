//! Attribute Protocol (ATT) layer.
//!
//! Implements ATT PDU encoding/decoding per
//! [Core Specification 6.0, Vol. 3, Part F](https://www.bluetooth.com/specifications/specs/core-specification-6-0/).

mod att_client;
mod att_pdu;
mod gatt;

pub use att_client::{AttClient, EncodedAttPdu};
pub use att_pdu::{
    AttError, AttErrorCode, AttHandle, AttHandleValue, AttOpcode, AttPdu, AttUuid, AttValue,
};
pub use gatt::{GattCharacteristic, GattClient, GattDescriptor, GattEvent, GattService};
