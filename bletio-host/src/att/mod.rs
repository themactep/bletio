//! Attribute Protocol (ATT) layer.
//!
//! Implements ATT PDU encoding/decoding per
//! [Core Specification 6.0, Vol. 3, Part F](https://www.bluetooth.com/specifications/specs/core-specification-6-0/).

mod att_client;
mod att_pdu;
mod gatt;
mod gatt_server;

pub use att_client::{AttClient, EncodedAttPdu};
pub use att_pdu::{
    AttError, AttErrorCode, AttHandle, AttHandleValue, AttOpcode, AttPdu, AttUuid, AttValue,
};
pub use gatt::{GattCharacteristic, GattClient, GattDescriptor, GattEvent, GattService};
pub use gatt_server::{
    Attribute, AttributePermissions, GattCharacteristicBuilder, GattCharacteristicDef,
    GattDescriptorBuilder, GattDescriptorDef, GattServer, GattServiceBuilder, GattServiceDef,
    CHAR_EXTENDED_PROPERTIES_UUID, CHAR_PRESENTATION_FORMAT_UUID, CHAR_USER_DESCRIPTION_UUID,
    CLIENT_CHAR_CONFIG_UUID, SERVER_CHAR_CONFIG_UUID,
};
