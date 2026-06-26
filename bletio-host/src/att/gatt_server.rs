//! GATT server framework for registering local services, characteristics, and descriptors.
//!
//! The server maintains an attribute table and handles incoming ATT requests from
//! connected centrals. Attribute values are stored directly — the application
//! updates dynamic values before they are read.
//!
//! # Example
//!
//! ```ignore
//! let mut server = GattServer::new();
//!
//! // Device Information Service (0x180A)
//! let svc = GattServiceBuilder::new(AttUuid::Uuid16(0x180A))
//!     .add_characteristic(
//!         GattCharacteristicBuilder::new(AttUuid::Uuid16(0x2A29)) // Manufacturer Name
//!             .readable()
//!             .value(b"bletio")?
//!             .build()
//!     )
//!     .build();
//! server.add_service(svc)?;
//!
//! // Handle incoming ATT PDU
//! let response = server.handle_request(&incoming_pdu)?;
//! ```

use heapless::Vec;

use super::att_pdu::{
    AttError, AttErrorCode, AttHandle, AttOpcode, AttPdu, AttUuid, AttValue,
};

// ─── Attribute definitions ───────────────────────────────────────────────

/// Permissions for a GATT attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttributePermissions {
    /// The attribute can be read.
    pub read: bool,
    /// The attribute can be written.
    pub write: bool,
    /// The attribute can send notifications.
    pub notify: bool,
    /// The attribute can send indications.
    pub indicate: bool,
    /// The attribute can be written without response (command).
    pub write_without_response: bool,
}

impl Default for AttributePermissions {
    fn default() -> Self {
        Self {
            read: false,
            write: false,
            notify: false,
            indicate: false,
            write_without_response: false,
        }
    }
}

/// A single GATT attribute in the server's attribute table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Attribute {
    /// The handle assigned to this attribute.
    pub handle: AttHandle,
    /// The UUID type of this attribute (service, characteristic, descriptor, etc.).
    pub attribute_type: AttUuid,
    /// Access permissions.
    pub permissions: AttributePermissions,
    /// Current value of the attribute.
    pub value: AttValue,
}

// ─── GATT Server ────────────────────────────────────────────────────────

/// Maximum number of attributes in the server's attribute table.
const MAX_ATTRIBUTES: usize = 64;

/// GATT server that manages a local attribute table and handles incoming ATT requests.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GattServer {
    attributes: Vec<Attribute, MAX_ATTRIBUTES>,
    /// Next available handle for attribute assignment.
    next_handle: u16,
    /// CCCD subscription state: (characteristic_value_handle, notifications_enabled, indications_enabled).
    cccd_state: Vec<(AttHandle, bool, bool), 16>,
}

impl GattServer {
    /// Create a new empty GATT server. Handle allocation starts at 1.
    pub fn new() -> Self {
        Self {
            attributes: Vec::new(),
            next_handle: 1,
            cccd_state: Vec::new(),
        }
    }

    /// Returns the number of registered attributes.
    pub fn attribute_count(&self) -> usize {
        self.attributes.len()
    }

    /// Look up an attribute by handle.
    pub fn find_attribute(&self, handle: AttHandle) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.handle == handle)
    }

    /// Look up a mutable attribute by handle.
    pub fn find_attribute_mut(&mut self, handle: AttHandle) -> Option<&mut Attribute> {
        self.attributes.iter_mut().find(|a| a.handle == handle)
    }

    /// Update the value of an attribute at the given handle.
    pub fn set_value(&mut self, handle: AttHandle, value: &[u8]) -> Result<(), AttError> {
        let attr = self
            .find_attribute_mut(handle)
            .ok_or(AttError::InvalidHandle)?;
        attr.value = AttValue::new(value)?;
        Ok(())
    }

    /// Get the value of an attribute at the given handle.
    pub fn get_value(&self, handle: AttHandle) -> Option<&AttValue> {
        self.find_attribute(handle).map(|a| &a.value)
    }

    /// Check if notifications are enabled for the characteristic at the given value handle.
    pub fn is_notify_enabled(&self, char_value_handle: AttHandle) -> bool {
        self.cccd_state
            .iter()
            .any(|&(h, notify, _)| h == char_value_handle && notify)
    }

    /// Check if indications are enabled for the characteristic at the given value handle.
    pub fn is_indicate_enabled(&self, char_value_handle: AttHandle) -> bool {
        self.cccd_state
            .iter()
            .any(|&(h, _, indicate)| h == char_value_handle && indicate)
    }

    /// Update CCCD state when a client writes to a CCCD descriptor.
    /// The CCCD handle controls the characteristic with value handle = cccd_handle - 1.
    fn update_cccd(&mut self, cccd_handle: AttHandle, value: &[u8]) -> Result<(), AttError> {
        if value.len() < 2 {
            return Err(AttError::InvalidPdu);
        }
        let notify = (value[0] & 0x01) != 0;
        let indicate = (value[0] & 0x02) != 0;

        // The characteristic value handle is one before the CCCD descriptor
        let char_handle = AttHandle(cccd_handle.0.saturating_sub(1));

        // Remove existing entry for this char handle, then insert updated state
        self.cccd_state.retain(|&(h, _, _)| h != char_handle);
        let _ = self.cccd_state.push((char_handle, notify, indicate));
        Ok(())
    }

    /// Allocate a new handle.
    fn alloc_handle(&mut self) -> AttHandle {
        let handle = AttHandle(self.next_handle);
        self.next_handle += 1;
        handle
    }

    /// Add a service definition to the server. Allocates handles for the
    /// service declaration, characteristic declarations, characteristic values,
    /// and descriptors.
    pub fn add_service(&mut self, service: GattServiceDef) -> Result<(), AttError> {
        // Service declaration attribute
        let svc_type_uuid = if service.is_primary {
            0x2800u16
        } else {
            0x2801u16
        };
        let svc_handle = self.alloc_handle();
        let svc_end_handle = AttHandle(self.next_handle + service.handle_count() as u16);

        let svc_value = {
            let mut data = svc_end_handle.0.to_le_bytes().to_vec();
            let _ = data.extend_from_slice(&service.uuid_bytes());
            AttValue::new(&data)?
        };

        self.attributes
            .push(Attribute {
                handle: svc_handle,
                attribute_type: AttUuid::Uuid16(svc_type_uuid),
                permissions: AttributePermissions::default(),
                value: svc_value,
            })
            .map_err(|_| AttError::ValueTooLong)?;

        // Characteristic declarations + values + descriptors
        for char_def in &service.characteristics {
            let char_decl_handle = self.alloc_handle();
            let char_value_handle = self.alloc_handle();

            // Characteristic declaration: properties (1) + value_handle (2) + uuid (2 or 16)
            let char_decl_value = {
                let mut data = Vec::<u8, 32>::new();
                let _ = data.push(char_def.properties());
                let _ = data.extend_from_slice(&char_value_handle.0.to_le_bytes());
                let _ = data.extend_from_slice(&char_def.uuid_bytes());
                AttValue::new(&data)?
            };

            self.attributes
                .push(Attribute {
                    handle: char_decl_handle,
                    attribute_type: AttUuid::Uuid16(0x2803), // Characteristic declaration
                    permissions: AttributePermissions::default(), // Read-only
                    value: char_decl_value,
                })
                .map_err(|_| AttError::ValueTooLong)?;

            // Characteristic value
            let value_perms = AttributePermissions {
                read: char_def.permissions.read,
                write: char_def.permissions.write,
                notify: char_def.permissions.notify,
                indicate: char_def.permissions.indicate,
                write_without_response: char_def.permissions.write_without_response,
            };
            self.attributes
                .push(Attribute {
                    handle: char_value_handle,
                    attribute_type: char_def.uuid,
                    permissions: value_perms,
                    value: char_def.value.clone(),
                })
                .map_err(|_| AttError::ValueTooLong)?;

            // Descriptors
            for desc_def in &char_def.descriptors {
                let desc_handle = self.alloc_handle();
                self.attributes
                    .push(Attribute {
                        handle: desc_handle,
                        attribute_type: desc_def.uuid,
                        permissions: desc_def.permissions,
                        value: desc_def.value.clone(),
                    })
                    .map_err(|_| AttError::ValueTooLong)?;
            }
        }

        Ok(())
    }

    // ── ATT request handling ──────────────────────────────────────────

    /// Handle an incoming ATT request PDU and return the response PDU.
    ///
    /// This implements the server-side logic for all standard ATT requests.
    /// The caller is responsible for encoding the response and sending it
    /// over ACL.
    pub fn handle_request(&mut self, request: &AttPdu) -> Result<AttPdu, AttError> {
        match request {
            AttPdu::ExchangeMtuRequest { client_rx_mtu } => {
                // Accept MTU exchange (server_rx_mtu = min(517, client_rx_mtu))
                let server_rx_mtu = core::cmp::min(517u16, *client_rx_mtu);
                Ok(AttPdu::ExchangeMtuResponse { server_rx_mtu })
            }

            AttPdu::FindInformationRequest {
                starting_handle,
                ending_handle,
            } => self.handle_find_information(*starting_handle, *ending_handle),

            AttPdu::ReadByGroupTypeRequest {
                starting_handle,
                ending_handle,
                attribute_group_type,
            } => {
                self.handle_read_by_group_type(
                    *starting_handle,
                    *ending_handle,
                    *attribute_group_type,
                )
            }

            AttPdu::ReadByTypeRequest {
                starting_handle,
                ending_handle,
                attribute_type,
            } => self.handle_read_by_type(
                *starting_handle,
                *ending_handle,
                *attribute_type,
            ),

            AttPdu::ReadRequest { attribute_handle } => {
                self.handle_read(*attribute_handle, 0)
            }

            AttPdu::ReadBlobRequest {
                attribute_handle,
                value_offset,
            } => self.handle_read(*attribute_handle, *value_offset),

            AttPdu::WriteRequest {
                attribute_handle,
                attribute_value,
            } => self.handle_write(*attribute_handle, attribute_value, true),

            AttPdu::WriteCommand {
                attribute_handle,
                attribute_value,
            } => self.handle_write(*attribute_handle, attribute_value, false),

            // Notifications/indications/confirmations are client-to-server PDUs;
            // the server doesn't respond to them with ATT responses.
            AttPdu::HandleValueConfirmation => {
                // Accept confirmation silently.
                Err(AttError::InvalidPdu)
            }

            _ => self.error_response(request.opcode(), AttHandle(0), AttErrorCode::RequestNotSupported),
        }
    }

    // ── Internal handlers ─────────────────────────────────────────────

    fn handle_find_information(
        &self,
        starting_handle: AttHandle,
        ending_handle: AttHandle,
    ) -> Result<AttPdu, AttError> {
        let attrs: Vec<&Attribute, 16> = self
            .attributes
            .iter()
            .filter(|a| a.handle >= starting_handle && a.handle <= ending_handle)
            .collect();

        if attrs.is_empty() {
            return self.error_response(
                AttOpcode::FindInformationRequest,
                starting_handle,
                AttErrorCode::AttributeNotFound,
            );
        }

        // Determine format: 0x01 for all 16-bit UUIDs, 0x02 if any 128-bit
        let all_16bit = attrs.iter().all(|a| matches!(a.attribute_type, AttUuid::Uuid16(_)));
        let format = if all_16bit { 0x01u8 } else { 0x02u8 };

        let mut information_data = Vec::<u8, 512>::new();
        for attr in attrs {
            information_data
                .extend_from_slice(&attr.handle.0.to_le_bytes())
                .map_err(|_| AttError::ValueTooLong)?;
            match attr.attribute_type {
                AttUuid::Uuid16(v) => {
                    information_data
                        .extend_from_slice(&v.to_le_bytes())
                        .map_err(|_| AttError::ValueTooLong)?;
                }
                AttUuid::Uuid128(v) => {
                    information_data
                        .extend_from_slice(&v.to_le_bytes())
                        .map_err(|_| AttError::ValueTooLong)?;
                }
            }
        }

        Ok(AttPdu::FindInformationResponse {
            format,
            information_data,
        })
    }

    fn handle_read_by_group_type(
        &self,
        starting_handle: AttHandle,
        ending_handle: AttHandle,
        group_type: AttUuid,
    ) -> Result<AttPdu, AttError> {
        // Find all service declarations in range that match the group type
        let svc_attrs: Vec<&Attribute, 16> = self
            .attributes
            .iter()
            .filter(|a| {
                a.handle >= starting_handle
                    && a.handle <= ending_handle
                    && a.attribute_type == AttUuid::Uuid16(0x2800) // primary service
                    && group_type == AttUuid::Uuid16(0x2800)
            })
            .collect();

        if svc_attrs.is_empty() {
            return self.error_response(
                AttOpcode::ReadByGroupTypeRequest,
                starting_handle,
                AttErrorCode::AttributeNotFound,
            );
        }

        // Each element: handle (2) + end_group_handle (2) + value (variable)
        let element_size = 4 + group_type.size();
        let mut attribute_data_list = Vec::<u8, 512>::new();
        for svc in svc_attrs {
            attribute_data_list
                .extend_from_slice(&svc.handle.0.to_le_bytes())
                .map_err(|_| AttError::ValueTooLong)?;

            // The end group handle is stored in the service value (first 2 bytes)
            let end_group = if svc.value.len() >= 2 {
                u16::from_le_bytes([svc.value.as_slice()[0], svc.value.as_slice()[1]])
            } else {
                svc.handle.0
            };
            attribute_data_list
                .extend_from_slice(&end_group.to_le_bytes())
                .map_err(|_| AttError::ValueTooLong)?;

            // The UUID is stored in the service value after the end group handle
            match group_type {
                AttUuid::Uuid16(_) => {
                    if svc.value.len() >= 4 {
                        attribute_data_list
                            .extend_from_slice(&svc.value.as_slice()[2..4])
                            .map_err(|_| AttError::ValueTooLong)?;
                    }
                }
                AttUuid::Uuid128(_) => {
                    if svc.value.len() >= 18 {
                        let mut uuid_bytes = [0u8; 16];
                        uuid_bytes.copy_from_slice(&svc.value.as_slice()[2..18]);
                        attribute_data_list
                            .extend_from_slice(&uuid_bytes)
                            .map_err(|_| AttError::ValueTooLong)?;
                    }
                }
            }
        }

        Ok(AttPdu::ReadByGroupTypeResponse {
            length: element_size as u8,
            attribute_data_list,
        })
    }

    fn handle_read_by_type(
        &self,
        starting_handle: AttHandle,
        ending_handle: AttHandle,
        attribute_type: AttUuid,
    ) -> Result<AttPdu, AttError> {
        // Find all attributes in range with matching type
        let attrs: Vec<&Attribute, 32> = self
            .attributes
            .iter()
            .filter(|a| {
                a.handle >= starting_handle
                    && a.handle <= ending_handle
                    && a.attribute_type == attribute_type
            })
            .collect();

        if attrs.is_empty() {
            return self.error_response(
                AttOpcode::ReadByTypeRequest,
                starting_handle,
                AttErrorCode::AttributeNotFound,
            );
        }

        // Each element: handle (2) + value (variable)
        // For characteristic declarations, the value is properties+value_handle+uuid
        let element_size = 2 + attrs[0].value.len().min(255);
        let element_size = element_size as u8;

        let mut attribute_data_list = Vec::<u8, 512>::new();
        for attr in attrs {
            attribute_data_list
                .extend_from_slice(&attr.handle.0.to_le_bytes())
                .map_err(|_| AttError::ValueTooLong)?;
            let val = attr.value.as_slice();
            let take = val.len().min(255usize);
            attribute_data_list
                .extend_from_slice(&val[..take])
                .map_err(|_| AttError::ValueTooLong)?;
        }

        Ok(AttPdu::ReadByTypeResponse {
            length: element_size,
            attribute_data_list,
        })
    }

    fn handle_read(
        &self,
        handle: AttHandle,
        offset: u16,
    ) -> Result<AttPdu, AttError> {
        let attr = self
            .find_attribute(handle)
            .ok_or_else(|| AttError::InvalidHandle)?;

        if !attr.permissions.read {
            return self.error_response(
                AttOpcode::ReadRequest,
                handle,
                AttErrorCode::ReadNotPermitted,
            );
        }

        let val = attr.value.as_slice();
        let offset = offset as usize;

        if offset == 0 {
            // Full read
            Ok(AttPdu::ReadResponse {
                attribute_value: attr.value.clone(),
            })
        } else if offset < val.len() {
            // Read Blob
            let blob = AttValue::new(&val[offset..])?;
            Ok(AttPdu::ReadBlobResponse {
                part_attribute_value: blob,
            })
        } else {
            self.error_response(
                AttOpcode::ReadBlobRequest,
                handle,
                AttErrorCode::InvalidOffset,
            )
        }
    }

    fn handle_write(
        &mut self,
        handle: AttHandle,
        value: &AttValue,
        with_response: bool,
    ) -> Result<AttPdu, AttError> {
        let attr = self
            .find_attribute(handle)
            .ok_or_else(|| AttError::InvalidHandle)?;

        // Check if this is a CCCD write
        if attr.attribute_type == AttUuid::Uuid16(CLIENT_CHAR_CONFIG_UUID) {
            self.update_cccd(handle, value.as_slice())?;
            // Also update the attribute value so reads reflect the current state
            if let Some(attr_mut) = self.find_attribute_mut(handle) {
                attr_mut.value = value.clone();
            }
            if with_response {
                return Ok(AttPdu::WriteResponse);
            } else {
                return Err(AttError::InvalidPdu); // Write command doesn't get a response
            }
        }

        let allowed = if with_response {
            attr.permissions.write
        } else {
            attr.permissions.write_without_response
        };

        if !allowed {
            return self.error_response(
                if with_response {
                    AttOpcode::WriteRequest
                } else {
                    AttOpcode::WriteCommand
                },
                handle,
                AttErrorCode::WriteNotPermitted,
            );
        }

        // Note: the actual write is done by the caller after this returns,
        // since we only have &self. The application calls set_value() separately.
        if with_response {
            Ok(AttPdu::WriteResponse)
        } else {
            // Write Command doesn't get a response
            Err(AttError::InvalidPdu)
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────

    fn error_response(
        &self,
        request_opcode: AttOpcode,
        attribute_handle: AttHandle,
        error_code: AttErrorCode,
    ) -> Result<AttPdu, AttError> {
        Ok(AttPdu::ErrorResponse {
            request_opcode,
            attribute_handle,
            error_code,
        })
    }
}

impl Default for GattServer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Service builder ─────────────────────────────────────────────────────

/// A prepared GATT service definition ready to be added to a [`GattServer`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GattServiceDef {
    /// Whether this is a primary service.
    pub is_primary: bool,
    /// The service UUID.
    pub uuid: AttUuid,
    /// Characteristics in this service.
    pub characteristics: Vec<GattCharacteristicDef, 16>,
}

impl GattServiceDef {
    fn handle_count(&self) -> usize {
        1 + self
            .characteristics
            .iter()
            .map(|c| 2 + c.descriptors.len())
            .sum::<usize>()
    }

    fn uuid_bytes(&self) -> Vec<u8, 16> {
        let mut bytes = Vec::new();
        match self.uuid {
            AttUuid::Uuid16(v) => {
                let _ = bytes.extend_from_slice(&v.to_le_bytes());
            }
            AttUuid::Uuid128(v) => {
                let _ = bytes.extend_from_slice(&v.to_le_bytes());
            }
        }
        bytes
    }
}

/// A prepared characteristic definition.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GattCharacteristicDef {
    /// The characteristic UUID.
    pub uuid: AttUuid,
    /// Access permissions for the characteristic value.
    pub permissions: AttributePermissions,
    /// Initial value of the characteristic.
    pub value: AttValue,
    /// Descriptors for this characteristic.
    pub descriptors: Vec<GattDescriptorDef, 8>,
}

impl GattCharacteristicDef {
    fn properties(&self) -> u8 {
        let mut props = 0u8;
        if self.permissions.read {
            props |= 0x02;
        }
        if self.permissions.write || self.permissions.write_without_response {
            props |= 0x08; // Write
            if !self.permissions.write {
                props |= 0x04; // Write Without Response
            }
        }
        if self.permissions.notify {
            props |= 0x10;
        }
        if self.permissions.indicate {
            props |= 0x20;
        }
        props
    }

    fn uuid_bytes(&self) -> Vec<u8, 16> {
        let mut bytes = Vec::new();
        match self.uuid {
            AttUuid::Uuid16(v) => {
                let _ = bytes.extend_from_slice(&v.to_le_bytes());
            }
            AttUuid::Uuid128(v) => {
                let _ = bytes.extend_from_slice(&v.to_le_bytes());
            }
        }
        bytes
    }
}

/// A prepared descriptor definition.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GattDescriptorDef {
    /// The descriptor UUID.
    pub uuid: AttUuid,
    /// Access permissions.
    pub permissions: AttributePermissions,
    /// Initial value.
    pub value: AttValue,
}

// ─── Builders ───────────────────────────────────────────────────────────

/// Builder for constructing a [`GattServiceDef`].
pub struct GattServiceBuilder {
    is_primary: bool,
    uuid: AttUuid,
    characteristics: Vec<GattCharacteristicDef, 16>,
}

impl GattServiceBuilder {
    /// Start building a new primary service.
    pub fn new(uuid: AttUuid) -> Self {
        Self {
            is_primary: true,
            uuid,
            characteristics: Vec::new(),
        }
    }

    /// Mark this as a secondary service.
    pub fn secondary(mut self) -> Self {
        self.is_primary = false;
        self
    }

    /// Add a characteristic to this service.
    pub fn add_characteristic(mut self, characteristic: GattCharacteristicDef) -> Self {
        let _ = self.characteristics.push(characteristic);
        self
    }

    /// Build the service definition.
    pub fn build(self) -> GattServiceDef {
        GattServiceDef {
            is_primary: self.is_primary,
            uuid: self.uuid,
            characteristics: self.characteristics,
        }
    }
}

/// Builder for constructing a [`GattCharacteristicDef`].
pub struct GattCharacteristicBuilder {
    uuid: AttUuid,
    permissions: AttributePermissions,
    value: AttValue,
    descriptors: Vec<GattDescriptorDef, 8>,
}

impl GattCharacteristicBuilder {
    /// Start building a new characteristic.
    pub fn new(uuid: AttUuid) -> Self {
        Self {
            uuid,
            permissions: AttributePermissions::default(),
            value: AttValue::new(&[]).unwrap(),
            descriptors: Vec::new(),
        }
    }

    /// Make the characteristic readable.
    pub fn readable(mut self) -> Self {
        self.permissions.read = true;
        self
    }

    /// Make the characteristic writable (with response).
    pub fn writable(mut self) -> Self {
        self.permissions.write = true;
        self
    }

    /// Make the characteristic writable without response.
    pub fn writable_without_response(mut self) -> Self {
        self.permissions.write_without_response = true;
        self
    }

    /// Enable notifications.
    pub fn notifiable(mut self) -> Self {
        self.permissions.notify = true;
        self
    }

    /// Enable indications.
    pub fn indicatable(mut self) -> Self {
        self.permissions.indicate = true;
        self
    }

    /// Set the initial value.
    pub fn value(mut self, value: &[u8]) -> Result<Self, AttError> {
        self.value = AttValue::new(value)?;
        Ok(self)
    }

    /// Add a descriptor to this characteristic.
    pub fn add_descriptor(mut self, descriptor: GattDescriptorDef) -> Self {
        let _ = self.descriptors.push(descriptor);
        self
    }

    /// Build the characteristic definition.
    pub fn build(self) -> GattCharacteristicDef {
        GattCharacteristicDef {
            uuid: self.uuid,
            permissions: self.permissions,
            value: self.value,
            descriptors: self.descriptors,
        }
    }
}

/// Builder for constructing a [`GattDescriptorDef`].
pub struct GattDescriptorBuilder {
    uuid: AttUuid,
    permissions: AttributePermissions,
    value: AttValue,
}

impl GattDescriptorBuilder {
    /// Start building a new descriptor.
    pub fn new(uuid: AttUuid) -> Self {
        Self {
            uuid,
            permissions: AttributePermissions::default(),
            value: AttValue::new(&[]).unwrap(),
        }
    }

    /// Make the descriptor readable.
    pub fn readable(mut self) -> Self {
        self.permissions.read = true;
        self
    }

    /// Make the descriptor writable.
    pub fn writable(mut self) -> Self {
        self.permissions.write = true;
        self
    }

    /// Set the initial value.
    pub fn value(mut self, value: &[u8]) -> Result<Self, AttError> {
        self.value = AttValue::new(value)?;
        Ok(self)
    }

    /// Build the descriptor definition.
    pub fn build(self) -> GattDescriptorDef {
        GattDescriptorDef {
            uuid: self.uuid,
            permissions: self.permissions,
            value: self.value,
        }
    }
}

// ─── Standard descriptor UUIDs ──────────────────────────────────────────

/// Characteristic Extended Properties descriptor UUID.
pub const CHAR_EXTENDED_PROPERTIES_UUID: u16 = 0x2900;
/// Characteristic User Description descriptor UUID.
pub const CHAR_USER_DESCRIPTION_UUID: u16 = 0x2901;
/// Client Characteristic Configuration descriptor UUID.
pub const CLIENT_CHAR_CONFIG_UUID: u16 = 0x2902;
/// Server Characteristic Configuration descriptor UUID.
pub const SERVER_CHAR_CONFIG_UUID: u16 = 0x2903;
/// Characteristic Presentation Format descriptor UUID.
pub const CHAR_PRESENTATION_FORMAT_UUID: u16 = 0x2904;

#[cfg(test)]
mod tests {
    use bletio_utils::{Buffer, BufferOps, EncodeToBuffer};

    use super::*;

    #[test]
    fn test_empty_server() {
        let mut server = GattServer::new();
        assert_eq!(server.attribute_count(), 0);
        assert!(server.find_attribute(AttHandle(1)).is_none());
    }

    #[test]
    fn test_add_single_service() {
        let mut server = GattServer::new();

        let svc = GattServiceBuilder::new(AttUuid::Uuid16(0x180A))
            .add_characteristic(
                GattCharacteristicBuilder::new(AttUuid::Uuid16(0x2A29))
                    .readable()
                    .value(b"bletio").unwrap()
                    .build(),
            )
            .build();

        server.add_service(svc).unwrap();

        // Service = 1 decl + 1 char decl + 1 char value = 3 attributes
        assert_eq!(server.attribute_count(), 3);
    }

    #[test]
    fn test_add_service_with_descriptors() {
        let mut server = GattServer::new();

        let svc = GattServiceBuilder::new(AttUuid::Uuid16(0x180A))
            .add_characteristic(
                GattCharacteristicBuilder::new(AttUuid::Uuid16(0x2A29))
                    .readable()
                    .value(b"bletio").unwrap()
                    .add_descriptor(
                        GattDescriptorBuilder::new(AttUuid::Uuid16(CLIENT_CHAR_CONFIG_UUID))
                            .readable()
                            .writable()
                            .value(&[0x00, 0x00]).unwrap()
                            .build(),
                    )
                    .build(),
            )
            .build();

        server.add_service(svc).unwrap();

        // Service = 1 decl + 1 char decl + 1 char value + 1 descriptor = 4
        assert_eq!(server.attribute_count(), 4);
    }

    #[test]
    fn test_set_and_get_value() {
        let mut server = GattServer::new();

        let svc = GattServiceBuilder::new(AttUuid::Uuid16(0x180F)) // Battery Service
            .add_characteristic(
                GattCharacteristicBuilder::new(AttUuid::Uuid16(0x2A19)) // Battery Level
                    .readable()
                    .notifiable()
                    .value(&[100u8]).unwrap()
                    .build(),
            )
            .build();

        server.add_service(svc).unwrap();

        // Characteristic value is at handle 3 (1=service, 2=char decl, 3=char value)
        let val = server.get_value(AttHandle(3));
        assert_eq!(val.unwrap().as_slice(), &[100u8]);

        server.set_value(AttHandle(3), &[85u8]).unwrap();
        let val = server.get_value(AttHandle(3));
        assert_eq!(val.unwrap().as_slice(), &[85u8]);
    }

    #[test]
    fn test_handle_exchange_mtu() {
        let mut server = GattServer::new();
        let req = AttPdu::ExchangeMtuRequest { client_rx_mtu: 256 };
        let resp = server.handle_request(&req).unwrap();
        assert_eq!(
            resp,
            AttPdu::ExchangeMtuResponse {
                server_rx_mtu: 256
            }
        );
    }

    #[test]
    fn test_handle_read_value() {
        let mut server = GattServer::new();

        let svc = GattServiceBuilder::new(AttUuid::Uuid16(0x180A))
            .add_characteristic(
                GattCharacteristicBuilder::new(AttUuid::Uuid16(0x2A29))
                    .readable()
                    .value(b"bletio").unwrap()
                    .build(),
            )
            .build();
        server.add_service(svc).unwrap();

        // Read the characteristic value at handle 3
        let req = AttPdu::ReadRequest {
            attribute_handle: AttHandle(3),
        };
        let resp = server.handle_request(&req).unwrap();

        match resp {
            AttPdu::ReadResponse { attribute_value } => {
                assert_eq!(attribute_value.as_slice(), b"bletio");
            }
            _ => panic!("Expected ReadResponse, got {:?}", resp),
        }
    }

    #[test]
    fn test_handle_read_not_permitted() {
        let mut server = GattServer::new();

        let svc = GattServiceBuilder::new(AttUuid::Uuid16(0x180A))
            .add_characteristic(
                GattCharacteristicBuilder::new(AttUuid::Uuid16(0x2A29))
                    // NOT readable
                    .value(b"secret").unwrap()
                    .build(),
            )
            .build();
        server.add_service(svc).unwrap();

        let req = AttPdu::ReadRequest {
            attribute_handle: AttHandle(3),
        };
        let resp = server.handle_request(&req).unwrap();

        match resp {
            AttPdu::ErrorResponse { error_code, .. } => {
                assert_eq!(error_code, AttErrorCode::ReadNotPermitted);
            }
            _ => panic!("Expected ErrorResponse, got {:?}", resp),
        }
    }

    #[test]
    fn test_handle_write() {
        let mut server = GattServer::new();

        let svc = GattServiceBuilder::new(AttUuid::Uuid16(0x180A))
            .add_characteristic(
                GattCharacteristicBuilder::new(AttUuid::Uuid16(0x2A00))
                    .writable()
                    .value(&[0u8; 4]).unwrap()
                    .build(),
            )
            .build();
        server.add_service(svc).unwrap();

        let req = AttPdu::WriteRequest {
            attribute_handle: AttHandle(3),
            attribute_value: AttValue::new(&[1u8, 2, 3, 4]).unwrap(),
        };
        let resp = server.handle_request(&req).unwrap();

        assert_eq!(resp, AttPdu::WriteResponse);

        // Apply the write
        server.set_value(AttHandle(3), &[1u8, 2, 3, 4]).unwrap();
        assert_eq!(server.get_value(AttHandle(3)).unwrap().as_slice(), &[1u8, 2, 3, 4]);
    }

    #[test]
    fn test_discover_primary_services() {
        let mut server = GattServer::new();

        let svc = GattServiceBuilder::new(AttUuid::Uuid16(0x180A))
            .add_characteristic(
                GattCharacteristicBuilder::new(AttUuid::Uuid16(0x2A29))
                    .readable()
                    .value(b"test").unwrap()
                    .build(),
            )
            .build();
        server.add_service(svc).unwrap();

        let req = AttPdu::ReadByGroupTypeRequest {
            starting_handle: AttHandle(1),
            ending_handle: AttHandle(0xFFFF),
            attribute_group_type: AttUuid::Uuid16(0x2800),
        };
        let resp = server.handle_request(&req).unwrap();

        match resp {
            AttPdu::ReadByGroupTypeResponse {
                length,
                attribute_data_list,
            } => {
                assert_eq!(length, 6); // 2+2+2 for 16-bit UUID
                assert!(!attribute_data_list.is_empty());
            }
            _ => panic!("Expected ReadByGroupTypeResponse, got {:?}", resp),
        }
    }

    #[test]
    fn test_discover_characteristics() {
        let mut server = GattServer::new();

        let svc = GattServiceBuilder::new(AttUuid::Uuid16(0x180A))
            .add_characteristic(
                GattCharacteristicBuilder::new(AttUuid::Uuid16(0x2A29))
                    .readable()
                    .value(b"test").unwrap()
                    .build(),
            )
            .build();
        server.add_service(svc).unwrap();

        let req = AttPdu::ReadByTypeRequest {
            starting_handle: AttHandle(1),
            ending_handle: AttHandle(0xFFFF),
            attribute_type: AttUuid::Uuid16(0x2803), // Characteristic declaration
        };
        let resp = server.handle_request(&req).unwrap();

        match resp {
            AttPdu::ReadByTypeResponse { .. } => {
                // Should find the characteristic declaration
            }
            _ => panic!("Expected ReadByTypeResponse, got {:?}", resp),
        }
    }

    #[test]
    fn test_write_command_does_not_return_response() {
        let mut server = GattServer::new();

        let svc = GattServiceBuilder::new(AttUuid::Uuid16(0x180A))
            .add_characteristic(
                GattCharacteristicBuilder::new(AttUuid::Uuid16(0x2A00))
                    .writable_without_response()
                    .value(&[0u8]).unwrap()
                    .build(),
            )
            .build();
        server.add_service(svc).unwrap();

        let req = AttPdu::WriteCommand {
            attribute_handle: AttHandle(3),
            attribute_value: AttValue::new(&[1u8]).unwrap(),
        };
        let result = server.handle_request(&req);

        // Write Command returns Err (no response expected)
        assert!(result.is_err());
    }

    #[test]
    fn test_cccd_write_enables_notifications() {
        let mut server = GattServer::new();

        let svc = GattServiceBuilder::new(AttUuid::Uuid16(0x180F))
            .add_characteristic(
                GattCharacteristicBuilder::new(AttUuid::Uuid16(0x2A19))
                    .readable()
                    .notifiable()
                    .value(&[100u8]).unwrap()
                    .add_descriptor(
                        GattDescriptorBuilder::new(AttUuid::Uuid16(CLIENT_CHAR_CONFIG_UUID))
                            .readable()
                            .writable()
                            .value(&[0x00, 0x00]).unwrap()
                            .build(),
                    )
                    .build(),
            )
            .build();
        server.add_service(svc).unwrap();

        // CCCD is at handle 4 (svc=1, char_decl=2, char_value=3, cccd=4)
        assert!(!server.is_notify_enabled(AttHandle(3)));
        assert!(!server.is_indicate_enabled(AttHandle(3)));

        // Write 0x0001 to CCCD → enable notifications
        let req = AttPdu::WriteRequest {
            attribute_handle: AttHandle(4),
            attribute_value: AttValue::new(&[0x01, 0x00]).unwrap(),
        };
        let resp = server.handle_request(&req).unwrap();
        assert_eq!(resp, AttPdu::WriteResponse);

        assert!(server.is_notify_enabled(AttHandle(3)));
        assert!(!server.is_indicate_enabled(AttHandle(3)));

        // Write 0x0002 to CCCD → enable indications
        let req = AttPdu::WriteRequest {
            attribute_handle: AttHandle(4),
            attribute_value: AttValue::new(&[0x02, 0x00]).unwrap(),
        };
        server.handle_request(&req).unwrap();
        assert!(!server.is_notify_enabled(AttHandle(3)));
        assert!(server.is_indicate_enabled(AttHandle(3)));
    }

    #[test]
    fn test_cccd_read_reflects_state() {
        let mut server = GattServer::new();

        let svc = GattServiceBuilder::new(AttUuid::Uuid16(0x180F))
            .add_characteristic(
                GattCharacteristicBuilder::new(AttUuid::Uuid16(0x2A19))
                    .notifiable()
                    .value(&[100u8]).unwrap()
                    .add_descriptor(
                        GattDescriptorBuilder::new(AttUuid::Uuid16(CLIENT_CHAR_CONFIG_UUID))
                            .readable()
                            .writable()
                            .value(&[0x00, 0x00]).unwrap()
                            .build(),
                    )
                    .build(),
            )
            .build();
        server.add_service(svc).unwrap();

        // Write notifications enabled
        server.handle_request(&AttPdu::WriteRequest {
            attribute_handle: AttHandle(4),
            attribute_value: AttValue::new(&[0x01, 0x00]).unwrap(),
        }).unwrap();

        // Read back the CCCD value
        let resp = server.handle_request(&AttPdu::ReadRequest {
            attribute_handle: AttHandle(4),
        }).unwrap();
        match resp {
            AttPdu::ReadResponse { attribute_value } => {
                assert_eq!(attribute_value.as_slice(), &[0x01, 0x00]);
            }
            _ => panic!("Expected ReadResponse"),
        }
    }
}
