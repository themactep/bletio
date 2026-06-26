//! GATT client for service, characteristic, and descriptor discovery.
//!
//! Implements Generic Attribute Profile discovery procedures per
//! [Core Specification 6.0, Vol. 3, Part G](https://www.bluetooth.com/specifications/specs/core-specification-6-0/).

use bletio_utils::{Buffer, EncodeToBuffer};

use super::att_client::{AttClient, EncodedAttPdu};
use super::att_pdu::{AttError, AttHandle, AttOpcode, AttPdu, AttUuid, AttValue};

/// UUID for the Primary Service declaration (0x2800).
const PRIMARY_SERVICE_UUID: u16 = 0x2800;

/// UUID for the Secondary Service declaration (0x2801).
const SECONDARY_SERVICE_UUID: u16 = 0x2801;

/// UUID for the Include declaration (0x2802).
const INCLUDE_UUID: u16 = 0x2802;

/// UUID for the Characteristic declaration (0x2803).
const CHARACTERISTIC_UUID: u16 = 0x2803;

// ─── Data types ─────────────────────────────────────────────────────────

/// A discovered GATT service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GattService {
    /// Start handle of the service (inclusive).
    pub start_handle: AttHandle,
    /// End handle of the service (inclusive).
    pub end_handle: AttHandle,
    /// Service UUID (16-bit or 128-bit).
    pub uuid: AttUuid,
    /// Whether this is a primary service.
    pub is_primary: bool,
}

/// A discovered GATT characteristic.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GattCharacteristic {
    /// Handle of the characteristic declaration.
    pub declaration_handle: AttHandle,
    /// Characteristic properties bitfield.
    pub properties: u8,
    /// Handle of the characteristic value.
    pub value_handle: AttHandle,
    /// Characteristic UUID.
    pub uuid: AttUuid,
}

/// A discovered GATT characteristic descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GattDescriptor {
    /// Handle of the descriptor.
    pub handle: AttHandle,
    /// Descriptor UUID.
    pub uuid: AttUuid,
}

// ─── GATT Client ────────────────────────────────────────────────────────

/// GATT client state for discovery procedures.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum GattState {
    Idle,
    DiscoveringServices {
        start: AttHandle,
        end: AttHandle,
        services: heapless::Vec<GattService, 16>,
        /// Next handle to continue from (None = first request).
        next_start: Option<AttHandle>,
    },
    DiscoveringCharacteristics {
        service_start: AttHandle,
        service_end: AttHandle,
        characteristics: heapless::Vec<GattCharacteristic, 32>,
        next_start: Option<AttHandle>,
    },
    DiscoveringDescriptors {
        char_start: AttHandle,
        char_end: AttHandle,
        descriptors: heapless::Vec<GattDescriptor, 32>,
        next_start: Option<AttHandle>,
    },
    /// Awaiting a Read Response for a characteristic or descriptor.
    ReadingValue { handle: AttHandle },
    /// Awaiting a Write Response acknowledgment.
    WritingValue { handle: AttHandle },
    /// Awaiting a Handle Value Confirmation after sending an indication response.
    AwaitingIndicationConfirmation,
}

/// Events produced by the GATT client during discovery and read/write operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GattEvent {
    /// A list of discovered primary services.
    ServicesDiscovered(heapless::Vec<GattService, 16>),
    /// A list of discovered characteristics for a service.
    CharacteristicsDiscovered(heapless::Vec<GattCharacteristic, 32>),
    /// A list of discovered descriptors for a characteristic.
    DescriptorsDiscovered(heapless::Vec<GattDescriptor, 32>),
    /// A characteristic or descriptor value was read.
    ValueRead {
        handle: AttHandle,
        value: AttValue,
    },
    /// A characteristic value was written (acknowledged by server).
    ValueWritten {
        handle: AttHandle,
    },
    /// A notification was received from the server.
    Notification {
        handle: AttHandle,
        value: AttValue,
    },
    /// An indication was received from the server and confirmation was sent.
    Indication {
        handle: AttHandle,
        value: AttValue,
    },
}

/// GATT client for service discovery, characteristic read/write, and notifications.
///
/// Built on top of [`AttClient`], this provides high-level GATT operations:
///
/// - **Service discovery**: [`discover_all_primary_services`](Self::discover_all_primary_services)
/// - **Characteristic discovery**: [`discover_characteristics`](Self::discover_characteristics)
/// - **Descriptor discovery**: [`discover_descriptors`](Self::discover_descriptors)
/// - **Read**: [`read_value`](Self::read_value), [`read_blob`](Self::read_blob)
/// - **Write**: [`write_value`](Self::write_value), [`write_value_without_response`](Self::write_value_without_response)
/// - **Notifications/Indications**: received via [`feed`](Self::feed) as [`GattEvent`]
///
/// Multi-response discovery uses [`continue_request`](Self::continue_request) for continuation.
///
/// See the [GATT client demo](https://github.com/themactep/bletio/blob/main/bletio-host/examples/gatt_client_demo.rs)
/// for a complete example.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GattClient {
    att: AttClient,
    state: GattState,
}

impl GattClient {
    /// Create a new GATT client.
    pub fn new() -> Self {
        Self {
            att: AttClient::new(),
            state: GattState::Idle,
        }
    }

    /// Returns a reference to the underlying ATT client.
    pub fn att(&self) -> &AttClient {
        &self.att
    }

    /// Returns a mutable reference to the underlying ATT client.
    pub fn att_mut(&mut self) -> &mut AttClient {
        &mut self.att
    }

    /// Returns true if no discovery procedure is in progress.
    pub fn is_idle(&self) -> bool {
        self.state == GattState::Idle
    }

    // ── Discovery procedures ───────────────────────────────────────────

    /// Begin primary service discovery. Returns the first Read By Group Type
    /// request PDU to send. Feed the response via `feed()`.
    pub fn discover_all_primary_services(
        &mut self,
        start: AttHandle,
        end: AttHandle,
    ) -> Result<EncodedAttPdu, AttError> {
        self.state = GattState::DiscoveringServices {
            start,
            end,
            services: heapless::Vec::new(),
            next_start: None,
        };
        // First request starts at `start`
        self.att.prepare_read_by_group_type(start, end, AttUuid::Uuid16(PRIMARY_SERVICE_UUID))
    }

    /// Begin characteristic discovery for a service range.
    pub fn discover_characteristics(
        &mut self,
        service_start: AttHandle,
        service_end: AttHandle,
    ) -> Result<EncodedAttPdu, AttError> {
        self.state = GattState::DiscoveringCharacteristics {
            service_start,
            service_end,
            characteristics: heapless::Vec::new(),
            next_start: None,
        };
        self.att.prepare_read_by_type(
            service_start,
            service_end,
            AttUuid::Uuid16(CHARACTERISTIC_UUID),
        )
    }

    /// Begin descriptor discovery for a characteristic.
    /// `char_value_handle` is the characteristic value handle;
    /// descriptors are discovered from `char_value_handle + 1` to the
    /// end of the service or the next characteristic.
    pub fn discover_descriptors(
        &mut self,
        char_value_handle: AttHandle,
        end_handle: AttHandle,
    ) -> Result<EncodedAttPdu, AttError> {
        let start = AttHandle(char_value_handle.0 + 1);
        if start.0 > end_handle.0 {
            // No space for descriptors
            return Err(AttError::InvalidHandle);
        }
        self.state = GattState::DiscoveringDescriptors {
            char_start: start,
            char_end: end_handle,
            descriptors: heapless::Vec::new(),
            next_start: None,
        };
        self.att
            .prepare_find_information(start, end_handle)
    }

    // ── Response feeding ────────────────────────────────────────────────

    /// Feed an ATT PDU (parsed from ACL data) into the GATT client.
    /// Returns `Ok(Some(event))` when a discovery completes, `Ok(None)` when
    /// the client needs more data (continuation), or `Err` on protocol errors.
    pub fn feed(&mut self, data: &[u8]) -> Result<Option<GattEvent>, AttError> {
        let response = self.att.receive(data)?;

        let response = match response {
            Some(pdu) => pdu,
            None => return Ok(None),
        };

        // Attribute Not Found terminates any discovery procedure.
        if matches!(
            &response,
            AttPdu::ErrorResponse {
                error_code: super::att_pdu::AttErrorCode::AttributeNotFound,
                ..
            }
        ) {
            let event = match &self.state {
                GattState::DiscoveringServices { services, .. } => {
                    Some(GattEvent::ServicesDiscovered(services.clone()))
                }
                GattState::DiscoveringCharacteristics { characteristics, .. } => {
                    Some(GattEvent::CharacteristicsDiscovered(characteristics.clone()))
                }
                GattState::DiscoveringDescriptors { descriptors, .. } => {
                    Some(GattEvent::DescriptorsDiscovered(descriptors.clone()))
                }
                GattState::Idle
                | GattState::ReadingValue { .. }
                | GattState::WritingValue { .. }
                | GattState::AwaitingIndicationConfirmation => None,
            };
            self.state = GattState::Idle;
            return Ok(event);
        }

        match &self.state {
            GattState::Idle => match response {
                AttPdu::HandleValueNotification {
                    attribute_handle,
                    attribute_value,
                } => Ok(Some(GattEvent::Notification {
                    handle: attribute_handle,
                    value: attribute_value,
                })),
                AttPdu::HandleValueIndication {
                    attribute_handle,
                    attribute_value,
                } => {
                    self.state = GattState::AwaitingIndicationConfirmation;
                    Ok(Some(GattEvent::Indication {
                        handle: attribute_handle,
                        value: attribute_value,
                    }))
                }
                _ => Ok(None),
            },
            GattState::DiscoveringServices {
                start,
                end,
                services,
                next_start,
            } => {
                let (last_handle, new_services) = parse_service_response(&response)?;
                let mut svcs = services.clone();
                svcs.extend(new_services);

                if last_handle < end.0 && self.att.is_ready() {
                    // More services to discover — continue
                    let next = AttHandle(last_handle + 1);
                    self.state = GattState::DiscoveringServices {
                        start: *start,
                        end: *end,
                        services: svcs,
                        next_start: Some(next),
                    };
                    // The caller needs to send the continuation request
                    // We signal this by returning None but the caller must check
                    // att.is_ready() to know to continue.
                    // Actually, we should provide the next PDU here.
                    Ok(None)
                } else {
                    // Done discovering services
                    self.state = GattState::Idle;
                    Ok(Some(GattEvent::ServicesDiscovered(svcs)))
                }
            }
            GattState::DiscoveringCharacteristics {
                service_start,
                service_end,
                characteristics,
                next_start,
            } => {
                let (last_handle, new_chars) = parse_characteristic_response(&response)?;
                let mut chars = characteristics.clone();
                chars.extend(new_chars);

                if last_handle < service_end.0 && self.att.is_ready() {
                    let next = AttHandle(last_handle + 1);
                    self.state = GattState::DiscoveringCharacteristics {
                        service_start: *service_start,
                        service_end: *service_end,
                        characteristics: chars,
                        next_start: Some(next),
                    };
                    Ok(None)
                } else {
                    self.state = GattState::Idle;
                    Ok(Some(GattEvent::CharacteristicsDiscovered(chars)))
                }
            }
            GattState::DiscoveringDescriptors {
                char_start,
                char_end,
                descriptors,
                next_start,
            } => {
                let (last_handle, new_descs) = parse_descriptor_response(&response)?;
                let mut descs = descriptors.clone();
                descs.extend(new_descs);

                if last_handle < char_end.0 && self.att.is_ready() {
                    let next = AttHandle(last_handle + 1);
                    self.state = GattState::DiscoveringDescriptors {
                        char_start: *char_start,
                        char_end: *char_end,
                        descriptors: descs,
                        next_start: Some(next),
                    };
                    Ok(None)
                } else {
                    self.state = GattState::Idle;
                    Ok(Some(GattEvent::DescriptorsDiscovered(descs)))
                }
            }
            GattState::ReadingValue { handle } => {
                let (new_state, result) = match response {
                    AttPdu::ReadResponse { attribute_value } => {
                        (GattState::Idle, Ok(Some(GattEvent::ValueRead {
                            handle: *handle,
                            value: attribute_value,
                        })))
                    }
                    AttPdu::ReadBlobResponse {
                        part_attribute_value,
                    } => {
                        (GattState::Idle, Ok(Some(GattEvent::ValueRead {
                            handle: *handle,
                            value: part_attribute_value,
                        })))
                    }
                    AttPdu::ErrorResponse { .. } => {
                        (GattState::Idle, Err(AttError::UnexpectedPdu {
                            expected: AttOpcode::ReadResponse as u8,
                            received: AttOpcode::ErrorResponse as u8,
                        }))
                    }
                    _ => {
                        (GattState::Idle, Err(AttError::UnexpectedPdu {
                            expected: AttOpcode::ReadResponse as u8,
                            received: response.opcode() as u8,
                        }))
                    }
                };
                self.state = new_state;
                result
            }
            GattState::WritingValue { handle } => {
                let (new_state, result) = match response {
                    AttPdu::WriteResponse => {
                        (GattState::Idle, Ok(Some(GattEvent::ValueWritten {
                            handle: *handle,
                        })))
                    }
                    AttPdu::ErrorResponse { .. } => {
                        (GattState::Idle, Err(AttError::UnexpectedPdu {
                            expected: AttOpcode::WriteResponse as u8,
                            received: AttOpcode::ErrorResponse as u8,
                        }))
                    }
                    _ => {
                        (GattState::Idle, Err(AttError::UnexpectedPdu {
                            expected: AttOpcode::WriteResponse as u8,
                            received: response.opcode() as u8,
                        }))
                    }
                };
                self.state = new_state;
                result
            }
            GattState::AwaitingIndicationConfirmation => {
                let result = match response {
                    AttPdu::HandleValueConfirmation => {
                        self.state = GattState::Idle;
                        Ok(None)
                    }
                    AttPdu::HandleValueIndication {
                        attribute_handle,
                        attribute_value,
                    } => Ok(Some(GattEvent::Indication {
                        handle: attribute_handle,
                        value: attribute_value,
                    })),
                    AttPdu::HandleValueNotification {
                        attribute_handle,
                        attribute_value,
                    } => Ok(Some(GattEvent::Notification {
                        handle: attribute_handle,
                        value: attribute_value,
                    })),
                    _ => Ok(None),
                };
                result
            }
        }
    }

    /// After `feed()` returns `Ok(None)` and `self.att().is_ready()`, call this
    /// to get the next continuation request PDU. Returns `None` if no continuation
    /// is needed.
    pub fn continue_request(&mut self) -> Option<EncodedAttPdu> {
        if !self.att.is_ready() {
            return None;
        }
        match &self.state {
            GattState::DiscoveringServices {
                start: _,
                end,
                services: _,
                next_start,
            } => {
                let next = (*next_start)?;
                self.att
                    .prepare_read_by_group_type(next, *end, AttUuid::Uuid16(PRIMARY_SERVICE_UUID))
                    .ok()
            }
            GattState::DiscoveringCharacteristics {
                service_start: _,
                service_end,
                characteristics: _,
                next_start,
            } => {
                let next = (*next_start)?;
                self.att
                    .prepare_read_by_type(next, *service_end, AttUuid::Uuid16(CHARACTERISTIC_UUID))
                    .ok()
            }
            GattState::DiscoveringDescriptors {
                char_start: _,
                char_end,
                descriptors: _,
                next_start,
            } => {
                let next = (*next_start)?;
                self.att
                    .prepare_find_information(next, *char_end)
                    .ok()
            }
            GattState::ReadingValue { .. }
            | GattState::WritingValue { .. }
            | GattState::AwaitingIndicationConfirmation
            | GattState::Idle => None,
        }
    }

    // ── Read / Write operations ───────────────────────────────────────

    /// Prepare a read request for a characteristic value or descriptor.
    /// Returns the encoded PDU to send over ACL.
    pub fn read_value(&mut self, handle: AttHandle) -> Result<EncodedAttPdu, AttError> {
        if !self.is_idle() {
            return Err(AttError::Timeout);
        }
        let encoded = self.att.prepare_read(handle)?;
        self.state = GattState::ReadingValue { handle };
        Ok(encoded)
    }

    /// Prepare a read blob request (long value continuation).
    pub fn read_blob(
        &mut self,
        handle: AttHandle,
        offset: u16,
    ) -> Result<EncodedAttPdu, AttError> {
        if !self.is_idle() {
            return Err(AttError::Timeout);
        }
        let encoded = self.att.prepare_read_blob(handle, offset)?;
        self.state = GattState::ReadingValue { handle };
        Ok(encoded)
    }

    /// Prepare a write request (with acknowledgment).
    pub fn write_value(
        &mut self,
        handle: AttHandle,
        value: &[u8],
    ) -> Result<EncodedAttPdu, AttError> {
        if !self.is_idle() {
            return Err(AttError::Timeout);
        }
        let encoded = self.att.prepare_write_request(handle, value)?;
        self.state = GattState::WritingValue { handle };
        Ok(encoded)
    }

    /// Prepare a write command (no acknowledgment, no state change).
    pub fn write_value_without_response(
        &self,
        handle: AttHandle,
        value: &[u8],
    ) -> Result<EncodedAttPdu, AttError> {
        self.att.prepare_write_command(handle, value)
    }

    /// Send a Handle Value Confirmation in response to a received indication.
    pub fn send_confirmation(&mut self) -> Result<EncodedAttPdu, AttError> {
        let encoded = Self::encode_pdu_static(&AttPdu::HandleValueConfirmation)?;
        self.state = GattState::AwaitingIndicationConfirmation;
        Ok(encoded)
    }

    /// Prepare a notification to send (server-to-client, no acknowledgment).
    pub fn notify(
        &self,
        handle: AttHandle,
        value: &[u8],
    ) -> Result<EncodedAttPdu, AttError> {
        self.att.prepare_notification(handle, value)
    }

    /// Prepare an indication to send (server-to-client, awaits confirmation).
    pub fn indicate(
        &mut self,
        handle: AttHandle,
        value: &[u8],
    ) -> Result<EncodedAttPdu, AttError> {
        if !self.is_idle() {
            return Err(AttError::Timeout);
        }
        let encoded = self.att.prepare_indication(handle, value)?;
        self.state = GattState::AwaitingIndicationConfirmation;
        Ok(encoded)
    }

    /// Encode a static PDU (one without state changes).
    fn encode_pdu_static(pdu: &AttPdu) -> Result<EncodedAttPdu, AttError> {
        let mut buffer: Buffer<512> = Buffer::default();
        pdu.encode(&mut buffer)
            .map_err(|_| AttError::ValueTooLong)?;
        Ok(EncodedAttPdu::from_buffer(buffer, pdu.encoded_size()))
    }
}

impl Default for GattClient {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Response parsing helpers ────────────────────────────────────────────

/// Parse a Read By Group Type response for service discovery.
/// Returns the last handle seen and the list of discovered services.
fn parse_service_response(
    response: &AttPdu,
) -> Result<(u16, heapless::Vec<GattService, 16>), AttError> {
    match response {
        AttPdu::ReadByGroupTypeResponse {
            length,
            attribute_data_list,
        } => {
            let element_size = *length as usize;
            let data = attribute_data_list.as_slice();
            let mut services = heapless::Vec::new();
            let mut last_handle = 0u16;
            let mut offset = 0;

            while offset + element_size <= data.len() {
                let start_handle = u16::from_le_bytes([data[offset], data[offset + 1]]);
                let end_handle = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);

                let uuid = if element_size == 6 {
                    AttUuid::Uuid16(u16::from_le_bytes([data[offset + 4], data[offset + 5]]))
                } else if element_size == 20 {
                    let mut uuid_bytes = [0u8; 16];
                    uuid_bytes.copy_from_slice(&data[offset + 4..offset + 20]);
                    AttUuid::Uuid128(u128::from_le_bytes(uuid_bytes))
                } else {
                    return Err(AttError::InvalidPdu);
                };

                services
                    .push(GattService {
                        start_handle: AttHandle(start_handle),
                        end_handle: AttHandle(end_handle),
                        uuid,
                        is_primary: true, // Read By Group Type with 0x2800 = primary
                    })
                    .map_err(|_| AttError::ValueTooLong)?;

                last_handle = end_handle;
                offset += element_size;
            }

            Ok((last_handle, services))
        }
        AttPdu::ErrorResponse { error_code, .. } => {
            if *error_code == super::att_pdu::AttErrorCode::AttributeNotFound {
                // No more services — return empty
                Ok((0, heapless::Vec::new()))
            } else {
                Err(AttError::ErrorResponse {
                    request_opcode: AttOpcode::ReadByGroupTypeRequest as u8,
                    attribute_handle: AttHandle(0),
                    error_code: 0,
                })
            }
        }
        _ => Err(AttError::UnexpectedPdu {
            expected: AttOpcode::ReadByGroupTypeResponse as u8,
            received: response.opcode() as u8,
        }),
    }
}

/// Parse a Read By Type response for characteristic discovery.
fn parse_characteristic_response(
    response: &AttPdu,
) -> Result<(u16, heapless::Vec<GattCharacteristic, 32>), AttError> {
    match response {
        AttPdu::ReadByTypeResponse {
            length,
            attribute_data_list,
        } => {
            // Characteristic declaration: handle (2) + properties (1) + value_handle (2) + uuid (2 or 16)
            let element_size = *length as usize;
            let data = attribute_data_list.as_slice();
            let mut chars = heapless::Vec::new();
            let mut last_handle = 0u16;
            let mut offset = 0;

            while offset + element_size <= data.len() {
                let decl_handle = u16::from_le_bytes([data[offset], data[offset + 1]]);
                let properties = data[offset + 2];
                let value_handle = u16::from_le_bytes([data[offset + 3], data[offset + 4]]);

                let uuid = if element_size == 7 {
                    AttUuid::Uuid16(u16::from_le_bytes([data[offset + 5], data[offset + 6]]))
                } else if element_size == 21 {
                    let mut uuid_bytes = [0u8; 16];
                    uuid_bytes.copy_from_slice(&data[offset + 5..offset + 21]);
                    AttUuid::Uuid128(u128::from_le_bytes(uuid_bytes))
                } else {
                    return Err(AttError::InvalidPdu);
                };

                chars
                    .push(GattCharacteristic {
                        declaration_handle: AttHandle(decl_handle),
                        properties,
                        value_handle: AttHandle(value_handle),
                        uuid,
                    })
                    .map_err(|_| AttError::ValueTooLong)?;

                last_handle = decl_handle;
                offset += element_size;
            }

            Ok((last_handle, chars))
        }
        AttPdu::ErrorResponse { error_code, .. } => {
            if *error_code == super::att_pdu::AttErrorCode::AttributeNotFound {
                Ok((0, heapless::Vec::new()))
            } else {
                Err(AttError::ErrorResponse {
                    request_opcode: AttOpcode::ReadByTypeRequest as u8,
                    attribute_handle: AttHandle(0),
                    error_code: 0,
                })
            }
        }
        _ => Err(AttError::UnexpectedPdu {
            expected: AttOpcode::ReadByTypeResponse as u8,
            received: response.opcode() as u8,
        }),
    }
}

/// Parse a Find Information response for descriptor discovery.
fn parse_descriptor_response(
    response: &AttPdu,
) -> Result<(u16, heapless::Vec<GattDescriptor, 32>), AttError> {
    match response {
        AttPdu::FindInformationResponse {
            format,
            information_data,
        } => {
            let data = information_data.as_slice();
            let mut descriptors = heapless::Vec::new();
            let mut last_handle = 0u16;

            match format {
                0x01 => {
                    // 16-bit UUIDs: handle (2) + uuid (2) = 4 bytes per entry
                    let element_size = 4;
                    let mut offset = 0;
                    while offset + element_size <= data.len() {
                        let handle =
                            u16::from_le_bytes([data[offset], data[offset + 1]]);
                        let uuid =
                            AttUuid::Uuid16(u16::from_le_bytes([data[offset + 2], data[offset + 3]]));
                        descriptors
                            .push(GattDescriptor {
                                handle: AttHandle(handle),
                                uuid,
                            })
                            .map_err(|_| AttError::ValueTooLong)?;
                        last_handle = handle;
                        offset += element_size;
                    }
                }
                0x02 => {
                    // 128-bit UUIDs: handle (2) + uuid (16) = 18 bytes per entry
                    let element_size = 18;
                    let mut offset = 0;
                    while offset + element_size <= data.len() {
                        let handle =
                            u16::from_le_bytes([data[offset], data[offset + 1]]);
                        let mut uuid_bytes = [0u8; 16];
                        uuid_bytes.copy_from_slice(&data[offset + 2..offset + 18]);
                        let uuid = AttUuid::Uuid128(u128::from_le_bytes(uuid_bytes));
                        descriptors
                            .push(GattDescriptor {
                                handle: AttHandle(handle),
                                uuid,
                            })
                            .map_err(|_| AttError::ValueTooLong)?;
                        last_handle = handle;
                        offset += element_size;
                    }
                }
                _ => return Err(AttError::InvalidPdu),
            }

            Ok((last_handle, descriptors))
        }
        AttPdu::ErrorResponse { error_code, .. } => {
            if *error_code == super::att_pdu::AttErrorCode::AttributeNotFound {
                Ok((0, heapless::Vec::new()))
            } else {
                Err(AttError::ErrorResponse {
                    request_opcode: AttOpcode::FindInformationRequest as u8,
                    attribute_handle: AttHandle(0),
                    error_code: 0,
                })
            }
        }
        _ => Err(AttError::UnexpectedPdu {
            expected: AttOpcode::FindInformationResponse as u8,
            received: response.opcode() as u8,
        }),
    }
}

#[cfg(test)]
mod tests {
    use bletio_utils::{Buffer, BufferOps, EncodeToBuffer};

    use super::*;

    /// Helper: build a Read By Group Type response for primary service discovery
    /// with 16-bit UUIDs (element_size = 6).
    fn build_service_response_16bit(
        services: &[(u16, u16, u16)],
    ) -> heapless::Vec<u8, 512> {
        let element_size = 6u8;
        let mut data = heapless::Vec::<u8, 512>::new();
        for &(start, end, uuid) in services {
            data.extend_from_slice(&start.to_le_bytes()).unwrap();
            data.extend_from_slice(&end.to_le_bytes()).unwrap();
            data.extend_from_slice(&uuid.to_le_bytes()).unwrap();
        }
        let pdu = AttPdu::ReadByGroupTypeResponse {
            length: element_size,
            attribute_data_list: data.clone(),
        };
        let mut buffer: Buffer<512> = Buffer::default();
        pdu.encode(&mut buffer).unwrap();
        let mut v = heapless::Vec::new();
        v.extend_from_slice(buffer.data()).unwrap();
        v
    }

    /// Helper: build a Read By Type response for characteristic discovery
    /// with 16-bit UUIDs (element_size = 7).
    fn build_char_response_16bit(
        chars: &[(u16, u8, u16, u16)],
    ) -> heapless::Vec<u8, 512> {
        let element_size = 7u8;
        let mut data = heapless::Vec::<u8, 512>::new();
        for &(handle, props, value_handle, uuid) in chars {
            data.extend_from_slice(&handle.to_le_bytes()).unwrap();
            data.push(props).unwrap();
            data.extend_from_slice(&value_handle.to_le_bytes()).unwrap();
            data.extend_from_slice(&uuid.to_le_bytes()).unwrap();
        }
        let pdu = AttPdu::ReadByTypeResponse {
            length: element_size,
            attribute_data_list: data.clone(),
        };
        let mut buffer: Buffer<512> = Buffer::default();
        pdu.encode(&mut buffer).unwrap();
        let mut v = heapless::Vec::new();
        v.extend_from_slice(buffer.data()).unwrap();
        v
    }

    /// Helper: build a Find Information response for descriptor discovery.
    fn build_descriptor_response_16bit(
        descs: &[(u16, u16)],
    ) -> heapless::Vec<u8, 512> {
        let mut data = heapless::Vec::<u8, 512>::new();
        for &(handle, uuid) in descs {
            data.extend_from_slice(&handle.to_le_bytes()).unwrap();
            data.extend_from_slice(&uuid.to_le_bytes()).unwrap();
        }
        let pdu = AttPdu::FindInformationResponse {
            format: 0x01,
            information_data: data,
        };
        let mut buffer: Buffer<512> = Buffer::default();
        pdu.encode(&mut buffer).unwrap();
        let mut v = heapless::Vec::new();
        v.extend_from_slice(buffer.data()).unwrap();
        v
    }

    /// Helper: build an Attribute Not Found error response.
    fn build_attr_not_found(opcode: AttOpcode) -> heapless::Vec<u8, 512> {
        let pdu = AttPdu::ErrorResponse {
            request_opcode: opcode,
            attribute_handle: AttHandle(0xFFFF),
            error_code: super::super::att_pdu::AttErrorCode::AttributeNotFound,
        };
        let mut buffer: Buffer<512> = Buffer::default();
        pdu.encode(&mut buffer).unwrap();
        let mut v = heapless::Vec::new();
        v.extend_from_slice(buffer.data()).unwrap();
        v
    }

    #[test]
    fn test_discover_single_service() {
        let mut gatt = GattClient::new();

        // Start discovery with exact range covering just this service
        let _req = gatt
            .discover_all_primary_services(AttHandle(0x0001), AttHandle(0x0010))
            .unwrap();
        assert!(!gatt.is_idle());

        // Feed a single service response
        let resp = build_service_response_16bit(&[(0x0001, 0x0010, 0x1800)]);
        let event = gatt.feed(&resp).unwrap();

        assert!(gatt.is_idle());
        match event {
            Some(GattEvent::ServicesDiscovered(services)) => {
                assert_eq!(services.len(), 1);
                assert_eq!(services[0].start_handle, AttHandle(0x0001));
                assert_eq!(services[0].end_handle, AttHandle(0x0010));
                assert_eq!(services[0].uuid, AttUuid::Uuid16(0x1800));
                assert!(services[0].is_primary);
            }
            _ => panic!("Expected ServicesDiscovered"),
        }
    }

    #[test]
    fn test_discover_multiple_services() {
        let mut gatt = GattClient::new();

        gatt.discover_all_primary_services(AttHandle(0x0001), AttHandle(0x0020))
            .unwrap();

        // Feed a response with two services
        let resp = build_service_response_16bit(&[
            (0x0001, 0x0010, 0x1800),
            (0x0011, 0x0020, 0x1801),
        ]);
        let event = gatt.feed(&resp).unwrap();

        assert!(gatt.is_idle());
        match event {
            Some(GattEvent::ServicesDiscovered(services)) => {
                assert_eq!(services.len(), 2);
                assert_eq!(services[0].uuid, AttUuid::Uuid16(0x1800));
                assert_eq!(services[1].uuid, AttUuid::Uuid16(0x1801));
            }
            _ => panic!("Expected ServicesDiscovered"),
        }
    }

    #[test]
    fn test_discover_services_continuation() {
        let mut gatt = GattClient::new();

        gatt.discover_all_primary_services(AttHandle(0x0001), AttHandle(0xFFFF))
            .unwrap();

        // Feed first response with one service ending at 0x0010
        let resp1 = build_service_response_16bit(&[(0x0001, 0x0010, 0x1800)]);
        let event = gatt.feed(&resp1).unwrap();

        // Should need continuation (0x0010 < 0xFFFF)
        assert!(event.is_none());
        assert!(!gatt.is_idle());

        // Get continuation request
        let _cont_req = gatt.continue_request().unwrap();

        // Feed second response with another service
        let resp2 = build_service_response_16bit(&[(0x0011, 0x0020, 0x1801)]);
        let event = gatt.feed(&resp2).unwrap();

        // Still needs continuation (0x0020 < 0xFFFF)
        assert!(event.is_none());
        assert!(!gatt.is_idle());

        // Get next continuation
        let _cont_req2 = gatt.continue_request().unwrap();

        // Feed Attribute Not Found to terminate
        let resp3 = build_attr_not_found(AttOpcode::ReadByGroupTypeRequest);
        let event = gatt.feed(&resp3).unwrap();

        assert!(gatt.is_idle());
        match event {
            Some(GattEvent::ServicesDiscovered(services)) => {
                assert_eq!(services.len(), 2);
            }
            _ => panic!("Expected ServicesDiscovered"),
        }
    }

    #[test]
    fn test_discover_services_attr_not_found() {
        let mut gatt = GattClient::new();

        gatt.discover_all_primary_services(AttHandle(0x0001), AttHandle(0xFFFF))
            .unwrap();

        // Attribute Not Found on first request terminates discovery immediately
        let resp = build_attr_not_found(AttOpcode::ReadByGroupTypeRequest);
        let event = gatt.feed(&resp).unwrap();

        assert!(gatt.is_idle());
        match event {
            Some(GattEvent::ServicesDiscovered(services)) => {
                assert_eq!(services.len(), 0);
            }
            _ => panic!("Expected empty ServicesDiscovered"),
        }
    }

    #[test]
    fn test_discover_characteristics() {
        let mut gatt = GattClient::new();

        gatt.discover_characteristics(AttHandle(0x0001), AttHandle(0x0002))
            .unwrap();
        assert!(!gatt.is_idle());

        // Characteristic: handle=2, props=0x02 (Read), value_handle=3, uuid=0x2A00
        let resp = build_char_response_16bit(&[(0x0002, 0x02, 0x0003, 0x2A00)]);
        let event = gatt.feed(&resp).unwrap();

        assert!(gatt.is_idle());
        match event {
            Some(GattEvent::CharacteristicsDiscovered(chars)) => {
                assert_eq!(chars.len(), 1);
                assert_eq!(chars[0].declaration_handle, AttHandle(0x0002));
                assert_eq!(chars[0].properties, 0x02);
                assert_eq!(chars[0].value_handle, AttHandle(0x0003));
                assert_eq!(chars[0].uuid, AttUuid::Uuid16(0x2A00));
            }
            _ => panic!("Expected CharacteristicsDiscovered"),
        }
    }

    #[test]
    fn test_discover_descriptors() {
        let mut gatt = GattClient::new();

        // Characteristic ends at value_handle 3, so descriptors start at 4
        // Set end range to exactly cover both descriptors
        gatt.discover_descriptors(AttHandle(0x0003), AttHandle(0x0005))
            .unwrap();
        assert!(!gatt.is_idle());

        // Descriptors: handles 4 (0x2902) and 5 (0x2901)
        let resp = build_descriptor_response_16bit(&[(0x0004, 0x2902), (0x0005, 0x2901)]);
        let event = gatt.feed(&resp).unwrap();

        assert!(gatt.is_idle());
        match event {
            Some(GattEvent::DescriptorsDiscovered(descs)) => {
                assert_eq!(descs.len(), 2);
                assert_eq!(descs[0].handle, AttHandle(0x0004));
                assert_eq!(descs[0].uuid, AttUuid::Uuid16(0x2902));
                assert_eq!(descs[1].handle, AttHandle(0x0005));
                assert_eq!(descs[1].uuid, AttUuid::Uuid16(0x2901));
            }
            _ => panic!("Expected DescriptorsDiscovered"),
        }
    }

    #[test]
    fn test_discover_descriptors_no_space() {
        let mut gatt = GattClient::new();

        // No descriptor space when char value handle equals end handle
        let result = gatt.discover_descriptors(AttHandle(0x0010), AttHandle(0x0010));
        assert!(result.is_err());
    }

    // ── Read / Write tests ─────────────────────────────────────────────

    fn build_read_response(value: &[u8]) -> heapless::Vec<u8, 512> {
        let pdu = AttPdu::ReadResponse {
            attribute_value: AttValue::new(value).unwrap(),
        };
        let mut buffer: Buffer<512> = Buffer::default();
        pdu.encode(&mut buffer).unwrap();
        let mut v = heapless::Vec::new();
        v.extend_from_slice(buffer.data()).unwrap();
        v
    }

    fn build_write_response() -> heapless::Vec<u8, 512> {
        let pdu = AttPdu::WriteResponse;
        let mut buffer: Buffer<512> = Buffer::default();
        pdu.encode(&mut buffer).unwrap();
        let mut v = heapless::Vec::new();
        v.extend_from_slice(buffer.data()).unwrap();
        v
    }

    fn build_notification(handle: u16, value: &[u8]) -> heapless::Vec<u8, 512> {
        let pdu = AttPdu::HandleValueNotification {
            attribute_handle: AttHandle(handle),
            attribute_value: AttValue::new(value).unwrap(),
        };
        let mut buffer: Buffer<512> = Buffer::default();
        pdu.encode(&mut buffer).unwrap();
        let mut v = heapless::Vec::new();
        v.extend_from_slice(buffer.data()).unwrap();
        v
    }

    fn build_indication(handle: u16, value: &[u8]) -> heapless::Vec<u8, 512> {
        let pdu = AttPdu::HandleValueIndication {
            attribute_handle: AttHandle(handle),
            attribute_value: AttValue::new(value).unwrap(),
        };
        let mut buffer: Buffer<512> = Buffer::default();
        pdu.encode(&mut buffer).unwrap();
        let mut v = heapless::Vec::new();
        v.extend_from_slice(buffer.data()).unwrap();
        v
    }

    fn build_confirmation() -> heapless::Vec<u8, 512> {
        let pdu = AttPdu::HandleValueConfirmation;
        let mut buffer: Buffer<512> = Buffer::default();
        pdu.encode(&mut buffer).unwrap();
        let mut v = heapless::Vec::new();
        v.extend_from_slice(buffer.data()).unwrap();
        v
    }

    #[test]
    fn test_read_characteristic_value() {
        let mut gatt = GattClient::new();
        assert!(gatt.is_idle());

        let _req = gatt.read_value(AttHandle(0x0003)).unwrap();
        assert!(!gatt.is_idle());

        let resp = build_read_response(&[0x42, 0x00]);
        let event = gatt.feed(&resp).unwrap();

        assert!(gatt.is_idle());
        match event {
            Some(GattEvent::ValueRead { handle, value }) => {
                assert_eq!(handle, AttHandle(0x0003));
                assert_eq!(value.as_slice(), &[0x42, 0x00]);
            }
            _ => panic!("Expected ValueRead"),
        }
    }

    #[test]
    fn test_write_characteristic_value() {
        let mut gatt = GattClient::new();

        let _req = gatt.write_value(AttHandle(0x0012), &[0x01, 0x00]).unwrap();
        assert!(!gatt.is_idle());

        let resp = build_write_response();
        let event = gatt.feed(&resp).unwrap();

        assert!(gatt.is_idle());
        match event {
            Some(GattEvent::ValueWritten { handle }) => {
                assert_eq!(handle, AttHandle(0x0012));
            }
            _ => panic!("Expected ValueWritten"),
        }
    }

    #[test]
    fn test_write_without_response_is_idempotent() {
        let gatt = GattClient::new();
        let _req = gatt.write_value_without_response(AttHandle(0x0012), &[0x01]).unwrap();
        assert!(gatt.is_idle());
    }

    #[test]
    fn test_receive_notification_while_idle() {
        let mut gatt = GattClient::new();

        let resp = build_notification(0x0015, &[0xDE, 0xAD]);
        let event = gatt.feed(&resp).unwrap();

        assert!(gatt.is_idle());
        match event {
            Some(GattEvent::Notification { handle, value }) => {
                assert_eq!(handle, AttHandle(0x0015));
                assert_eq!(value.as_slice(), &[0xDE, 0xAD]);
            }
            _ => panic!("Expected Notification"),
        }
    }

    #[test]
    fn test_cannot_start_read_while_busy() {
        let mut gatt = GattClient::new();
        gatt.read_value(AttHandle(0x0003)).unwrap();
        let result = gatt.read_value(AttHandle(0x0004));
        assert!(result.is_err());
    }
}
