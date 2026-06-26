//! ATT Protocol Data Unit (PDU) types and wire-format encoding/decoding.
//!
//! Implements the Attribute Protocol per
//! [Core Specification 6.0, Vol. 3, Part F](https://www.bluetooth.com/specifications/specs/core-specification-6-0/).

use bletio_utils::{BufferOps, EncodeToBuffer, Error as UtilsError};

/// ATT attribute handle (16-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttHandle(pub u16);

/// ATT attribute value — a variable-length byte slice.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttValue {
    data: heapless::Vec<u8, 512>,
}

impl AttValue {
    pub fn new(data: &[u8]) -> Result<Self, AttError> {
        let mut v = heapless::Vec::new();
        v.extend_from_slice(data).map_err(|_| AttError::ValueTooLong)?;
        Ok(Self { data: v })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// ATT UUID — 16-bit or 128-bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AttUuid {
    Uuid16(u16),
    Uuid128(u128),
}

impl AttUuid {
    pub fn size(&self) -> usize {
        match self {
            AttUuid::Uuid16(_) => 2,
            AttUuid::Uuid128(_) => 16,
        }
    }
}

/// A handle-value pair used in Read By Type / Read By Group Type responses.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttHandleValue {
    pub handle: AttHandle,
    pub end_group_handle: Option<AttHandle>, // Only for Read By Group Type
    pub value: AttValue,
}

/// Errors specific to the ATT layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AttError {
    /// Value exceeds maximum allowed length.
    ValueTooLong,
    /// Invalid PDU opcode.
    InvalidOpcode(u8),
    /// Invalid PDU format or truncated data.
    InvalidPdu,
    /// The attribute handle is invalid.
    InvalidHandle,
    /// The ATT request timed out.
    Timeout,
    /// The peer sent an ATT Error Response.
    ErrorResponse { request_opcode: u8, attribute_handle: AttHandle, error_code: u8 },
    /// Unexpected PDU received.
    UnexpectedPdu { expected: u8, received: u8 },
}

// ─── ATT PDU Opcodes ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum AttOpcode {
    ErrorResponse = 0x01,
    ExchangeMtuRequest = 0x02,
    ExchangeMtuResponse = 0x03,
    FindInformationRequest = 0x04,
    FindInformationResponse = 0x05,
    FindByTypeValueRequest = 0x06,
    FindByTypeValueResponse = 0x07,
    ReadByTypeRequest = 0x08,
    ReadByTypeResponse = 0x09,
    ReadRequest = 0x0A,
    ReadResponse = 0x0B,
    ReadBlobRequest = 0x0C,
    ReadBlobResponse = 0x0D,
    ReadMultipleRequest = 0x0E,
    ReadMultipleResponse = 0x0F,
    ReadByGroupTypeRequest = 0x10,
    ReadByGroupTypeResponse = 0x11,
    WriteRequest = 0x12,
    WriteResponse = 0x13,
    WriteCommand = 0x52,
    PrepareWriteRequest = 0x16,
    PrepareWriteResponse = 0x17,
    ExecuteWriteRequest = 0x18,
    ExecuteWriteResponse = 0x19,
    HandleValueNotification = 0x1B,
    HandleValueIndication = 0x1D,
    HandleValueConfirmation = 0x1E,
    ReadMultipleVariableRequest = 0x20,
    ReadMultipleVariableResponse = 0x21,
    WriteMultipleRequest = 0x26,
    WriteMultipleResponse = 0x27,
}

impl TryFrom<u8> for AttOpcode {
    type Error = AttError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::ErrorResponse),
            0x02 => Ok(Self::ExchangeMtuRequest),
            0x03 => Ok(Self::ExchangeMtuResponse),
            0x04 => Ok(Self::FindInformationRequest),
            0x05 => Ok(Self::FindInformationResponse),
            0x06 => Ok(Self::FindByTypeValueRequest),
            0x07 => Ok(Self::FindByTypeValueResponse),
            0x08 => Ok(Self::ReadByTypeRequest),
            0x09 => Ok(Self::ReadByTypeResponse),
            0x0A => Ok(Self::ReadRequest),
            0x0B => Ok(Self::ReadResponse),
            0x0C => Ok(Self::ReadBlobRequest),
            0x0D => Ok(Self::ReadBlobResponse),
            0x0E => Ok(Self::ReadMultipleRequest),
            0x0F => Ok(Self::ReadMultipleResponse),
            0x10 => Ok(Self::ReadByGroupTypeRequest),
            0x11 => Ok(Self::ReadByGroupTypeResponse),
            0x12 => Ok(Self::WriteRequest),
            0x13 => Ok(Self::WriteResponse),
            0x16 => Ok(Self::PrepareWriteRequest),
            0x17 => Ok(Self::PrepareWriteResponse),
            0x18 => Ok(Self::ExecuteWriteRequest),
            0x19 => Ok(Self::ExecuteWriteResponse),
            0x1B => Ok(Self::HandleValueNotification),
            0x1D => Ok(Self::HandleValueIndication),
            0x1E => Ok(Self::HandleValueConfirmation),
            0x20 => Ok(Self::ReadMultipleVariableRequest),
            0x21 => Ok(Self::ReadMultipleVariableResponse),
            0x26 => Ok(Self::WriteMultipleRequest),
            0x27 => Ok(Self::WriteMultipleResponse),
            0x52 => Ok(Self::WriteCommand),
            _ => Err(AttError::InvalidOpcode(value)),
        }
    }
}

impl From<AttOpcode> for u8 {
    fn from(opcode: AttOpcode) -> Self {
        opcode as u8
    }
}

/// ATT Error Response error codes per Core Spec Vol. 3, Part F, §3.4.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum AttErrorCode {
    InvalidHandle = 0x01,
    ReadNotPermitted = 0x02,
    WriteNotPermitted = 0x03,
    InvalidPdu = 0x04,
    InsufficientAuthentication = 0x05,
    RequestNotSupported = 0x06,
    InvalidOffset = 0x07,
    InsufficientAuthorization = 0x08,
    PrepareQueueFull = 0x09,
    AttributeNotFound = 0x0A,
    AttributeNotLong = 0x0B,
    InsufficientEncryptionKeySize = 0x0C,
    InvalidAttributeValueLength = 0x0D,
    UnlikelyError = 0x0E,
    InsufficientEncryption = 0x0F,
    UnsupportedGroupType = 0x10,
    InsufficientResources = 0x11,
}

impl TryFrom<u8> for AttErrorCode {
    type Error = AttError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::InvalidHandle),
            0x02 => Ok(Self::ReadNotPermitted),
            0x03 => Ok(Self::WriteNotPermitted),
            0x04 => Ok(Self::InvalidPdu),
            0x05 => Ok(Self::InsufficientAuthentication),
            0x06 => Ok(Self::RequestNotSupported),
            0x07 => Ok(Self::InvalidOffset),
            0x08 => Ok(Self::InsufficientAuthorization),
            0x09 => Ok(Self::PrepareQueueFull),
            0x0A => Ok(Self::AttributeNotFound),
            0x0B => Ok(Self::AttributeNotLong),
            0x0C => Ok(Self::InsufficientEncryptionKeySize),
            0x0D => Ok(Self::InvalidAttributeValueLength),
            0x0E => Ok(Self::UnlikelyError),
            0x0F => Ok(Self::InsufficientEncryption),
            0x10 => Ok(Self::UnsupportedGroupType),
            0x11 => Ok(Self::InsufficientResources),
            _ => Err(AttError::InvalidOpcode(value)),
        }
    }
}

// ─── ATT PDU Enum ─────────────────────────────────────────────────────────

/// An ATT Protocol Data Unit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AttPdu {
    /// Error Response — carries the opcode of the request that caused the error.
    ErrorResponse {
        request_opcode: AttOpcode,
        attribute_handle: AttHandle,
        error_code: AttErrorCode,
    },

    // ── MTU Exchange ──
    ExchangeMtuRequest {
        client_rx_mtu: u16,
    },
    ExchangeMtuResponse {
        server_rx_mtu: u16,
    },

    // ── Find Information ──
    FindInformationRequest {
        starting_handle: AttHandle,
        ending_handle: AttHandle,
    },
    FindInformationResponse {
        format: u8,
        information_data: heapless::Vec<u8, 512>,
    },

    // ── Read By Type ──
    ReadByTypeRequest {
        starting_handle: AttHandle,
        ending_handle: AttHandle,
        attribute_type: AttUuid,
    },
    ReadByTypeResponse {
        length: u8,
        attribute_data_list: heapless::Vec<u8, 512>,
    },

    // ── Read ──
    ReadRequest {
        attribute_handle: AttHandle,
    },
    ReadResponse {
        attribute_value: AttValue,
    },

    // ── Read Blob ──
    ReadBlobRequest {
        attribute_handle: AttHandle,
        value_offset: u16,
    },
    ReadBlobResponse {
        part_attribute_value: AttValue,
    },

    // ── Read By Group Type ──
    ReadByGroupTypeRequest {
        starting_handle: AttHandle,
        ending_handle: AttHandle,
        attribute_group_type: AttUuid,
    },
    ReadByGroupTypeResponse {
        length: u8,
        attribute_data_list: heapless::Vec<u8, 512>,
    },

    // ── Write ──
    WriteRequest {
        attribute_handle: AttHandle,
        attribute_value: AttValue,
    },
    WriteResponse,

    /// Write Command — no response expected.
    WriteCommand {
        attribute_handle: AttHandle,
        attribute_value: AttValue,
    },

    // ── Handle Value Notification / Indication ──
    HandleValueNotification {
        attribute_handle: AttHandle,
        attribute_value: AttValue,
    },
    HandleValueIndication {
        attribute_handle: AttHandle,
        attribute_value: AttValue,
    },
    HandleValueConfirmation,
}

impl AttPdu {
    /// Returns the ATT opcode for this PDU.
    pub fn opcode(&self) -> AttOpcode {
        match self {
            Self::ErrorResponse { .. } => AttOpcode::ErrorResponse,
            Self::ExchangeMtuRequest { .. } => AttOpcode::ExchangeMtuRequest,
            Self::ExchangeMtuResponse { .. } => AttOpcode::ExchangeMtuResponse,
            Self::FindInformationRequest { .. } => AttOpcode::FindInformationRequest,
            Self::FindInformationResponse { .. } => AttOpcode::FindInformationResponse,
            Self::ReadByTypeRequest { .. } => AttOpcode::ReadByTypeRequest,
            Self::ReadByTypeResponse { .. } => AttOpcode::ReadByTypeResponse,
            Self::ReadRequest { .. } => AttOpcode::ReadRequest,
            Self::ReadResponse { .. } => AttOpcode::ReadResponse,
            Self::ReadBlobRequest { .. } => AttOpcode::ReadBlobRequest,
            Self::ReadBlobResponse { .. } => AttOpcode::ReadBlobResponse,
            Self::ReadByGroupTypeRequest { .. } => AttOpcode::ReadByGroupTypeRequest,
            Self::ReadByGroupTypeResponse { .. } => AttOpcode::ReadByGroupTypeResponse,
            Self::WriteRequest { .. } => AttOpcode::WriteRequest,
            Self::WriteResponse => AttOpcode::WriteResponse,
            Self::WriteCommand { .. } => AttOpcode::WriteCommand,
            Self::HandleValueNotification { .. } => AttOpcode::HandleValueNotification,
            Self::HandleValueIndication { .. } => AttOpcode::HandleValueIndication,
            Self::HandleValueConfirmation => AttOpcode::HandleValueConfirmation,
        }
    }
}

// ─── Encoding ─────────────────────────────────────────────────────────────

impl EncodeToBuffer for AttHandle {
    fn encode<B: BufferOps>(&self, buffer: &mut B) -> Result<usize, UtilsError> {
        buffer.encode_le_u16(self.0)
    }

    fn encoded_size(&self) -> usize {
        2
    }
}

impl EncodeToBuffer for AttUuid {
    fn encode<B: BufferOps>(&self, buffer: &mut B) -> Result<usize, UtilsError> {
        match self {
            AttUuid::Uuid16(v) => buffer.encode_le_u16(*v),
            AttUuid::Uuid128(v) => buffer.encode_le_u128(*v),
        }
    }

    fn encoded_size(&self) -> usize {
        self.size()
    }
}

impl EncodeToBuffer for AttValue {
    fn encode<B: BufferOps>(&self, buffer: &mut B) -> Result<usize, UtilsError> {
        buffer.copy_from_slice(&self.data)
    }

    fn encoded_size(&self) -> usize {
        self.data.len()
    }
}

impl EncodeToBuffer for AttPdu {
    fn encode<B: BufferOps>(&self, buffer: &mut B) -> Result<usize, UtilsError> {
        let mut written = 0;

        // Opcode
        written += buffer.try_push(self.opcode() as u8)?;

        // Parameters
        written += match self {
            Self::ErrorResponse {
                request_opcode,
                attribute_handle,
                error_code,
            } => {
                let mut w = buffer.try_push(*request_opcode as u8)?;
                w += attribute_handle.encode(buffer)?;
                w += buffer.try_push(*error_code as u8)?;
                w
            }

            Self::ExchangeMtuRequest { client_rx_mtu } => {
                buffer.encode_le_u16(*client_rx_mtu)?
            }
            Self::ExchangeMtuResponse { server_rx_mtu } => {
                buffer.encode_le_u16(*server_rx_mtu)?
            }

            Self::FindInformationRequest {
                starting_handle,
                ending_handle,
            } => {
                let mut w = starting_handle.encode(buffer)?;
                w += ending_handle.encode(buffer)?;
                w
            }
            Self::FindInformationResponse {
                format,
                information_data,
            } => {
                let mut w = buffer.try_push(*format)?;
                w += buffer.copy_from_slice(information_data)?;
                w
            }

            Self::ReadByTypeRequest {
                starting_handle,
                ending_handle,
                attribute_type,
            } => {
                let mut w = starting_handle.encode(buffer)?;
                w += ending_handle.encode(buffer)?;
                w += attribute_type.encode(buffer)?;
                w
            }
            Self::ReadByTypeResponse {
                length,
                attribute_data_list,
            } => {
                let mut w = buffer.try_push(*length)?;
                w += buffer.copy_from_slice(attribute_data_list)?;
                w
            }

            Self::ReadRequest { attribute_handle } => attribute_handle.encode(buffer)?,
            Self::ReadResponse { attribute_value } => attribute_value.encode(buffer)?,

            Self::ReadBlobRequest {
                attribute_handle,
                value_offset,
            } => {
                let mut w = attribute_handle.encode(buffer)?;
                w += buffer.encode_le_u16(*value_offset)?;
                w
            }
            Self::ReadBlobResponse {
                part_attribute_value,
            } => part_attribute_value.encode(buffer)?,

            Self::ReadByGroupTypeRequest {
                starting_handle,
                ending_handle,
                attribute_group_type,
            } => {
                let mut w = starting_handle.encode(buffer)?;
                w += ending_handle.encode(buffer)?;
                w += attribute_group_type.encode(buffer)?;
                w
            }
            Self::ReadByGroupTypeResponse {
                length,
                attribute_data_list,
            } => {
                let mut w = buffer.try_push(*length)?;
                w += buffer.copy_from_slice(attribute_data_list)?;
                w
            }

            Self::WriteRequest {
                attribute_handle,
                attribute_value,
            } => {
                let mut w = attribute_handle.encode(buffer)?;
                w += attribute_value.encode(buffer)?;
                w
            }
            Self::WriteResponse => 0,

            Self::WriteCommand {
                attribute_handle,
                attribute_value,
            } => {
                let mut w = attribute_handle.encode(buffer)?;
                w += attribute_value.encode(buffer)?;
                w
            }

            Self::HandleValueNotification {
                attribute_handle,
                attribute_value,
            }
            | Self::HandleValueIndication {
                attribute_handle,
                attribute_value,
            } => {
                let mut w = attribute_handle.encode(buffer)?;
                w += attribute_value.encode(buffer)?;
                w
            }
            Self::HandleValueConfirmation => 0,
        };

        Ok(written)
    }

    fn encoded_size(&self) -> usize {
        1 + match self {
            Self::ErrorResponse { .. } => 1 + 2 + 1, // opcode + handle + error_code
            Self::ExchangeMtuRequest { .. } | Self::ExchangeMtuResponse { .. } => 2,
            Self::FindInformationRequest { .. } => 4,
            Self::FindInformationResponse { information_data, .. } => 1 + information_data.len(),
            Self::ReadByTypeRequest { attribute_type, .. } => 4 + attribute_type.size(),
            Self::ReadByTypeResponse { attribute_data_list, .. } => {
                1 + attribute_data_list.len()
            }
            Self::ReadRequest { .. } => 2,
            Self::ReadResponse { attribute_value } => attribute_value.encoded_size(),
            Self::ReadBlobRequest { .. } => 4,
            Self::ReadBlobResponse { part_attribute_value } => part_attribute_value.encoded_size(),
            Self::ReadByGroupTypeRequest { attribute_group_type, .. } => {
                4 + attribute_group_type.size()
            }
            Self::ReadByGroupTypeResponse { attribute_data_list, .. } => {
                1 + attribute_data_list.len()
            }
            Self::WriteRequest { attribute_value, .. } => 2 + attribute_value.encoded_size(),
            Self::WriteResponse => 0,
            Self::WriteCommand { attribute_value, .. } => 2 + attribute_value.encoded_size(),
            Self::HandleValueNotification { attribute_value, .. }
            | Self::HandleValueIndication { attribute_value, .. } => {
                2 + attribute_value.encoded_size()
            }
            Self::HandleValueConfirmation => 0,
        }
    }
}

// ─── Decoding ─────────────────────────────────────────────────────────────

pub(crate) mod parser {
    use nom::{
        bytes::complete::take, combinator::map_res, number::complete::le_u16,
        sequence::pair, IResult, Parser,
    };

    use super::*;

    /// Helper: parse all remaining input as a heapless vec of bytes.
    fn take_rest_as_vec<const N: usize>(input: &[u8]) -> IResult<&[u8], heapless::Vec<u8, N>> {
        let data = input;
        let mut v = heapless::Vec::new();
        v.extend_from_slice(data)
            .map_err(|_| {
                nom::Err::<nom::error::Error<&[u8]>>::Failure(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::TooLarge,
                ))
            })?;
        Ok((&[] as &[u8], v))
    }

    /// Helper: parse all remaining input as an AttValue.
    fn take_rest_as_att_value(input: &[u8]) -> IResult<&[u8], AttValue> {
        map_res(take(input.len()), |data: &[u8]| AttValue::new(data)).parse(input)
    }

    fn att_handle(input: &[u8]) -> IResult<&[u8], AttHandle> {
        nom::combinator::map(le_u16, AttHandle).parse(input)
    }

    fn att_uuid16(input: &[u8]) -> IResult<&[u8], AttUuid> {
        nom::combinator::map(le_u16, AttUuid::Uuid16).parse(input)
    }

    fn att_uuid128(input: &[u8]) -> IResult<&[u8], AttUuid> {
        nom::combinator::map(nom::number::complete::le_u128, AttUuid::Uuid128)
            .parse(input)
    }

    fn att_error_code(input: &[u8]) -> IResult<&[u8], AttErrorCode> {
        map_res(nom::number::complete::le_u8, AttErrorCode::try_from).parse(input)
    }

    fn att_opcode(input: &[u8]) -> IResult<&[u8], AttOpcode> {
        map_res(nom::number::complete::le_u8, AttOpcode::try_from).parse(input)
    }

    /// Parse a complete ATT PDU from raw bytes (typically from an ACL data payload).
    pub(crate) fn att_pdu(input: &[u8]) -> IResult<&[u8], AttPdu> {
        let (input, opcode) = att_opcode(input)?;

        match opcode {
            AttOpcode::ErrorResponse => {
                let (input, (request_opcode, attribute_handle, error_code)) =
                    (att_opcode, att_handle, att_error_code).parse(input)?;
                Ok((
                    input,
                    AttPdu::ErrorResponse {
                        request_opcode,
                        attribute_handle,
                        error_code,
                    },
                ))
            }

            AttOpcode::ExchangeMtuRequest => {
                let (input, client_rx_mtu) = le_u16(input)?;
                Ok((input, AttPdu::ExchangeMtuRequest { client_rx_mtu }))
            }
            AttOpcode::ExchangeMtuResponse => {
                let (input, server_rx_mtu) = le_u16(input)?;
                Ok((input, AttPdu::ExchangeMtuResponse { server_rx_mtu }))
            }

            AttOpcode::FindInformationRequest => {
                let (input, (starting_handle, ending_handle)) =
                    pair(att_handle, att_handle).parse(input)?;
                Ok((
                    input,
                    AttPdu::FindInformationRequest {
                        starting_handle,
                        ending_handle,
                    },
                ))
            }
            AttOpcode::FindInformationResponse => {
                let (input, format) = nom::number::complete::le_u8(input)?;
                let (_input, information_data) = take_rest_as_vec(input)?;
                Ok((
                    &[] as &[u8],
                    AttPdu::FindInformationResponse {
                        format,
                        information_data,
                    },
                ))
            }

            AttOpcode::ReadByTypeRequest => {
                let (input, (starting_handle, ending_handle)) =
                    pair(att_handle, att_handle).parse(input)?;
                let (input, attribute_type) = nom::branch::alt((att_uuid16, att_uuid128)).parse(input)?;
                Ok((
                    input,
                    AttPdu::ReadByTypeRequest {
                        starting_handle,
                        ending_handle,
                        attribute_type,
                    },
                ))
            }
            AttOpcode::ReadByTypeResponse => {
                let (input, length) = nom::number::complete::le_u8(input)?;
                let (_input, attribute_data_list) = take_rest_as_vec(input)?;
                Ok((
                    &[] as &[u8],
                    AttPdu::ReadByTypeResponse {
                        length,
                        attribute_data_list,
                    },
                ))
            }

            AttOpcode::ReadRequest => {
                let (input, attribute_handle) = att_handle(input)?;
                Ok((input, AttPdu::ReadRequest { attribute_handle }))
            }
            AttOpcode::ReadResponse => {
                let (_input, attribute_value) = take_rest_as_att_value(input)?;
                Ok((&[] as &[u8], AttPdu::ReadResponse { attribute_value }))
            }

            AttOpcode::ReadBlobRequest => {
                let (input, (attribute_handle, value_offset)) =
                    pair(att_handle, le_u16).parse(input)?;
                Ok((
                    input,
                    AttPdu::ReadBlobRequest {
                        attribute_handle,
                        value_offset,
                    },
                ))
            }

            AttOpcode::ReadByGroupTypeRequest => {
                let (input, (starting_handle, ending_handle)) =
                    pair(att_handle, att_handle).parse(input)?;
                let (input, attribute_group_type) =
                    nom::branch::alt((att_uuid16, att_uuid128)).parse(input)?;
                Ok((
                    input,
                    AttPdu::ReadByGroupTypeRequest {
                        starting_handle,
                        ending_handle,
                        attribute_group_type,
                    },
                ))
            }
            AttOpcode::ReadByGroupTypeResponse => {
                let (input, length) = nom::number::complete::le_u8(input)?;
                let (_input, attribute_data_list) = take_rest_as_vec(input)?;
                Ok((
                    &[] as &[u8],
                    AttPdu::ReadByGroupTypeResponse {
                        length,
                        attribute_data_list,
                    },
                ))
            }

            AttOpcode::WriteRequest => {
                let (input, (attribute_handle, attribute_value)) =
                    pair(att_handle, take_rest_as_att_value).parse(input)?;
                Ok((
                    &[] as &[u8],
                    AttPdu::WriteRequest {
                        attribute_handle,
                        attribute_value,
                    },
                ))
            }
            AttOpcode::WriteResponse => Ok((&[] as &[u8], AttPdu::WriteResponse)),

            AttOpcode::WriteCommand => {
                let (input, (attribute_handle, attribute_value)) =
                    pair(att_handle, take_rest_as_att_value).parse(input)?;
                Ok((
                    &[] as &[u8],
                    AttPdu::WriteCommand {
                        attribute_handle,
                        attribute_value,
                    },
                ))
            }

            AttOpcode::HandleValueNotification | AttOpcode::HandleValueIndication => {
                let (input, (attribute_handle, attribute_value)) =
                    pair(att_handle, take_rest_as_att_value).parse(input)?;
                let pdu = match opcode {
                    AttOpcode::HandleValueNotification => AttPdu::HandleValueNotification {
                        attribute_handle,
                        attribute_value,
                    },
                    AttOpcode::HandleValueIndication => AttPdu::HandleValueIndication {
                        attribute_handle,
                        attribute_value,
                    },
                    _ => unreachable!(),
                };
                Ok((&[] as &[u8], pdu))
            }
            AttOpcode::HandleValueConfirmation => {
                Ok((&[] as &[u8], AttPdu::HandleValueConfirmation))
            }

            // Unsupported for now
            _ => Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use bletio_utils::{Buffer, BufferOps};

    use super::*;

    fn encode_pdu(pdu: &AttPdu) -> heapless::Vec<u8, 256> {
        let mut buffer: Buffer<512> = Buffer::default();
        pdu.encode(&mut buffer).unwrap();
        let mut v = heapless::Vec::new();
        v.extend_from_slice(buffer.data()).unwrap();
        v
    }

    #[test]
    fn test_att_handle_encode() {
        let mut buffer: Buffer<4> = Buffer::default();
        AttHandle(0x0003).encode(&mut buffer).unwrap();
        assert_eq!(buffer.data(), &[0x03, 0x00]);
    }

    #[test]
    fn test_error_response_roundtrip() {
        let pdu = AttPdu::ErrorResponse {
            request_opcode: AttOpcode::ReadByTypeRequest,
            attribute_handle: AttHandle(0x0003),
            error_code: AttErrorCode::AttributeNotFound,
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::att_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_exchange_mtu_roundtrip() {
        let pdu = AttPdu::ExchangeMtuRequest { client_rx_mtu: 517 };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::att_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_read_request_roundtrip() {
        let pdu = AttPdu::ReadRequest {
            attribute_handle: AttHandle(0x0010),
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::att_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_read_response_roundtrip() {
        let pdu = AttPdu::ReadResponse {
            attribute_value: AttValue::new(&[0x41, 0x42, 0x43]).unwrap(),
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::att_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_write_request_roundtrip() {
        let pdu = AttPdu::WriteRequest {
            attribute_handle: AttHandle(0x0012),
            attribute_value: AttValue::new(&[0x01, 0x00]).unwrap(),
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::att_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_write_command_roundtrip() {
        let pdu = AttPdu::WriteCommand {
            attribute_handle: AttHandle(0x0012),
            attribute_value: AttValue::new(&[0x00]).unwrap(),
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::att_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_handle_value_notification_roundtrip() {
        let pdu = AttPdu::HandleValueNotification {
            attribute_handle: AttHandle(0x0015),
            attribute_value: AttValue::new(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap(),
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::att_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_handle_value_indication_confirmation_roundtrip() {
        let pdu = AttPdu::HandleValueIndication {
            attribute_handle: AttHandle(0x0015),
            attribute_value: AttValue::new(&[0x01]).unwrap(),
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::att_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);

        let conf = AttPdu::HandleValueConfirmation;
        let encoded = encode_pdu(&conf);
        let (rest, decoded) = parser::att_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, conf);
    }

    #[test]
    fn test_read_by_type_request_16bit_uuid_roundtrip() {
        let pdu = AttPdu::ReadByTypeRequest {
            starting_handle: AttHandle(0x0001),
            ending_handle: AttHandle(0xFFFF),
            attribute_type: AttUuid::Uuid16(0x2A00),
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::att_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_read_by_group_type_request_roundtrip() {
        let pdu = AttPdu::ReadByGroupTypeRequest {
            starting_handle: AttHandle(0x0001),
            ending_handle: AttHandle(0xFFFF),
            attribute_group_type: AttUuid::Uuid16(0x2800),
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::att_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_find_information_request_roundtrip() {
        let pdu = AttPdu::FindInformationRequest {
            starting_handle: AttHandle(0x0010),
            ending_handle: AttHandle(0x0020),
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::att_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_invalid_opcode() {
        let result = parser::att_pdu(&[0xFF, 0x00]);
        assert!(result.is_err());
    }
}
