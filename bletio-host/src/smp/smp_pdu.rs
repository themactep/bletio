//! Security Manager Protocol (SMP) PDU types and wire-format encoding/decoding.
//!
//! Implements SMP per
//! [Core Specification 6.0, Vol. 3, Part H](https://www.bluetooth.com/specifications/specs/core-specification-6-0/).

use bletio_utils::{BufferOps, EncodeToBuffer, Error as UtilsError};

// ─── SMP Command Codes ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum SmpOpcode {
    PairingRequest = 0x01,
    PairingResponse = 0x02,
    PairingConfirm = 0x03,
    PairingRandom = 0x04,
    PairingFailed = 0x05,
    EncryptionInformation = 0x06,
    MasterIdentification = 0x07,
    IdentityInformation = 0x08,
    IdentityAddressInformation = 0x09,
    SigningInformation = 0x0A,
    SecurityRequest = 0x0B,
    PairingPublicKey = 0x0C,
    PairingDhkeyCheck = 0x0D,
    PairingKeypressNotification = 0x0E,
}

impl TryFrom<u8> for SmpOpcode {
    type Error = SmpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::PairingRequest),
            0x02 => Ok(Self::PairingResponse),
            0x03 => Ok(Self::PairingConfirm),
            0x04 => Ok(Self::PairingRandom),
            0x05 => Ok(Self::PairingFailed),
            0x06 => Ok(Self::EncryptionInformation),
            0x07 => Ok(Self::MasterIdentification),
            0x08 => Ok(Self::IdentityInformation),
            0x09 => Ok(Self::IdentityAddressInformation),
            0x0A => Ok(Self::SigningInformation),
            0x0B => Ok(Self::SecurityRequest),
            0x0C => Ok(Self::PairingPublicKey),
            0x0D => Ok(Self::PairingDhkeyCheck),
            0x0E => Ok(Self::PairingKeypressNotification),
            _ => Err(SmpError::InvalidOpcode(value)),
        }
    }
}

// ─── I/O Capabilities ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum IoCapability {
    DisplayOnly = 0x00,
    DisplayYesNo = 0x01,
    KeyboardOnly = 0x02,
    NoInputNoOutput = 0x03,
    KeyboardDisplay = 0x04,
}

impl TryFrom<u8> for IoCapability {
    type Error = SmpError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x00 => Ok(Self::DisplayOnly),
            0x01 => Ok(Self::DisplayYesNo),
            0x02 => Ok(Self::KeyboardOnly),
            0x03 => Ok(Self::NoInputNoOutput),
            0x04 => Ok(Self::KeyboardDisplay),
            _ => Err(SmpError::InvalidIoCapability(v)),
        }
    }
}

// ─── AuthReq flags ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AuthReq {
    pub bonding: bool,
    pub mitm: bool,
    pub secure_connections: bool,
    pub keypress: bool,
    pub ct2: bool,
}

impl AuthReq {
    pub fn to_byte(&self) -> u8 {
        let mut b = 0u8;
        if self.bonding { b |= 0x01; }
        if self.mitm { b |= 0x04; }
        if self.secure_connections { b |= 0x08; }
        if self.keypress { b |= 0x10; }
        if self.ct2 { b |= 0x20; }
        b
    }

    pub fn from_byte(b: u8) -> Self {
        Self {
            bonding: (b & 0x01) != 0,
            mitm: (b & 0x04) != 0,
            secure_connections: (b & 0x08) != 0,
            keypress: (b & 0x10) != 0,
            ct2: (b & 0x20) != 0,
        }
    }
}

// ─── Key Distribution flags ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyDistribution {
    pub enc_key: bool,
    pub id_key: bool,
    pub sign_key: bool,
    pub link_key: bool,
}

impl KeyDistribution {
    pub fn to_byte(&self) -> u8 {
        let mut b = 0u8;
        if self.enc_key { b |= 0x01; }
        if self.id_key { b |= 0x02; }
        if self.sign_key { b |= 0x04; }
        if self.link_key { b |= 0x08; }
        b
    }

    pub fn from_byte(b: u8) -> Self {
        Self {
            enc_key: (b & 0x01) != 0,
            id_key: (b & 0x02) != 0,
            sign_key: (b & 0x04) != 0,
            link_key: (b & 0x08) != 0,
        }
    }
}

// ─── Pairing Failed reason ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum PairingFailedReason {
    PasskeyEntryFailed = 0x01,
    OobNotAvailable = 0x02,
    AuthenticationRequirements = 0x03,
    ConfirmValueFailed = 0x04,
    PairingNotSupported = 0x05,
    EncryptionKeySize = 0x06,
    CommandNotSupported = 0x07,
    UnspecifiedReason = 0x08,
    RepeatedAttempts = 0x09,
    InvalidParameters = 0x0A,
    DhkeyCheckFailed = 0x0B,
    NumericComparisonFailed = 0x0C,
    BrEdrPairingInProgress = 0x0D,
    CrossTransportKeyDerivationNotAllowed = 0x0E,
}

impl TryFrom<u8> for PairingFailedReason {
    type Error = SmpError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::PasskeyEntryFailed),
            0x02 => Ok(Self::OobNotAvailable),
            0x03 => Ok(Self::AuthenticationRequirements),
            0x04 => Ok(Self::ConfirmValueFailed),
            0x05 => Ok(Self::PairingNotSupported),
            0x06 => Ok(Self::EncryptionKeySize),
            0x07 => Ok(Self::CommandNotSupported),
            0x08 => Ok(Self::UnspecifiedReason),
            0x09 => Ok(Self::RepeatedAttempts),
            0x0A => Ok(Self::InvalidParameters),
            0x0B => Ok(Self::DhkeyCheckFailed),
            0x0C => Ok(Self::NumericComparisonFailed),
            0x0D => Ok(Self::BrEdrPairingInProgress),
            0x0E => Ok(Self::CrossTransportKeyDerivationNotAllowed),
            _ => Err(SmpError::InvalidOpcode(v)),
        }
    }
}

// ─── SMP Errors ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SmpError {
    InvalidOpcode(u8),
    InvalidIoCapability(u8),
    InvalidPdu,
    PduTooLong,
    UnexpectedPdu,
    PairingFailed(PairingFailedReason),
    EncryptionFailed,
    NotSupported,
}

// ─── SMP PDU Enum ────────────────────────────────────────────────────────

/// An SMP Protocol Data Unit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SmpPdu {
    /// Pairing Request sent by the initiator.
    PairingRequest {
        io_capability: IoCapability,
        oob_data_flag: bool,
        auth_req: AuthReq,
        max_encryption_key_size: u8,
        initiator_key_distribution: KeyDistribution,
        responder_key_distribution: KeyDistribution,
    },
    /// Pairing Response sent by the responder.
    PairingResponse {
        io_capability: IoCapability,
        oob_data_flag: bool,
        auth_req: AuthReq,
        max_encryption_key_size: u8,
        initiator_key_distribution: KeyDistribution,
        responder_key_distribution: KeyDistribution,
    },
    /// Pairing Confirm — contains the confirm value (16 bytes).
    PairingConfirm {
        confirm_value: [u8; 16],
    },
    /// Pairing Random — contains the random value (16 bytes).
    PairingRandom {
        random_value: [u8; 16],
    },
    /// Pairing Failed — sent when pairing cannot proceed.
    PairingFailed {
        reason: PairingFailedReason,
    },
    /// Encryption Information — LTK (16 bytes).
    EncryptionInformation {
        long_term_key: [u8; 16],
    },
    /// Master Identification — EDIV (2 bytes) + Rand (8 bytes).
    MasterIdentification {
        ediv: u16,
        rand: [u8; 8],
    },
    /// Identity Information — IRK (16 bytes).
    IdentityInformation {
        identity_resolving_key: [u8; 16],
    },
    /// Identity Address Information — address type (1 byte) + address (6 bytes).
    IdentityAddressInformation {
        address_type: u8,
        address: [u8; 6],
    },
    /// Signing Information — CSRK (16 bytes).
    SigningInformation {
        connection_signature_resolving_key: [u8; 16],
    },
    /// Security Request — sent by the slave to request security.
    SecurityRequest {
        auth_req: AuthReq,
    },
    // ── LE Secure Connections ──
    /// Pairing Public Key (64 bytes) — X coordinate followed by Y coordinate.
    PairingPublicKey {
        x: [u8; 32],
        y: [u8; 32],
    },
    /// Pairing DHKey Check (16 bytes) — f6 confirmation of the DHKey.
    PairingDhkeyCheck {
        dhkey_check: [u8; 16],
    },
}

impl SmpPdu {
    pub fn opcode(&self) -> SmpOpcode {
        match self {
            Self::PairingRequest { .. } => SmpOpcode::PairingRequest,
            Self::PairingResponse { .. } => SmpOpcode::PairingResponse,
            Self::PairingConfirm { .. } => SmpOpcode::PairingConfirm,
            Self::PairingRandom { .. } => SmpOpcode::PairingRandom,
            Self::PairingFailed { .. } => SmpOpcode::PairingFailed,
            Self::EncryptionInformation { .. } => SmpOpcode::EncryptionInformation,
            Self::MasterIdentification { .. } => SmpOpcode::MasterIdentification,
            Self::IdentityInformation { .. } => SmpOpcode::IdentityInformation,
            Self::IdentityAddressInformation { .. } => SmpOpcode::IdentityAddressInformation,
            Self::SigningInformation { .. } => SmpOpcode::SigningInformation,
            Self::SecurityRequest { .. } => SmpOpcode::SecurityRequest,
            Self::PairingPublicKey { .. } => SmpOpcode::PairingPublicKey,
            Self::PairingDhkeyCheck { .. } => SmpOpcode::PairingDhkeyCheck,
        }
    }
}

// ─── Encoding ────────────────────────────────────────────────────────────

impl EncodeToBuffer for SmpPdu {
    fn encode<B: BufferOps>(&self, buffer: &mut B) -> Result<usize, UtilsError> {
        let mut written = 0;
        written += buffer.try_push(self.opcode() as u8)?;

        match self {
            Self::PairingRequest {
                io_capability,
                oob_data_flag,
                auth_req,
                max_encryption_key_size,
                initiator_key_distribution,
                responder_key_distribution,
            }
            | Self::PairingResponse {
                io_capability,
                oob_data_flag,
                auth_req,
                max_encryption_key_size,
                initiator_key_distribution,
                responder_key_distribution,
            } => {
                written += buffer.try_push(*io_capability as u8)?;
                written += buffer.try_push(if *oob_data_flag { 0x01 } else { 0x00 })?;
                written += buffer.try_push(auth_req.to_byte())?;
                written += buffer.try_push(*max_encryption_key_size)?;
                written += buffer.try_push(initiator_key_distribution.to_byte())?;
                written += buffer.try_push(responder_key_distribution.to_byte())?;
            }
            Self::PairingConfirm { confirm_value } => {
                written += buffer.copy_from_slice(confirm_value)?;
            }
            Self::PairingRandom { random_value } => {
                written += buffer.copy_from_slice(random_value)?;
            }
            Self::PairingFailed { reason } => {
                written += buffer.try_push(*reason as u8)?;
            }
            Self::EncryptionInformation { long_term_key } => {
                written += buffer.copy_from_slice(long_term_key)?;
            }
            Self::MasterIdentification { ediv, rand } => {
                written += buffer.encode_le_u16(*ediv)?;
                written += buffer.copy_from_slice(rand)?;
            }
            Self::IdentityInformation { identity_resolving_key } => {
                written += buffer.copy_from_slice(identity_resolving_key)?;
            }
            Self::IdentityAddressInformation {
                address_type,
                address,
            } => {
                written += buffer.try_push(*address_type)?;
                written += buffer.copy_from_slice(address)?;
            }
            Self::SigningInformation {
                connection_signature_resolving_key,
            } => {
                written += buffer.copy_from_slice(connection_signature_resolving_key)?;
            }
            Self::SecurityRequest { auth_req } => {
                written += buffer.try_push(auth_req.to_byte())?;
            }
            Self::PairingPublicKey { x, y } => {
                written += buffer.copy_from_slice(&x[..])?;
                written += buffer.copy_from_slice(&y[..])?;
            }
            Self::PairingDhkeyCheck { dhkey_check } => {
                written += buffer.copy_from_slice(dhkey_check)?;
            }
        }

        Ok(written)
    }

    fn encoded_size(&self) -> usize {
        1 + match self {
            Self::PairingRequest { .. } | Self::PairingResponse { .. } => 6,
            Self::PairingConfirm { .. } => 16,
            Self::PairingRandom { .. } => 16,
            Self::PairingFailed { .. } => 1,
            Self::EncryptionInformation { .. } => 16,
            Self::MasterIdentification { .. } => 10,
            Self::IdentityInformation { .. } => 16,
            Self::IdentityAddressInformation { .. } => 7,
            Self::SigningInformation { .. } => 16,
            Self::SecurityRequest { .. } => 1,
            Self::PairingPublicKey { .. } => 64,
            Self::PairingDhkeyCheck { .. } => 16,
        }
    }
}

// ─── Decoding ────────────────────────────────────────────────────────────

pub(crate) mod parser {
    use nom::{
        bytes::complete::take,
        combinator::{map, map_res},
        number::complete::{le_u16, le_u8},
        IResult, Parser,
    };

    use super::*;

    fn smp_opcode(input: &[u8]) -> IResult<&[u8], SmpOpcode> {
        map_res(le_u8, SmpOpcode::try_from).parse(input)
    }

    fn io_capability(input: &[u8]) -> IResult<&[u8], IoCapability> {
        map_res(le_u8, IoCapability::try_from).parse(input)
    }

    fn auth_req(input: &[u8]) -> IResult<&[u8], AuthReq> {
        map(le_u8, AuthReq::from_byte).parse(input)
    }

    fn key_distribution(input: &[u8]) -> IResult<&[u8], KeyDistribution> {
        map(le_u8, KeyDistribution::from_byte).parse(input)
    }

    fn take_16(input: &[u8]) -> IResult<&[u8], [u8; 16]> {
        map_res(take(16usize), |slice: &[u8]| {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(slice);
            Ok::<_, nom::Err<nom::error::Error<&[u8]>>>(arr)
        })
        .parse(input)
    }

    fn take_8(input: &[u8]) -> IResult<&[u8], [u8; 8]> {
        map_res(take(8usize), |slice: &[u8]| {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(slice);
            Ok::<_, nom::Err<nom::error::Error<&[u8]>>>(arr)
        })
        .parse(input)
    }

    fn take_6(input: &[u8]) -> IResult<&[u8], [u8; 6]> {
        map_res(take(6usize), |slice: &[u8]| {
            let mut arr = [0u8; 6];
            arr.copy_from_slice(slice);
            Ok::<_, nom::Err<nom::error::Error<&[u8]>>>(arr)
        })
        .parse(input)
    }

    fn take_32(input: &[u8]) -> IResult<&[u8], [u8; 32]> {
        map_res(take(32usize), |slice: &[u8]| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(slice);
            Ok::<_, nom::Err<nom::error::Error<&[u8]>>>(arr)
        })
        .parse(input)
    }

    fn pairing_failed_reason(input: &[u8]) -> IResult<&[u8], PairingFailedReason> {
        map_res(le_u8, PairingFailedReason::try_from).parse(input)
    }

    /// Parse a complete SMP PDU from raw bytes (typically from ACL data on SMP channel).
    pub(crate) fn smp_pdu(input: &[u8]) -> IResult<&[u8], SmpPdu> {
        let (input, opcode) = smp_opcode(input)?;

        match opcode {
            SmpOpcode::PairingRequest | SmpOpcode::PairingResponse => {
                let (input, io_capability) = io_capability(input)?;
                let (input, oob_data) = le_u8(input)?;
                let (input, auth_req) = auth_req(input)?;
                let (input, max_key_size) = le_u8(input)?;
                let (input, initiator_key_dist) = key_distribution(input)?;
                let (input, responder_key_dist) = key_distribution(input)?;

                let pdu = if opcode == SmpOpcode::PairingRequest {
                    SmpPdu::PairingRequest {
                        io_capability,
                        oob_data_flag: oob_data != 0,
                        auth_req,
                        max_encryption_key_size: max_key_size,
                        initiator_key_distribution: initiator_key_dist,
                        responder_key_distribution: responder_key_dist,
                    }
                } else {
                    SmpPdu::PairingResponse {
                        io_capability,
                        oob_data_flag: oob_data != 0,
                        auth_req,
                        max_encryption_key_size: max_key_size,
                        initiator_key_distribution: initiator_key_dist,
                        responder_key_distribution: responder_key_dist,
                    }
                };
                Ok((input, pdu))
            }
            SmpOpcode::PairingConfirm => {
                let (input, confirm_value) = take_16(input)?;
                Ok((input, SmpPdu::PairingConfirm { confirm_value }))
            }
            SmpOpcode::PairingRandom => {
                let (input, random_value) = take_16(input)?;
                Ok((input, SmpPdu::PairingRandom { random_value }))
            }
            SmpOpcode::PairingFailed => {
                let (input, reason) = pairing_failed_reason(input)?;
                Ok((input, SmpPdu::PairingFailed { reason }))
            }
            SmpOpcode::EncryptionInformation => {
                let (input, long_term_key) = take_16(input)?;
                Ok((
                    input,
                    SmpPdu::EncryptionInformation { long_term_key },
                ))
            }
            SmpOpcode::MasterIdentification => {
                let (input, ediv) = le_u16(input)?;
                let (input, rand) = take_8(input)?;
                Ok((input, SmpPdu::MasterIdentification { ediv, rand }))
            }
            SmpOpcode::IdentityInformation => {
                let (input, identity_resolving_key) = take_16(input)?;
                Ok((
                    input,
                    SmpPdu::IdentityInformation {
                        identity_resolving_key,
                    },
                ))
            }
            SmpOpcode::IdentityAddressInformation => {
                let (input, address_type) = le_u8(input)?;
                let (input, address) = take_6(input)?;
                Ok((
                    input,
                    SmpPdu::IdentityAddressInformation {
                        address_type,
                        address,
                    },
                ))
            }
            SmpOpcode::SigningInformation => {
                let (input, connection_signature_resolving_key) = take_16(input)?;
                Ok((
                    input,
                    SmpPdu::SigningInformation {
                        connection_signature_resolving_key,
                    },
                ))
            }
            SmpOpcode::SecurityRequest => {
                let (input, auth_req) = auth_req(input)?;
                Ok((input, SmpPdu::SecurityRequest { auth_req }))
            }
            // LE Secure Connections PDUs
            SmpOpcode::PairingPublicKey => {
                let (input, x) = take_32(input)?;
                let (input, y) = take_32(input)?;
                Ok((input, SmpPdu::PairingPublicKey { x, y }))
            }
            SmpOpcode::PairingDhkeyCheck => {
                let (input, dhkey_check) = take_16(input)?;
                Ok((input, SmpPdu::PairingDhkeyCheck { dhkey_check }))
            }
            SmpOpcode::PairingKeypressNotification => {
                // Keypress notifications are optional — accept but don't parse payload
                Ok((&[] as &[u8], SmpPdu::SecurityRequest {
                    auth_req: AuthReq { bonding: false, mitm: false, secure_connections: false, keypress: false, ct2: false },
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bletio_utils::{Buffer, BufferOps};

    use super::*;

    fn encode_pdu(pdu: &SmpPdu) -> heapless::Vec<u8, 128> {
        let mut buffer: Buffer<256> = Buffer::default();
        pdu.encode(&mut buffer).unwrap();
        let mut v = heapless::Vec::new();
        v.extend_from_slice(buffer.data()).unwrap();
        v
    }

    #[test]
    fn test_pairing_request_roundtrip() {
        let pdu = SmpPdu::PairingRequest {
            io_capability: IoCapability::NoInputNoOutput,
            oob_data_flag: false,
            auth_req: AuthReq {
                bonding: true,
                mitm: false,
                secure_connections: false,
                keypress: false,
                ct2: false,
            },
            max_encryption_key_size: 16,
            initiator_key_distribution: KeyDistribution {
                enc_key: true,
                id_key: true,
                sign_key: false,
                link_key: false,
            },
            responder_key_distribution: KeyDistribution {
                enc_key: true,
                id_key: true,
                sign_key: false,
                link_key: false,
            },
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::smp_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_pairing_response_roundtrip() {
        let pdu = SmpPdu::PairingResponse {
            io_capability: IoCapability::DisplayOnly,
            oob_data_flag: false,
            auth_req: AuthReq {
                bonding: false,
                mitm: false,
                secure_connections: false,
                keypress: false,
                ct2: false,
            },
            max_encryption_key_size: 16,
            initiator_key_distribution: KeyDistribution {
                enc_key: false,
                id_key: false,
                sign_key: false,
                link_key: false,
            },
            responder_key_distribution: KeyDistribution {
                enc_key: false,
                id_key: false,
                sign_key: false,
                link_key: false,
            },
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::smp_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_pairing_confirm_roundtrip() {
        let val = [0xAAu8; 16];
        let pdu = SmpPdu::PairingConfirm { confirm_value: val };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::smp_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_pairing_random_roundtrip() {
        let val = [0x42u8; 16];
        let pdu = SmpPdu::PairingRandom { random_value: val };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::smp_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_pairing_failed_roundtrip() {
        let pdu = SmpPdu::PairingFailed {
            reason: PairingFailedReason::PasskeyEntryFailed,
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::smp_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_key_distribution_roundtrip() {
        let ltk = [0x11u8; 16];
        let pdu = SmpPdu::EncryptionInformation {
            long_term_key: ltk,
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::smp_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_security_request_roundtrip() {
        let pdu = SmpPdu::SecurityRequest {
            auth_req: AuthReq {
                bonding: true,
                mitm: true,
                secure_connections: false,
                keypress: false,
                ct2: false,
            },
        };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::smp_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_invalid_opcode() {
        let result = parser::smp_pdu(&[0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn fuzz_smp_pdu_parser_no_panic() {
        let inputs: &[&[u8]] = &[
            &[], &[0x01], &[0x01, 0x00], &[0x03],
            &[0x01, 0x03, 0x00, 0x01, 0x10, 0x03, 0x03],
            &[0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0xFFu8; 32],
            &[0u8; 32],
        ];
        for input in inputs {
            let _ = parser::smp_pdu(input);
        }
    }

    #[test]
    fn test_pairing_public_key_roundtrip() {
        let pdu = SmpPdu::PairingPublicKey { x: [0x01u8; 32], y: [0x02u8; 32] };
        let encoded = encode_pdu(&pdu);
        assert_eq!(encoded.len(), 65);
        assert_eq!(encoded[0], 0x0C); // PairingPublicKey opcode
        let (rest, decoded) = parser::smp_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_pairing_dhkey_check_roundtrip() {
        let pdu = SmpPdu::PairingDhkeyCheck { dhkey_check: [0x55u8; 16] };
        let encoded = encode_pdu(&pdu);
        let (rest, decoded) = parser::smp_pdu(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, pdu);
    }
}
