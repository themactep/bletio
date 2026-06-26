//! ATT client state machine for sending requests and matching responses.
//!
//! The client tracks one outstanding request at a time (ATT is strictly sequential).
//! It encodes PDUs for sending over ACL and parses incoming ACL data to match responses.
//!
//! # Usage with BleHostObserver
//!
//! ```ignore
//! struct MyObserver { att: AttClient }
//!
//! impl BleHostObserver for MyObserver {
//!     async fn acl_data_received<H: HciDriver>(
//!         &self, host: BleHostStates<H>, acl: &AclData,
//!     ) -> BleHostStates<H> {
//!         if let Some(response) = self.att.receive(&acl.data()) {
//!             // handle response PDU
//!         }
//!         host
//!     }
//! }
//! ```

use bletio_utils::{Buffer, BufferOps, EncodeToBuffer};

use super::att_pdu::{AttError, AttErrorCode, AttHandle, AttOpcode, AttPdu, AttUuid, AttValue};

/// State of the ATT client.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum AttClientState {
    /// No request outstanding; ready to send.
    Idle,
    /// A request has been sent and we're waiting for the matching response.
    AwaitingResponse {
        /// The opcode of the request we sent (used for error response matching).
        request_opcode: AttOpcode,
        /// The expected response opcode.
        expected_response_opcode: AttOpcode,
    },
    /// We sent an indication and are waiting for a confirmation.
    AwaitingConfirmation,
}

/// ATT client for sending requests and receiving responses.
///
/// Tracks the ATT MTU, one outstanding request, and parses incoming ACL data
/// into response PDUs.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttClient {
    /// Negotiated ATT MTU (defaults to 23 per spec).
    mtu: u16,
    state: AttClientState,
}

impl AttClient {
    /// Create a new ATT client in the Idle state with default MTU (23).
    pub fn new() -> Self {
        Self {
            mtu: 23,
            state: AttClientState::Idle,
        }
    }

    /// Returns the current ATT MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Returns true if the client is ready to send a new request.
    pub fn is_ready(&self) -> bool {
        self.state == AttClientState::Idle
    }

    // ── Request preparation (encoding) ──────────────────────────────────

    /// Prepare an Exchange MTU request. Returns the encoded bytes to send over ACL.
    pub fn prepare_exchange_mtu(&mut self, client_rx_mtu: u16) -> Result<EncodedAttPdu, AttError> {
        let pdu = AttPdu::ExchangeMtuRequest { client_rx_mtu };
        self.prepare_request(pdu, AttOpcode::ExchangeMtuResponse)
    }

    /// Prepare a Find Information request.
    pub fn prepare_find_information(
        &mut self,
        starting_handle: AttHandle,
        ending_handle: AttHandle,
    ) -> Result<EncodedAttPdu, AttError> {
        let pdu = AttPdu::FindInformationRequest {
            starting_handle,
            ending_handle,
        };
        self.prepare_request(pdu, AttOpcode::FindInformationResponse)
    }

    /// Prepare a Read By Group Type request (service discovery).
    pub fn prepare_read_by_group_type(
        &mut self,
        starting_handle: AttHandle,
        ending_handle: AttHandle,
        group_type: AttUuid,
    ) -> Result<EncodedAttPdu, AttError> {
        let pdu = AttPdu::ReadByGroupTypeRequest {
            starting_handle,
            ending_handle,
            attribute_group_type: group_type,
        };
        self.prepare_request(pdu, AttOpcode::ReadByGroupTypeResponse)
    }

    /// Prepare a Read By Type request (characteristic discovery).
    pub fn prepare_read_by_type(
        &mut self,
        starting_handle: AttHandle,
        ending_handle: AttHandle,
        attribute_type: AttUuid,
    ) -> Result<EncodedAttPdu, AttError> {
        let pdu = AttPdu::ReadByTypeRequest {
            starting_handle,
            ending_handle,
            attribute_type,
        };
        self.prepare_request(pdu, AttOpcode::ReadByTypeResponse)
    }

    /// Prepare a Read request.
    pub fn prepare_read(
        &mut self,
        attribute_handle: AttHandle,
    ) -> Result<EncodedAttPdu, AttError> {
        let pdu = AttPdu::ReadRequest { attribute_handle };
        self.prepare_request(pdu, AttOpcode::ReadResponse)
    }

    /// Prepare a Read Blob request (long value continuation).
    pub fn prepare_read_blob(
        &mut self,
        attribute_handle: AttHandle,
        value_offset: u16,
    ) -> Result<EncodedAttPdu, AttError> {
        let pdu = AttPdu::ReadBlobRequest {
            attribute_handle,
            value_offset,
        };
        self.prepare_request(pdu, AttOpcode::ReadBlobResponse)
    }

    /// Prepare a Write Request (with response).
    pub fn prepare_write_request(
        &mut self,
        attribute_handle: AttHandle,
        value: &[u8],
    ) -> Result<EncodedAttPdu, AttError> {
        let pdu = AttPdu::WriteRequest {
            attribute_handle,
            attribute_value: AttValue::new(value)?,
        };
        self.prepare_request(pdu, AttOpcode::WriteResponse)
    }

    /// Prepare a Write Command (no response — does not change client state).
    pub fn prepare_write_command(
        &self,
        attribute_handle: AttHandle,
        value: &[u8],
    ) -> Result<EncodedAttPdu, AttError> {
        let pdu = AttPdu::WriteCommand {
            attribute_handle,
            attribute_value: AttValue::new(value)?,
        };
        Self::encode_pdu(&pdu)
    }

    /// Prepare a Handle Value Notification (server → client, no response).
    pub fn prepare_notification(
        &self,
        attribute_handle: AttHandle,
        value: &[u8],
    ) -> Result<EncodedAttPdu, AttError> {
        let pdu = AttPdu::HandleValueNotification {
            attribute_handle,
            attribute_value: AttValue::new(value)?,
        };
        Self::encode_pdu(&pdu)
    }

    /// Prepare a Handle Value Indication (server → client, await confirmation).
    pub fn prepare_indication(
        &mut self,
        attribute_handle: AttHandle,
        value: &[u8],
    ) -> Result<EncodedAttPdu, AttError> {
        let pdu = AttPdu::HandleValueIndication {
            attribute_handle,
            attribute_value: AttValue::new(value)?,
        };
        let encoded = Self::encode_pdu(&pdu)?;
        self.state = AttClientState::AwaitingConfirmation;
        Ok(encoded)
    }

    /// Manually prepare any request PDU and set the expected response.
    pub fn prepare_request(
        &mut self,
        pdu: AttPdu,
        expected_response: AttOpcode,
    ) -> Result<EncodedAttPdu, AttError> {
        if !self.is_ready() {
            return Err(AttError::Timeout); // Reuse: client is busy
        }
        let request_opcode = pdu.opcode();
        let encoded = Self::encode_pdu(&pdu)?;
        self.state = AttClientState::AwaitingResponse {
            request_opcode,
            expected_response_opcode: expected_response,
        };
        Ok(encoded)
    }

    // ── Response processing ────────────────────────────────────────────

    /// Feed received ACL data to the client. If the data completes a pending
    /// request, returns the response PDU. Returns `Ok(None)` if the data is
    /// handled but doesn't complete a request (e.g. notifications).
    ///
    /// Returns an error for malformed PDUs or unexpected responses.
    pub fn receive(&mut self, data: &[u8]) -> Result<Option<AttPdu>, AttError> {
        let pdu = super::att_pdu::parser::att_pdu(data)
            .map(|(_, pdu)| pdu)
            .map_err(|_| AttError::InvalidPdu)?;

        match &self.state {
            AttClientState::Idle => {
                // We're not expecting a response, but we may receive
                // unsolicited notifications/indications.
                match pdu.opcode() {
                    AttOpcode::HandleValueNotification
                    | AttOpcode::HandleValueIndication => Ok(Some(pdu)),
                    _ => {
                        // Unexpected PDU while idle — could be stale data
                        Ok(None)
                    }
                }
            }
            AttClientState::AwaitingResponse {
                request_opcode,
                expected_response_opcode,
            } => {
                let response_opcode = pdu.opcode();
                if response_opcode == *expected_response_opcode {
                    self.state = AttClientState::Idle;
                    Ok(Some(pdu))
                } else if response_opcode == AttOpcode::ErrorResponse {
                    // Error responses are always valid responses to any request
                    self.state = AttClientState::Idle;
                    Ok(Some(pdu))
                } else if response_opcode == AttOpcode::HandleValueNotification
                    || response_opcode == AttOpcode::HandleValueIndication
                {
                    // Server can send notifications while a request is outstanding.
                    // Return the notification but don't change state — the response
                    // is still pending.
                    Ok(Some(pdu))
                } else {
                    Err(AttError::UnexpectedPdu {
                        expected: (*expected_response_opcode) as u8,
                        received: response_opcode as u8,
                    })
                }
            }
            AttClientState::AwaitingConfirmation => {
                if pdu.opcode() == AttOpcode::HandleValueConfirmation {
                    self.state = AttClientState::Idle;
                    Ok(Some(pdu))
                } else {
                    Err(AttError::UnexpectedPdu {
                        expected: AttOpcode::HandleValueConfirmation as u8,
                        received: pdu.opcode() as u8,
                    })
                }
            }
        }
    }

    // ── Internal helpers ────────────────────────────────────────────────

    fn encode_pdu(pdu: &AttPdu) -> Result<EncodedAttPdu, AttError> {
        let mut buffer: Buffer<512> = Buffer::default();
        pdu
            .encode(&mut buffer)
            .map_err(|_| AttError::ValueTooLong)?;
        Ok(EncodedAttPdu::from_buffer(buffer, pdu.encoded_size()))
    }
}

impl Default for AttClient {
    fn default() -> Self {
        Self::new()
    }
}

/// An encoded ATT PDU ready to be sent over ACL.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EncodedAttPdu {
    data: Buffer<512>,
    len: usize,
}

impl EncodedAttPdu {
    /// Create a new encoded PDU from a Buffer and its logical length.
    pub(crate) fn from_buffer(data: Buffer<512>, len: usize) -> Self {
        Self { data, len }
    }

    /// Returns the raw bytes of the encoded PDU.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data.data()[..self.len]
    }

    /// Returns the length of the encoded PDU in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the PDU is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use bletio_utils::{Buffer, BufferOps, EncodeToBuffer};

    use super::*;

    fn e(data: &[u8]) -> heapless::Vec<u8, 512> {
        let mut v = heapless::Vec::new();
        v.extend_from_slice(data).unwrap();
        v
    }

    #[test]
    fn test_att_client_new_is_idle() {
        let client = AttClient::new();
        assert!(client.is_ready());
        assert_eq!(client.mtu(), 23);
    }

    #[test]
    fn test_exchange_mtu_roundtrip() {
        let mut client = AttClient::new();

        // Prepare request
        let encoded = client.prepare_exchange_mtu(517).unwrap();
        assert!(!client.is_ready());

        // Simulate response
        let response_pdu = AttPdu::ExchangeMtuResponse { server_rx_mtu: 65 };
        let mut buffer: Buffer<512> = Buffer::default();
        response_pdu.encode(&mut buffer).unwrap();
        let response_bytes = buffer.data();

        // Process response
        let result = client.receive(&response_bytes).unwrap();
        assert!(client.is_ready());
        assert_eq!(
            result,
            Some(AttPdu::ExchangeMtuResponse { server_rx_mtu: 65 })
        );
    }

    #[test]
    fn test_error_response_clears_pending() {
        let mut client = AttClient::new();

        // Send read request
        client
            .prepare_read(AttHandle(0x0003))
            .unwrap();
        assert!(!client.is_ready());

        // Server responds with error
        let error_pdu = AttPdu::ErrorResponse {
            request_opcode: AttOpcode::ReadRequest,
            attribute_handle: AttHandle(0x0003),
            error_code: AttErrorCode::ReadNotPermitted,
        };
        let mut buffer: Buffer<512> = Buffer::default();
        error_pdu.encode(&mut buffer).unwrap();

        let result = client.receive(buffer.data()).unwrap();
        assert!(client.is_ready());
        assert_eq!(result, Some(error_pdu));
    }

    #[test]
    fn test_write_command_does_not_change_state() {
        let client = AttClient::new();
        assert!(client.is_ready());

        // Write command should not set state to awaiting
        let encoded = client.prepare_write_command(AttHandle(0x0010), &[0x01]).unwrap();
        assert!(client.is_ready());
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_notification_does_not_change_state() {
        let client = AttClient::new();
        assert!(client.is_ready());

        let encoded = client.prepare_notification(AttHandle(0x0015), &[0x42]).unwrap();
        assert!(client.is_ready());
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_indication_await_confirmation() {
        let mut client = AttClient::new();

        // Send indication
        client
            .prepare_indication(AttHandle(0x0015), &[0x42])
            .unwrap();
        assert!(!client.is_ready());

        // Server confirms
        let conf_pdu = AttPdu::HandleValueConfirmation;
        let mut buffer: Buffer<512> = Buffer::default();
        conf_pdu.encode(&mut buffer).unwrap();

        let result = client.receive(buffer.data()).unwrap();
        assert!(client.is_ready());
        assert_eq!(result, Some(conf_pdu));
    }

    #[test]
    fn test_unexpected_response_returns_error() {
        let mut client = AttClient::new();

        // Send read request
        client
            .prepare_read(AttHandle(0x0003))
            .unwrap();

        // Server sends wrong response type
        let wrong_pdu = AttPdu::WriteResponse;
        let mut buffer: Buffer<512> = Buffer::default();
        wrong_pdu.encode(&mut buffer).unwrap();

        let result = client.receive(buffer.data());
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_send_two_requests() {
        let mut client = AttClient::new();

        client.prepare_read(AttHandle(0x0003)).unwrap();
        let result = client.prepare_read(AttHandle(0x0004));
        assert!(result.is_err());
    }

    #[test]
    fn test_read_multiple_requests_sequential() {
        let mut client = AttClient::new();

        // First request
        client.prepare_read(AttHandle(0x0003)).unwrap();
        let response = AttPdu::ReadResponse {
            attribute_value: AttValue::new(&[0x01, 0x02]).unwrap(),
        };
        let mut buf: Buffer<512> = Buffer::default();
        response.encode(&mut buf).unwrap();
        client.receive(buf.data()).unwrap();
        assert!(client.is_ready());

        // Second request
        client.prepare_read(AttHandle(0x0004)).unwrap();
        let response2 = AttPdu::ReadResponse {
            attribute_value: AttValue::new(&[0xFF]).unwrap(),
        };
        let mut buf2: Buffer<512> = Buffer::default();
        response2.encode(&mut buf2).unwrap();
        let result = client.receive(buf2.data()).unwrap();
        assert_eq!(result, Some(response2));
        assert!(client.is_ready());
    }
}
