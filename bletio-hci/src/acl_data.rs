use bletio_utils::{Buffer, BufferOps, EncodeToBuffer, Error as UtilsError};
use num_enum::TryFromPrimitive;

use crate::{ConnectionHandle, Error, PacketType};

pub(crate) const ACL_DATA_MAX_SIZE: usize = 27;

/// Packet boundary flag of an ACL data packet.
///
/// See [Core Specification 6.0, Vol. 4, Part E, 5.4.2](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-60/out/en/host-controller-interface/host-controller-interface-functional-specification.html#UUID-bc4ffa33-44ef-e93c-16c8-14aa99597cfc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[num_enum(error_type(name = Error, constructor = Error::InvalidPacketBoundaryFlag))]
#[repr(u8)]
#[non_exhaustive]
pub enum PacketBoundaryFlag {
    /// First non-automatically-flushable packet of a higher layer message (start of a
    /// non-automatically-flushable L2CAP PDU) from Host to Controller.
    FirstNonAutomaticallyFlushablePacket = 0b00,
    /// Continuing fragment of a higher layer message.
    ContinuingFragment = 0b01,
    /// First automatically flushable packet of a higher layer message (start of an
    /// automatically-flushable L2CAP PDU).
    FirstAutomaticallyFlushablePacket = 0b10,
}

/// Broadcast flag of an ACL data packet.
///
/// See [Core Specification 6.0, Vol. 4, Part E, 5.4.2](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-60/out/en/host-controller-interface/host-controller-interface-functional-specification.html#UUID-bc4ffa33-44ef-e93c-16c8-14aa99597cfc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[num_enum(error_type(name = Error, constructor = Error::InvalidBroadcastFlag))]
#[repr(u8)]
#[non_exhaustive]
pub enum BroadcastFlag {
    /// Point-to-point (ACL-U or LE-U).
    PointToPoint,
    /// BR/EDR broadcast (APB-U).
    BrEdrBroadcast,
}

/// ACL data packet received from or to be sent to the controller.
///
/// Represents an HCI ACL Data Packet per [Core Spec 6.0, Vol. 4, Part E, §5.4.2].
/// ACL data carries L2CAP PDUs which in turn carry ATT, SMP, or other upper-layer data.
///
/// Use [`build`](Self::build) to construct packets for sending, or inspect received
/// packets via [`handle`](Self::handle), [`data`](Self::data), and the flag accessors.
///
/// Maximum payload size is constrained by the controller's buffer size
/// (obtained via [`cmd_le_read_buffer_size`](crate::Hci::cmd_le_read_buffer_size)).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AclData {
    handle: ConnectionHandle,
    packet_boundary_flag: PacketBoundaryFlag,
    broadcast_flag: BroadcastFlag,
    data: Buffer<ACL_DATA_MAX_SIZE>,
}

impl AclData {
    pub(crate) fn try_new(
        handle: ConnectionHandle,
        packet_boundary_flag: PacketBoundaryFlag,
        broadcast_flag: BroadcastFlag,
        data: &[u8],
    ) -> Result<Self, Error> {
        let mut s = Self {
            handle,
            packet_boundary_flag,
            broadcast_flag,
            data: Buffer::default(),
        };
        s.data
            .copy_from_slice(data)
            .map_err(|_| Error::DataWillNotFitAclDataPacket)?;
        Ok(s)
    }

    /// The connection handle this ACL data is associated with.
    pub fn handle(&self) -> ConnectionHandle {
        self.handle
    }

    /// The packet boundary flag (start/continuation of an L2CAP PDU).
    pub fn packet_boundary_flag(&self) -> PacketBoundaryFlag {
        self.packet_boundary_flag
    }

    /// The broadcast flag (point-to-point or broadcast).
    pub fn broadcast_flag(&self) -> BroadcastFlag {
        self.broadcast_flag
    }

    /// The ACL payload data.
    pub fn data(&self) -> &[u8] {
        self.data.data()
    }

    /// Length of the ACL payload.
    pub fn data_len(&self) -> usize {
        self.data.len()
    }

    /// Build an ACL data packet for sending.
    pub fn build(
        handle: ConnectionHandle,
        packet_boundary_flag: PacketBoundaryFlag,
        broadcast_flag: BroadcastFlag,
        data: &[u8],
    ) -> Result<Self, Error> {
        Self::try_new(handle, packet_boundary_flag, broadcast_flag, data)
    }
}

impl EncodeToBuffer for AclData {
    fn encode<B: BufferOps>(&self, buffer: &mut B) -> Result<usize, UtilsError> {
        // Encode the HCI ACL data header: Connection Handle + PB Flag + BC Flag (2 bytes)
        let handle_flags: u16 = self.handle.value()
            | ((self.packet_boundary_flag as u16) << 12)
            | ((self.broadcast_flag as u16) << 14);
        let mut written = 0;

        // Packet type
        buffer.try_push(PacketType::AclData as u8)?;
        written += 1;

        // Connection handle + flags
        written += buffer.encode_le_u16(handle_flags)?;

        // Data total length
        written += buffer.encode_le_u16(self.data.len() as u16)?;

        // Payload data
        written += buffer.copy_from_slice(self.data())?;

        Ok(written)
    }

    fn encoded_size(&self) -> usize {
        // Packet Type (1) + Handle+Flags (2) + Data Length (2) + Payload
        5 + self.data.len()
    }
}

pub(crate) mod parser {
    use nom::bytes::take;
    use nom::{combinator::map_res, number::complete::le_u16, IResult, Parser};

    use super::*;
    use crate::{packet::Packet, ConnectionHandle};

    fn connection_handle_and_flags(
        input: &[u8],
    ) -> IResult<&[u8], (ConnectionHandle, PacketBoundaryFlag, BroadcastFlag)> {
        map_res(le_u16, |v| {
            let connection_handle = ConnectionHandle::try_new(v & 0xEFF)?;
            let packet_boundary_flag: PacketBoundaryFlag =
                (((v >> 12) & 0b0011) as u8).try_into()?;
            let broadcast_flag: BroadcastFlag = ((v >> 14) as u8).try_into()?;
            Ok::<_, Error>((connection_handle, packet_boundary_flag, broadcast_flag))
        })
        .parse(input)
    }

    fn data_total_length(input: &[u8]) -> IResult<&[u8], u16> {
        le_u16(input)
    }

    pub(crate) fn acl_data(input: &[u8]) -> IResult<&[u8], Packet> {
        let (rest, ((connection_handle, packet_boundary_flag, broadcast_flag), data_total_length)) =
            (connection_handle_and_flags, data_total_length).parse(input)?;
        let (rest, acl_data) = map_res(take(data_total_length), |data| {
            AclData::try_new(
                connection_handle,
                packet_boundary_flag,
                broadcast_flag,
                data,
            )
        })
        .parse(rest)?;
        Ok((rest, Packet::AclData(acl_data)))
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::packet::parser::packet;
    use crate::Packet;

    #[rstest]
    #[case(
        &[2, 0, 32, 16, 0, 12, 0, 5, 0, 18, 1, 8, 0, 24, 0, 40, 0, 0, 0, 42, 0],
        Packet::AclData(AclData::try_new(
            ConnectionHandle::try_new(0).unwrap(),
            PacketBoundaryFlag::FirstAutomaticallyFlushablePacket,
            BroadcastFlag::PointToPoint,
            &[12, 0, 5, 0, 18, 1, 8, 0, 24, 0, 40, 0, 0, 0, 42, 0]
        ).unwrap())
    )]
    fn test_acl_data_parsing_success(#[case] input: &[u8], #[case] expected: Packet) {
        assert_eq!(packet(input), Ok((&[] as &[u8], expected)));
    }
}
