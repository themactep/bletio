//! LE PHY Update Complete event.
//!
//! See [Core Specification 6.0, Vol. 4, Part E, 7.7.65.12](https://www.bluetooth.com/).

use crate::{ConnectionHandle, Error};

/// LE PHY types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum LePhy {
    /// LE 1M PHY.
    Le1M = 0x01,
    /// LE 2M PHY.
    Le2M = 0x02,
    /// LE Coded PHY with S=8 coding.
    LeCodedS8 = 0x03,
    /// LE Coded PHY with S=2 coding.
    LeCodedS2 = 0x04,
}

impl TryFrom<u8> for LePhy {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Le1M),
            0x02 => Ok(Self::Le2M),
            0x03 => Ok(Self::LeCodedS8),
            0x04 => Ok(Self::LeCodedS2),
            _ => Err(Error::InvalidPacket),
        }
    }
}

/// LE PHY Update Complete event (LE Meta sub-event 0x0C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LePhyUpdateCompleteEvent {
    /// Status of the PHY update.
    pub status: crate::ErrorCode,
    /// Connection handle.
    pub connection_handle: ConnectionHandle,
    /// Current transmitter PHY.
    pub tx_phy: LePhy,
    /// Current receiver PHY.
    pub rx_phy: LePhy,
}

impl LePhyUpdateCompleteEvent {
    pub(crate) fn new(
        status: crate::ErrorCode,
        connection_handle: ConnectionHandle,
        tx_phy: LePhy,
        rx_phy: LePhy,
    ) -> Self {
        Self {
            status,
            connection_handle,
            tx_phy,
            rx_phy,
        }
    }
}

pub(crate) mod parser {
    use nom::{combinator::map_res, number::complete::le_u8, sequence::tuple, IResult, Parser};

    use super::*;
    use crate::connection::connection_handle::parser::connection_handle;
    use crate::event::le_meta::LeMetaEvent;
    use crate::event::parser::hci_error_code;

    pub(crate) fn le_phy_update_complete_event(
        input: &[u8],
    ) -> IResult<&[u8], LeMetaEvent> {
        let (input, (status, connection_handle, tx_phy, rx_phy)) = tuple((
            hci_error_code,
            connection_handle,
            map_res(le_u8, LePhy::try_from),
            map_res(le_u8, LePhy::try_from),
        ))
        .parse(input)?;

        Ok((
            input,
            LeMetaEvent::LePhyUpdateComplete(LePhyUpdateCompleteEvent::new(
                status,
                connection_handle,
                tx_phy,
                rx_phy,
            )),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{packet::parser::packet, Event, LeMetaEvent, Packet};

    use super::*;

    #[test]
    fn test_le_phy_update_complete_event_parsing() {
        let (rest, packet) = packet(&[
            0x04, 0x3E, 0x06, 0x0C, 0x00, 0x00, 0x00, 0x01, 0x01,
        ])
        .unwrap();
        match packet {
            Packet::Event(Event::LeMeta(LeMetaEvent::LePhyUpdateComplete(event))) => {
                assert_eq!(event.status, crate::ErrorCode::Success);
                assert_eq!(event.connection_handle.value(), 0);
                assert_eq!(event.tx_phy, LePhy::Le1M);
                assert_eq!(event.rx_phy, LePhy::Le1M);
            }
            _ => panic!("Unexpected packet: {:?}", packet),
        }
        assert!(rest.is_empty());
    }
}
