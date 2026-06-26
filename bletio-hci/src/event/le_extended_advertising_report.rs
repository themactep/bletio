//! LE Extended Advertising Report event (BLE 5.0).
//!
//! See [Core Specification 6.0, Vol. 4, Part E, 7.7.65.13](https://www.bluetooth.com/).

use crate::{ConnectionPeerAddress, Error, Rssi};

/// LE Extended Advertising Report event type (LE Meta sub-event 0x0D).
///
/// Carries advertising reports from BLE 5.0 extended advertising. Each report
/// includes the advertising set handle, event type, address, RSSI, and data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeExtendedAdvertisingReport {
    /// Number of reports in this event.
    pub num_reports: u8,
    /// Advertising event type (connectable, scannable, directed, scan response, legacy).
    pub event_type: u16,
    /// Address type (0 = public, 1 = random, etc.).
    pub address_type: u8,
    /// Advertiser address.
    pub address: ConnectionPeerAddress,
    /// Primary advertising PHY (1 = LE 1M, 2 = LE 2M, 4 = LE Coded).
    pub primary_phy: u8,
    /// Secondary advertising PHY.
    pub secondary_phy: u8,
    /// Advertising SID (set ID, 0x00–0x0F).
    pub advertising_sid: u8,
    /// Transmit power in dBm (127 = unknown).
    pub tx_power: i8,
    /// RSSI in dBm (127 = unknown).
    pub rssi: i8,
    /// Periodic advertising interval (0 = no periodic advertising).
    pub periodic_advertising_interval: u16,
    /// Direct address type (for directed advertising).
    pub direct_address_type: u8,
    /// Direct address (for directed advertising).
    pub direct_address: ConnectionPeerAddress,
    /// Length of the advertising data.
    pub data_length: u8,
    /// Raw advertising data bytes.
    pub data: heapless::Vec<u8, 255>,
}

impl LeExtendedAdvertisingReport {
    pub(crate) fn new(
        num_reports: u8,
        event_type: u16,
        address_type: u8,
        address: ConnectionPeerAddress,
        primary_phy: u8,
        secondary_phy: u8,
        advertising_sid: u8,
        tx_power: i8,
        rssi: i8,
        periodic_advertising_interval: u16,
        direct_address_type: u8,
        direct_address: ConnectionPeerAddress,
        data: heapless::Vec<u8, 255>,
    ) -> Self {
        Self {
            num_reports, event_type, address_type, address,
            primary_phy, secondary_phy, advertising_sid,
            tx_power, rssi, periodic_advertising_interval,
            direct_address_type, direct_address, data_length: data.len() as u8,
            data,
        }
    }

    /// Returns the RSSI as an [`Rssi`] value, or `None` if unknown.
    pub fn rssi_value(&self) -> Option<Rssi> {
        Rssi::try_new(self.rssi).ok()
    }
}

pub(crate) mod parser {
    use heapless::Vec;
    use nom::{
        bytes::complete::take,
        combinator::map_res,
        number::complete::{le_u16, le_u8, i8 as le_i8},
        IResult, Parser,
    };

    use super::*;
    use crate::connection::connection_peer_address::parser::connection_peer_address;
    use crate::event::le_meta::LeMetaEvent;

    pub(crate) fn le_extended_advertising_report_event(
        input: &[u8],
    ) -> IResult<&[u8], LeMetaEvent> {
        let (rest, num_reports) = le_u8(input)?;
        let (rest, event_type) = le_u16(rest)?;
        let (rest, address_type) = le_u8(rest)?;
        let (rest, address) = connection_peer_address(rest)?;
        let (rest, primary_phy) = le_u8(rest)?;
        let (rest, secondary_phy) = le_u8(rest)?;
        let (rest, advertising_sid) = le_u8(rest)?;
        let (rest, tx_power) = le_i8(rest)?;
        let (rest, rssi) = le_i8(rest)?;
        let (rest, periodic_advertising_interval) = le_u16(rest)?;
        let (rest, direct_address_type) = le_u8(rest)?;
        let (rest, direct_address) = connection_peer_address(rest)?;
        let (rest, data_length) = le_u8(rest)?;
        let (rest, data) = map_res(take(data_length as usize), |d: &[u8]| {
            let mut v = Vec::new();
            v.extend_from_slice(d).map_err(|_| {
                nom::Err::<nom::error::Error<&[u8]>>::Failure(nom::error::Error::new(rest, nom::error::ErrorKind::TooLarge))
            })?;
            Ok::<_, nom::Err<nom::error::Error<&[u8]>>>(v)
        }).parse(rest)?;

        Ok((rest, LeMetaEvent::LeExtendedAdvertisingReport(
            LeExtendedAdvertisingReport::new(
                num_reports, event_type, address_type, address,
                primary_phy, secondary_phy, advertising_sid,
                tx_power, rssi, periodic_advertising_interval,
                direct_address_type, direct_address,
                data,
            ),
        )))
    }
}
