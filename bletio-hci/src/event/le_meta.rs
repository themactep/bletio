use num_enum::{FromPrimitive, IntoPrimitive};

use crate::{LeAdvertisingReportList, LeConnectionCompleteEvent, LeConnectionUpdateCompleteEvent};

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(clippy::large_enum_variant)]
pub enum LeMetaEvent {
    LeConnectionComplete(LeConnectionCompleteEvent),
    LeAdvertisingReport(LeAdvertisingReportList),
    LeConnectionUpdateComplete(LeConnectionUpdateCompleteEvent),
    LePhyUpdateComplete(crate::event::le_phy_update_complete::LePhyUpdateCompleteEvent),
    LeFlowControlCredit(crate::event::le_flow_control_credit::LeFlowControlCreditEvent),
    LeExtendedAdvertisingReport(crate::event::le_extended_advertising_report::LeExtendedAdvertisingReport),
    /// BLE 5.2+ isochronous events (CIS/BIG).
    IsochronousUnsupported(u8),
    /// BLE 5.4 PAwR events.
    PawrUnsupported(u8),
    Unsupported(u8),
}

#[derive(Debug, IntoPrimitive, FromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
enum LeMetaEventCode {
    LeConnectionComplete = 0x01,
    LeAdvertisingReport = 0x02,
    LeConnectionUpdateComplete = 0x03,
    LePhyUpdateComplete = 0x0C,
    LeExtendedAdvertisingReport = 0x0D,
    LeFlowControlCredit = 0x0E,
    // Isochronous Channels (BLE 5.2)
    LeCisEstablished = 0x19,
    LeCisRequest = 0x1A,
    LeBigInfoAdvertisingReport = 0x22,
    // PAwR (BLE 5.4)
    LePeriodicAdvertisingResponseReport = 0x26,
    #[num_enum(catch_all)]
    Unsupported(u8),
}

pub(crate) mod parser {
    use nom::{combinator::map_res, number::complete::le_u8, IResult, Parser};

    use super::*;
    use crate::event::le_advertising_report::parser::le_advertising_report_event;
    use crate::event::le_connection_complete::parser::le_connection_complete_event;
    use crate::event::le_connection_update_complete::parser::le_connection_update_complete_event;
    use crate::event::le_flow_control_credit::parser::le_flow_control_credit_event;
    use crate::event::le_phy_update_complete::parser::le_phy_update_complete_event;
    use crate::event::le_extended_advertising_report::parser::le_extended_advertising_report_event;

    fn le_meta_event_code(input: &[u8]) -> IResult<&[u8], LeMetaEventCode> {
        map_res(le_u8, LeMetaEventCode::try_from).parse(input)
    }

    pub(crate) fn le_meta_event(input: &[u8]) -> IResult<&[u8], LeMetaEvent> {
        let (parameters, le_meta_event_code) = le_meta_event_code(input)?;
        match le_meta_event_code {
            LeMetaEventCode::LeConnectionComplete => le_connection_complete_event(parameters),
            LeMetaEventCode::LeAdvertisingReport => le_advertising_report_event(parameters),
            LeMetaEventCode::LeConnectionUpdateComplete => {
                le_connection_update_complete_event(parameters)
            }
            LeMetaEventCode::LePhyUpdateComplete => {
                le_phy_update_complete_event(parameters)
            }
            LeMetaEventCode::LeFlowControlCredit => {
                le_flow_control_credit_event(parameters)
            }
            LeMetaEventCode::LeExtendedAdvertisingReport => {
                le_extended_advertising_report_event(parameters)
            }
            // Isochronous/PAwR events — parsed as unsupported for now
            LeMetaEventCode::LeCisEstablished
            | LeMetaEventCode::LeCisRequest
            | LeMetaEventCode::LeBigInfoAdvertisingReport => {
                Ok((&[], LeMetaEvent::IsochronousUnsupported(u8::from(le_meta_event_code))))
            }
            LeMetaEventCode::LePeriodicAdvertisingResponseReport => {
                Ok((&[], LeMetaEvent::PawrUnsupported(u8::from(le_meta_event_code))))
            }
            LeMetaEventCode::Unsupported(event_code) => {
                Ok((&[], LeMetaEvent::Unsupported(event_code)))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{packet::parser::packet, Event, LeMetaEvent, Packet};

    #[test]
    fn test_unsupported_le_meta_event_parsing() {
        // Using LE Monitored Advertisers Report event
        let (rest, packet) = packet(&[
            0x04, 0x3E, 0x09, 0x34, 0x00, 0xCD, 0x2E, 0x0B, 0x04, 0x32, 0x56, 0x00,
        ])
        .unwrap();
        assert!(matches!(
            packet,
            Packet::Event(Event::LeMeta(LeMetaEvent::Unsupported(0x34)))
        ));
        assert!(rest.is_empty());
    }
}
