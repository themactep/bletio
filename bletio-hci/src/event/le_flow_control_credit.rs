//! LE Flow Control Credit event.
//!
//! See [Core Specification 6.0, Vol. 4, Part E, 7.7.65.14](https://www.bluetooth.com/).

use crate::ConnectionHandle;

/// LE Flow Control Credit event (LE Meta sub-event 0x0E).
///
/// The controller sends this event to return credits to the host. Each entry
/// indicates a connection handle and the number of credits returned. The host
/// increments its credit count for that connection by the given amount.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeFlowControlCreditEvent {
    /// Number of connection entries in this event.
    pub count: u8,
    /// Pairs of (connection_handle, credits_returned).
    pub entries: heapless::Vec<(ConnectionHandle, u16), 4>,
}

impl LeFlowControlCreditEvent {
    pub(crate) fn new(
        count: u8,
        entries: heapless::Vec<(ConnectionHandle, u16), 4>,
    ) -> Self {
        Self { count, entries }
    }
}

pub(crate) mod parser {
    use heapless::Vec;
    use nom::{combinator::map_res, number::complete::{le_u8, le_u16}, IResult, Parser};

    use super::*;
    use crate::connection::connection_handle::parser::connection_handle;
    use crate::event::le_meta::LeMetaEvent;

    pub(crate) fn le_flow_control_credit_event(
        input: &[u8],
    ) -> IResult<&[u8], LeMetaEvent> {
        let (mut rest, count) = le_u8(input)?;
        let mut entries = Vec::<(ConnectionHandle, u16), 4>::new();

        for _ in 0..count {
            let (r, handle) = connection_handle(rest)?;
            let (r, credits) = le_u16(r)?;
            rest = r;
            let _ = entries.push((handle, credits));
        }

        Ok((rest, LeMetaEvent::LeFlowControlCredit(
            LeFlowControlCreditEvent::new(count, entries),
        )))
    }
}

#[cfg(test)]
mod tests {
    use crate::{packet::parser::packet, Event, LeMetaEvent, Packet, ConnectionHandle};

    use super::*;

    #[test]
    fn test_le_flow_control_credit_event_parsing() {
        // Event: LE Meta, sub-event 0x0E, count=2, handle=0, credits=10, handle=1, credits=5
        let data = [0x04, 0x3E, 0x0A, 0x0E, 0x02, 0x00, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x05, 0x00];
        let (rest, packet) = packet(&data).unwrap();
        assert!(rest.is_empty());
        match packet {
            Packet::Event(Event::LeMeta(LeMetaEvent::LeFlowControlCredit(event))) => {
                assert_eq!(event.count, 2);
                assert_eq!(event.entries.len(), 2);
                assert_eq!(event.entries[0], (ConnectionHandle::try_new(0).unwrap(), 10));
                assert_eq!(event.entries[1], (ConnectionHandle::try_new(1).unwrap(), 5));
            }
            _ => panic!("Unexpected packet"),
        }
    }
}
