//! Data Buffer Overflow event.
//!
//! See [Core Specification 6.0, Vol. 4, Part E, 7.7.16](https://www.bluetooth.com/).

use crate::ConnectionHandle;

/// Data Buffer Overflow event (event code 0x1A).
///
/// Indicates that the controller's data buffers have overflowed. The host should
/// reduce the rate at which it sends ACL data packets to the controller.
/// Multiple link types may be reported in the same event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DataBufferOverflowEvent {
    /// The link type that caused the overflow (1 = ACL, 2 = SCO/eSCO).
    pub link_type: u8,
}

impl DataBufferOverflowEvent {
    pub(crate) fn new(link_type: u8) -> Self {
        Self { link_type }
    }

    /// Returns true if the overflow was on the ACL link.
    pub fn is_acl_overflow(&self) -> bool {
        self.link_type == 0x01
    }

    /// Returns true if the overflow was on the SCO/eSCO link.
    pub fn is_sco_overflow(&self) -> bool {
        self.link_type == 0x02
    }
}

pub(crate) mod parser {
    use nom::{combinator::map, number::complete::le_u8, IResult, Parser};

    use super::*;

    pub(crate) fn data_buffer_overflow_event(input: &[u8]) -> IResult<&[u8], DataBufferOverflowEvent> {
        map(le_u8, DataBufferOverflowEvent::new).parse(input)
    }
}

#[cfg(test)]
mod tests {
    use crate::{packet::parser::packet, Event, Packet};

    use super::*;

    #[test]
    fn test_data_buffer_overflow_event_parsing() {
        let expected = DataBufferOverflowEvent::new(0x01);
        let (rest, packet) = packet(&[0x04, 0x1A, 0x01, 0x01]).unwrap();
        assert_eq!(packet, Packet::Event(Event::DataBufferOverflow(expected)));
        assert!(rest.is_empty());
    }

    #[test]
    fn test_data_buffer_overflow_flags() {
        let event = DataBufferOverflowEvent::new(0x01);
        assert!(event.is_acl_overflow());
        assert!(!event.is_sco_overflow());

        let event = DataBufferOverflowEvent::new(0x02);
        assert!(event.is_sco_overflow());
        assert!(!event.is_acl_overflow());
    }
}
