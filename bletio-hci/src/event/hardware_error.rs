//! Hardware Error event.
//!
//! See [Core Specification 6.0, Vol. 4, Part E, 7.7.19](https://www.bluetooth.com/).

use crate::Error;

/// Hardware Error event (event code 0x10).
///
/// Indicates a hardware failure in the controller. The `hardware_code` is
/// vendor-specific and indicates the type of failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct HardwareErrorEvent {
    /// Vendor-specific hardware error code.
    pub hardware_code: u8,
}

impl HardwareErrorEvent {
    pub(crate) fn new(hardware_code: u8) -> Self {
        Self { hardware_code }
    }
}

pub(crate) mod parser {
    use nom::{combinator::map, number::complete::le_u8, IResult, Parser};

    use super::*;

    pub(crate) fn hardware_error_event(input: &[u8]) -> IResult<&[u8], HardwareErrorEvent> {
        map(le_u8, HardwareErrorEvent::new).parse(input)
    }
}

#[cfg(test)]
mod tests {
    use crate::{packet::parser::packet, Event, Packet};

    use super::*;

    #[test]
    fn test_hardware_error_event_parsing() {
        let expected = HardwareErrorEvent::new(0x42);
        let (rest, packet) = packet(&[0x04, 0x10, 0x01, 0x42]).unwrap();
        assert_eq!(packet, Packet::Event(Event::HardwareError(expected)));
        assert!(rest.is_empty());
    }
}
