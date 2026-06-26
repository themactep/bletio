use core::ops::{Deref, DerefMut};

use heapless::Vec;
use num_enum::{FromPrimitive, IntoPrimitive};

use crate::event::command_status::CommandStatusEvent;
use crate::event::data_buffer_overflow::DataBufferOverflowEvent;
use crate::event::hardware_error::HardwareErrorEvent;
use crate::{AclData, CommandCompleteEvent, DisconnectionCompleteEvent, LeMetaEvent};

pub(crate) mod command_complete;
pub(crate) mod command_status;
pub(crate) mod data_buffer_overflow;
pub(crate) mod disconnection_complete;
pub(crate) mod hardware_error;
pub(crate) mod le_advertising_report;
pub(crate) mod le_connection_complete;
pub(crate) mod le_connection_update_complete;
pub(crate) mod le_extended_advertising_report;
pub(crate) mod le_flow_control_credit;
pub(crate) mod le_meta;
pub(crate) mod le_phy_update_complete;

/// Number of events that can be buffered before older events are dropped.
///
/// Adjust this if you experience event loss under bursty advertising or
/// connection traffic. Each event is ~264 bytes on the stack.
const EVENT_LIST_NB_EVENTS: usize = 8;

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    AclData(AclData),
    CommandComplete(CommandCompleteEvent),
    CommandStatus(CommandStatusEvent),
    DataBufferOverflow(DataBufferOverflowEvent),
    DisconnectionComplete(DisconnectionCompleteEvent),
    HardwareError(HardwareErrorEvent),
    LeMeta(LeMetaEvent),
    Unsupported(u8),
}

#[derive(Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EventList {
    events: Vec<Event, EVENT_LIST_NB_EVENTS>,
}

impl Deref for EventList {
    type Target = Vec<Event, EVENT_LIST_NB_EVENTS>;

    fn deref(&self) -> &Self::Target {
        &self.events
    }
}

impl DerefMut for EventList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.events
    }
}

#[derive(Debug, IntoPrimitive, FromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
enum EventCode {
    DisconnectionComplete = 0x05,
    HardwareError = 0x10,
    DataBufferOverflow = 0x1A,
    CommandComplete = 0x0E,
    CommandStatus = 0x0F,
    LeMeta = 0x3E,
    #[num_enum(catch_all)]
    Unsupported(u8),
}

pub(crate) mod parser {
    use nom::{
        bytes::take, combinator::map_res, number::complete::le_u8, sequence::pair, IResult, Parser,
    };

    use super::*;
    use crate::event::command_status::parser::command_status_event;
    use crate::event::data_buffer_overflow::parser::data_buffer_overflow_event;
    use crate::event::disconnection_complete::parser::disconnection_complete_event;
    use crate::event::hardware_error::parser::hardware_error_event;
    use crate::{
        event::{
            command_complete::parser::command_complete_event, le_meta::parser::le_meta_event,
            EventCode,
        },
        packet::parser::parameter_total_length,
        ErrorCode, Packet,
    };

    fn event_code(input: &[u8]) -> IResult<&[u8], EventCode> {
        map_res(le_u8, EventCode::try_from).parse(input)
    }

    pub(crate) fn num_hci_command_packets(input: &[u8]) -> IResult<&[u8], u8> {
        le_u8.parse(input)
    }

    pub(crate) fn hci_error_code(input: &[u8]) -> IResult<&[u8], ErrorCode> {
        map_res(le_u8, ErrorCode::try_from).parse(input)
    }

    pub(crate) fn event(input: &[u8]) -> IResult<&[u8], Packet> {
        let (input, (event_code, parameter_total_length)) =
            pair(event_code, parameter_total_length).parse(input)?;
        let (input, parameters) = take(parameter_total_length).parse(input)?;
        Ok((
            input,
            Packet::Event(match event_code {
                EventCode::DisconnectionComplete => {
                    let (_, event) = disconnection_complete_event(parameters)?;
                    Event::DisconnectionComplete(event)
                }
                EventCode::HardwareError => {
                    let (_, event) = hardware_error_event(parameters)?;
                    Event::HardwareError(event)
                }
                EventCode::DataBufferOverflow => {
                    let (_, event) = data_buffer_overflow_event(parameters)?;
                    Event::DataBufferOverflow(event)
                }
                EventCode::CommandComplete => {
                    let (_, event) = command_complete_event(parameters)?;
                    Event::CommandComplete(event)
                }
                EventCode::CommandStatus => {
                    let (_, event) = command_status_event(parameters)?;
                    Event::CommandStatus(event)
                }
                EventCode::LeMeta => {
                    let (_, event) = le_meta_event(parameters)?;
                    Event::LeMeta(event)
                }
                EventCode::Unsupported(event_code) => Event::Unsupported(event_code),
            }),
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::{packet::parser::packet, Packet};

    use super::*;

    #[test]
    fn test_event_code() {
        let event_code: EventCode = 0x0Eu8.into();
        assert!(matches!(event_code, EventCode::CommandComplete));

        let event_code: EventCode = 0xFFu8.into();
        assert!(matches!(event_code, EventCode::Unsupported(0xFF)));
    }

    #[test]
    fn test_event_list() {
        let event_list = EventList::default();
        assert_eq!(event_list.deref(), &event_list.events);
    }

    #[test]
    fn test_unsupported_event_parsing() {
        // Using Inquiry Complete event
        let (rest, packet) = packet(&[4, 1, 1, 0]).unwrap();
        assert!(matches!(packet, Packet::Event(Event::Unsupported(1))));
        assert!(rest.is_empty());
    }

    // ── Fuzz tests ─────────────────────────────────────────────────────

    #[test]
    fn fuzz_event_parser_no_panic() {
        let inputs: &[&[u8]] = &[
            &[], &[4], &[4, 0], &[4, 0, 0],
            &[4, 0xFF, 0, 0],
            &[4, 1, 50, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            &[0xFFu8; 32],
            &[0u8; 32],
        ];
        for input in inputs {
            let _ = super::parser::event(input);
        }
    }
}
