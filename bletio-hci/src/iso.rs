//! LE Isochronous Channels scaffolding (BLE 5.2).
//!
//! Provides command opcodes and event types for Connected Isochronous Streams
//! (CIS) and Broadcast Isochronous Streams (BIS). Full implementation requires
//! ISO data packet handling in the HCI layer.
//!
//! See [Core Specification 6.0, Vol. 4, Part E, §7.8.95+](https://www.bluetooth.com/).

use crate::ConnectionHandle;

// ─── ISO data packet type ────────────────────────────────────────────────

/// HCI packet type indicator for ISO data packets (0x05).
pub const ISO_DATA_PACKET_TYPE: u8 = 0x05;

/// ISO data packet header flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct IsoDataHeader {
    /// Connection handle (12 bits).
    pub connection_handle: ConnectionHandle,
    /// Packet boundary flag (2 bits).
    pub pb_flag: u8,
    /// Timestamp flag.
    pub ts_flag: bool,
    /// Packet sequence number (2 bits).
    pub packet_sequence_number: u8,
    /// ISO data load length (14 bits).
    pub iso_data_load_length: u16,
}

// ─── CIS / CIG types ─────────────────────────────────────────────────────

/// CIG (Connected Isochronous Group) identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CigId(pub u8);

/// CIS (Connected Isochronous Stream) identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CisId(pub u8);

/// CIS parameters for CIG setup.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CisParams {
    pub cis_id: CisId,
    pub max_sdu_m_to_s: u16,
    pub max_sdu_s_to_m: u16,
    pub phy_m_to_s: u8,
    pub phy_s_to_m: u8,
    pub rtn_m_to_s: u8,
    pub rtn_s_to_m: u8,
}

/// ISO data path direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum IsoDataPathDirection {
    Input = 0x00,
    Output = 0x01,
}

// ─── CIS events ──────────────────────────────────────────────────────────

/// LE CIS Established event (LE Meta sub-event 0x19).
///
/// Sent when a CIS connection is established.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeCisEstablishedEvent {
    pub status: crate::ErrorCode,
    pub connection_handle: ConnectionHandle,
    pub cig_sync_delay: [u8; 3],
    pub cis_sync_delay: [u8; 3],
    pub transport_latency_m_to_s: [u8; 3],
    pub transport_latency_s_to_m: [u8; 3],
    pub phy_m_to_s: u8,
    pub phy_s_to_m: u8,
    pub nse: u8,
    pub bn_m_to_s: u8,
    pub bn_s_to_m: u8,
    pub ft_m_to_s: u8,
    pub ft_s_to_m: u8,
    pub max_pdu_m_to_s: u16,
    pub max_pdu_s_to_m: u16,
    pub iso_interval: u16,
}

/// LE CIS Request event (LE Meta sub-event 0x1A).
///
/// Controller requests host to accept/reject a CIS.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeCisRequestEvent {
    pub acl_connection_handle: ConnectionHandle,
    pub cis_connection_handle: ConnectionHandle,
    pub cig_id: u8,
    pub cis_id: u8,
}

/// LE BIG (Broadcast Isochronous Group) Info Advertising Report
/// (LE Meta sub-event 0x22).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeBigInfoAdvertisingReportEvent {
    pub sync_handle: u16,
    pub num_bis: u8,
    pub nse: u8,
    pub iso_interval: u16,
    pub bn: u8,
    pub pto: u8,
    pub irc: u8,
    pub max_pdu: u16,
    pub sdu_interval: [u8; 3],
    pub max_sdu: u16,
    pub phy: u8,
    pub framing: u8,
    pub encryption: bool,
}
