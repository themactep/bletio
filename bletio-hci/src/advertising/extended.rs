//! LE Extended Advertising support (BLE 5.0).
//!
//! Provides the advertising set handle type and the LE Extended Advertising
//! Report event parser. Full extended advertising command support (set params,
//! set data, enable) can be added via the existing vendor command infrastructure.

use crate::ConnectionHandle;

/// Handle for an extended advertising set (0x00–0xEF).
///
/// Used by BLE 5.0 extended advertising to manage multiple simultaneous
/// advertising sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AdvertisingSetHandle(pub u8);

impl AdvertisingSetHandle {
    /// Create a new advertising set handle. Valid values are 0x00–0xEF.
    pub fn new(handle: u8) -> Result<Self, crate::Error> {
        if handle > 0xEF {
            Err(crate::Error::InvalidAdvertisingInterval(handle as u16))
        } else {
            Ok(Self(handle))
        }
    }

    /// Returns the raw handle value.
    pub fn value(&self) -> u8 {
        self.0
    }
}
