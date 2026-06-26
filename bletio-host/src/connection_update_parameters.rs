use core::ops::Deref;

use bletio_hci::{
    ConnectionEventLengthRange, ConnectionHandle, ConnectionIntervalRange, Latency,
    SupervisionTimeout,
};

use crate::Error;

/// Builder to create [`ConnectionUpdateParameters`].
#[derive(Debug, Default)]
pub struct ConnectionUpdateParametersBuilder {
    connection_handle: ConnectionHandle,
    connection_interval_range: ConnectionIntervalRange,
    max_latency: Latency,
    supervision_timeout: SupervisionTimeout,
    connection_event_length_range: ConnectionEventLengthRange,
}

impl ConnectionUpdateParametersBuilder {
    /// Create a builder to instantiate [`ConnectionUpdateParameters`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Try building the [`ConnectionUpdateParameters`], checking that every set parameters are valid.
    pub fn try_build(self) -> Result<ConnectionUpdateParameters, Error> {
        Ok(ConnectionUpdateParameters {
            inner: bletio_hci::ConnectionUpdateParameters::try_new(
                self.connection_handle,
                self.connection_interval_range,
                self.max_latency,
                self.supervision_timeout,
                self.connection_event_length_range,
            )
            .map_err(|_| Error::InvalidConnectionUpdateParameters)?,
        })
    }

    /// Define the connection event length range to be used.
    pub fn with_connection_event_length_range(
        mut self,
        connection_event_length_range: ConnectionEventLengthRange,
    ) -> Self {
        self.connection_event_length_range = connection_event_length_range;
        self
    }

    /// Define the connection handle of the connection to be updated.
    pub fn with_connection_handle(mut self, connection_handle: ConnectionHandle) -> Self {
        self.connection_handle = connection_handle;
        self
    }

    /// Define the connection interval range to be used.
    pub fn with_connection_interval_range(
        mut self,
        connection_interval_range: ConnectionIntervalRange,
    ) -> Self {
        self.connection_interval_range = connection_interval_range;
        self
    }

    /// Define the max latency to be used.
    pub fn with_max_latency(mut self, max_latency: Latency) -> Self {
        self.max_latency = max_latency;
        self
    }

    /// Define the supervision timeout to be used.
    pub fn with_supervision_timeout(mut self, supervision_timeout: SupervisionTimeout) -> Self {
        self.supervision_timeout = supervision_timeout;
        self
    }
}

/// Connection update parameters to use to create a connection.
///
/// It contains this information:
///  - the connection handle
///  - the connection interval range
///  - the max latency
///  - the supervision timeout
///  - the connection event length range
///
/// See [Core Specification 6.0, Vol.4, Part E, 7.8.18](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-60/out/en/host-controller-interface/host-controller-interface-functional-specification.html#UUID-93abb353-5b77-9ab0-096b-6d0e6052c788).
///
/// Use the [`ConnectionUpdateParametersBuilder`] to instantiate it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectionUpdateParameters {
    inner: bletio_hci::ConnectionUpdateParameters,
}

impl ConnectionUpdateParameters {
    /// Instantiate a builder to create Connection Parameters.
    pub fn builder() -> ConnectionUpdateParametersBuilder {
        ConnectionUpdateParametersBuilder::new()
    }
}

impl Deref for ConnectionUpdateParameters {
    type Target = bletio_hci::ConnectionUpdateParameters;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(test)]
mod test {
    use bletio_hci::{
        connection_event_length_range, connection_interval_range, latency, supervision_timeout,
    };

    use super::*;

    #[test]
    fn test_default_connection_update_parameters() -> Result<(), Error> {
        let params = ConnectionUpdateParameters::builder().try_build()?;
        assert_eq!(
            params.deref(),
            &bletio_hci::ConnectionUpdateParameters::default()
        );
        Ok(())
    }

    #[test]
    fn test_valid_connection_update_parameters() -> Result<(), Error> {
        let connection_event_length_range = connection_event_length_range!(16, 16);
        let connection_interval_range = connection_interval_range!(16, 32);
        let max_latency = latency!(0);
        let supervision_timeout = supervision_timeout!(16);
        let params = ConnectionUpdateParameters::builder()
            .with_connection_event_length_range(connection_event_length_range.clone())
            .with_connection_handle(ConnectionHandle::default())
            .with_connection_interval_range(connection_interval_range.clone())
            .with_max_latency(max_latency)
            .with_supervision_timeout(supervision_timeout)
            .try_build()?;
        assert_eq!(
            params.connection_event_length_range(),
            &connection_event_length_range
        );
        assert_eq!(params.connection_handle().value(), 0);
        assert_eq!(
            params.connection_interval_range(),
            &connection_interval_range
        );
        assert_eq!(params.max_latency(), max_latency);
        assert_eq!(params.supervision_timeout(), supervision_timeout);
        Ok(())
    }

    #[test]
    fn test_invalid_connection_update_parameters_supervision_timeout_too_short() {
        let err = ConnectionUpdateParameters::builder()
            .with_connection_interval_range(connection_interval_range!(0x0030, 0x0050))
            .with_supervision_timeout(supervision_timeout!(0x0010))
            .try_build();
        assert_eq!(err, Err(Error::InvalidConnectionUpdateParameters));
    }
}

// ─── Connection Profiles ─────────────────────────────────────────────────

/// Pre-defined connection parameter profiles for common use cases.
///
/// Each profile maps to a set of connection interval, latency, and supervision
/// timeout values optimized for a specific use case per the Bluetooth Core Spec
/// recommendations.
///
/// # Usage
///
/// ```ignore
/// use bletio_host::connection_update_parameters::ConnectionProfile;
///
/// let profile = ConnectionProfile::LowPower;
/// let params = profile.to_update_params(connection_handle)?;
/// host.update_connection(params).await?;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConnectionProfile {
    /// Low power — long connection interval, high latency.
    /// Interval: 100–125 ms. Good for battery-powered sensors.
    LowPower,
    /// Balanced — medium interval, low latency.
    /// Interval: 25–35 ms. Good for general-purpose peripherals.
    Balanced,
    /// High throughput — short interval, zero latency.
    /// Interval: 7.5–15 ms. Good for firmware updates or bulk data.
    HighThroughput,
    /// Low latency — short interval, zero latency, short timeout.
    /// Interval: 7.5–15 ms, timeout 100 ms. Good for HID devices.
    LowLatency,
    /// Custom — user-defined parameters.
    Custom {
        interval_min_ms: u16,
        interval_max_ms: u16,
        latency: u16,
        supervision_timeout_ms: u16,
    },
}

impl ConnectionProfile {
    /// Convert a profile into a [`ConnectionUpdateParameters`] for the given connection handle.
    ///
    /// Returns an error if the parameters are invalid (e.g. supervision timeout too short
    /// relative to the interval range and latency).
    pub fn to_update_params(
        &self,
        connection_handle: bletio_hci::ConnectionHandle,
    ) -> Result<ConnectionUpdateParameters, Error> {
        let (interval_min, interval_max, latency, timeout) = match self {
            Self::LowPower => (100, 125, 1, 2000),
            Self::Balanced => (25, 35, 0, 500),
            Self::HighThroughput => (8, 15, 0, 200),
            Self::LowLatency => (8, 15, 0, 100),
            Self::Custom {
                interval_min_ms,
                interval_max_ms,
                latency,
                supervision_timeout_ms,
            } => (
                *interval_min_ms,
                *interval_max_ms,
                *latency,
                *supervision_timeout_ms,
            ),
        };

        // Convert milliseconds to 1.25ms units for the BLE stack
        let interval_min_units = (interval_min as f32 / 1.25) as u16;
        let interval_max_units = (interval_max as f32 / 1.25) as u16;
        let timeout_units = (timeout as f32 / 10.0) as u16;

        ConnectionUpdateParameters::builder()
            .with_connection_handle(connection_handle)
            .with_connection_interval_range(
                bletio_hci::ConnectionIntervalRange::try_new(interval_min_units, interval_max_units)
                    .map_err(|_| Error::InvalidConnectionUpdateParameters)?
            )
            .with_max_latency(bletio_hci::Latency::try_new(latency).map_err(|_| Error::InvalidConnectionUpdateParameters)?)
            .with_supervision_timeout(bletio_hci::SupervisionTimeout::try_new(timeout_units).map_err(|_| Error::InvalidConnectionUpdateParameters)?)
            .try_build()
    }
}

impl Default for ConnectionProfile {
    fn default() -> Self {
        Self::Balanced
    }
}

#[cfg(test)]
mod profile_tests {
    use bletio_hci::ConnectionHandle;

    use super::*;

    #[test]
    fn test_low_power_profile() {
        let params = ConnectionProfile::LowPower
            .to_update_params(ConnectionHandle::default())
            .unwrap();
        // 100ms → 80 units → 100ms (exact)
        assert_eq!(params.connection_interval_range().min().milliseconds(), 100.0);
        assert_eq!(params.max_latency().value(), 1);
    }

    #[test]
    fn test_low_latency_profile() {
        let params = ConnectionProfile::LowLatency
            .to_update_params(ConnectionHandle::default())
            .unwrap();
        // 8ms / 1.25 = 6 units → 6 * 1.25 = 7.5ms
        assert_eq!(params.connection_interval_range().min().milliseconds(), 7.5);
        assert_eq!(params.max_latency().value(), 0);
    }

    #[test]
    fn test_custom_profile() {
        let params = ConnectionProfile::Custom {
            interval_min_ms: 30,
            interval_max_ms: 50,
            latency: 2,
            supervision_timeout_ms: 1000,
        }
        .to_update_params(ConnectionHandle::default())
        .unwrap();
        // 30ms → 24 units → 30ms (exact)
        assert_eq!(params.connection_interval_range().min().milliseconds(), 30.0);
        assert_eq!(params.connection_interval_range().max().milliseconds(), 50.0);
        assert_eq!(params.max_latency().value(), 2);
        assert_eq!(params.supervision_timeout().milliseconds(), 1000.0);
    }
}
