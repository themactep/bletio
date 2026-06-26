//! Power profiling and low-power optimization helpers.
//!
//! Provides estimates of current draw and battery life based on BLE connection
//! and advertising parameters. All values are estimates assuming typical BLE
//! controller characteristics (nRF52-class). Actual power consumption varies
//! with the specific controller, TX power, and environmental factors.
//!
//! # Quick estimates
//!
//! ```ignore
//! use bletio_host::power::PowerEstimator;
//!
//! let est = PowerEstimator::default();
//!
//! // Estimate battery life for a peripheral advertising at 1-second intervals
//! let hours = est.advertising_battery_hours(1000, 220); // 1000ms interval, 220mAh battery
//! println!("Battery life: ~{} hours ({:.1} days)", hours, hours as f32 / 24.0);
//!
//! // Estimate connected battery life
//! let hours = est.connected_battery_hours(30, 4, 100, 220); // 30ms interval, 4s latency, 100ms payload, 220mAh
//! ```

/// Typical BLE controller current draws in microamps (µA).
///
/// These values are approximate for an nRF52840 at 0dBm TX power with DC/DC enabled.
/// Adjust for your specific controller and TX power level.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PowerProfile {
    /// Current draw during a TX/RX radio event (µA). Typical: 5000–7000.
    pub radio_event_ua: u32,
    /// Current draw during idle/sleep (µA). Typical: 1–3 for System ON sleep.
    pub sleep_ua: u32,
    /// Current draw during advertising TX (µA). Typical: 6000.
    pub adv_tx_ua: u32,
    /// Current draw during advertising RX (µA). Typical: 6000.
    pub adv_rx_ua: u32,
    /// Duration of a single radio event in microseconds (µs). Typical: 800–2500.
    pub radio_event_duration_us: u32,
    /// Duration of an advertising event in microseconds (µs). Typical: 2000.
    pub adv_event_duration_us: u32,
}

impl Default for PowerProfile {
    fn default() -> Self {
        Self {
            radio_event_ua: 5500,
            sleep_ua: 2,
            adv_tx_ua: 6000,
            adv_rx_ua: 6000,
            radio_event_duration_us: 1500,
            adv_event_duration_us: 2500,
        }
    }
}

/// Battery capacity presets for common coin-cell and Li-Po batteries.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BatteryCapacity {
    /// CR2032 coin cell (~220 mAh).
    Cr2032,
    /// CR2450 coin cell (~620 mAh).
    Cr2450,
    /// CR2477 coin cell (~1000 mAh).
    Cr2477,
    /// Small Li-Po (~150 mAh).
    Lipo150,
    /// Medium Li-Po (~500 mAh).
    Lipo500,
    /// Large Li-Po (~2000 mAh).
    Lipo2000,
    /// Custom capacity in mAh.
    CustomMah(u32),
}

impl BatteryCapacity {
    /// Capacity in milliampere-hours (mAh).
    pub fn mah(&self) -> u32 {
        match self {
            Self::Cr2032 => 220,
            Self::Cr2450 => 620,
            Self::Cr2477 => 1000,
            Self::Lipo150 => 150,
            Self::Lipo500 => 500,
            Self::Lipo2000 => 2000,
            Self::CustomMah(mah) => *mah,
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &str {
        match self {
            Self::Cr2032 => "CR2032 (220 mAh)",
            Self::Cr2450 => "CR2450 (620 mAh)",
            Self::Cr2477 => "CR2477 (1000 mAh)",
            Self::Lipo150 => "Li-Po 150 mAh",
            Self::Lipo500 => "Li-Po 500 mAh",
            Self::Lipo2000 => "Li-Po 2000 mAh",
            Self::CustomMah(_) => "Custom",
        }
    }
}

/// Advertising interval presets optimized for different power targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AdvertisingPowerProfile {
    /// Aggressive discovery: 100ms interval. Best responsiveness, highest power.
    Aggressive,
    /// Balanced: 500ms interval. Good balance of latency and power.
    Balanced,
    /// Power saving: 1000ms (1s) interval. Good for battery-powered beacons.
    PowerSaving,
    /// Extreme power saving: 2000ms (2s) interval. Maximum battery life.
    ExtremePowerSaving,
    /// Custom interval in milliseconds (20–10240 ms range per BLE spec).
    CustomMs(u32),
}

impl AdvertisingPowerProfile {
    /// Advertising interval in milliseconds.
    pub fn interval_ms(&self) -> u32 {
        match self {
            Self::Aggressive => 100,
            Self::Balanced => 500,
            Self::PowerSaving => 1000,
            Self::ExtremePowerSaving => 2000,
            Self::CustomMs(ms) => core::cmp::max(*ms, 20),
        }
    }

    /// Human-readable description.
    pub fn description(&self) -> &str {
        match self {
            Self::Aggressive => "Aggressive (100ms) — short latency, higher power",
            Self::Balanced => "Balanced (500ms) — good for general use",
            Self::PowerSaving => "Power Saving (1s) — reduced duty cycle",
            Self::ExtremePowerSaving => "Extreme Power Saving (2s) — maximum battery life",
            Self::CustomMs(_) => "Custom interval",
        }
    }
}

/// Power consumption estimator for battery life calculations.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PowerEstimator {
    profile: PowerProfile,
}

impl PowerEstimator {
    /// Create with default power profile (nRF52-class).
    pub fn new() -> Self {
        Self {
            profile: PowerProfile::default(),
        }
    }

    /// Create with a custom power profile.
    pub fn with_profile(profile: PowerProfile) -> Self {
        Self { profile }
    }

    /// Estimate average current draw while advertising (µA).
    ///
    /// `interval_ms` is the advertising interval in milliseconds.
    pub fn advertising_average_current_ua(&self, interval_ms: u32) -> u32 {
        let interval_us = interval_ms * 1000;
        let event_power = (self.profile.adv_tx_ua + self.profile.adv_rx_ua)
            * self.profile.adv_event_duration_us;
        let idle_power = self.profile.sleep_ua * (interval_us - self.profile.adv_event_duration_us);

        (event_power + idle_power) / interval_us
    }

    /// Estimate average current draw while connected (µA).
    ///
    /// `connection_interval_ms` is the connection interval in milliseconds.
    /// `latency` is the number of connection events that can be skipped.
    /// `payload_time_us` is the estimated payload transmission time in microseconds
    /// (typically 300–800 µs for a small notification).
    pub fn connected_average_current_ua(
        &self,
        connection_interval_ms: u32,
        latency: u32,
        payload_time_us: u32,
    ) -> u32 {
        let effective_interval_us = connection_interval_ms * 1000 * (latency + 1);
        let event_power = self.profile.radio_event_ua * (self.profile.radio_event_duration_us + payload_time_us);
        let idle_power = self.profile.sleep_ua * (effective_interval_us.saturating_sub(self.profile.radio_event_duration_us + payload_time_us));

        (event_power + idle_power) / effective_interval_us.max(1)
    }

    /// Estimate battery life in hours while advertising.
    pub fn advertising_battery_hours(
        &self,
        interval_ms: u32,
        battery: BatteryCapacity,
    ) -> u32 {
        let avg_ua = self.advertising_average_current_ua(interval_ms);
        if avg_ua == 0 {
            return u32::MAX;
        }
        (battery.mah() * 1000) / avg_ua
    }

    /// Estimate battery life in hours while connected.
    pub fn connected_battery_hours(
        &self,
        connection_interval_ms: u32,
        latency: u32,
        payload_time_us: u32,
        battery: BatteryCapacity,
    ) -> u32 {
        let avg_ua = self.connected_average_current_ua(connection_interval_ms, latency, payload_time_us);
        if avg_ua == 0 {
            return u32::MAX;
        }
        (battery.mah() * 1000) / avg_ua
    }

    /// Get a human-readable battery life estimate.
    pub fn format_battery_life(&self, hours: u32) -> heapless::String<64> {
        let mut s = heapless::String::new();
        if hours >= 8760 {
            // >= 1 year
            let _ = core::fmt::write(&mut s, format_args!("~{:.1} years", hours as f32 / 8760.0));
        } else if hours >= 720 {
            // >= 1 month
            let _ = core::fmt::write(&mut s, format_args!("~{:.0} days", hours as f32 / 24.0));
        } else if hours >= 48 {
            let _ = core::fmt::write(&mut s, format_args!("~{:.0} days", hours as f32 / 24.0));
        } else {
            let _ = core::fmt::write(&mut s, format_args!("~{:.0} hours", hours as f32));
        }
        s
    }
}

impl Default for PowerEstimator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advertising_power_profiles() {
        assert_eq!(AdvertisingPowerProfile::Aggressive.interval_ms(), 100);
        assert_eq!(AdvertisingPowerProfile::Balanced.interval_ms(), 500);
        assert_eq!(AdvertisingPowerProfile::PowerSaving.interval_ms(), 1000);
        assert_eq!(AdvertisingPowerProfile::ExtremePowerSaving.interval_ms(), 2000);
        assert_eq!(AdvertisingPowerProfile::CustomMs(10).interval_ms(), 20); // clamped
        assert_eq!(AdvertisingPowerProfile::CustomMs(3000).interval_ms(), 3000);
    }

    #[test]
    fn test_battery_capacity() {
        assert_eq!(BatteryCapacity::Cr2032.mah(), 220);
        assert_eq!(BatteryCapacity::Cr2450.mah(), 620);
        assert_eq!(BatteryCapacity::Lipo500.mah(), 500);
        assert_eq!(BatteryCapacity::CustomMah(100).mah(), 100);
    }

    #[test]
    fn test_power_estimator_advertising() {
        let est = PowerEstimator::default();

        // Aggressive advertising
        let current_100ms = est.advertising_average_current_ua(100);
        // Power saving advertising
        let current_1000ms = est.advertising_average_current_ua(1000);

        // Power saving should draw significantly less average current
        assert!(current_1000ms < current_100ms);

        // CR2032 battery life
        let hours = est.advertising_battery_hours(1000, BatteryCapacity::Cr2032);
        // Should be reasonable (a few hundred hours at least)
        assert!(hours > 100);
    }

    #[test]
    fn test_power_estimator_connected() {
        let est = PowerEstimator::default();

        // Low power connection (100ms interval, latency 1)
        let low_power = est.connected_average_current_ua(100, 1, 500);
        // High throughput connection (10ms interval, no latency)
        let high_throughput = est.connected_average_current_ua(10, 0, 500);

        // Low power should draw less
        assert!(low_power < high_throughput);

        // Battery life estimate
        let hours = est.connected_battery_hours(100, 1, 500, BatteryCapacity::Cr2032);
        assert!(hours > 50);
    }

    #[test]
    fn test_format_battery_life() {
        let est = PowerEstimator::default();

        let s = est.format_battery_life(24);
        assert!(s.contains("day") || s.contains("hour"));

        let s = est.format_battery_life(10000);
        assert!(s.contains("year"));
    }
}
