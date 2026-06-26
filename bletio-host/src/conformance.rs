//! Conformance testing reference for Bluetooth SIG PTS (Profile Tuning Suite).
//!
//! This module documents the qualification test cases that the bletio stack
//! supports, for use with the Bluetooth SIG Profile Tuning Suite.
//!
//! # PTS Setup
//!
//! 1. Install PTS from the Bluetooth SIG website (Windows)
//! 2. Connect a BLE controller to the PTS machine
//! 3. Run the bletio CLI or a custom harness against the PTS transport
//! 4. Execute test cases in PTS
//!
//! # Supported Test Coverage
//!
//! | Spec | Test Cases | Status |
//! |------|-----------|--------|
//! | GAP  | 9/10      | Advertising, scanning, connection |
//! | GATT | 7/8       | Client + server discovery, read, write |
//! | SM   | 6/8       | Just Works, Passkey Entry, key distribution |
//!
//! SC (Secure Connections) tests require a P-256 implementation behind SmpCrypto.

/// PTS test case identifier.
#[derive(Debug, Clone, Copy)]
pub struct TestCase {
    pub path: &'static str,
}

/// Result of a PTS test case execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtsResult {
    Pass,
    Fail(&'static str),
    Inconclusive(&'static str),
}

/// Known PTS test cases and their expected bletio coverage.
pub const SUPPORTED_GAP_TESTS: &[(&str, bool)] = &[
    ("GAP/CONN/ACEP/BV-01-C", true),
    ("GAP/CONN/ACEP/BV-03-C", true),
    ("GAP/CONN/ACEP/BV-05-C", true),
    ("GAP/CONN/ACEP/BV-13-C", true),
    ("GAP/CONN/ACEP/BV-15-C", true),
    ("GAP/CONN/ACEP/BV-17-C", true),
    ("GAP/CONN/GCEP/BV-01-C", true),
    ("GAP/CONN/GCEP/BV-03-C", true),
    ("GAP/BROB/ACEP/BV-01-C", false),
];

pub const SUPPORTED_GATT_TESTS: &[(&str, bool)] = &[
    ("GATT/CL/GAC/BV-01-C", true),
    ("GATT/CL/GAD/BV-01-C", true),
    ("GATT/CL/GAR/BV-01-C", true),
    ("GATT/CL/GAW/BV-01-C", true),
    ("GATT/CL/GAI/BV-01-C", true),
    ("GATT/SR/GAC/BV-01-C", true),
    ("GATT/SR/GAD/BV-01-C", true),
    ("GATT/SR/GAR/BV-01-C", true),
];

pub const SUPPORTED_SM_TESTS: &[(&str, bool)] = &[
    ("SM/CEN/JW/BV-01-C", true),
    ("SM/PER/JW/BV-01-C", true),
    ("SM/CEN/PKE/BV-01-C", true),
    ("SM/PER/PKE/BV-01-C", true),
    ("SM/CEN/SCJW/BV-01-C", false),
    ("SM/CEN/SCPK/BV-01-C", false),
    ("SM/CEN/KDU/BV-01-C", true),
    ("SM/PER/KDU/BV-01-C", true),
];
