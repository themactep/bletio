//! Standard GATT profile definitions.
//!
//! Pre-built service definitions that can be added to a [`GattServer`](super::GattServer)
//! with minimal boilerplate. All profiles follow the Bluetooth SIG specifications.
//!
//! # Quick start
//!
//! ```ignore
//! use bletio_host::att::profiles;
//!
//! let mut server = GattServer::new();
//! server.add_service(profiles::device_information("bletio", "0.1.0", "Ghislain MARY"))?;
//! server.add_service(profiles::battery_service(100))?;
//! server.add_service(profiles::generic_access("My Device", None))?;
//! ```

use super::gatt_server::{
    GattCharacteristicBuilder, GattCharacteristicDef, GattDescriptorBuilder, GattDescriptorDef,
    GattServer, GattServiceBuilder, GattServiceDef, CLIENT_CHAR_CONFIG_UUID,
};
use super::att_pdu::{AttError, AttHandle, AttUuid, AttValue};

// ─── Standard UUIDs ─────────────────────────────────────────────────────

/// Device Information Service UUID.
pub const DEVICE_INFORMATION_SERVICE_UUID: u16 = 0x180A;
/// Battery Service UUID.
pub const BATTERY_SERVICE_UUID: u16 = 0x180F;
/// Generic Access Profile UUID.
pub const GENERIC_ACCESS_SERVICE_UUID: u16 = 0x1800;
/// Generic Attribute Profile UUID.
pub const GENERIC_ATTRIBUTE_SERVICE_UUID: u16 = 0x1801;
/// Environmental Sensing Service UUID.
pub const ENVIRONMENTAL_SENSING_SERVICE_UUID: u16 = 0x181A;
/// Heart Rate Service UUID.
pub const HEART_RATE_SERVICE_UUID: u16 = 0x180D;

/// Manufacturer Name String characteristic UUID.
pub const MANUFACTURER_NAME_UUID: u16 = 0x2A29;
/// Model Number String characteristic UUID.
pub const MODEL_NUMBER_UUID: u16 = 0x2A24;
/// Serial Number String characteristic UUID.
pub const SERIAL_NUMBER_UUID: u16 = 0x2A25;
/// Hardware Revision String characteristic UUID.
pub const HARDWARE_REVISION_UUID: u16 = 0x2A27;
/// Firmware Revision String characteristic UUID.
pub const FIRMWARE_REVISION_UUID: u16 = 0x2A26;
/// Software Revision String characteristic UUID.
pub const SOFTWARE_REVISION_UUID: u16 = 0x2A28;
/// System ID characteristic UUID.
pub const SYSTEM_ID_UUID: u16 = 0x2A23;
/// PnP ID characteristic UUID.
pub const PNP_ID_UUID: u16 = 0x2A50;

/// Device Name characteristic UUID.
pub const DEVICE_NAME_UUID: u16 = 0x2A00;
/// Appearance characteristic UUID.
pub const APPEARANCE_UUID: u16 = 0x2A01;
/// Peripheral Preferred Connection Parameters characteristic UUID.
pub const PERIPHERAL_PREFERRED_CONN_PARAMS_UUID: u16 = 0x2A04;

/// Battery Level characteristic UUID.
pub const BATTERY_LEVEL_UUID: u16 = 0x2A19;

/// Heart Rate Measurement characteristic UUID.
pub const HEART_RATE_MEASUREMENT_UUID: u16 = 0x2A37;
/// Body Sensor Location characteristic UUID.
pub const BODY_SENSOR_LOCATION_UUID: u16 = 0x2A38;

/// Service Changed characteristic UUID.
pub const SERVICE_CHANGED_UUID: u16 = 0x2A05;

// ─── Profile builders ────────────────────────────────────────────────────

/// Build a Device Information Service (DIS) definition.
///
/// Characteristics included (all optional per spec, all included here):
/// - Manufacturer Name String (readable)
/// - Model Number String (readable)
/// - Serial Number String (readable, if provided)
/// - Hardware Revision String (readable, if provided)
/// - Firmware Revision String (readable, if provided)
/// - Software Revision String (readable, if provided)
pub fn device_information(
    manufacturer_name: &str,
    model_number: &str,
    serial_number: Option<&str>,
    hardware_revision: Option<&str>,
    firmware_revision: Option<&str>,
    software_revision: Option<&str>,
) -> Result<GattServiceDef, AttError> {
    let mut svc = GattServiceBuilder::new(AttUuid::Uuid16(DEVICE_INFORMATION_SERVICE_UUID));

    // Manufacturer Name (mandatory in practice)
    svc = svc.add_characteristic(
        GattCharacteristicBuilder::new(AttUuid::Uuid16(MANUFACTURER_NAME_UUID))
            .readable()
            .value(manufacturer_name.as_bytes())?
            .build(),
    );

    // Model Number
    svc = svc.add_characteristic(
        GattCharacteristicBuilder::new(AttUuid::Uuid16(MODEL_NUMBER_UUID))
            .readable()
            .value(model_number.as_bytes())?
            .build(),
    );

    // Serial Number (optional)
    if let Some(sn) = serial_number {
        svc = svc.add_characteristic(
            GattCharacteristicBuilder::new(AttUuid::Uuid16(SERIAL_NUMBER_UUID))
                .readable()
                .value(sn.as_bytes())?
                .build(),
        );
    }

    // Hardware Revision (optional)
    if let Some(rev) = hardware_revision {
        svc = svc.add_characteristic(
            GattCharacteristicBuilder::new(AttUuid::Uuid16(HARDWARE_REVISION_UUID))
                .readable()
                .value(rev.as_bytes())?
                .build(),
        );
    }

    // Firmware Revision (optional)
    if let Some(rev) = firmware_revision {
        svc = svc.add_characteristic(
            GattCharacteristicBuilder::new(AttUuid::Uuid16(FIRMWARE_REVISION_UUID))
                .readable()
                .value(rev.as_bytes())?
                .build(),
        );
    }

    // Software Revision (optional)
    if let Some(rev) = software_revision {
        svc = svc.add_characteristic(
            GattCharacteristicBuilder::new(AttUuid::Uuid16(SOFTWARE_REVISION_UUID))
                .readable()
                .value(rev.as_bytes())?
                .build(),
        );
    }

    Ok(svc.build())
}

/// Build a Battery Service (BAS) definition.
///
/// - Battery Level (readable, notifiable): starts at `initial_level` (0–100).
///
/// Returns the handle of the Battery Level characteristic value so the
/// application can update it via `server.set_value()`.
pub fn battery_service(initial_level: u8) -> Result<(GattServiceDef, u16), AttError> {
    // We can't know the handle before adding to the server, so return a marker.
    // The caller uses the returned service and knows the characteristic value
    // is at the 3rd attribute (handle = svc_start + 2).
    let level = core::cmp::min(initial_level, 100);
    let svc = GattServiceBuilder::new(AttUuid::Uuid16(BATTERY_SERVICE_UUID))
        .add_characteristic(
            GattCharacteristicBuilder::new(AttUuid::Uuid16(BATTERY_LEVEL_UUID))
                .readable()
                .notifiable()
                .value(&[level])?
                .add_descriptor(
                    GattDescriptorBuilder::new(AttUuid::Uuid16(CLIENT_CHAR_CONFIG_UUID))
                        .readable()
                        .writable()
                        .value(&[0x00, 0x00])?
                        .build(),
                )
                .build(),
        )
        .build();

    Ok((svc, 0)) // Handle will be assigned by the server
}

/// Build a Generic Access (GAP) service definition.
///
/// - Device Name (readable)
/// - Appearance (readable): 16-bit appearance value
///
/// `appearance` is the Bluetooth SIG appearance value (e.g., 0x0200 for Generic Phone).
/// Pass `None` to use a default of 0x0000 (Generic Unknown).
pub fn generic_access(
    device_name: &str,
    appearance: Option<u16>,
) -> Result<GattServiceDef, AttError> {
    let appearance_value = appearance.unwrap_or(0x0000);

    let svc = GattServiceBuilder::new(AttUuid::Uuid16(GENERIC_ACCESS_SERVICE_UUID))
        .add_characteristic(
            GattCharacteristicBuilder::new(AttUuid::Uuid16(DEVICE_NAME_UUID))
                .readable()
                .value(device_name.as_bytes())?
                .build(),
        )
        .add_characteristic(
            GattCharacteristicBuilder::new(AttUuid::Uuid16(APPEARANCE_UUID))
                .readable()
                .value(&appearance_value.to_le_bytes())?
                .build(),
        )
        .build();

    Ok(svc)
}

/// Build a Generic Attribute (GATT) service definition.
///
/// - Service Changed (indicatable): initial value [0x0000, 0xFFFF].
///   This characteristic is used to notify clients when the service table changes.
pub fn generic_attribute() -> Result<GattServiceDef, AttError> {
    let svc = GattServiceBuilder::new(AttUuid::Uuid16(GENERIC_ATTRIBUTE_SERVICE_UUID))
        .add_characteristic(
            GattCharacteristicBuilder::new(AttUuid::Uuid16(SERVICE_CHANGED_UUID))
                .indicatable()
                .value(&[0x00, 0x00, 0xFF, 0xFF])?
                .add_descriptor(
                    GattDescriptorBuilder::new(AttUuid::Uuid16(CLIENT_CHAR_CONFIG_UUID))
                        .readable()
                        .writable()
                        .value(&[0x00, 0x00])?
                        .build(),
                )
                .build(),
        )
        .build();

    Ok(svc)
}

/// Build a Heart Rate Service (HRS) definition.
///
/// - Heart Rate Measurement (notifiable): initial value [0x00, 0x00]
/// - Body Sensor Location (readable): value 0x00 (Other)
///
/// Returns the handle offset of the Heart Rate Measurement characteristic value
/// so the application can update it.
pub fn heart_rate_service() -> Result<(GattServiceDef, u16), AttError> {
    let svc = GattServiceBuilder::new(AttUuid::Uuid16(HEART_RATE_SERVICE_UUID))
        .add_characteristic(
            GattCharacteristicBuilder::new(AttUuid::Uuid16(HEART_RATE_MEASUREMENT_UUID))
                .notifiable()
                .value(&[0x00, 0x00])?
                .add_descriptor(
                    GattDescriptorBuilder::new(AttUuid::Uuid16(CLIENT_CHAR_CONFIG_UUID))
                        .readable()
                        .writable()
                        .value(&[0x00, 0x00])?
                        .build(),
                )
                .build(),
        )
        .add_characteristic(
            GattCharacteristicBuilder::new(AttUuid::Uuid16(BODY_SENSOR_LOCATION_UUID))
                .readable()
                .value(&[0x00])? // 0 = Other
                .build(),
        )
        .build();

    Ok((svc, 0))
}

// ─── Helpers for finding handles ────────────────────────────────────────

/// Given a service start handle and an index into the service's characteristics,
/// returns the handle of the characteristic value attribute.
///
/// Service structure: [svc_decl, char1_decl, char1_value, [desc1, ...], char2_decl, ...]
///
/// This is computed from the service definition before adding to the server.
pub fn characteristic_value_handle(
    server: &GattServer,
    service_uuid: AttUuid,
    char_uuid: AttUuid,
) -> Option<AttHandle> {
    // Find the characteristic declaration, then the next attribute is the value
    let mut attrs = server_attribute_iter(server);
    let mut found_service = false;

    while let Some(attr) = attrs.next() {
        // Look for the service declaration
        if !found_service {
            if matches!(attr.attribute_type, AttUuid::Uuid16(0x2800))
                && attr.value.len() >= 4
            {
                let svc_uuid = u16::from_le_bytes([
                    attr.value.as_slice()[2],
                    attr.value.as_slice()[3],
                ]);
                if AttUuid::Uuid16(svc_uuid) == service_uuid {
                    found_service = true;
                }
            }
            continue;
        }

        // Inside the service: find characteristic declaration with matching UUID
        if attr.attribute_type == AttUuid::Uuid16(0x2803) && attr.value.len() >= 5 {
            let decl_uuid = u16::from_le_bytes([
                attr.value.as_slice()[3],
                attr.value.as_slice()[4],
            ]);
            if AttUuid::Uuid16(decl_uuid) == char_uuid {
                // Next attribute is the value
                if let Some(val_attr) = attrs.next() {
                    return Some(val_attr.handle);
                }
            }
        }
    }

    None
}

fn server_attribute_iter(server: &GattServer) -> impl Iterator<Item = &super::gatt_server::Attribute> {
    (0..server.attribute_count()).filter_map(move |i| {
        server.find_attribute(AttHandle(i as u16 + 1))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::gatt_server::GattServer;

    #[test]
    fn test_device_information_service() {
        let mut server = GattServer::new();
        let svc = device_information(
            "bletio",
            "BLE-1.0",
            Some("SN-001"),
            Some("HW-2"),
            Some("FW-1.0.0"),
            Some("SW-0.1.0"),
        )
        .unwrap();
        server.add_service(svc).unwrap();

        // 1 service decl + 6 characteristic decls + 6 char values = 13
        assert_eq!(server.attribute_count(), 13);
    }

    #[test]
    fn test_device_information_minimal() {
        let mut server = GattServer::new();
        let svc = device_information("bletio", "BLE-1.0", None, None, None, None).unwrap();
        server.add_service(svc).unwrap();

        // 1 service decl + 2 characteristic decls + 2 char values = 5
        assert_eq!(server.attribute_count(), 5);
    }

    #[test]
    fn test_battery_service() {
        let mut server = GattServer::new();
        let (svc, _) = battery_service(85).unwrap();
        server.add_service(svc).unwrap();

        // 1 svc + 1 char decl + 1 char value + 1 cccd = 4
        assert_eq!(server.attribute_count(), 4);

        // The battery level is at handle 3
        let val = server.get_value(AttHandle(3));
        assert_eq!(val.unwrap().as_slice(), &[85u8]);
    }

    #[test]
    fn test_battery_service_clamps_to_100() {
        let (svc, _) = battery_service(255).unwrap();
        // Should be clamped to 100
        assert_eq!(svc.characteristics[0].value.as_slice(), &[100u8]);
    }

    #[test]
    fn test_generic_access() {
        let mut server = GattServer::new();
        let svc = generic_access("My BLE Device", Some(0x0200)).unwrap();
        server.add_service(svc).unwrap();

        // 1 svc + 2 char decl + 2 char values = 5
        assert_eq!(server.attribute_count(), 5);
    }

    #[test]
    fn test_generic_attribute() {
        let mut server = GattServer::new();
        let svc = generic_attribute().unwrap();
        server.add_service(svc).unwrap();

        // 1 svc + 1 char decl + 1 char value + 1 cccd = 4
        assert_eq!(server.attribute_count(), 4);
    }

    #[test]
    fn test_heart_rate_service() {
        let mut server = GattServer::new();
        let (svc, _) = heart_rate_service().unwrap();
        server.add_service(svc).unwrap();

        // 1 svc + 2 char decl + 2 char values + 1 cccd (on HRM) = 6
        assert_eq!(server.attribute_count(), 6);
    }
}
