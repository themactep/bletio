//! GATT Server Demo — shows how to set up a BLE peripheral with GATT services.
//!
//! This example demonstrates:
//! - Creating a GattServer with standard profiles (DIS, BAS, GAP)
//! - Handling ATT requests (read, write, discovery)
//! - CCCD subscription tracking for notifications
//! - Updating characteristic values dynamically
//!
//! Run with: `cargo run --example gatt_server_demo`

use bletio_host::att::profiles;
use bletio_host::att::{
    AttErrorCode, AttHandle, AttOpcode, AttPdu, AttUuid, AttValue, GattServer,
};

fn main() {
    println!("=== bletio GATT Server Demo ===\n");

    // ── Step 1: Create server and add profiles ─────────────────────────
    let mut server = GattServer::new();

    // Device Information Service
    let dis = profiles::device_information(
        "bletio",
        "BLE-1.0",
        Some("SN-2024-0001"),
        Some("HW-Rev-C"),
        Some("1.0.0"),
        Some("0.1.0"),
    )
    .unwrap();
    server.add_service(dis).unwrap();

    // Battery Service (starts at 100%)
    let (bas, _) = profiles::battery_service(100).unwrap();
    server.add_service(bas).unwrap();

    // Generic Access Profile
    let gap = profiles::generic_access("bletio Demo", Some(0x0200)).unwrap();
    server.add_service(gap).unwrap();

    // Generic Attribute Profile
    let gatt = profiles::generic_attribute().unwrap();
    server.add_service(gatt).unwrap();

    println!(
        "✓ Registered {} attributes across 4 services",
        server.attribute_count()
    );

    // ── Step 2: Simulate a connected central discovering services ──────
    println!("\n── Service Discovery ──");

    let req = AttPdu::ReadByGroupTypeRequest {
        starting_handle: AttHandle(1),
        ending_handle: AttHandle(0xFFFF),
        attribute_group_type: AttUuid::Uuid16(0x2800), // Primary Service
    };

    match server.handle_request(&req).unwrap() {
        AttPdu::ReadByGroupTypeResponse {
            length,
            attribute_data_list,
        } => {
            println!(
                "✓ Discovered services (element size: {}, data: {} bytes)",
                length,
                attribute_data_list.len()
            );
        }
        _ => println!("✗ Unexpected response"),
    }

    // ── Step 3: Discover characteristics of the Battery Service ────────
    println!("\n── Characteristic Discovery (Battery Service) ──");

    let req = AttPdu::ReadByTypeRequest {
        starting_handle: AttHandle(1),
        ending_handle: AttHandle(0xFFFF),
        attribute_type: AttUuid::Uuid16(0x2803), // Characteristic declaration
    };

    match server.handle_request(&req).unwrap() {
        AttPdu::ReadByTypeResponse {
            length,
            attribute_data_list,
        } => {
            println!(
                "✓ Discovered characteristics (element size: {}, data: {} bytes)",
                length,
                attribute_data_list.len()
            );
        }
        _ => println!("✗ Unexpected response"),
    }

    // ── Step 4: Read Manufacturer Name ─────────────────────────────────
    println!("\n── Read Characteristic ──");

    // Find the Manufacturer Name handle (it's the first char value, handle 3)
    let req = AttPdu::ReadRequest {
        attribute_handle: AttHandle(3),
    };

    match server.handle_request(&req).unwrap() {
        AttPdu::ReadResponse { attribute_value } => {
            let name = core::str::from_utf8(attribute_value.as_slice()).unwrap_or("<utf8 error>");
            println!("✓ Manufacturer Name: \"{}\"", name);
        }
        _ => println!("✗ Unexpected response"),
    }

    // ── Step 5: Enable notifications via CCCD write ────────────────────
    println!("\n── CCCD Subscription ──");

    // Battery Level is at handle 3 of BAS. Let's find it dynamically.
    if let Some(battery_handle) =
        profiles::characteristic_value_handle(
            &server,
            AttUuid::Uuid16(profiles::BATTERY_SERVICE_UUID),
            AttUuid::Uuid16(profiles::BATTERY_LEVEL_UUID),
        )
    {
        // CCCD is one handle after the value
        let cccd_handle = AttHandle(battery_handle.0 + 1);

        let req = AttPdu::WriteRequest {
            attribute_handle: cccd_handle,
            attribute_value: AttValue::new(&[0x01, 0x00]).unwrap(), // Enable notifications
        };

        match server.handle_request(&req).unwrap() {
            AttPdu::WriteResponse => {
                println!("✓ Notifications enabled for Battery Level");
                println!(
                    "  notify_enabled: {}",
                    server.is_notify_enabled(battery_handle)
                );
            }
            _ => println!("✗ Unexpected response"),
        }
    }

    // ── Step 6: Read Manufacturer Name from DIS ───────────────────────
    println!("\n── Read Multiple Characteristics ──");

    // Read Software Revision (handle 13 in our setup)
    let req = AttPdu::ReadRequest {
        attribute_handle: AttHandle(13),
    };
    match server.handle_request(&req).unwrap() {
        AttPdu::ReadResponse { attribute_value } => {
            let ver = core::str::from_utf8(attribute_value.as_slice()).unwrap_or("<utf8 error>");
            println!("✓ Software Revision: \"{}\"", ver);
        }
        _ => println!("✗ Unexpected response"),
    }

    // ── Step 7: Update Battery Level and show it ───────────────────────
    println!("\n── Dynamic Value Updates ──");

    if let Some(battery_handle) = profiles::characteristic_value_handle(
        &server,
        AttUuid::Uuid16(profiles::BATTERY_SERVICE_UUID),
        AttUuid::Uuid16(profiles::BATTERY_LEVEL_UUID),
    ) {
        server.set_value(battery_handle, &[85u8]).unwrap();

        let req = AttPdu::ReadRequest {
            attribute_handle: battery_handle,
        };
        match server.handle_request(&req).unwrap() {
            AttPdu::ReadResponse { attribute_value } => {
                println!(
                    "✓ Battery Level updated to: {}%",
                    attribute_value.as_slice()[0]
                );
            }
            _ => println!("✗ Unexpected response"),
        }
    }

    println!("\n=== Demo Complete ===");
}
