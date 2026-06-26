//! GATT Client Demo — shows GATT client API for discovery and read/write.
//!
//! Run with: `cargo run --example gatt_client_demo`

use bletio_host::att::{
    AttHandle, AttPdu, AttUuid, AttValue, GattClient, GattEvent,
};

// Each step creates a fresh GattClient to demonstrate the API independently.

fn main() {
    println!("=== bletio GATT Client Demo ===\n");

    demo_mtu();
    demo_service_discovery();
    demo_char_discovery();
    demo_read();
    demo_write_without_response();
    demo_notification();

    println!("\n=== Demo Complete ===");
}

fn demo_mtu() {
    println!("── MTU Negotiation ──");
    let mut gatt = GattClient::new();
    println!("Initial MTU: {}", gatt.att().mtu());

    gatt.att_mut().prepare_exchange_mtu(256).unwrap();
    let resp = encode_pdu(&AttPdu::ExchangeMtuResponse { server_rx_mtu: 128 });
    let _ = gatt.feed(&resp).unwrap();
    println!("Negotiated MTU: {}\n", gatt.att().mtu());
}

fn demo_service_discovery() {
    println!("── Service Discovery ──");
    let mut gatt = GattClient::new();
    gatt.discover_all_primary_services(AttHandle(1), AttHandle(0xFFFF)).unwrap();

    let resp = build_read_by_group_type(&[(1, 5, 0x1800), (6, 9, 0x1801)]);
    if let Some(GattEvent::ServicesDiscovered(svcs)) = gatt.feed(&resp).unwrap() {
        for svc in &svcs {
            println!("  • handle {}-{}, UUID: 0x{:04X}", svc.start_handle.0, svc.end_handle.0,
                match svc.uuid { AttUuid::Uuid16(u) => u, _ => 0 });
        }
    }
    println!();
}

fn demo_char_discovery() {
    println!("── Characteristic Discovery ──");
    let mut gatt = GattClient::new();
    gatt.discover_characteristics(AttHandle(1), AttHandle(5)).unwrap();

    let resp = build_read_by_type(&[(2, 0x02, 3, 0x2A00), (4, 0x02, 5, 0x2A01)]);
    if let Some(GattEvent::CharacteristicsDiscovered(chars)) = gatt.feed(&resp).unwrap() {
        for ch in &chars {
            println!("  • decl: {}, value: {}, UUID: 0x{:04X}",
                ch.declaration_handle.0, ch.value_handle.0,
                match ch.uuid { AttUuid::Uuid16(u) => u, _ => 0 });
        }
    }
    println!();
}

fn demo_read() {
    println!("── Read Characteristic ──");
    let mut gatt = GattClient::new();
    gatt.read_value(AttHandle(3)).unwrap();
    let resp = encode_pdu(&AttPdu::ReadResponse {
        attribute_value: AttValue::new(b"bletio Device").unwrap(),
    });
    if let Some(GattEvent::ValueRead { value, .. }) = gatt.feed(&resp).unwrap() {
        let name = core::str::from_utf8(value.as_slice()).unwrap_or("?");
        println!("  Device Name: \"{}\"\n", name);
    }
}

fn demo_write_without_response() {
    println!("── Write Without Response ──");
    let gatt = GattClient::new();
    let req = gatt.write_value_without_response(AttHandle(3), b"NewName").unwrap();
    println!("  Sent Write Command ({} bytes)\n", req.len());
}

fn demo_notification() {
    println!("── Notification ──");
    let mut gatt = GattClient::new();
    let resp = encode_pdu(&AttPdu::HandleValueNotification {
        attribute_handle: AttHandle(7),
        attribute_value: AttValue::new(&[85u8]).unwrap(),
    });
    if let Some(GattEvent::Notification { handle, value }) = gatt.feed(&resp).unwrap() {
        println!("  Handle {}: {:02X?}\n", handle.0, value.as_slice());
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

fn encode_pdu(pdu: &AttPdu) -> heapless::Vec<u8, 512> {
    use bletio_utils::{Buffer, BufferOps, EncodeToBuffer};
    let mut buf: Buffer<512> = Buffer::default();
    pdu.encode(&mut buf).unwrap();
    let mut v = heapless::Vec::new();
    v.extend_from_slice(buf.data()).unwrap();
    v
}

fn build_read_by_group_type(services: &[(u16, u16, u16)]) -> heapless::Vec<u8, 512> {
    let mut data = heapless::Vec::<u8, 512>::new();
    for &(s, e, u) in services {
        let _ = data.extend_from_slice(&s.to_le_bytes());
        let _ = data.extend_from_slice(&e.to_le_bytes());
        let _ = data.extend_from_slice(&u.to_le_bytes());
    }
    encode_pdu(&AttPdu::ReadByGroupTypeResponse { length: 6, attribute_data_list: data })
}

fn build_read_by_type(entries: &[(u16, u8, u16, u16)]) -> heapless::Vec<u8, 512> {
    let mut data = heapless::Vec::<u8, 512>::new();
    for &(h, p, v, u) in entries {
        let _ = data.extend_from_slice(&h.to_le_bytes());
        let _ = data.push(p);
        let _ = data.extend_from_slice(&v.to_le_bytes());
        let _ = data.extend_from_slice(&u.to_le_bytes());
    }
    encode_pdu(&AttPdu::ReadByTypeResponse { length: 7, attribute_data_list: data })
}
