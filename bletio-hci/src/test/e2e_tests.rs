//! End-to-end integration tests using tokio_test::io::Mock as a virtual controller.

use core::time::Duration;

use super::TokioHciDriver;
use crate::{
    ConnectionHandle, ConnectionParameters, ConnectionPeerAddress, ErrorCode, Event,
    FilterDuplicates, Hci, InitiatorFilterPolicy, Latency, LeMetaEvent, OwnAddressType,
    PublicDeviceAddress, Reason, ScanEnable, ScanInterval, ScanParameters, ScanType,
    ScanningFilterPolicy, ScanWindow, SupervisionTimeout, connection_event_length_range,
    ConnectionIntervalRange,
};

/// Full flow: scan → receive advertising report → stop scan.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_e2e_scan_and_receive_report() {
    let adv_report = [
        4, 0x3E, 12, 0x02, 0x01, 0x00, 0x00,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,
        0x00, 0xD0,
    ];

    let mock = tokio_test::io::Builder::new()
        .write(&[1, 3, 12, 0])
        .read(&[4, 14, 4, 1, 3, 12, 0])
        .write(&[1, 0x0B, 0x20, 7, 0x00, 0xA0, 0x00, 0x50, 0x00, 0x00, 0x00])
        .read(&[4, 14, 4, 1, 0x0B, 0x20, 0])
        .write(&[1, 0x0C, 0x20, 2, 0x01, 0x00])
        .read(&[4, 14, 4, 1, 0x0C, 0x20, 0])
        .read(&adv_report)
        .write(&[1, 0x0C, 0x20, 2, 0x00, 0x00])
        .read(&[4, 14, 4, 1, 0x0C, 0x20, 0])
        .build();

    let mut hci = Hci::new(TokioHciDriver { hci: mock });
    hci.set_num_hci_command_packets(1);

    hci.cmd_reset().await.unwrap();

    let params = ScanParameters::try_new(
        ScanType::PassiveScanning,
        crate::scan_interval!(160),
        crate::scan_window!(80),
        OwnAddressType::PublicDeviceAddress,
        ScanningFilterPolicy::BasicUnfiltered,
    ).unwrap();
    hci.cmd_le_set_scan_parameters(params).await.unwrap();
    hci.cmd_le_set_scan_enable(ScanEnable::Enabled, FilterDuplicates::Disabled).await.unwrap();

    let events = hci.wait_for_event().await.unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        Event::LeMeta(LeMetaEvent::LeAdvertisingReport(reports)) => {
            assert_eq!(reports.len(), 1);
            let r = reports.iter().next().unwrap();
            assert_eq!(r.address().value(), &[0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]);
            assert_eq!(r.rssi().map(|v| v.value()), Some(-48));
        }
        _ => panic!("Expected advertising report"),
    }

    hci.cmd_le_set_scan_enable(ScanEnable::Disabled, FilterDuplicates::Disabled).await.unwrap();
}

/// Full flow: create connection → receive connection complete → disconnect.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_e2e_connect_and_disconnect() {
    let mock = tokio_test::io::Builder::new()
        .write(&[
            1, 13, 32, 25, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00,
            0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,
            0x00, 0x40, 0x00, 0x40, 0x00, 0x00, 0x00, 0x20, 0x00, 0x0A, 0x00, 0x64, 0x00,
        ])
        .read(&[4, 15, 4, 0, 1, 13, 32])
        .wait(Duration::from_millis(10))
        .read(&[
            4, 0x3E, 19, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,
            0x40, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
        ])
        .write(&[1, 6, 4, 3, 0, 0, 0x13])
        .read(&[4, 15, 4, 0, 1, 6, 4])
        .wait(Duration::from_millis(10))
        .read(&[4, 5, 4, 0, 0, 0, 0x16])
        .build();

    let mut hci = Hci::new(TokioHciDriver { hci: mock });
    hci.set_num_hci_command_packets(1);

    let conn_params = ConnectionParameters::try_new(
        ScanInterval::default(),
        ScanWindow::default(),
        InitiatorFilterPolicy::FilterAcceptListNotUsed,
        ConnectionPeerAddress::PublicDevice(
            PublicDeviceAddress::new([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]).into(),
        ),
        OwnAddressType::PublicDeviceAddress,
        ConnectionIntervalRange::default(),
        Latency::default(),
        SupervisionTimeout::default(),
        connection_event_length_range!(10, 100),
    ).unwrap();

    hci.cmd_le_create_connection(conn_params).await.unwrap();

    let events = hci.wait_for_event().await.unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        Event::LeMeta(LeMetaEvent::LeConnectionComplete(event)) => {
            assert_eq!(event.status(), ErrorCode::Success);
            assert_eq!(event.connection_handle().value(), 0);
        }
        _ => panic!("Expected connection complete"),
    }

    hci.cmd_disconnect(ConnectionHandle::try_new(0).unwrap(), Reason::RemoteUserTerminatedConnection).await.unwrap();

    let events = hci.wait_for_event().await.unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], Event::DisconnectionComplete(_)));
}

/// Full GATT read: send ACL ATT Read Request, receive ACL ATT Read Response.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_e2e_gatt_read_over_acl() {
    let mock = tokio_test::io::Builder::new()
        .write(&[0x02, 0x00, 0x00, 0x03, 0x00, 0x0A, 0x03, 0x00])
        .read(&[0x02, 0x00, 0x00, 0x04, 0x00, 0x0B, 0x62, 0x6C, 0x65])
        .build();

    let mut hci = Hci::new(TokioHciDriver { hci: mock });
    hci.set_num_hci_command_packets(1);
    hci.set_le_acl_credits(1);

    use crate::acl_data::{AclData, BroadcastFlag, PacketBoundaryFlag};
    let acl = AclData::build(
        ConnectionHandle::try_new(0).unwrap(),
        PacketBoundaryFlag::FirstNonAutomaticallyFlushablePacket,
        BroadcastFlag::PointToPoint,
        &[0x0A, 0x03, 0x00],
    ).unwrap();
    hci.write_acl_data(&acl).await.unwrap();

    let events = hci.wait_for_event().await.unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        Event::AclData(data) => {
            assert_eq!(data.handle().value(), 0);
            assert_eq!(data.data(), &[0x0B, 0x62, 0x6C, 0x65]); // "ble"
        }
        _ => panic!("Expected AclData"),
    }
}
