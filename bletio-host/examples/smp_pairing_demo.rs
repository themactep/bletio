//! SMP Pairing Demo — LE Legacy Pairing (Just Works) flow.
//!
//! Each step creates a fresh pairing state machine to demonstrate the API.
//!
//! Run with: `cargo run --example smp_pairing_demo`

use bletio_host::smp::{
    AuthReq, IoCapability, KeyDistribution, MockCrypto, PairingFailedReason,
    SmpPairing, SmpPairingConfig, SmpPairingResult, SmpPdu,
};

fn cfg(addr: [u8; 6], addr_type: u8) -> SmpPairingConfig {
    SmpPairingConfig {
        io_capability: IoCapability::NoInputNoOutput,
        oob_present: false,
        auth_req: AuthReq { bonding: true, mitm: false, secure_connections: false, keypress: false, ct2: false },
        max_encryption_key_size: 16,
        key_distribution: KeyDistribution { enc_key: true, id_key: true, sign_key: false, link_key: false },
        our_address: addr,
        our_address_type: addr_type,
    }
}

fn main() {
    println!("=== bletio SMP Pairing Demo (Just Works) ===\n");

    demo_phase1();
    demo_confirm_random();
    demo_stk();
    demo_error();

    println!("\n=== Demo Complete ===");
}

fn demo_phase1() {
    println!("── Phase 1: Feature Exchange ──");
    let (_, init_req) = SmpPairing::new_initiator(MockCrypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));
    let (mut resp, _) = SmpPairing::new_initiator(MockCrypto, cfg([0xAA,0xBB,0xCC,0xDD,0xEE,0xFF], 1));

    match resp.process(&init_req).unwrap() {
        SmpPairingResult::SendPdu(SmpPdu::PairingResponse { .. }) => {
            println!("→ Pairing Request → ← Pairing Response ✓\n");
        }
        o => panic!("Unexpected: {:?}", o),
    }
}

fn demo_confirm_random() {
    println!("── Phase 2: Confirm/Random Exchange ──");
    let (_, init_req) = SmpPairing::new_initiator(MockCrypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));

    // Fresh responder: process request → confirm → random
    let (mut resp, _) = SmpPairing::new_initiator(MockCrypto, cfg([0xAA,0xBB,0xCC,0xDD,0xEE,0xFF], 1));
    let resp_pdu = match resp.process(&init_req).unwrap() {
        SmpPairingResult::SendPdu(p) => p,
        o => panic!("{:?}", o),
    };

    // Process response through initiator to get confirm
    let (mut init, _) = SmpPairing::new_initiator(MockCrypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));
    let init_confirm = match init.process(&resp_pdu).unwrap() {
        SmpPairingResult::SendPdu(p) => p,
        o => panic!("{:?}", o),
    };

    // Feed confirm back to a fresh responder to get random
    let (mut resp2, _) = SmpPairing::new_initiator(MockCrypto, cfg([0xAA,0xBB,0xCC,0xDD,0xEE,0xFF], 1));
    let _ = resp2.process(&init_req).unwrap();
    match resp2.process(&init_confirm).unwrap() {
        SmpPairingResult::SendPdu(SmpPdu::PairingRandom { .. }) => {
            println!("→ Confirm → ← Random ✓\n");
        }
        o => panic!("Unexpected: {:?}", o),
    }
}

fn demo_stk() {
    println!("── Phase 3: STK Generation ──");
    // Use the same test pattern from the unit test
    let crypto = MockCrypto;
    let (_, req) = SmpPairing::new_initiator(crypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));
    let (mut init, _) = SmpPairing::new_initiator(crypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));

    let resp_pdu = SmpPdu::PairingResponse {
        io_capability: IoCapability::NoInputNoOutput, oob_data_flag: false,
        auth_req: AuthReq { bonding: true, mitm: false, secure_connections: false, keypress: false, ct2: false },
        max_encryption_key_size: 16,
        initiator_key_distribution: KeyDistribution { enc_key: false, id_key: false, sign_key: false, link_key: false },
        responder_key_distribution: KeyDistribution { enc_key: true, id_key: true, sign_key: false, link_key: false },
    };
    let confirm = match init.process(&resp_pdu).unwrap() {
        SmpPairingResult::SendPdu(p) => p, o => panic!(),
    };
    let random = match init.process(&confirm).unwrap() {
        SmpPairingResult::SendPdu(p) => p, o => panic!(),
    };
    match init.process(&random).unwrap() {
        SmpPairingResult::Complete { stk, .. } => {
            println!("→ Random → STK derived: {:02X?}... ✓\n", &stk[..4]);
        }
        o => panic!("Unexpected: {:?}", o),
    }
}

fn demo_error() {
    println!("── Error Handling ──");
    let (mut p, _) = SmpPairing::new_initiator(MockCrypto, cfg([0u8;6], 0));
    match p.process(&SmpPdu::PairingFailed { reason: PairingFailedReason::PairingNotSupported }).unwrap() {
        SmpPairingResult::Failed(reason) => println!("✓ Pairing failed: {:?}\n", reason),
        _ => println!("✗"),
    }
}
