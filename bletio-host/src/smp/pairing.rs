//! SMP pairing state machine for LE Legacy Pairing (Just Works).
//!
//! Crypto operations are abstracted behind the [`SmpCrypto`] trait.

use bletio_utils::{Buffer, BufferOps, EncodeToBuffer};

use super::smp_pdu::{
    AuthReq, IoCapability, KeyDistribution, PairingFailedReason, SmpError, SmpOpcode, SmpPdu,
};

// ─── Crypto trait ────────────────────────────────────────────────────────

pub trait SmpCrypto {
    fn aes_cmac(&self, key: &[u8; 16], data: &[u8]) -> Result<[u8; 16], SmpError>;

    fn c1(
        &self,
        tk: &[u8; 16],
        r: &[u8; 16],
        preq: &[u8; 16],
        pres: &[u8; 16],
        iat: u8,
        rat: u8,
        ia: &[u8; 6],
        ra: &[u8; 6],
    ) -> Result<[u8; 16], SmpError> {
        let mut buf = [0u8; 62];
        let mut off = 0;
        buf[off..off + 16].copy_from_slice(r); off += 16;
        buf[off..off + 16].copy_from_slice(preq); off += 16;
        buf[off..off + 16].copy_from_slice(pres); off += 16;
        buf[off] = iat; off += 1;
        buf[off] = rat; off += 1;
        buf[off..off + 6].copy_from_slice(ia); off += 6;
        buf[off..off + 6].copy_from_slice(ra);
        self.aes_cmac(tk, &buf[..off + 6])
    }

    fn s1(
        &self,
        tk: &[u8; 16],
        r1: &[u8; 16],
        r2: &[u8; 16],
    ) -> Result<[u8; 16], SmpError> {
        let mut buf = [0u8; 16];
        for i in 0..8 {
            buf[i] = r1[15 - i];
            buf[8 + i] = r2[15 - i];
        }
        self.aes_cmac(tk, &buf)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MockCrypto;
impl SmpCrypto for MockCrypto {
    fn aes_cmac(&self, key: &[u8; 16], _data: &[u8]) -> Result<[u8; 16], SmpError> {
        let mut r = [0u8; 16];
        for i in 0..16 { r[i] = key[i] ^ 0x5A; }
        Ok(r)
    }
}

// ─── Keys ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SmpKeys {
    pub long_term_key: [u8; 16],
    pub ediv: u16,
    pub rand: [u8; 8],
    pub identity_resolving_key: [u8; 16],
    pub connection_signature_resolving_key: [u8; 16],
}

// ─── Config ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SmpPairingConfig {
    pub io_capability: IoCapability,
    pub oob_present: bool,
    pub auth_req: AuthReq,
    pub max_encryption_key_size: u8,
    pub key_distribution: KeyDistribution,
    pub our_address: [u8; 6],
    pub our_address_type: u8,
}

// ─── Phases, results ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SmpPairingPhase {
    AwaitingResponse,
    AwaitingConfirm,
    AwaitingRandom,
    Complete,
    Failed(PairingFailedReason),
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SmpPairingResult {
    SendPdu(SmpPdu),
    Complete { stk: [u8; 16], keys: Option<SmpKeys> },
    Failed(PairingFailedReason),
}

// ─── Pairing state machine ───────────────────────────────────────────────

pub struct SmpPairing<C: SmpCrypto> {
    crypto: C,
    our_config: SmpPairingConfig,
    is_initiator: bool,
    peer_config: Option<SmpPairingConfig>,
    phase: SmpPairingPhase,
    our_random: [u8; 16],
    peer_random: [u8; 16],
    our_confirm: [u8; 16],
    peer_confirm: [u8; 16],
    tk: [u8; 16],
    /// Our pairing PDU bytes (c1 uses preq/pres; caller must ensure correct assignment).
    our_pairing_bytes: [u8; 16],
    peer_pairing_bytes: [u8; 16],
    stk: [u8; 16],
}

impl<C: SmpCrypto> SmpPairing<C> {
    pub fn new_initiator(crypto: C, config: SmpPairingConfig) -> (Self, SmpPdu) {
        let pdu = SmpPdu::PairingRequest {
            io_capability: config.io_capability,
            oob_data_flag: config.oob_present,
            auth_req: config.auth_req,
            max_encryption_key_size: config.max_encryption_key_size,
            initiator_key_distribution: config.key_distribution,
            responder_key_distribution: KeyDistribution { enc_key: false, id_key: false, sign_key: false, link_key: false },
        };
        let mut s = Self {
            crypto,
            our_config: config,
            is_initiator: true,
            peer_config: None,
            phase: SmpPairingPhase::AwaitingResponse,
            our_random: [0u8; 16], peer_random: [0u8; 16],
            our_confirm: [0u8; 16], peer_confirm: [0u8; 16],
            tk: [0u8; 16],
            our_pairing_bytes: [0u8; 16], peer_pairing_bytes: [0u8; 16],
            stk: [0u8; 16],
        };
        s.store_bytes(&pdu, true);
        (s, pdu)
    }

    pub fn process(&mut self, pdu: &SmpPdu) -> Result<SmpPairingResult, SmpError> {
        match (&self.phase, pdu) {
            // Phase 1: Pairing Request → PairingResponse
            (SmpPairingPhase::AwaitingResponse, SmpPdu::PairingRequest {
                io_capability, oob_data_flag, auth_req,
                max_encryption_key_size, initiator_key_distribution, ..
            }) => {
                self.peer_config = Some(SmpPairingConfig {
                    io_capability: *io_capability, oob_present: *oob_data_flag,
                    auth_req: *auth_req, max_encryption_key_size: *max_encryption_key_size,
                    key_distribution: *initiator_key_distribution,
                    our_address: [0u8; 6], our_address_type: 0,
                });
                self.store_bytes(pdu, false); // peer's = request
                self.is_initiator = false;

                let resp = SmpPdu::PairingResponse {
                    io_capability: self.our_config.io_capability,
                    oob_data_flag: self.our_config.oob_present,
                    auth_req: self.our_config.auth_req,
                    max_encryption_key_size: self.our_config.max_encryption_key_size,
                    initiator_key_distribution: KeyDistribution { enc_key: false, id_key: false, sign_key: false, link_key: false },
                    responder_key_distribution: self.our_config.key_distribution,
                };
                self.store_bytes(&resp, true); // our = response
                self.generate_confirm()?;
                self.phase = SmpPairingPhase::AwaitingConfirm;
                Ok(SmpPairingResult::SendPdu(resp))
            }

            // Phase 1: Pairing Response → compute/send confirm
            (SmpPairingPhase::AwaitingResponse, SmpPdu::PairingResponse {
                io_capability, oob_data_flag, auth_req,
                max_encryption_key_size, responder_key_distribution, ..
            }) => {
                self.peer_config = Some(SmpPairingConfig {
                    io_capability: *io_capability, oob_present: *oob_data_flag,
                    auth_req: *auth_req, max_encryption_key_size: *max_encryption_key_size,
                    key_distribution: *responder_key_distribution,
                    our_address: [0u8; 6], our_address_type: 0,
                });
                self.store_bytes(pdu, false); // peer's = response
                self.generate_confirm()?;
                self.phase = SmpPairingPhase::AwaitingConfirm;
                Ok(SmpPairingResult::SendPdu(SmpPdu::PairingConfirm {
                    confirm_value: self.our_confirm,
                }))
            }

            // Phase 2: Receive confirm → send random
            (SmpPairingPhase::AwaitingConfirm, SmpPdu::PairingConfirm { confirm_value }) => {
                self.peer_confirm = *confirm_value;
                self.phase = SmpPairingPhase::AwaitingRandom;
                Ok(SmpPairingResult::SendPdu(SmpPdu::PairingRandom {
                    random_value: self.our_random,
                }))
            }

            // Phase 3: Receive random → verify, compute STK
            (SmpPairingPhase::AwaitingRandom, SmpPdu::PairingRandom { random_value }) => {
                self.peer_random = *random_value;

                // verify confirm: c1(tk, peer_rand, preq, pres, iat, rat, ia, ra)
                let expected = self.compute_c1(&self.peer_random)?;
                if expected != self.peer_confirm {
                    self.phase = SmpPairingPhase::Failed(PairingFailedReason::ConfirmValueFailed);
                    return Ok(SmpPairingResult::Failed(PairingFailedReason::ConfirmValueFailed));
                }

                let stk = self.crypto.s1(&self.tk, &self.our_random, &self.peer_random)?;
                self.stk = stk;
                self.phase = SmpPairingPhase::Complete;
                Ok(SmpPairingResult::Complete { stk, keys: None })
            }

            // Error
            (_, SmpPdu::PairingFailed { reason }) => {
                self.phase = SmpPairingPhase::Failed(*reason);
                Ok(SmpPairingResult::Failed(*reason))
            }
            _ => Err(SmpError::UnexpectedPdu),
        }
    }

    pub fn phase(&self) -> &SmpPairingPhase { &self.phase }
    pub fn is_complete(&self) -> bool { matches!(self.phase, SmpPairingPhase::Complete) }

    /// Returns the derived STK if pairing is complete.
    pub fn stk(&self) -> Option<&[u8; 16]> {
        if self.is_complete() { Some(&self.stk) } else { None }
    }

    /// Set the Temporary Key for Passkey Entry pairing.
    ///
    /// Must be called BEFORE processing any pairing PDUs. The `passkey` is a
    /// 6-digit number (000000–999999). The TK is derived from the passkey
    /// per Core Spec Vol. 3, Part H, §2.3.5.1.
    ///
    /// # IO Capability → Pairing Method
    ///
    /// | Initiator | Responder | Method |
    /// |-----------|-----------|--------|
    /// | NoInputNoOutput | NoInputNoOutput | Just Works (TK=0) |
    /// | DisplayOnly | KeyboardOnly | Passkey Entry (display shows, keyboard inputs) |
    /// | KeyboardOnly | DisplayOnly | Passkey Entry |
    /// | KeyboardDisplay | KeyboardDisplay | Passkey Entry or Numeric Comparison |
    /// | DisplayYesNo | DisplayYesNo | Numeric Comparison |
    ///
    /// For Just Works, do not call this method (TK defaults to 0).
    pub fn set_passkey(&mut self, passkey: u32) -> Result<(), SmpError> {
        if passkey > 999999 {
            return Err(SmpError::NotSupported);
        }
        let mut tk = [0u8; 16];
        let mut remaining = passkey;
        for i in 0..6 {
            tk[i] = (remaining % 10) as u8;
            remaining /= 10;
        }
        // remaining bytes stay 0
        self.tk = tk;
        self.our_confirm = self.compute_c1(&self.our_random)?;
        Ok(())
    }

    /// Returns the current Temporary Key (for debugging only, never log in production).
    #[doc(hidden)]
    pub fn _debug_tk(&self) -> &[u8; 16] {
        &self.tk
    }

    /// Generate bond keys after pairing completes.
    ///
    /// Returns an [`SmpKeys`] containing the LTK, EDIV, Rand, IRK, and CSRK
    /// that should be distributed to the peer and persisted via a [`BondStore`].
    /// Keys are derived from the STK and random values.
    pub fn generate_keys(&self) -> SmpKeys {
        // In a production stack, keys would be derived using cryptographic
        // functions (h6, etc.) from the STK. For the mock/initial implementation,
        // we use the STK directly as the LTK and generate placeholder values.
        SmpKeys {
            long_term_key: self.stk,
            ediv: 0,
            rand: self.our_random[..8].try_into().unwrap(),
            identity_resolving_key: self.stk,
            connection_signature_resolving_key: self.stk,
        }
    }

    /// Build the key distribution PDUs to send to the peer after pairing.
    ///
    /// Returns a sequence of SMP PDUs (Encryption Information, Master Identification,
    /// Identity Information, Identity Address Information, Signing Information)
    /// that should be sent over ACL to complete bonding.
    pub fn build_distribution_pdus(&self, keys: &SmpKeys) -> heapless::Vec<SmpPdu, 5> {
        let mut pdus = heapless::Vec::new();
        let _ = pdus.push(SmpPdu::EncryptionInformation {
            long_term_key: keys.long_term_key,
        });
        let _ = pdus.push(SmpPdu::MasterIdentification {
            ediv: keys.ediv,
            rand: keys.rand,
        });
        let _ = pdus.push(SmpPdu::IdentityInformation {
            identity_resolving_key: keys.identity_resolving_key,
        });
        let _ = pdus.push(SmpPdu::IdentityAddressInformation {
            address_type: self.our_config.our_address_type,
            address: self.our_config.our_address,
        });
        let _ = pdus.push(SmpPdu::SigningInformation {
            connection_signature_resolving_key: keys.connection_signature_resolving_key,
        });
        pdus
    }

    // ── Helpers ────────────────────────────────────────────────────────

    fn store_bytes(&mut self, pdu: &SmpPdu, is_ours: bool) {
        if let Ok(arr) = Self::pdu_to_array(pdu) {
            if is_ours {
                self.our_pairing_bytes = arr;
            } else {
                self.peer_pairing_bytes = arr;
            }
        }
    }

    fn pdu_to_array(pdu: &SmpPdu) -> Result<[u8; 16], SmpError> {
        let mut buffer: Buffer<32> = Buffer::default();
        pdu.encode(&mut buffer).map_err(|_| SmpError::PduTooLong)?;
        let data = buffer.data();
        let mut arr = [0u8; 16];
        let len = data.len().min(16);
        arr[..len].copy_from_slice(&data[..len]);
        Ok(arr)
    }

    fn generate_confirm(&mut self) -> Result<(), SmpError> {
        let seed = self.our_config.io_capability as u8;
        for i in 0..16 { self.our_random[i] = seed.wrapping_add(i as u8).wrapping_mul(7); }
        self.our_confirm = self.compute_c1(&self.our_random)?;
        Ok(())
    }

    fn compute_c1(&self, rand: &[u8; 16]) -> Result<[u8; 16], SmpError> {
        let (preq, pres) = if self.is_initiator {
            (&self.our_pairing_bytes, &self.peer_pairing_bytes)
        } else {
            (&self.peer_pairing_bytes, &self.our_pairing_bytes)
        };
        let peer = self.peer_config.as_ref().unwrap_or(&self.our_config);
        self.crypto.c1(
            &self.tk, rand, preq, pres,
            self.our_config.our_address_type,
            peer.our_address_type,
            &self.our_config.our_address,
            &peer.our_address,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_pairing_request_to_response() {
        let crypto = MockCrypto;
        let (_, req) = SmpPairing::new_initiator(crypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));
        let (mut resp, _) = SmpPairing::new_initiator(crypto, cfg([0xAA,0xBB,0xCC,0xDD,0xEE,0xFF], 1));
        let r = resp.process(&req).unwrap();
        assert!(matches!(r, SmpPairingResult::SendPdu(SmpPdu::PairingResponse { .. })));
    }

    #[test]
    fn test_pairing_response_to_confirm() {
        let crypto = MockCrypto;
        let resp_pdu = SmpPdu::PairingResponse {
            io_capability: IoCapability::NoInputNoOutput, oob_data_flag: false,
            auth_req: AuthReq { bonding: true, mitm: false, secure_connections: false, keypress: false, ct2: false },
            max_encryption_key_size: 16,
            initiator_key_distribution: KeyDistribution { enc_key: false, id_key: false, sign_key: false, link_key: false },
            responder_key_distribution: KeyDistribution { enc_key: true, id_key: true, sign_key: false, link_key: false },
        };
        let (mut init, _) = SmpPairing::new_initiator(crypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));
        let r = init.process(&resp_pdu).unwrap();
        assert!(matches!(r, SmpPairingResult::SendPdu(SmpPdu::PairingConfirm { .. })));
    }

    #[test]
    fn test_pairing_confirm_to_random() {
        let crypto = MockCrypto;
        let (_, req) = SmpPairing::new_initiator(crypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));
        let (mut resp, _) = SmpPairing::new_initiator(crypto, cfg([0xAA,0xBB,0xCC,0xDD,0xEE,0xFF], 1));
        let _ = resp.process(&req).unwrap(); // → AwaitingConfirm

        let confirm = SmpPdu::PairingConfirm { confirm_value: [0x90u8; 16] };
        let r = resp.process(&confirm).unwrap();
        assert!(matches!(r, SmpPairingResult::SendPdu(SmpPdu::PairingRandom { .. })));
    }

    #[test]
    fn test_pairing_random_completes() {
        let crypto = MockCrypto;
        // Build a state machine in AwaitingRandom and feed it a PairingRandom
        let (_, req) = SmpPairing::new_initiator(crypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));
        let (mut init, _) = SmpPairing::new_initiator(crypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));

        // Advance to AwaitingRandom: PairingResponse → PairingConfirm
        let resp_pdu = SmpPdu::PairingResponse {
            io_capability: IoCapability::NoInputNoOutput, oob_data_flag: false,
            auth_req: AuthReq { bonding: true, mitm: false, secure_connections: false, keypress: false, ct2: false },
            max_encryption_key_size: 16,
            initiator_key_distribution: KeyDistribution { enc_key: false, id_key: false, sign_key: false, link_key: false },
            responder_key_distribution: KeyDistribution { enc_key: true, id_key: true, sign_key: false, link_key: false },
        };
        let confirm = match init.process(&resp_pdu).unwrap() {
            SmpPairingResult::SendPdu(p) => p,
            o => panic!("{:?}", o),
        };

        // Feed init its own confirm as if from the peer → AwaitingRandom
        let random = match init.process(&confirm).unwrap() {
            SmpPairingResult::SendPdu(p) => p,
            o => panic!("{:?}", o),
        };

        // Now feed the random → Complete
        let r = init.process(&random).unwrap();
        match r {
            SmpPairingResult::Complete { stk, .. } => {
                assert!(stk.iter().any(|&b| b != 0));
            }
            o => panic!("{:?}", o),
        }
    }

    #[test]
    fn test_passkey_entry_different_stk() {
        let crypto = MockCrypto;

        // Pairing with passkey 123456 should produce different STK than passkey 654321
        let passkey1 = 123456u32;
        let passkey2 = 654321u32;

        let resp_pdu = SmpPdu::PairingResponse {
            io_capability: IoCapability::DisplayOnly, oob_data_flag: false,
            auth_req: AuthReq { bonding: true, mitm: true, secure_connections: false, keypress: false, ct2: false },
            max_encryption_key_size: 16,
            initiator_key_distribution: KeyDistribution { enc_key: false, id_key: false, sign_key: false, link_key: false },
            responder_key_distribution: KeyDistribution { enc_key: true, id_key: true, sign_key: false, link_key: false },
        };

        // First pairing with passkey1
        let (mut init1, _) = SmpPairing::new_initiator(crypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));
        init1.set_passkey(passkey1).unwrap();
        let confirm1 = match init1.process(&resp_pdu).unwrap() {
            SmpPairingResult::SendPdu(p) => p, o => panic!("{:?}", o),
        };
        let random1 = match init1.process(&confirm1).unwrap() {
            SmpPairingResult::SendPdu(p) => p, o => panic!("{:?}", o),
        };
        let stk1 = match init1.process(&random1).unwrap() {
            SmpPairingResult::Complete { stk, .. } => stk,
            o => panic!("{:?}", o),
        };

        // Second pairing with passkey2
        let (mut init2, _) = SmpPairing::new_initiator(crypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));
        init2.set_passkey(passkey2).unwrap();
        let confirm2 = match init2.process(&resp_pdu).unwrap() {
            SmpPairingResult::SendPdu(p) => p, o => panic!("{:?}", o),
        };
        let random2 = match init2.process(&confirm2).unwrap() {
            SmpPairingResult::SendPdu(p) => p, o => panic!("{:?}", o),
        };
        let stk2 = match init2.process(&random2).unwrap() {
            SmpPairingResult::Complete { stk, .. } => stk,
            o => panic!("{:?}", o),
        };

        // Different passkeys must produce different STKs
        assert_ne!(stk1, stk2);
    }

    #[test]
    fn test_invalid_passkey_rejected() {
        let crypto = MockCrypto;
        let (mut init, _) = SmpPairing::new_initiator(crypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));
        assert!(init.set_passkey(1000000).is_err()); // > 999999
        assert!(init.set_passkey(0).is_ok());
        assert!(init.set_passkey(999999).is_ok());
    }

    #[test]
    fn test_generate_keys_and_distribution_pdus() {
        let crypto = MockCrypto;
        let resp_pdu = SmpPdu::PairingResponse {
            io_capability: IoCapability::NoInputNoOutput, oob_data_flag: false,
            auth_req: AuthReq { bonding: true, mitm: false, secure_connections: false, keypress: false, ct2: false },
            max_encryption_key_size: 16,
            initiator_key_distribution: KeyDistribution { enc_key: false, id_key: false, sign_key: false, link_key: false },
            responder_key_distribution: KeyDistribution { enc_key: true, id_key: true, sign_key: false, link_key: false },
        };

        let (mut init, _) = SmpPairing::new_initiator(crypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));
        let confirm = match init.process(&resp_pdu).unwrap() {
            SmpPairingResult::SendPdu(p) => p, o => panic!(),
        };
        let random = match init.process(&confirm).unwrap() {
            SmpPairingResult::SendPdu(p) => p, o => panic!(),
        };
        let _ = match init.process(&random).unwrap() {
            SmpPairingResult::Complete { .. } => {},
            o => panic!("{:?}", o),
        };

        assert!(init.is_complete());
        assert!(init.stk().is_some());

        let keys = init.generate_keys();
        let pdus = init.build_distribution_pdus(&keys);
        assert_eq!(pdus.len(), 5);
    }

    #[test]
    fn test_pairing_failed_handling() {
        let crypto = MockCrypto;
        let (mut p, _) = SmpPairing::new_initiator(crypto, cfg([0u8;6], 0));
        let r = p.process(&SmpPdu::PairingFailed { reason: PairingFailedReason::PairingNotSupported }).unwrap();
        assert!(matches!(r, SmpPairingResult::Failed(PairingFailedReason::PairingNotSupported)));
    }
}
