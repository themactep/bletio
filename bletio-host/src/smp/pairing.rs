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
    fn test_just_works_pairing_flow() {
        let crypto = MockCrypto;
        let (mut init, init_req) = SmpPairing::new_initiator(crypto, cfg([0x11,0x22,0x33,0x44,0x55,0x66], 0));
        let (mut resp, _) = SmpPairing::new_initiator(crypto, cfg([0xAA,0xBB,0xCC,0xDD,0xEE,0xFF], 1));

        // Step 1: Resp ← Request → Response
        let resp_pdu = match resp.process(&init_req).unwrap() {
            SmpPairingResult::SendPdu(p) => p,
            o => panic!("step1: {:?}", o),
        };
        assert_eq!(*resp.phase(), SmpPairingPhase::AwaitingConfirm);
        assert!(matches!(resp_pdu, SmpPdu::PairingResponse { .. }));

        // Step 2: Init ← Response → Confirm
        let step2 = init.process(&resp_pdu).unwrap();
        let init_pdu = match step2 {
            SmpPairingResult::SendPdu(p) => p,
            ref o => panic!("step2: {:?}", o),
        };

        // Step 3: Resp ← Confirm → Random
        let resp_pdu = match resp.process(&init_pdu).unwrap() {
            SmpPairingResult::SendPdu(p) => p,
            o => panic!("step3: {:?}", o),
        };

        // Step 4: Init ← Random → Complete
        match init.process(&resp_pdu).unwrap() {
            SmpPairingResult::Complete { stk, .. } => {
                assert!(init.is_complete());
                assert!(stk.iter().any(|&b| b != 0));
            }
            o => panic!("step4: {:?}", o),
        }
    }

    #[test]
    fn test_pairing_failed_handling() {
        let crypto = MockCrypto;
        let (mut p, _) = SmpPairing::new_initiator(crypto, cfg([0u8;6], 0));
        let r = p.process(&SmpPdu::PairingFailed { reason: PairingFailedReason::PairingNotSupported }).unwrap();
        assert!(matches!(r, SmpPairingResult::Failed(PairingFailedReason::PairingNotSupported)));
    }
}
