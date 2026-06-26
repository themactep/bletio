//! Bond store for persistent pairing key storage.
//!
//! After SMP pairing completes, bond data (LTK, EDIV, Rand, IRK, CSRK, peer address)
//! must be persisted so future connections can be encrypted without re-pairing.
//!
//! # Usage
//!
//! ```ignore
//! use bletio_host::bond_store::{BondStore, MemoryBondStore};
//! use bletio_host::smp::{SmpPairing, SmpPairingConfig};
//!
//! // After pairing completes:
//! if pairing.is_complete() {
//!     let keys = pairing.generate_keys();
//!
//!     // Store bond for future connections
//!     let bond = Bond {
//!         long_term_key: keys.long_term_key,
//!         ediv: keys.ediv,
//!         rand: keys.rand,
//!         identity_resolving_key: keys.identity_resolving_key,
//!         connection_signature_resolving_key: keys.connection_signature_resolving_key,
//!         peer_address: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
//!         peer_address_type: 1,
//!     };
//!     bond_store.store_bond(&bond)?;
//!
//!     // Send key distribution PDUs to peer
//!     for pdu in pairing.build_distribution_pdus(&keys) {
//!         // encode and send over ACL...
//!     }
//! }
//!
//! // Later, when reconnecting:
//! if let Some(bond) = bond_store.load_bond(&peer_address) {
//!     // Use bond.long_term_key for HCI LE Start Encryption
//!     hci.cmd_le_start_encryption(handle, bond.rand, bond.ediv, bond.long_term_key).await?;
//! }
//! ```
//!
//! Implement [`BondStore`] for your platform's persistent storage (flash, EEPROM, filesystem).
//! An in-memory [`MemoryBondStore`] is provided for testing and platforms without persistence.

use heapless::Vec;

/// Bond data for a paired device.
///
/// Contains all keys exchanged during SMP key distribution.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Bond {
    /// Long Term Key (16 bytes) — used for link encryption.
    pub long_term_key: [u8; 16],
    /// Encrypted Diversifier (2 bytes) — used with LTK to identify the key.
    pub ediv: u16,
    /// Random value (8 bytes) — used with LTK and EDIV.
    pub rand: [u8; 8],
    /// Identity Resolving Key (16 bytes) — used to resolve random private addresses.
    pub identity_resolving_key: [u8; 16],
    /// Connection Signature Resolving Key (16 bytes) — used for data signing.
    pub connection_signature_resolving_key: [u8; 16],
    /// Peer's Bluetooth device address.
    pub peer_address: [u8; 6],
    /// Peer's address type (0 = public, 1 = random).
    pub peer_address_type: u8,
}

/// Trait for persistent bond storage.
///
/// Implement this trait for your platform's non-volatile storage. The SMP pairing
/// state machine calls these methods during key distribution and encryption setup.
pub trait BondStore {
    /// Store bond data for a peer device. Overwrites any existing bond for the same address.
    fn store_bond(&mut self, bond: &Bond) -> Result<(), BondStoreError>;

    /// Load bond data for a peer device by its address.
    fn load_bond(&self, peer_address: &[u8; 6]) -> Option<Bond>;

    /// Remove bond data for a peer device.
    fn remove_bond(&mut self, peer_address: &[u8; 6]) -> Result<(), BondStoreError>;

    /// Check if a bond exists for a peer device.
    fn has_bond(&self, peer_address: &[u8; 6]) -> bool {
        self.load_bond(peer_address).is_some()
    }

    /// Return the number of stored bonds.
    fn bond_count(&self) -> usize;
}

/// Errors from bond storage operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BondStoreError {
    /// Storage is full.
    Full,
    /// Storage operation failed (hardware error).
    StorageFailure,
    /// Bond not found.
    NotFound,
}

/// In-memory bond store for testing and platforms without persistence.
///
/// Stores up to `MAX_BONDS` bonds in RAM. Bonds are lost on power cycle.
#[derive(Debug, Clone)]
pub struct MemoryBondStore<const MAX_BONDS: usize> {
    bonds: Vec<Bond, MAX_BONDS>,
}

impl<const MAX_BONDS: usize> MemoryBondStore<MAX_BONDS> {
    /// Create an empty in-memory bond store.
    pub fn new() -> Self {
        Self {
            bonds: Vec::new(),
        }
    }
}

impl<const MAX_BONDS: usize> BondStore for MemoryBondStore<MAX_BONDS> {
    fn store_bond(&mut self, bond: &Bond) -> Result<(), BondStoreError> {
        // Replace existing bond for the same address
        self.remove_bond(&bond.peer_address).ok();

        self.bonds
            .push(bond.clone())
            .map_err(|_| BondStoreError::Full)
    }

    fn load_bond(&self, peer_address: &[u8; 6]) -> Option<Bond> {
        self.bonds
            .iter()
            .find(|b| &b.peer_address == peer_address)
            .cloned()
    }

    fn remove_bond(&mut self, peer_address: &[u8; 6]) -> Result<(), BondStoreError> {
        if let Some(pos) = self
            .bonds
            .iter()
            .position(|b| &b.peer_address == peer_address)
        {
            self.bonds.remove(pos);
            Ok(())
        } else {
            Err(BondStoreError::NotFound)
        }
    }

    fn bond_count(&self) -> usize {
        self.bonds.len()
    }
}

impl<const MAX_BONDS: usize> Default for MemoryBondStore<MAX_BONDS> {
    fn default() -> Self {
        Self::new()
    }
}

/// Default bond store capacity for typical use (10 bonded devices).
pub type DefaultBondStore = MemoryBondStore<10>;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bond(addr: [u8; 6]) -> Bond {
        Bond {
            long_term_key: [0x11; 16],
            ediv: 0x1234,
            rand: [0x42; 8],
            identity_resolving_key: [0x33; 16],
            connection_signature_resolving_key: [0x44; 16],
            peer_address: addr,
            peer_address_type: 0,
        }
    }

    #[test]
    fn test_store_and_load() {
        let mut store: MemoryBondStore<4> = MemoryBondStore::new();
        assert_eq!(store.bond_count(), 0);
        assert!(!store.has_bond(&[0xAA; 6]));

        let bond = test_bond([0xAA; 6]);
        store.store_bond(&bond).unwrap();
        assert_eq!(store.bond_count(), 1);
        assert!(store.has_bond(&[0xAA; 6]));

        let loaded = store.load_bond(&[0xAA; 6]).unwrap();
        assert_eq!(loaded.long_term_key, bond.long_term_key);
        assert_eq!(loaded.ediv, bond.ediv);
        assert_eq!(loaded.peer_address, bond.peer_address);
    }

    #[test]
    fn test_replace_existing() {
        let mut store: MemoryBondStore<4> = MemoryBondStore::new();
        store.store_bond(&test_bond([0xAA; 6])).unwrap();

        let bond2 = Bond {
            long_term_key: [0x22; 16],
            ..test_bond([0xAA; 6])
        };
        store.store_bond(&bond2).unwrap();
        assert_eq!(store.bond_count(), 1);

        let loaded = store.load_bond(&[0xAA; 6]).unwrap();
        assert_eq!(loaded.long_term_key, [0x22; 16]);
    }

    #[test]
    fn test_remove() {
        let mut store: MemoryBondStore<4> = MemoryBondStore::new();
        store.store_bond(&test_bond([0xAA; 6])).unwrap();
        store.store_bond(&test_bond([0xBB; 6])).unwrap();
        assert_eq!(store.bond_count(), 2);

        store.remove_bond(&[0xAA; 6]).unwrap();
        assert_eq!(store.bond_count(), 1);
        assert!(!store.has_bond(&[0xAA; 6]));
        assert!(store.has_bond(&[0xBB; 6]));
    }

    #[test]
    fn test_full() {
        let mut store: MemoryBondStore<2> = MemoryBondStore::new();
        store.store_bond(&test_bond([0x11; 6])).unwrap();
        store.store_bond(&test_bond([0x22; 6])).unwrap();

        let err = store.store_bond(&test_bond([0x33; 6]));
        assert!(matches!(err, Err(BondStoreError::Full)));
    }
}
