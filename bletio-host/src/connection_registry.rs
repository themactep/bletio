//! Connection registry for tracking active BLE connections.
//!
//! Maps connection handles to connection state (parameters, role, ACL queues).
//! Supports multiple simultaneous connections (peripheral + multiple centrals).

use bletio_hci::{ConnectionHandle, ConnectionIntervalRange, Latency, SupervisionTimeout};
use heapless::Vec;

/// Role of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConnectionRole {
    Central,
    Peripheral,
}

/// State of a single active connection.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Connection {
    /// The connection handle assigned by the controller.
    pub handle: ConnectionHandle,
    /// Our role in this connection.
    pub role: ConnectionRole,
    /// Current connection interval range.
    pub interval: ConnectionIntervalRange,
    /// Current peripheral latency.
    pub latency: Latency,
    /// Current supervision timeout.
    pub supervision_timeout: SupervisionTimeout,
    /// Peer's Bluetooth device address type (0 = public, 1 = random).
    pub peer_address_type: u8,
    /// Peer's Bluetooth device address.
    pub peer_address: [u8; 6],
}

/// Registry of active BLE connections.
///
/// Supports up to `MAX_CONNECTIONS` simultaneous connections. On a peripheral,
/// this is typically 1. On a central, this can be higher.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectionRegistry<const MAX_CONNECTIONS: usize> {
    connections: Vec<Connection, MAX_CONNECTIONS>,
}

impl<const MAX_CONNECTIONS: usize> ConnectionRegistry<MAX_CONNECTIONS> {
    /// Create an empty connection registry.
    pub fn new() -> Self {
        Self {
            connections: Vec::new(),
        }
    }

    /// Number of active connections.
    pub fn count(&self) -> usize {
        self.connections.len()
    }

    /// Returns true if no connections are active.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Find a connection by handle.
    pub fn find(&self, handle: ConnectionHandle) -> Option<&Connection> {
        self.connections.iter().find(|c| c.handle == handle)
    }

    /// Find a mutable connection by handle.
    pub fn find_mut(&mut self, handle: ConnectionHandle) -> Option<&mut Connection> {
        self.connections.iter_mut().find(|c| c.handle == handle)
    }

    /// Register a new connection. Returns an error if the registry is full.
    pub fn add(&mut self, connection: Connection) -> Result<(), Connection> {
        self.connections.push(connection)
    }

    /// Remove a connection by handle. Returns the removed connection or None.
    pub fn remove(&mut self, handle: ConnectionHandle) -> Option<Connection> {
        if let Some(pos) = self.connections.iter().position(|c| c.handle == handle) {
            Some(self.connections.remove(pos))
        } else {
            None
        }
    }

    /// Update connection parameters for a given handle.
    pub fn update_params(
        &mut self,
        handle: ConnectionHandle,
        interval: ConnectionIntervalRange,
        latency: Latency,
        supervision_timeout: SupervisionTimeout,
    ) -> Result<(), ()> {
        if let Some(conn) = self.find_mut(handle) {
            conn.interval = interval;
            conn.latency = latency;
            conn.supervision_timeout = supervision_timeout;
            Ok(())
        } else {
            Err(())
        }
    }

    /// Iterate over all active connections.
    pub fn iter(&self) -> impl Iterator<Item = &Connection> {
        self.connections.iter()
    }

    /// Returns the first connection (useful for single-connection peripherals).
    pub fn first(&self) -> Option<&Connection> {
        self.connections.first()
    }

    /// Returns the handle of the first connection, if any.
    pub fn first_handle(&self) -> Option<ConnectionHandle> {
        self.connections.first().map(|c| c.handle)
    }
}

impl<const MAX_CONNECTIONS: usize> Default for ConnectionRegistry<MAX_CONNECTIONS> {
    fn default() -> Self {
        Self::new()
    }
}

/// Default registry size for a peripheral (single connection).
pub type PeripheralConnectionRegistry = ConnectionRegistry<1>;

/// Default registry size for a central (up to 4 connections).
pub type CentralConnectionRegistry = ConnectionRegistry<4>;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connection(handle: u16) -> Connection {
        Connection {
            handle: ConnectionHandle::try_new(handle).unwrap(),
            role: ConnectionRole::Peripheral,
            interval: Default::default(),
            latency: Default::default(),
            supervision_timeout: Default::default(),
            peer_address_type: 0,
            peer_address: [0u8; 6],
        }
    }

    #[test]
    fn test_registry_add_find_remove() {
        let mut registry: ConnectionRegistry<4> = ConnectionRegistry::new();
        assert!(registry.is_empty());

        registry.add(test_connection(0)).unwrap();
        assert_eq!(registry.count(), 1);
        assert!(registry.find(ConnectionHandle::try_new(0).unwrap()).is_some());

        registry.add(test_connection(1)).unwrap();
        assert_eq!(registry.count(), 2);

        let removed = registry.remove(ConnectionHandle::try_new(0).unwrap()).unwrap();
        assert_eq!(removed.handle.value(), 0);
        assert_eq!(registry.count(), 1);
        assert!(registry.find(ConnectionHandle::try_new(0).unwrap()).is_none());
    }

    #[test]
    fn test_registry_update_params() {
        let mut registry: ConnectionRegistry<1> = ConnectionRegistry::new();
        registry.add(test_connection(0)).unwrap();

        let new_interval = bletio_hci::connection_interval_range!(16, 32);
        let new_latency = bletio_hci::latency!(1);
        let new_timeout = bletio_hci::supervision_timeout!(100);

        registry.update_params(
            ConnectionHandle::try_new(0).unwrap(),
            new_interval.clone(),
            new_latency,
            new_timeout,
        ).unwrap();

        let conn = registry.find(ConnectionHandle::try_new(0).unwrap()).unwrap();
        assert_eq!(conn.interval, new_interval);
        assert_eq!(conn.latency, new_latency);
        assert_eq!(conn.supervision_timeout, new_timeout);
    }

    #[test]
    fn test_registry_full() {
        let mut registry: ConnectionRegistry<1> = ConnectionRegistry::new();
        registry.add(test_connection(0)).unwrap();
        let err = registry.add(test_connection(1));
        assert!(err.is_err());
    }

    #[test]
    fn test_first_handle() {
        let mut registry: ConnectionRegistry<4> = ConnectionRegistry::new();
        assert!(registry.first_handle().is_none());

        registry.add(test_connection(42)).unwrap();
        assert_eq!(
            registry.first_handle().unwrap(),
            ConnectionHandle::try_new(42).unwrap()
        );
    }
}
