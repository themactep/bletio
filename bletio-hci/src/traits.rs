use core::future::Future;
use core::time::Duration;

/// Error from an HCI driver transport operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HciDriverError {
    /// The write operation failed.
    WriteFailure,
    /// The read operation failed.
    ReadFailure,
    /// A command timed out.
    Timeout,
}

/// Trait for HCI transport drivers (UART, USB, SPI, etc.).
///
/// Implement this trait for your hardware to enable communication with the
/// BLE controller via [`Hci`](crate::Hci).
///
/// # Example (Tokio)
///
/// ```ignore
/// struct UartDriver { port: tokio_serial::SerialStream }
///
/// impl HciDriver for UartDriver {
///     async fn read(&mut self, buf: &mut [u8]) -> Result<usize, HciDriverError> {
///         self.port.read(buf).await.map_err(|_| HciDriverError::ReadFailure)
///     }
///     async fn write(&mut self, buf: &[u8]) -> Result<usize, HciDriverError> {
///         self.port.write(buf).await.map_err(|_| HciDriverError::WriteFailure)
///     }
/// }
/// ```
pub trait HciDriver {
    fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize, HciDriverError>>;
    fn write(&mut self, buf: &[u8]) -> impl Future<Output = Result<usize, HciDriverError>>;
}

pub trait WithTimeout {
    type Output;

    fn with_timeout(
        self,
        timeout_duration: Duration,
    ) -> impl Future<Output = Result<Self::Output, HciDriverError>>;
}
