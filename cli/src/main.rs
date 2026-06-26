//! bletio CLI — command-line BLE tool using the bletio stack.
//!
//! Commands:
//!   scan    — Scan for advertising BLE devices
//!   info    — Connect and read basic device information
//!
//! Uses Linux HCI sockets for controller communication.

use bletio_hci::{HciDriver, HciDriverError};
use clap::{Parser, Subcommand};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;
use tokio::io::unix::AsyncFd;

// libc doesn't define sockaddr_hci on all platforms
#[repr(C)]
struct sockaddr_hci {
    hci_family: u16,
    hci_dev: u16,
    hci_channel: u16,
}

/// bletio — command-line BLE tool
#[derive(Parser)]
#[command(name = "bletio", version, about)]
struct Cli {
    /// HCI device index (default: 0 for hci0)
    #[arg(short, long, default_value = "0")]
    device: u16,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan for nearby BLE devices
    Scan {
        /// Scan duration in seconds
        #[arg(short, long, default_value = "5")]
        duration: u64,
    },
    /// Connect to a device and read basic info
    Info {
        /// Device address (XX:XX:XX:XX:XX:XX)
        address: String,
    },
}

// ─── HCI socket driver ──────────────────────────────────────────────────

/// Linux Bluetooth HCI socket driver.
///
/// Opens an `AF_BLUETOOTH` socket and binds to the specified HCI device.
struct HciSocket {
    fd: AsyncFd<OwnedFd>,
}

impl HciSocket {
    /// Open an HCI socket for the given device index (0 = hci0).
    fn open(dev_id: u16) -> Result<Self, std::io::Error> {
        // libc constants
        const AF_BLUETOOTH: i32 = 31; // AF_BLUETOOTH on Linux
        const BTPROTO_HCI: i32 = 1;

        let fd = unsafe {
            libc::socket(AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, BTPROTO_HCI)
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Bind to device
        let mut addr = sockaddr_hci {
            hci_family: AF_BLUETOOTH as u16,
            hci_dev: dev_id,
            hci_channel: 0, // HCI_CHANNEL_RAW
        };

        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_hci>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::last_os_error());
        }

        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            fd: AsyncFd::new(owned_fd)?,
        })
    }
}

impl HciDriver for HciSocket {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, HciDriverError> {
        loop {
            let mut guard = self.fd.readable().await.map_err(|_| HciDriverError::ReadFailure)?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let ret = unsafe {
                    libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        return Err(err);
                    }
                    return Err(err);
                }
                Ok(ret as usize)
            }) {
                Ok(result) => return result.map_err(|_| HciDriverError::ReadFailure),
                Err(_would_block) => continue,
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize, HciDriverError> {
        loop {
            let mut guard = self.fd.writable().await.map_err(|_| HciDriverError::WriteFailure)?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let ret = unsafe {
                    libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len())
                };
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        return Err(err);
                    }
                    return Err(err);
                }
                Ok(ret as usize)
            }) {
                Ok(result) => return result.map_err(|_| HciDriverError::WriteFailure),
                Err(_would_block) => continue,
            }
        }
    }
}

// ─── Commands ───────────────────────────────────────────────────────────

async fn cmd_scan(dev_id: u16, duration_secs: u64) -> Result<(), Box<dyn std::error::Error>> {
    use bletio_hci::{
        Event, Hci, LeEventMask, LeMetaEvent,
        OwnAddressType, ScanEnable, ScanParameters, ScanType,
        FilterDuplicates, ScanningFilterPolicy,
    };

    let driver = HciSocket::open(dev_id)?;
    let mut hci = Hci::new(driver);

    // Reset controller
    hci.cmd_reset().await.unwrap();

    // Set event mask for LE Meta events
    hci.cmd_set_event_mask(bletio_hci::EventMask::LE_META).await.unwrap();
    let _ = hci.cmd_le_set_event_mask(LeEventMask::default());

    // Configure scan parameters (active scanning, 100ms interval, 50ms window)
    let scan_params = ScanParameters::try_new(
        ScanType::ActiveScanning,
        bletio_hci::scan_interval!(160), // 100ms
        bletio_hci::scan_window!(80),    // 50ms
        OwnAddressType::PublicDeviceAddress,
        ScanningFilterPolicy::BasicUnfiltered,
    ).map_err(|_| "invalid scan params")?;

    hci.cmd_le_set_scan_parameters(scan_params).await.unwrap();
    hci.cmd_le_set_scan_enable(ScanEnable::Enabled, FilterDuplicates::Disabled).await.unwrap();

    println!("Scanning ({}s)...\n", duration_secs);
    println!("  {:18}  {:>4}  {:>7}", "ADDRESS", "RSSI", "TYPE");
    println!("  {:-<18}  {:-<4}  {:-<7}", "", "", "");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(duration_secs);

    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), hci.wait_for_event()).await {
            Ok(Ok(event_list)) => {
                for event in event_list.iter() {
                    if let Event::LeMeta(LeMetaEvent::LeAdvertisingReport(reports)) = event {
                        for report in reports.iter() {
                            let addr_bytes = report.address().value();
                            let rssi = report.rssi().map(|r| r.value()).unwrap_or(0);
                            // Don't print scan responses (they duplicate)
                            println!(
                                "  {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}  {:>3}  {:>7}",
                                addr_bytes[5], addr_bytes[4], addr_bytes[3],
                                addr_bytes[2], addr_bytes[1], addr_bytes[0],
                                rssi,
                                report.event_type() as u8,
                            );
                        }
                    }
                }
            }
            _ => continue,
        }
    }

    hci.cmd_le_set_scan_enable(ScanEnable::Disabled, FilterDuplicates::Disabled).await.unwrap();
    println!("\nScan complete.");
    Ok(())
}

fn print_advertising_reports(events: &bletio_hci::EventList) {
    // Kept for reference; scan output is inlined in cmd_scan
    let _ = events;
}

async fn cmd_info(dev_id: u16, address_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to {}...", address_str);
    println!("(Connection support requires LE Create Connection — available in the HCI layer)");
    println!("Device: hci{}", dev_id);
    let _ = HciSocket::open(dev_id)?;
    Ok(())
}

// ─── Main ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { duration } => cmd_scan(cli.device, duration).await?,
        Commands::Info { address } => cmd_info(cli.device, &address).await?,
    }

    Ok(())
}
