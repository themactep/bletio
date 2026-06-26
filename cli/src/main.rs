//! bletio CLI — scan for BLE devices using raw HCI socket.

use clap::{Parser, Subcommand};
use std::time::{Duration, Instant};

const AF_BLUETOOTH: i32 = 31;
const BTPROTO_HCI: i32 = 1;

#[repr(C)]
struct sockaddr_hci { family: u16, dev: u16, channel: u16 }

struct HciSocket { fd: i32 }

impl HciSocket {
    fn open(dev: u16) -> Result<Self, String> {
        let fd = unsafe { libc::socket(AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, BTPROTO_HCI) };
        if fd < 0 { return Err(format!("socket: {}", std::io::Error::last_os_error())); }
        let addr = sockaddr_hci { family: AF_BLUETOOTH as u16, dev, channel: 0 };
        let ret = unsafe {
            libc::bind(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<sockaddr_hci>() as u32)
        };
        if ret < 0 { unsafe { libc::close(fd) }; return Err(format!("bind: {}", std::io::Error::last_os_error())); }
        // Set 2-second socket timeout
        let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32);
        }
        Ok(Self { fd })
    }

    fn write_cmd(&self, data: &[u8]) -> Result<(), String> {
        let ret = unsafe { libc::write(self.fd, data.as_ptr() as *const libc::c_void, data.len()) };
        if ret < 0 { return Err(format!("write: {}", std::io::Error::last_os_error())); }
        Ok(())
    }

    fn read_evt(&self, buf: &mut [u8; 260]) -> Result<usize, String> {
        let ret = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, 260) };
        if ret < 0 { return Err(format!("read: {}", std::io::Error::last_os_error())); }
        Ok(ret as usize)
    }
}

impl Drop for HciSocket {
    fn drop(&mut self) { unsafe { libc::close(self.fd) }; }
}

/// bletio CLI
#[derive(Parser)]
#[command(name = "bletio", version)]
struct Cli {
    #[arg(short, long, default_value = "0")]
    device: u16,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan { #[arg(short, long, default_value = "5")] duration: u64 },
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { duration } => cmd_scan(cli.device, duration),
    }
}

fn cmd_scan(dev_id: u16, secs: u64) -> Result<(), String> {
    let sock = HciSocket::open(dev_id)?;

    // HCI Reset: opcode 0x0C03, param len 0
    sock.write_cmd(&[0x01, 0x03, 0x0C, 0x00])?;
    let mut buf = [0u8; 260];
    sock.read_evt(&mut buf)?;

    // Set Event Mask: LE Meta events
    // opcode 0x0C01, len 8
    sock.write_cmd(&[0x01, 0x01, 0x0C, 0x08, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])?;
    sock.read_evt(&mut buf)?;

    // LE Set Scan Parameters: passive, interval 160 (100ms), window 80 (50ms), own addr public, filter unfiltered
    // opcode 0x200B, len 7
    sock.write_cmd(&[0x01, 0x0B, 0x20, 0x07, 0x00, 0xA0, 0x00, 0x50, 0x00, 0x00, 0x00])?;
    sock.read_evt(&mut buf)?;

    // LE Set Scan Enable: enable, no duplicates
    // opcode 0x200C, len 2
    sock.write_cmd(&[0x01, 0x0C, 0x20, 0x02, 0x01, 0x00])?;
    sock.read_evt(&mut buf)?;

    println!("Scanning ({}s)...\n", secs);
    let deadline = Instant::now() + Duration::from_secs(secs);

    while Instant::now() < deadline {
        // Set 1-second read timeout so we don't block forever
        let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
        unsafe {
            libc::setsockopt(
                sock.fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
        }
        let ret = unsafe {
            libc::read(sock.fd, buf.as_mut_ptr() as *mut libc::c_void, 260)
        };
        if ret <= 0 {
            continue;
        }
        if ret > 0 {
            let len = ret as usize;
            // Parse advertising reports from LE Meta events (0x3E with subevent 0x02)
            if len >= 4 && buf[0] == 0x04 && buf[1] == 0x3E {
                let param_len = buf[2] as usize;
                if param_len >= 2 && buf[3] == 0x02 {
                    // LE Advertising Report
                    let num_reports = buf[4] as usize;
                    let mut off = 5;
                    for _ in 0..num_reports {
                        if off + 10 > len { break; }
                        let evt_type = buf[off];
                        let addr_type = buf[off + 1];
                        let addr = &buf[off + 2..off + 8];
                        let data_len = buf[off + 8] as usize;
                        off += 9 + data_len;
                        let rssi = if off <= len { buf[off] as i8 } else { 0 };
                        off += 1;

                        let type_str = match evt_type {
                            0x00 => "ADV_IND",
                            0x01 => "ADV_DIRECT_IND",
                            0x02 => "ADV_SCAN_IND",
                            0x03 => "ADV_NONCONN_IND",
                            0x04 => "SCAN_RSP",
                            _ => "OTHER",
                        };
                        if evt_type != 0x04 { // skip scan responses
                            println!("  {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}  {:>4} dBm  {}",
                                addr[5], addr[4], addr[3], addr[2], addr[1], addr[0],
                                rssi, type_str);
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Stop scanning
    sock.write_cmd(&[0x01, 0x0C, 0x20, 0x02, 0x00, 0x00])?;
    sock.read_evt(&mut buf)?;
    println!("\nScan complete.");
    Ok(())
}
