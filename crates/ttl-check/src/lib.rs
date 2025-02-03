use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkReceiver, NetworkInterface};
use pnet::packet::ipv4::Ipv4Packet;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task;

#[derive(Error, Debug)]
pub enum TtlError {
    #[error("Packet capture error")]
    CaptureError,
    #[error("Invalid TCP packet")]
    InvalidTcpPacket,
    #[error("Channel error")]
    ChannelError,
    #[error("Timeout error")]
    TimeoutError,
}

#[derive(Debug)]
pub struct Packet {
    ttl: u8,
}

pub struct TtlDetector {
    interface: NetworkInterface,
    packet_tx: mpsc::Sender<Packet>,
    packet_rx: mpsc::Receiver<Packet>,
    running: bool,
}

#[derive(Debug)]
pub struct TtlAnalysis {
    pub value: u8,
    pub is_suspicious: bool,
    pub probable_os: Option<&'static str>,
    pub is_vpn: bool,
}

impl TtlDetector {
    pub fn new(interface: NetworkInterface) -> Result<Self, TtlError> {
        let (packet_tx, packet_rx) = mpsc::channel(100);

        Ok(Self {
            interface,
            packet_tx,
            packet_rx,
            running: false,
        })
    }

    pub async fn start(&mut self) -> Result<(), TtlError> {
        if self.running {
            return Ok(());
        }

        self.running = true;
        let tx = self.packet_tx.clone();

        task::spawn_blocking(move || {
            let interfaces = datalink::interfaces();
            let interface = interfaces
                .into_iter()
                .filter(|iface| !iface.is_loopback())
                .find(|iface| iface.ips.iter().any(|ip| ip.is_ipv4()))
                .ok_or(TtlError::CaptureError)
                .unwrap();

            let mut rx: Box<dyn DataLinkReceiver> =
                match datalink::channel(&interface, Default::default()) {
                    Ok(Ethernet(_, rx)) => rx,
                    Ok(_) | Err(_) => return,
                };

            loop {
                match rx.next() {
                    Ok(packet) => {
                        if let Some(ipv4_packet) = Ipv4Packet::new(packet) {
                            let ttl = ipv4_packet.get_ttl();
                            let packet = Packet { ttl };

                            if tx.blocking_send(packet).is_err() {
                                break;
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        });

        Ok(())
    }

    pub async fn stop(&mut self) {
        self.running = false;
    }

    pub async fn capture_ttl(&mut self) -> Result<u8, TtlError> {
        if !self.running {
            self.start().await?;
        }

        match self.packet_rx.recv().await {
            Some(packet) => Ok(packet.ttl),
            None => Err(TtlError::ChannelError),
        }
    }

    pub async fn capture_ttl_with_timeout(&mut self, timeout: Duration) -> Result<u8, TtlError> {
        if !self.running {
            self.start().await?;
        }

        tokio::time::timeout(timeout, self.capture_ttl())
            .await
            .map_err(|_| TtlError::TimeoutError)?
    }

    pub fn is_suspicious_ttl(ttl: u8) -> bool {
        !matches!(ttl, 64 | 128 | 255)
    }

    pub fn analyze_ttl(&self, ttl: u8) -> TtlAnalysis {
        let is_suspicious = Self::is_suspicious_ttl(ttl);

        let probable_os = match ttl {
            64 => Some("Linux/Unix"),
            128 => Some("Windows"),
            255 => Some("Network Equipment"),
            _ => None,
        };

        let is_vpn = match probable_os {
            Some("Linux/Unix") if ttl < 64 => true,
            Some("Windows") if ttl < 126 => true,
            _ => false,
        };

        TtlAnalysis {
            value: ttl,
            is_suspicious,
            probable_os,
            is_vpn,
        }
    }

    pub fn get_interface(&self) -> &NetworkInterface {
        &self.interface
    }
}
