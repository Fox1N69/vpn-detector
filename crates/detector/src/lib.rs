use async_trait::async_trait;
use dns_check::{DnsAnalyzer, DnsDetector};
use geo_ip::IpDatabase;
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Error, Debug)]
pub enum DetectionError {
    #[error("IP analysis failed: {0}")]
    IpError(#[from] geo_ip::GeoIpError),
    #[error("DNS check failed: {0}")]
    DnsError(#[from] dns_check::DnsError),
}

#[async_trait]
pub trait VpnDetector {
    async fn check_vpn(&self, ip: IpAddr) -> Result<DetectionResult, DetectionError>;
}

pub struct DetectionResult {
    pub is_vpn: bool,
    pub score: f32,
    pub details: DetectionDetails,
}

pub struct DetectionDetails {
    pub ip_check: bool,
    pub dns_score: f32,
    pub ttl_analysis: Option<bool>,
}

pub struct VpnDetectorImpl {
    ip_db: Arc<Mutex<IpDatabase>>,
    dns_detector: Arc<Mutex<DnsDetector>>,
}

impl VpnDetectorImpl {
    pub fn new(ip_db: IpDatabase, dns_detector: DnsDetector) -> Self {
        Self {
            ip_db: Arc::new(Mutex::new(ip_db)),
            dns_detector: Arc::new(Mutex::new(dns_detector)),
        }
    }
}

#[async_trait]
impl VpnDetector for VpnDetectorImpl {
    async fn check_vpn(&self, ip: IpAddr) -> Result<DetectionResult, DetectionError> {
        let mut ip_db = self.ip_db.lock().await;
        let ip_check = ip_db.is_vpn_ip(ip);

        // Получаем блокировку для dns_detector
        let dns_detector = self.dns_detector.lock().await;
        let dns_score = dns_detector.check_vpn_patterns(ip).await?;

        let total_score = ip_check as u8 as f32 * 0.7 + dns_score;

        Ok(DetectionResult {
            is_vpn: total_score >= 0.8,
            score: total_score,
            details: DetectionDetails {
                ip_check,
                dns_score,
                ttl_analysis: None,
            },
        })
    }
}
