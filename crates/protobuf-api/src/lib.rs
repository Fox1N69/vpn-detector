#![allow(clippy::derive_partial_eq_without_eq)]

pub mod vpn_detector {
    include!("generated/vpn_detector.rs");
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DetectionResult {
    pub ip: String,
    pub is_vpn: bool,
    pub score: f32,
}

impl From<DetectionResult> for vpn_detector::CheckIpResponse {
    fn from(item: DetectionResult) -> Self {
        vpn_detector::CheckIpResponse {
            ip: item.ip,
            is_vpn: item.is_vpn,
            score: item.score,
        }
    }
}
