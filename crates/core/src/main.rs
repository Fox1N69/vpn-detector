use config::Settings;
use detector::{VpnDetector, VpnDetectorImpl};
use protobuf_api::vpn_detector::{
    vpn_detector_service_server::{VpnDetectorService, VpnDetectorServiceServer},
    CheckIpRequest, CheckIpResponse,
};
use std::net::IpAddr;
use tonic::{transport::Server, Request, Response, Status};

struct VpnDetectorServiceImpl {
    detector: VpnDetectorImpl,
}

#[tonic::async_trait]
impl VpnDetectorService for VpnDetectorServiceImpl {
    async fn check_ip(
        &self,
        request: Request<CheckIpRequest>,
    ) -> Result<Response<CheckIpResponse>, Status> {
        let ip = request.into_inner().ip;
        let ip_addr: IpAddr = ip
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid IP"))?;

        let result = self
            .detector
            .check_vpn(ip_addr)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CheckIpResponse {
            ip,
            is_vpn: result.is_vpn,
            score: result.score,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Settings::load()?;

    let addr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("Failed to parse address");

    let ip_db = geo_ip::IpDatabase::load_from_csv(&config.ip_database_path)?;
    let dns_detector = dns_check::DnsDetector::new(config.dns_timeout_sec);
    let detector = VpnDetectorImpl::new(ip_db, dns_detector);
    let service = VpnDetectorServiceImpl { detector };

    println!("GRPC Server starting on {}", addr);

    Server::builder()
        .add_service(VpnDetectorServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
