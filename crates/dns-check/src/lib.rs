use async_trait::async_trait;
use std::{net::IpAddr, time::Duration};
use thiserror::Error;
use trust_dns_proto::op::ResponseCode;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    error::ResolveError,
    TokioAsyncResolver,
};

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("DNS resolution timeout")]
    Timeout,
    #[error("DNS server error: {0}")]
    ServerError(ResponseCode),
    #[error("Network error: {0}")]
    NetworkError(#[from] ResolveError),
}

#[async_trait]
pub trait DnsAnalyzer {
    async fn check_vpn_patterns(&self, ip: IpAddr) -> Result<f32, DnsError>;
}

#[derive(Clone)]
pub struct DnsDetector {
    resolver: TokioAsyncResolver,
    timeout: Duration,
}

impl DnsDetector {
    pub fn new(timeout_sec: u64) -> Self {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(timeout_sec);

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);

        Self {
            resolver,
            timeout: Duration::from_secs(timeout_sec),
        }
    }

    pub async fn reverse_lookup(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        let result = tokio::time::timeout(self.timeout, self.resolver.reverse_lookup(ip)).await;

        match result {
            Ok(Ok(lookup)) => Ok(lookup.iter().map(|name| name.to_string()).collect()),
            Ok(Err(e)) => Err(DnsError::NetworkError(e)),
            Err(_) => Err(DnsError::Timeout),
        }
    }

    pub async fn measure_resolve_time(&self, domain: &str) -> Result<Duration, DnsError> {
        let start = std::time::Instant::now();

        let result = tokio::time::timeout(self.timeout, self.resolver.lookup_ip(domain)).await;

        match result {
            Ok(Ok(_)) => Ok(start.elapsed()),
            Ok(Err(e)) => Err(DnsError::NetworkError(e)),
            Err(_) => Err(DnsError::Timeout),
        }
    }
}

#[async_trait]
impl DnsAnalyzer for DnsDetector {
    async fn check_vpn_patterns(&self, ip: IpAddr) -> Result<f32, DnsError> {
        let mut score = 0.0;

        let hostnames = self.reverse_lookup(ip).await?;
        if hostnames
            .iter()
            .any(|h| h.contains("vpn") || h.ends_with(".vps"))
        {
            score += 0.4;
        }

        let resolve_time = self.measure_resolve_time("example.com").await?;
        if resolve_time > Duration::from_millis(500) {
            score += 0.2;
        }

        let first_lookup = self.measure_resolve_time("google.com").await?;
        let second_lookup = self.measure_resolve_time("google.com").await?;

        if (first_lookup - second_lookup).as_millis() > 100 {
            score += 0.3;
        }

        Ok(score)
    }
}
