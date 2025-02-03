use cidr_utils::cidr::IpCidr;
use lru::LruCache;
use serde::Deserialize;
use std::num::NonZeroUsize;
use std::{collections::HashMap, net::IpAddr, path::Path};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GeoIpError {
    #[error("CSV parsing error")]
    CsvError(#[from] csv::Error),
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
    #[error("Invalid CIDR format")]
    InvalidCidr,
}

#[derive(Debug, Deserialize)]
struct CsvRecord {
    cidr: String,
    asn: String,
    provider: String,
}

#[derive(Debug, Clone)]
pub struct IpDatabase {
    cidr_ranges: Vec<IpCidr>,
    asn_cache: LruCache<IpAddr, u32>,
    vpn_providers: HashMap<String, u32>,
}

impl IpDatabase {
    pub fn load_from_csv<P: AsRef<Path>>(path: P) -> Result<Self, GeoIpError> {
        let mut rdr = csv::Reader::from_path(path)?;
        let mut cidr_ranges = Vec::new();
        let mut vpn_providers = HashMap::new();

        for result in rdr.deserialize() {
            let record: CsvRecord = result?;

            match record.cidr.parse::<IpCidr>() {
                Ok(cidr) => {
                    cidr_ranges.push(cidr);
                    vpn_providers.insert(record.provider, record.asn.parse().unwrap_or(0));
                }
                Err(_) => return Err(GeoIpError::InvalidCidr),
            }
        }

        Ok(Self {
            cidr_ranges,
            asn_cache: LruCache::new(NonZeroUsize::new(1000).unwrap()),
            vpn_providers,
        })
    }

    pub fn is_vpn_ip(&mut self, ip: IpAddr) -> bool {
        if let Some(asn) = self.asn_cache.get(&ip) {
            return self.vpn_providers.values().any(|v| v == asn);
        }

        for cidr in &self.cidr_ranges {
            if cidr.contains(&ip) {
                let asn = self
                    .vpn_providers
                    .get(cidr.to_string().as_str())
                    .copied()
                    .unwrap_or(0);

                self.asn_cache.put(ip, asn);
                return asn != 0;
            }
        }
        false
    }
}
