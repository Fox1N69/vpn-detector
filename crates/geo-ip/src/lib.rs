use cidr_utils::cidr::IpCidr;
use lru::LruCache;
use serde::Deserialize;
use std::num::NonZeroUsize;
use std::{net::IpAddr, path::Path};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GeoIpError {
    #[error("CSV parsing error: {0}")]
    CsvError(#[from] csv::Error),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid CIDR format in record: {0}")]
    InvalidCidr(String),
    #[error("Invalid ASN format in record: {0}")]
    InvalidAsn(String),
}

#[derive(Debug, Deserialize)]
struct CsvRecord {
    cidr: String,
    asn: String,
    provider: String,
}

#[derive(Debug, Clone)]
struct IpEntry {
    cidr: IpCidr,
    asn: u32,

    #[allow(dead_code)]
    provider: String,
}

#[derive(Debug, Clone)]
pub struct IpDatabase {
    entries: Vec<IpEntry>,
    asn_cache: LruCache<IpAddr, u32>,
}

impl IpDatabase {
    pub fn load_from_csv<P: AsRef<Path>>(path: P) -> Result<Self, GeoIpError> {
        let mut rdr = csv::Reader::from_path(path)?;
        let mut entries = Vec::new();

        for result in rdr.deserialize() {
            let record: CsvRecord = result?;
            let cidr = record
                .cidr
                .parse::<IpCidr>()
                .map_err(|_| GeoIpError::InvalidCidr(record.cidr.clone()))?;
            let asn: u32 = record
                .asn
                .parse()
                .map_err(|_| GeoIpError::InvalidAsn(record.asn.clone()))?;

            entries.push(IpEntry {
                cidr,
                asn,
                provider: record.provider,
            });
        }

        Ok(Self {
            entries,
            asn_cache: LruCache::new(NonZeroUsize::new(1000).expect("Cache size must be > 0")),
        })
    }

    pub fn is_vpn_ip(&mut self, ip: IpAddr) -> bool {
        if let Some(&asn) = self.asn_cache.get(&ip) {
            return asn != 0;
        }

        for entry in &self.entries {
            if entry.cidr.contains(&ip) {
                self.asn_cache.put(ip, entry.asn);
                return entry.asn != 0;
            }
        }
        false
    }
}
