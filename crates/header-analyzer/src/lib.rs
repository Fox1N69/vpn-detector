use actix_web::http::header::HeaderMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HeaderError {
    #[error("Suspicious header(s) detected: {0:?}")]
    SuspiciousHeaders(Vec<String>),
}

pub struct HeaderAnalyzer;

impl HeaderAnalyzer {
    const SUSPICIOUS_HEADERS: &'static [&'static str] = &[
        "x-forwarded-for",
        "cf-connecting-ip",
        "proxy-connection",
        "via",
        "x-proxy-id",
    ];

    pub fn analyze(headers: &HeaderMap) -> Result<(), HeaderError> {
        let suspicious: Vec<String> = headers
            .keys()
            .filter_map(|name| {
                let name_lower = name.as_str().to_ascii_lowercase();
                if Self::SUSPICIOUS_HEADERS.contains(&name_lower.as_str()) {
                    Some(name_lower)
                } else {
                    None
                }
            })
            .collect();

        if !suspicious.is_empty() {
            return Err(HeaderError::SuspiciousHeaders(suspicious));
        }

        Ok(())
    }
}
