use actix_web::http::header::HeaderMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HeaderError {
    #[error("Suspicious header pattern detected")]
    SuspiciousHeaders,
}

pub struct HeaderAnalyzer;

impl HeaderAnalyzer {
    pub fn analyze(headers: &HeaderMap) -> Result<(), HeaderError> {
        if headers.contains_key("x-forwarded-for") {
            return Err(HeaderError::SuspiciousHeaders);
        }

        let first_header = headers.iter().next();
        if let Some((name, _)) = first_header {
            if name.as_str() == "cf-connecting-ip" {
                return Err(HeaderError::SuspiciousHeaders);
            }
        }

        let vpn_header = ["proxy-connection", "via", "x-proxy-id"];
        if headers.keys().any(|h| vpn_header.contains(&h.as_str())) {
            return Err(HeaderError::SuspiciousHeaders);
        }

        Ok(())
    }
}
