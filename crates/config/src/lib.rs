use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use validator::Validate;

#[derive(Debug, Clone, Validate, Deserialize, Serialize)]
pub struct Settings {
    #[serde(default)]
    pub server: ServerConfig,

    #[validate(length(min = 1))]
    #[serde(default = "default_ip_database_path")]
    pub ip_database_path: String,

    #[serde(default = "default_threshold")]
    #[validate(range(min = 0.1, max = 1.0))]
    pub vpn_threshold: f32,

    #[serde(default = "default_dns_timeout")]
    pub dns_timeout_sec: u64,
}

#[derive(Debug, Clone, Validate, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port")]
    #[validate(range(min = 1, max = 65535))]
    pub port: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            ip_database_path: default_ip_database_path(),
            vpn_threshold: default_threshold(),
            dns_timeout_sec: default_dns_timeout(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

fn default_host() -> String {
    "0.0.0.0".into()
}

fn default_port() -> u16 {
    8080
}

fn default_threshold() -> f32 {
    0.8
}

fn default_dns_timeout() -> u64 {
    3
}

fn default_ip_database_path() -> String {
    "assets/vpn_ips.csv".into()
}

impl Settings {
    pub fn load() -> Result<Self, figment::Error> {
        let config = Figment::new()
            .merge(Toml::file("config/default.toml"))
            .merge(Env::prefixed("VPN_"))
            .extract()?;

        Ok(config)
    }
}

impl ServerConfig {
    pub fn socket_addr(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        format!("{}:{}", self.host, self.port).parse()
    }
}
