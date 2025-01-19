use dropshot::ConfigTls;
use serde::Deserialize;
use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
/// Server specific settings
pub struct Server {
    // IP
    pub host: IpAddr,
    /// Port
    pub port: u16,
    /// Number of tokio worker threads
    pub threads: Option<usize>,
    /// Drop privs (useful if not running under smf)
    pub reduce_privs: Option<bool>,
    /// Direcotry the server will watch and stream out of
    pub watch_dir: PathBuf,
    /// How often to scan for new files in seconds
    pub scan_interval: Option<u64>,
    /// Is the server enabled by default
    pub default_enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct User {
    pub auth_token: String,
    admin: bool,
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.admin
    }
}

#[derive(Deserialize)]
pub struct Tls {
    pub key: PathBuf,
    pub cert: PathBuf,
}

impl From<Tls> for ConfigTls {
    fn from(t: Tls) -> Self {
        Self::AsFile { cert_file: t.cert, key_file: t.key }
    }
}

#[derive(Deserialize)]
pub struct Config {
    pub server: Server,
    pub users: Vec<User>,
    pub tls: Option<Tls>,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let file = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&file)?;

        Ok(config)
    }
}
