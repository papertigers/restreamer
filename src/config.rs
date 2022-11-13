use serde::Deserialize;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

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

#[derive(Deserialize)]
pub struct Config {
    pub watch_dir: PathBuf,
    pub users: Vec<User>,
    pub tls: Option<Tls>,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref();
        let mut f = File::open(path)?;
        let mut buf: Vec<u8> = Vec::new();
        f.read_to_end(&mut buf)?;
        let config: Self = toml::from_slice(&buf)?;

        Ok(config)
    }
}
