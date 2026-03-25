use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Parser;

#[derive(Debug, Clone, Parser)]
#[command(name = "wireproxy-rs", about = "Userspace WireGuard to SOCKS5 proxy")]
pub struct Cli {
    #[arg(long, default_value = "wg.conf")]
    pub config: PathBuf,

    #[arg(long, default_value = "127.0.0.1")]
    pub socks_host: String,

    #[arg(long, default_value_t = 1080)]
    pub socks_port: u16,

    #[arg(long)]
    pub socks_username: Option<String>,

    #[arg(long)]
    pub socks_password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksAuth {
    None,
    Password { username: String, password: String },
}

impl Cli {
    pub fn socks_bind(&self) -> String {
        format!("{}:{}", self.socks_host, self.socks_port)
    }

    pub fn socks_auth_label(&self) -> &'static str {
        if self.socks_username.is_some() {
            "password"
        } else {
            "none"
        }
    }

    pub fn socks_auth(&self) -> Result<SocksAuth> {
        match (&self.socks_username, &self.socks_password) {
            (None, None) => Ok(SocksAuth::None),
            (Some(username), Some(password)) => Ok(SocksAuth::Password {
                username: username.clone(),
                password: password.clone(),
            }),
            _ => bail!("--socks-username and --socks-password must be provided together"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, SocksAuth};

    #[test]
    fn auth_defaults_to_none() {
        let cli = Cli {
            config: "wg.conf".into(),
            socks_host: "127.0.0.1".into(),
            socks_port: 1080,
            socks_username: None,
            socks_password: None,
        };

        assert_eq!(cli.socks_auth().unwrap(), SocksAuth::None);
    }

    #[test]
    fn password_auth_requires_both_values() {
        let cli = Cli {
            config: "wg.conf".into(),
            socks_host: "127.0.0.1".into(),
            socks_port: 1080,
            socks_username: Some("user".into()),
            socks_password: None,
        };

        assert!(cli.socks_auth().is_err());
    }
}
