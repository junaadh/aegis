use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub tls_cert: Option<String>,
    #[serde(default)]
    pub tls_key: Option<String>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_log_format")]
    pub log_format: String,
    #[serde(default = "default_log_output")]
    pub log_output: Vec<String>,
}

fn default_host() -> String {
    "0.0.0.0".to_owned()
}

fn default_port() -> u16 {
    8080
}

fn default_log_level() -> String {
    "info".to_owned()
}

fn default_log_format() -> String {
    "json".to_owned()
}

fn default_log_output() -> Vec<String> {
    vec!["stdout".to_owned()]
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            public_url: None,
            tls_cert: None,
            tls_key: None,
            log_level: default_log_level(),
            log_format: default_log_format(),
            log_output: default_log_output(),
        }
    }
}

impl ServerConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.tls_cert.is_some() && self.tls_key.is_none() {
            return Err("tls_cert requires tls_key".to_owned());
        }
        if self.tls_key.is_some() && self.tls_cert.is_none() {
            return Err("tls_key requires tls_cert".to_owned());
        }
        if !["debug", "info", "warn", "error"].contains(&self.log_level.as_str()) {
            return Err(format!("invalid log_level: {}", self.log_level));
        }
        if !["json", "text"].contains(&self.log_format.as_str()) {
            return Err(format!("invalid log_format: {}", self.log_format));
        }
        Ok(())
    }
}
