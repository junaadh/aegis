use crate::enums::{LogFormat, LogLevel};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[schemars(title = "Bind host", description = "IP address to bind the server to.")]
    #[serde(default = "default_host")]
    pub host: String,

    #[schemars(title = "Bind port", description = "TCP port to listen on.")]
    #[serde(default = "default_port")]
    pub port: u16,

    #[schemars(title = "Public URL", description = "External URL for this server (used for redirects, CORS, etc.).")]
    #[serde(default)]
    pub public_url: Option<String>,

    #[schemars(title = "TLS certificate", description = "Path to TLS certificate file.")]
    #[serde(default)]
    pub tls_cert: Option<String>,

    #[schemars(title = "TLS private key", description = "Path to TLS private key file.")]
    #[serde(default)]
    pub tls_key: Option<String>,

    #[schemars(title = "Log level", description = "Server log verbosity.")]
    #[serde(default)]
    pub log_level: LogLevel,

    #[schemars(title = "Log format", description = "Structured or plain log output.")]
    #[serde(default)]
    pub log_format: LogFormat,

    #[schemars(title = "Log outputs", description = "List of log output destinations.")]
    #[serde(default = "default_log_output")]
    pub log_output: Vec<String>,
}

fn default_host() -> String {
    "0.0.0.0".to_owned()
}

fn default_port() -> u16 {
    8080
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
            log_level: LogLevel::default(),
            log_format: LogFormat::default(),
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
        Ok(())
    }
}
