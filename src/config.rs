use std::path::PathBuf;

use anyhow::Context;
use futures_util::StreamExt;
use poem::listener::{
    acme::{AutoCert, ChallengeType},
    BoxListener, Listener, RustlsCertificate, RustlsConfig,
};
use rc_fcm::ApplicationCredentials;
use serde::{Deserialize, Deserializer, Serialize};

use crate::api::LangId;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyConfig {
    pub server_id: String,
    pub server_key: String,
    pub third_party_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub system: SystemConfig,
    pub network: NetworkConfig,
    #[serde(default)]
    pub template: TemplatesConfig,
    #[serde(default, rename = "user")]
    pub users: Vec<UserConfig>,
    pub webclient_url: Option<String>,
    #[serde(default)]
    pub offical_fcm_config: ApplicationCredentials,
}

#[derive(Debug, Deserialize)]
pub struct SystemConfig {
    pub data_dir: PathBuf,
    #[serde(default = "default_token_expiry_seconds")]
    pub token_expiry_seconds: i64,
    #[serde(default = "default_refresh_token_expiry_seconds")]
    pub refresh_token_expiry_seconds: i64,
    #[serde(default = "default_magic_token_expiry_seconds")]
    pub magic_token_expiry_seconds: i64,
    #[serde(default = "default_upload_avatar_limit")]
    pub upload_avatar_limit: usize,
    #[serde(default = "default_send_image_limit")]
    pub send_image_limit: usize,
    #[serde(default = "default_upload_timeout_seconds")]
    pub upload_timeout_seconds: i64,
    #[serde(default = "default_file_expiry_days")]
    pub file_expiry_days: i64,
    #[serde(default = "default_max_favorite_archives")]
    pub max_favorite_archives: usize,
}

const fn default_token_expiry_seconds() -> i64 {
    60 * 5
}

const fn default_refresh_token_expiry_seconds() -> i64 {
    60 * 60 * 24 * 7
}

const fn default_magic_token_expiry_seconds() -> i64 {
    60 * 15
}

const fn default_upload_avatar_limit() -> usize {
    1024 * 512
}

const fn default_send_image_limit() -> usize {
    1024 * 1024 * 2
}

const fn default_upload_timeout_seconds() -> i64 {
    300
}

const fn default_file_expiry_days() -> i64 {
    30 * 3
}

const fn default_max_favorite_archives() -> usize {
    100
}

impl SystemConfig {
    pub fn sqlite_filename(&self) -> PathBuf {
        self.db_dir().join("db.sqlite")
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.data_dir.join("upload").join("tmp")
    }

    pub fn db_dir(&self) -> PathBuf {
        self.data_dir.join("db")
    }

    pub fn msg_dir(&self) -> PathBuf {
        self.data_dir.join("msg")
    }

    pub fn avatar_dir(&self) -> PathBuf {
        self.data_dir.join("avatar")
    }

    pub fn group_avatar_dir(&self) -> PathBuf {
        self.data_dir.join("group_avatar")
    }

    pub fn thumbnail_dir(&self) -> PathBuf {
        self.data_dir.join("upload").join("thumbnail")
    }

    pub fn file_dir(&self) -> PathBuf {
        self.data_dir.join("upload").join("file")
    }

    pub fn archive_msg_dir(&self) -> PathBuf {
        self.data_dir.join("archive_msgs")
    }

    pub fn wwwroot_dir(&self) -> PathBuf {
        self.data_dir.join("wwwroot")
    }

    pub fn temp_wwwroot_dir(&self) -> PathBuf {
        self.data_dir.join("wwwroot.temp")
    }

    pub fn favorite_dir(&self, uid: i64) -> PathBuf {
        self.data_dir.join("favorite").join(format!("{}", uid))
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TlsConfig {
    SelfSigned,
    Certificate {
        cert: Option<String>,
        cert_path: Option<String>,
        key: Option<String>,
        key_path: Option<String>,
    },
    #[serde(rename = "acme_http_01")]
    AcmeHttp01 {
        #[serde(default = "acme_http_bind")]
        http_bind: String,
        directory_url: Option<String>,
        cache_path: Option<String>,
    },
    #[serde(rename = "acme_tls_alpn_01")]
    AcmeTlsAlpn01 {
        directory_url: Option<String>,
        cache_path: Option<String>,
    },
}

fn acme_http_bind() -> String {
    "0.0.0.0:80".to_string()
}

impl TlsConfig {
    pub fn create_auto_cert(&self, domains: &[String]) -> anyhow::Result<Option<AutoCert>> {
        match self {
            TlsConfig::SelfSigned | TlsConfig::Certificate { .. } => Ok(None),
            TlsConfig::AcmeHttp01 {
                cache_path,
                directory_url,
                ..
            } => {
                anyhow::ensure!(!domains.is_empty(), "missing `network.domain` config");
                let mut auto_cert = domains.iter().fold(
                    AutoCert::builder().challenge_type(ChallengeType::Http01),
                    |acc, domain| acc.domain(domain),
                );
                if let Some(directory_url) = directory_url {
                    auto_cert = auto_cert.directory_url(directory_url);
                }
                if let Some(cache_path) = cache_path {
                    let _ = std::fs::create_dir_all(cache_path);
                    auto_cert = auto_cert.cache_path(cache_path);
                }
                Ok(Some(auto_cert.build()?))
            }
            TlsConfig::AcmeTlsAlpn01 {
                cache_path,
                directory_url,
            } => {
                anyhow::ensure!(!domains.is_empty(), "missing `network.domain` config");
                let mut auto_cert = domains.iter().fold(
                    AutoCert::builder().challenge_type(ChallengeType::TlsAlpn01),
                    |acc, domain| acc.domain(domain),
                );
                if let Some(directory_url) = directory_url {
                    auto_cert = auto_cert.directory_url(directory_url);
                }
                if let Some(cache_path) = cache_path {
                    let _ = std::fs::create_dir_all(cache_path);
                    auto_cert = auto_cert.cache_path(cache_path);
                }
                Ok(Some(auto_cert.build()?))
            }
        }
    }

    pub fn transform_listener(
        &self,
        listener: impl Listener + 'static,
        auto_cert: Option<AutoCert>,
    ) -> anyhow::Result<BoxListener> {
        let listener = match self {
            TlsConfig::SelfSigned => listener
                .rustls(crate::self_signed::create_self_signed_config().boxed())
                .boxed(),
            TlsConfig::Certificate {
                cert,
                cert_path,
                key,
                key_path,
            } => {
                let cert = match (cert, cert_path) {
                    (Some(cert), _) => cert.clone(),
                    (None, Some(cert_path)) => std::fs::read_to_string(cert_path)
                        .with_context(|| format!("failed to load certificate `{}`", cert_path))?,
                    (None, None) => anyhow::bail!("missing `network.tls.cert` config"),
                };
                let key = match (key, key_path) {
                    (Some(key), _) => key.clone(),
                    (None, Some(key_path)) => std::fs::read_to_string(key_path)
                        .with_context(|| format!("failed to load private key `{}`", key_path))?,
                    (None, None) => anyhow::bail!("missing `network.tls.key` config"),
                };

                listener
                    .rustls(
                        RustlsConfig::new().fallback(RustlsCertificate::new().cert(cert).key(key)),
                    )
                    .boxed()
            }
            TlsConfig::AcmeHttp01 { .. } => listener.acme(auto_cert.unwrap()).boxed(),
            TlsConfig::AcmeTlsAlpn01 { .. } => listener.acme(auto_cert.unwrap()).boxed(),
        };
        Ok(listener)
    }
}

fn deserialize_domains<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum Domains {
        One(String),
        Array(Vec<String>),
    }

    Domains::deserialize(deserializer).map(|domains| match domains {
        Domains::One(domain) => vec![domain],
        Domains::Array(domains) => domains,
    })
}

#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    #[serde(deserialize_with = "deserialize_domains", default)]
    pub domain: Vec<String>,
    pub bind: String,
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub frontend_url: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct TemplateConfig {
    pub subject: String,
    pub file: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct TemplatesConfig {
    /// Register code content
    ///
    /// params:
    ///     - code: string
    #[serde(default)]
    pub register_by_email: Option<TemplateConfig>,

    /// Login by email content
    ///
    /// params:
    ///     - email: string
    ///     - token: string
    #[serde(default)]
    pub login_by_email: Option<TemplateConfig>,
}

#[derive(Debug, Deserialize)]
pub struct UserConfig {
    pub name: String,
    pub password: String,
    pub email: String,
    #[serde(default)]
    pub gender: i32,
    #[serde(default)]
    pub language: LangId,
    #[serde(default)]
    pub is_admin: bool,
}
