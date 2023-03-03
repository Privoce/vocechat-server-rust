#![allow(clippy::large_enum_variant)]
#![allow(clippy::uninlined_format_args)]

mod api;
mod api_key;
mod config;
mod create_user;
mod license;
mod middleware;
mod self_signed;
mod server;
mod state;
#[cfg(test)]
mod test_harness;

use std::{
    fs::File,
    io::Cursor,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use clap::Parser;
use futures_util::TryFutureExt;
use poem::{
    listener::{Listener, TcpListener},
    EndpointExt, RouteScheme, Server,
};
use serde::Deserialize;
use sqlx::SqlitePool;
use tokio::runtime::Runtime;
use tracing_subscriber::{fmt::Subscriber, util::SubscriberInitExt, EnvFilter};
use zip::ZipArchive;

use crate::{
    config::{Config, TlsConfig},
    state::State,
};

#[derive(Debug, Default, Deserialize)]
struct EnvironmentVars {
    data_dir: Option<PathBuf>,

    fcm_project_id: String,
    fcm_private_key: String,
    fcm_client_email: String,
    token_uri: String,
}

impl EnvironmentVars {
    fn merge_to_config(self, mut config: Config) -> Config {
        if let Some(data_dir) = self.data_dir {
            config.system.data_dir = data_dir;
        }

        config.offical_fcm_config.project_id = self.fcm_project_id;
        config.offical_fcm_config.private_key = self.fcm_private_key;
        config.offical_fcm_config.client_email = self.fcm_client_email;
        config.offical_fcm_config.token_uri = self.token_uri;

        config
    }
}

#[derive(Debug, Parser)]
#[clap(name = "vocechat", author, version, about)]
struct Options {
    /// Path of the config file
    #[clap(default_value = "config/config.toml")]
    pub config: PathBuf,
    /// Start a daemon in the background
    #[cfg(not(windows))]
    #[clap(long = "daemon")]
    pub daemon: bool,
    /// Create pid file, lock it exclusive and write daemon pid.
    #[cfg(not(windows))]
    #[clap(long = "pid.file")]
    pub pid_file: Option<PathBuf>,
    /// Standard output file of the daemon
    #[clap(long = "stdout")]
    pub stdout: Option<PathBuf>,
    /// Server domain
    #[clap(long = "network.domain")]
    network_domain: Vec<String>,
    /// Listener bind address
    #[clap(long = "network.bind")]
    network_bind: Option<String>,
    /// Tls type (none, self_signed, certificate, acme_http_01,
    /// acme_tls_alpn_01)
    #[clap(long = "network.tls.type")]
    network_tls_type: Option<String>,
    /// Certificate file path
    #[clap(long = "network.tls.cert")]
    network_tls_cert_path: Option<String>,
    /// Certificate key path
    #[clap(long = "network.tls.key")]
    network_tls_key_path: Option<String>,
    /// Listener bind address for AcmeHTTP_01
    #[clap(long = "network.tls.acme.http_bind")]
    network_tls_acme_http_bind: Option<String>,
    /// Frontend url
    #[clap(long = "network.frontend_url")]
    frontend_url: Option<String>,
    /// Acme directory url
    #[clap(
        long = "network.tls.acme.directory_url",
        default_value = "https://acme-v02.api.letsencrypt.org/directory"
    )]
    network_tls_acme_directory_url: String,
    /// Cache path for certificates
    #[clap(long = "network.tls.acme.cache_path")]
    network_tls_acme_cache_path: Option<String>,
}

impl Options {
    fn merge_to_config(self, mut config: Config) -> Config {
        config.network.domain.extend(self.network_domain);
        if let Some(network_bind) = self.network_bind {
            config.network.bind = network_bind;
        }

        if let Some(network_tls_type) = self.network_tls_type {
            match network_tls_type.as_str() {
                "none" => config.network.tls = None,
                "self_signed" => config.network.tls = Some(TlsConfig::SelfSigned),
                "certificate" => match (self.network_tls_cert_path, self.network_tls_key_path) {
                    (Some(cert_path), Some(key_path)) => {
                        config.network.tls = Some(TlsConfig::Certificate {
                            cert: None,
                            cert_path: Some(cert_path),
                            key: None,
                            key_path: Some(key_path),
                        });
                    }
                    (None, _) => {
                        tracing::warn!("`network.tls.cert` is required");
                    }
                    (_, None) => {
                        tracing::warn!("`network.tls.key` is required");
                    }
                },
                "acme_http_01" => match self.network_tls_acme_http_bind {
                    Some(http_bind) => {
                        config.network.tls = Some(TlsConfig::AcmeHttp01 {
                            http_bind,
                            directory_url: Some(self.network_tls_acme_directory_url),
                            cache_path: self.network_tls_acme_cache_path,
                        });
                    }
                    None => {
                        tracing::warn!("`network.tls.acme.http_bind` is required");
                    }
                },
                "acme_tls_alpn_01" => {
                    config.network.tls = Some(TlsConfig::AcmeTlsAlpn01 {
                        directory_url: Some(self.network_tls_acme_directory_url),
                        cache_path: self.network_tls_acme_cache_path,
                    });
                }
                _ => {
                    tracing::warn!(
                        r#type = network_tls_type.as_str(),
                        "unknown `network.tls.type`"
                    );
                }
            }
        }

        if let Some(frontend_url) = self.frontend_url {
            config.network.frontend_url = frontend_url;
        }

        config
    }
}

fn init_tracing(with_ansi: bool) {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "vocechat=debug,poem=debug");
    }

    let subscriber = Subscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_ansi(with_ansi)
        .finish();
    subscriber.try_init().unwrap();
}

fn load_config(path: &Path) -> anyhow::Result<Config> {
    let data = std::fs::read(path)?;
    Ok(toml::from_slice(&data)?)
}

fn main() {
    let options: Options = Options::parse();

    #[cfg(not(windows))]
    if options.daemon {
        use daemonize::Daemonize;

        let mut daemon = Daemonize::new().working_directory(std::env::current_dir().unwrap());

        if let Some(stdout_file) = &options.stdout {
            match File::create(stdout_file) {
                Ok(file) => {
                    daemon = daemon.stdout(file);
                }
                Err(err) => {
                    tracing::error!(
                        path = %stdout_file.display(),
                        error = %err,
                        "failed to create file"
                    );
                }
            }
        }

        if let Some(pid_file) = &options.pid_file {
            daemon = daemon.pid_file(pid_file);
        }

        if let Err(err) = daemon.start() {
            tracing::error!(error = %err, "failed to create daemon");
            return;
        }

        init_tracing(false);
    } else {
        init_tracing(true);
    }

    #[cfg(windows)]
    init_tracing(true);

    Runtime::new().unwrap().block_on(async move {
        // load config
        tracing::info!(
            current_dir = %std::env::current_dir().unwrap().display(),
            path = %options.config.display(),
            "load configuration file.",
        );
        let config_path = options.config.clone();
        let config = Arc::new(match load_config(&config_path) {
            Ok(config) => envy::prefixed("VOCECHAT_")
                .from_env::<EnvironmentVars>()
                .unwrap_or_default()
                .merge_to_config(options.merge_to_config(config)),
            Err(err) => {
                tracing::error!(
                    path = %config_path.display(),
                    error = %err,
                    "failed to load configuration file."
                );
                return;
            }
        });

        let state = match server::create_state(config_path.parent().unwrap(), config.clone()).await
        {
            Ok(state) => state,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "failed to create server."
                );
                return;
            }
        };

        let auto_cert = match &config.network.tls {
            Some(tls) => match tls.create_auto_cert(&config.network.domain) {
                Ok(auto_cert) => auto_cert,
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        "failed to create auto certificate manager"
                    );
                    return;
                }
            },
            None => None,
        };

        crate::license::load_license(&state).await.unwrap();

        let app = match &config.network.tls {
            Some(TlsConfig::AcmeHttp01 { .. }) => RouteScheme::new()
                .https(server::create_endpoint(state.clone()).await)
                .http(auto_cert.as_ref().unwrap().http_01_endpoint())
                .boxed(),
            _ => server::create_endpoint(state.clone()).await
                .map_to_response()
                .boxed(),
        };

        tokio::spawn({
            let state = state.clone();
            async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    state.magic_code_clean().await;
                    state.clean_mute().await;
                    state.sync_bot_key_last_used().await;

                    tokio::task::spawn_blocking({
                        let state = state.clone();
                        move || {
                            state.clean_temp_files();
                            state.clean_files();
                        }
                    });
                }
            }
        });

        tokio::spawn({
            let state = state.clone();
            async move {
                loop {
                    state.clean_guest().await;
                    tokio::time::sleep(Duration::from_secs(60 * 60 * 24)).await;
                }
            }
        });

        tokio::spawn({
            let state = state.clone();
            async move {
                loop {
                    update_webclient(&state).await;
                    tokio::time::sleep(Duration::from_secs(60 * 5)).await;
                }
            }
        });

        let mut listener = TcpListener::bind(config.network.bind.to_string()).boxed();
        if let Some(tls_config) = &config.network.tls {
            listener = match tls_config.transform_listener(listener, auto_cert) {
                Ok(listener) => listener,
                Err(err) => {
                    tracing::error!(error = %err, "failed to create listener");
                    return;
                }
            };
            if let TlsConfig::AcmeHttp01 { http_bind, .. } = &tls_config {
                listener = listener
                    .combine(TcpListener::bind(http_bind.clone()))
                    .boxed();
            }
        }

        Server::new(listener).run(app).await.unwrap();
    });
}

async fn update_webclient(state: &State) {
    let webclient_url = match &state.config.webclient_url {
        Some(webclient_url) => webclient_url,
        None => return,
    };

    let mut current_hash = None;

    let wwwroot_dir = state.config.system.wwwroot_dir();
    if wwwroot_dir.exists() {
        current_hash = std::fs::read_to_string(wwwroot_dir.join(".hash")).ok();
    }

    let hash_url = format!("{}/web.vocechat.md5", webclient_url);
    tracing::info!(url = hash_url.as_str(), "check web client md5");
    let least_hash = match reqwest::get(&hash_url)
        .and_then(|resp| async move { resp.error_for_status() })
        .and_then(|resp| resp.text())
        .await
    {
        Ok(hash) => hash,
        Err(err) => {
            tracing::error!(url = hash_url.as_str(), err = %err, "failed to download hash file");
            return;
        }
    };

    if current_hash.as_deref() == Some(least_hash.as_str()) {
        tracing::info!("web client is up to date");
        return;
    }

    let zip_url = format!("{}/web.vocechat.zip", webclient_url);
    tracing::info!(url = zip_url.as_str(), "downloading web client");
    let zip_data = match reqwest::get(&zip_url)
        .and_then(|resp| async move { resp.error_for_status() })
        .and_then(|resp| resp.bytes())
        .await
    {
        Ok(zip_data) => zip_data,
        Err(err) => {
            tracing::error!(url = zip_url.as_str(), err = %err, "failed to download zip file");
            return;
        }
    };

    let temp_wwwroot_dir = state.config.system.temp_wwwroot_dir();
    let _ = std::fs::remove_dir_all(&temp_wwwroot_dir);
    let _ = std::fs::create_dir(&temp_wwwroot_dir);

    tracing::info!("extract web client");
    if let Err(err) = ZipArchive::new(Cursor::new(zip_data))
        .context("failed to open zip archive")
        .and_then(|mut archive| {
            for i in 0..archive.len() {
                let mut file = archive.by_index(i)?;
                if let Some(path) = file.enclosed_name().map(|path| path.to_path_buf()) {
                    if file.is_file() {
                        let path = temp_wwwroot_dir.join(path);
                        if let Some(parent) = path.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        std::io::copy(&mut file, &mut File::create(path)?)?;
                    }
                }
            }
            Ok(())
        })
        .and_then(|_| {
            std::fs::write(temp_wwwroot_dir.join(".hash"), least_hash)
                .context("failed to write hash file")
        })
    {
        tracing::error!(err = %err, "failed to extract zip file");
        return;
    }

    let _ = std::fs::remove_dir_all(&wwwroot_dir);
    let _ = std::fs::rename(temp_wwwroot_dir, wwwroot_dir);
    tracing::info!("web client updated");
}
