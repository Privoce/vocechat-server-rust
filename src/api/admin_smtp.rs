use poem::{http::StatusCode, web::Data, Error, Result};
use poem_openapi::{payload::Json, Object, OpenApi};
use serde::{Deserialize, Serialize};

use crate::{
    api::{tags::ApiTags, token::Token},
    config::Config,
    state::{DynamicConfig, DynamicConfigEntry},
    State,
};

pub struct ApiAdminSmtp;

#[derive(Debug, Object, Serialize, Deserialize, Default)]
pub struct SmtpConfig {
    pub host: String,
    pub port: Option<u16>,
    pub from: String,
    pub username: String,
    pub password: String,
}

impl DynamicConfig for SmtpConfig {
    type Instance = Self;

    fn name() -> &'static str {
        "smtp"
    }

    fn create_instance(self, _config: &Config) -> Self::Instance {
        self
    }
}

/// SMTP config
#[derive(Debug, Object)]
pub struct SmtpConfigObject {
    enabled: bool,
    #[oai(flatten)]
    config: SmtpConfig,
}

#[OpenApi(prefix_path = "/admin/smtp", tag = "ApiTags::AdminSmtp")]
impl ApiAdminSmtp {
    /// Set SMTP config
    #[oai(path = "/config", method = "post")]
    async fn set_config(
        &self,
        state: Data<&State>,
        token: Token,
        config: Json<SmtpConfigObject>,
    ) -> Result<()> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }
        state
            .set_dynamic_config(DynamicConfigEntry {
                enabled: config.0.enabled,
                config: config.0.config,
            })
            .await?;
        Ok(())
    }

    /// Get SMTP config
    #[oai(path = "/config", method = "get")]
    async fn get_config(
        &self,
        state: Data<&State>,
        token: Token,
    ) -> Result<Json<SmtpConfigObject>> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }
        let entry = state.load_dynamic_config::<SmtpConfig>().await?;
        Ok(Json(SmtpConfigObject {
            enabled: entry.enabled,
            config: entry.config,
        }))
    }

    /// Get SMTP config is enabled
    #[oai(path = "/enabled", method = "get")]
    async fn is_enabled(&self, state: Data<&State>) -> Result<Json<bool>> {
        let entry = state.load_dynamic_config::<SmtpConfig>().await?;
        Ok(Json(entry.enabled))
    }
}
