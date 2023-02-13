use poem::{
    error::{InternalServerError, ServiceUnavailable},
    http::StatusCode,
    web::Data,
    Error, Result,
};
use poem_openapi::{param::Query, payload::Json, Object, OpenApi};
use serde::{Deserialize, Serialize};

use crate::{
    api::{tags::ApiTags, token::Token, DateTime},
    config::Config,
    state::{DynamicConfig, DynamicConfigEntry},
    State,
};

pub struct ApiAdminAgora;

#[derive(Debug, Object, Serialize, Deserialize, Default)]
pub struct AgoraConfig {
    #[oai(default = "default_agora_url")]
    pub url: String,
    pub project_id: String,
    pub app_id: String,
    pub app_certificate: String,
    pub rtm_key: String,
    pub rtm_secret: String,
}

fn default_agora_url() -> String {
    "https://api.agora.io".to_string()
}

impl DynamicConfig for AgoraConfig {
    type Instance = Self;

    fn name() -> &'static str {
        "agora"
    }

    fn create_instance(self, _config: &Config) -> Self::Instance {
        self
    }
}

/// Agora config
#[derive(Debug, Object)]
pub struct AgoraConfigObject {
    enabled: bool,
    #[oai(flatten)]
    config: AgoraConfig,
}

/// Agora usage response
#[derive(Deserialize, Object)]
struct AgoraUsagesResponse {
    usages: Vec<AgoraUsageItem>,
}

/// Agora usage item
#[derive(Deserialize, Object)]
struct AgoraUsageItem {
    date: DateTime,
    usage: AgoraUsage,
}

/// Agora usage
#[derive(Deserialize, Object)]
#[serde(rename_all = "camelCase")]
struct AgoraUsage {
    duration_audio_all: i64,
    duration_video_hd: i64,
    duration_video_hdp: i64,
}

#[OpenApi(prefix_path = "/admin/agora", tag = "ApiTags::AdminAgora")]
impl ApiAdminAgora {
    /// Set Agora config
    #[oai(path = "/config", method = "post")]
    async fn set_config(
        &self,
        state: Data<&State>,
        token: Token,
        config: Json<AgoraConfigObject>,
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

    /// Get Agora config
    #[oai(path = "/config", method = "get")]
    async fn get_config(
        &self,
        state: Data<&State>,
        _token: Token,
    ) -> Result<Json<AgoraConfigObject>> {
        // if !token.is_admin {
        //     return Err(Error::from_status(StatusCode::FORBIDDEN));
        // }
        let entry = state.load_dynamic_config::<AgoraConfig>().await?;
        Ok(Json(AgoraConfigObject {
            enabled: entry.enabled,
            config: entry.config,
        }))
    }

    /// Get Agora usage
    #[oai(path = "/usages", method = "get")]
    async fn usage(
        &self,
        state: Data<&State>,
        token: Token,
        /// Start date(YYYY-MM-DD)
        from_date: Query<String>,
        /// End date(YYYY-MM-DD)
        to_date: Query<String>,
    ) -> Result<Json<AgoraUsagesResponse>> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let agora = state
            .get_dynamic_config_instance::<AgoraConfig>()
            .await
            .ok_or_else(|| Error::from_status(StatusCode::SERVICE_UNAVAILABLE))?;
        let resp = reqwest::Client::new()
            .get(format!("{}/dev/v3/usage", agora.url))
            .query(&[
                ("project_id", agora.project_id.as_str()),
                ("from_date", from_date.as_str()),
                ("to_date", to_date.as_str()),
                ("business", "default"),
            ])
            .header("accept", "application/json")
            .basic_auth(&agora.rtm_key, Some(&agora.rtm_secret))
            .send()
            .await
            .map_err(ServiceUnavailable)?
            .error_for_status()
            .map_err(ServiceUnavailable)?
            .json::<AgoraUsagesResponse>()
            .await
            .map_err(InternalServerError)?;
        Ok(Json(resp))
    }
}
