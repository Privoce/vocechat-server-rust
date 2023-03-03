use poem::{http::StatusCode, web::Data, Error, Result};
use poem_openapi::{payload::Json, Object, OpenApi};
use rc_fcm::{ApplicationCredentials, FcmClient};
use serde::{Deserialize, Serialize};

use crate::{
    api::{tags::ApiTags, token::Token},
    config::Config,
    state::{DynamicConfig, DynamicConfigEntry},
    State,
};

pub struct ApiAdminFirebase;

/// Firebase config
#[derive(Debug, Object, Serialize, Deserialize, Default)]
pub struct FcmConfig {
    #[serde(default = "default_use_official")]
    pub use_official: bool,
    #[oai(default = "default_token_url")]
    pub token_url: String,
    pub project_id: String,
    pub private_key: String,
    pub client_email: String,
}

fn default_use_official() -> bool {
    true
}

fn default_token_url() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

impl DynamicConfig for FcmConfig {
    type Instance = FcmClient;

    fn name() -> &'static str {
        "fcm"
    }

    fn create_instance(self, config: &Config) -> Self::Instance {
        if self.use_official {
            FcmClient::new(ApplicationCredentials {
                project_id: config.offical_fcm_config.project_id.clone(),
                private_key: config.offical_fcm_config.private_key.clone(),
                client_email: config.offical_fcm_config.client_email.clone(),
                token_uri: config.offical_fcm_config.token_uri.clone(),
            })
        } else {
            FcmClient::new(ApplicationCredentials {
                project_id: self.project_id,
                private_key: self.private_key,
                client_email: self.client_email,
                token_uri: self.token_url,
            })
        }
    }
}

/// Firebase config
#[derive(Debug, Object)]
pub struct FcmConfigObject {
    enabled: bool,
    #[oai(flatten)]
    config: FcmConfig,
}

#[OpenApi(prefix_path = "/admin/fcm", tag = "ApiTags::AdminFirebase")]
impl ApiAdminFirebase {
    /// Set Firebase config
    #[oai(path = "/config", method = "post")]
    async fn set_config(
        &self,
        state: Data<&State>,
        token: Token,
        config: Json<FcmConfigObject>,
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

    /// Get Firebase config
    #[oai(path = "/config", method = "get")]
    async fn get_config(&self, state: Data<&State>, token: Token) -> Result<Json<FcmConfigObject>> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }
        let entry = state.load_dynamic_config::<FcmConfig>().await?;
        Ok(Json(FcmConfigObject {
            enabled: entry.enabled,
            config: entry.config,
        }))
    }
}
