use poem::{http::StatusCode, web::Data, Error, Result};
use poem_openapi::{payload::Json, Object, OpenApi};
use serde::{Deserialize, Serialize};

use crate::{
    api::{tags::ApiTags, token::Token},
    state::{DynamicConfig, DynamicConfigEntry},
    State,
};

pub struct ApiAdminGoogleAuth;

/// Google authentication config
#[derive(Debug, Object, Serialize, Deserialize, Default)]
pub struct GoogleAuthConfig {
    pub client_id: String,
}

impl DynamicConfig for GoogleAuthConfig {
    type Instance = GoogleAuthConfig;

    fn name() -> &'static str {
        "google-auth"
    }

    fn create_instance(self) -> Self::Instance {
        GoogleAuthConfig {
            client_id: String::new(),
        }
    }
}

#[OpenApi(prefix_path = "/admin/google_auth", tag = "ApiTags::AdminGoogleAuth")]
impl ApiAdminGoogleAuth {
    /// Set Google auth config
    #[oai(path = "/config", method = "post")]
    async fn set_config(
        &self,
        state: Data<&State>,
        token: Token,
        config: Json<GoogleAuthConfig>,
    ) -> Result<()> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }
        state
            .set_dynamic_config(DynamicConfigEntry {
                enabled: true,
                config: config.0,
            })
            .await?;
        Ok(())
    }

    /// Get Google auth config
    #[oai(path = "/config", method = "get")]
    async fn get_config(&self, state: Data<&State>) -> Result<Json<GoogleAuthConfig>> {
        let entry = state.load_dynamic_config::<GoogleAuthConfig>().await?;
        Ok(Json(entry.config))
    }
}
