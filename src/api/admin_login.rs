use poem::{http::StatusCode, web::Data, Error, Result};
use poem_openapi::{payload::Json, Enum, Object, OpenApi};
use serde::{Deserialize, Serialize};

use crate::{
    api::{tags::ApiTags, token::Token},
    config::Config,
    state::{DynamicConfig, DynamicConfigEntry},
    State,
};

pub struct ApiAdminLogin;

#[derive(Debug, Object, Serialize, Deserialize)]
pub struct OIDCConfig {
    pub enable: bool,
    pub favicon: String,
    pub domain: String,
}

#[derive(Debug, Enum, Serialize, Deserialize, Eq, PartialEq, Copy, Clone)]
pub enum WhoCanSignUp {
    EveryOne,
    InvitationOnly,
}

/// Login config
#[derive(Debug, Object, Serialize, Deserialize)]
pub struct LoginConfig {
    /// Who can sign up
    #[serde(default = "default_who_can_sign_up")]
    pub who_can_sign_up: WhoCanSignUp,
    /// Login as guest
    #[serde(default)]
    pub guest: bool,
    /// Login with password
    #[serde(default)]
    pub password: bool,
    /// Login with magic link
    #[serde(default)]
    pub magic_link: bool,
    /// Login with Google
    #[serde(default)]
    pub google: bool,
    /// Login with Github
    #[serde(default)]
    pub github: bool,
    /// Login with OpenID Connect
    #[serde(default)]
    pub oidc: Vec<OIDCConfig>,
    /// Login with Metamask
    #[serde(default)]
    pub metamask: bool,
    /// Login with third party
    #[serde(default)]
    pub third_party: bool,
}

const fn default_who_can_sign_up() -> WhoCanSignUp {
    WhoCanSignUp::EveryOne
}

impl Default for LoginConfig {
    fn default() -> Self {
        Self {
            who_can_sign_up: WhoCanSignUp::EveryOne,
            guest: false,
            password: true,
            magic_link: true,
            google: false,
            github: false,
            oidc: vec![],
            metamask: false,
            third_party: false,
        }
    }
}

impl DynamicConfig for LoginConfig {
    type Instance = Self;

    fn name() -> &'static str {
        "login"
    }

    fn create_instance(self, _config: &Config) -> Self::Instance {
        self
    }
}

#[OpenApi(prefix_path = "/admin/login", tag = "ApiTags::AdminLogin")]
impl ApiAdminLogin {
    /// Set login config
    #[oai(path = "/config", method = "post")]
    async fn set_config(
        &self,
        state: Data<&State>,
        token: Token,
        config: Json<LoginConfig>,
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

    /// Get login config
    #[oai(path = "/config", method = "get")]
    async fn get_config(&self, state: Data<&State>) -> Result<Json<LoginConfig>> {
        let entry = state.load_dynamic_config::<LoginConfig>().await?;
        Ok(Json(entry.config))
    }
}
