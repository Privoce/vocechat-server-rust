use poem::{http::StatusCode, web::Data, Error, Result};
use poem_openapi::{payload::Json, Object, OpenApi};
use serde::{Deserialize, Serialize};

use crate::{
    api::{tags::ApiTags, token::Token},
    config::Config,
    state::{DynamicConfig, DynamicConfigEntry},
    State,
};

pub struct ApiAdminGithubAuth;

/// Github authentication config
#[derive(Debug, Object, Serialize, Deserialize, Default)]
pub struct GithubAuthConfig {
    pub client_id: String,
    pub client_secret: String,
}

impl DynamicConfig for GithubAuthConfig {
    type Instance = GithubAuthConfig;

    fn name() -> &'static str {
        "github-auth"
    }

    fn create_instance(self, _config: &Config) -> Self::Instance {
        GithubAuthConfig {
            client_id: String::new(),
            client_secret: String::new(),
        }
    }
}

#[OpenApi(prefix_path = "/admin/github_auth", tag = "ApiTags::AdminGithubAuth")]
impl ApiAdminGithubAuth {
    /// Set Github auth config
    #[oai(path = "/config", method = "post")]
    async fn set_config(
        &self,
        state: Data<&State>,
        token: Token,
        config: Json<GithubAuthConfig>,
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

    /// Get Github auth config
    #[oai(path = "/config", method = "get")]
    async fn get_config(&self, state: Data<&State>) -> Result<Json<GithubAuthConfig>> {
        let entry = state.load_dynamic_config::<GithubAuthConfig>().await?;
        Ok(Json(entry.config))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::test_harness::TestServer;

    #[tokio::test]
    async fn set_get_github_oauth() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        let resp = server
            .post("/api/admin/github_auth/config")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "client_id": "test",
                "client_secret": "test",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        let resp = server
            .get("/api/admin/github_auth/config")
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();

        // let body = resp.0.take_body().into_string().await.unwrap();
        // dbg!(body);

        let json = resp.json().await;
        json.value().object().get("client_id").assert_string("test");
    }
}
