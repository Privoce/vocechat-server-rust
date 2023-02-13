use image::ImageFormat;
use poem::{error::InternalServerError, http::StatusCode, web::Data, Error, Result};
use poem_openapi::{
    payload::{Binary, Json, PlainText},
    types::Email,
    ApiRequest, Object, OpenApi,
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{tags::ApiTags, token::Token, SmtpConfig, UserInfo},
    config::Config,
    create_user::{CreateUser, CreateUserBy},
    server::create_random_str,
    state::{send_mail, DynamicConfig, DynamicConfigEntry},
    State,
};

/// Server metrics
#[derive(Debug, Object)]
pub struct Metrics {
    user_count: usize,
    group_count: usize,
    online_user_count: usize,
    version: String,
}

/// Frontend url
#[derive(Debug, Object, Serialize, Deserialize, Default)]
pub struct FrontendUrlConfig {
    pub url: Option<String>,
}

impl DynamicConfig for FrontendUrlConfig {
    type Instance = Self;

    fn name() -> &'static str {
        "frontend-url"
    }

    fn create_instance(self, _config: &Config) -> Self::Instance {
        self
    }
}

/// Organization info
#[derive(Debug, Object, Serialize, Deserialize)]
pub struct OrganizationConfig {
    name: String,
    description: Option<String>,
}

impl DynamicConfig for OrganizationConfig {
    type Instance = Self;

    fn name() -> &'static str {
        "organization"
    }

    fn create_instance(self, _config: &Config) -> Self::Instance {
        self
    }
}

impl Default for OrganizationConfig {
    fn default() -> Self {
        Self {
            name: "unknown".to_string(),
            description: None,
        }
    }
}

#[derive(ApiRequest)]
enum UploadLogoRequest {
    #[oai(content_type = "image/png")]
    Image(Binary<Vec<u8>>),
}

#[derive(Object)]
struct SendMailRequest {
    to: String,
    subject: String,
    content: String,
}

#[derive(Object)]
struct CreateAdminRequest {
    email: Email,
    name: String,
    password: String,
    gender: i32,
}

pub struct ApiAdminSystem;

#[OpenApi(prefix_path = "/admin/system", tag = "ApiTags::AdminSystem")]
impl ApiAdminSystem {
    /// Get the server version
    #[oai(path = "/version", method = "get")]
    async fn version(&self) -> PlainText<&'static str> {
        PlainText(env!("CARGO_PKG_VERSION"))
    }

    /// Create administrator user
    #[oai(path = "/create_admin", method = "post")]
    async fn create_admin_user(
        &self,
        state: Data<&State>,
        mut req: Json<CreateAdminRequest>,
    ) -> Result<Json<UserInfo>> {
        if !state.cache.read().await.users.is_empty() {
            return Err(poem::Error::from_status(StatusCode::FORBIDDEN));
        }

        req.email.0 = req.email.0.to_lowercase();
        let (uid, user) = match state
            .create_user(
                CreateUser::new(
                    &req.name,
                    CreateUserBy::Password {
                        email: &req.email,
                        password: &req.password,
                    },
                    true,
                )
                .gender(req.gender),
            )
            .await
        {
            Ok(res) => res,
            Err(_) => return Err(poem::Error::from_status(StatusCode::FORBIDDEN)),
        };

        // update user.is_admin
        Ok(Json(user.api_user_info(uid)))
    }

    /// Returns `true` means that the server has been initialized
    #[oai(path = "/initialized", method = "get")]
    async fn initialized(&self, state: Data<&State>) -> Json<bool> {
        let cache = state.cache.read().await;
        Json(!cache.users.is_empty())
    }

    /// Get the system metrics
    #[oai(path = "/metrics", method = "get")]
    async fn get_metrics(&self, state: Data<&State>, token: Token) -> Result<Json<Metrics>> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let cache = state.cache.read().await;
        Ok(Json(Metrics {
            user_count: cache.users.iter().filter(|user| !user.1.is_guest).count(),
            group_count: cache.groups.len(),
            online_user_count: cache
                .users
                .values()
                .filter(|user| !user.is_guest && user.is_online())
                .count(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }

    /// Get the organization info
    #[oai(path = "/organization", method = "get")]
    async fn get_organization(&self, state: Data<&State>) -> Result<Json<OrganizationConfig>> {
        let entry = state.load_dynamic_config::<OrganizationConfig>().await?;
        Ok(Json(entry.config))
    }

    /// Set the organization info
    #[oai(path = "/organization", method = "post")]
    async fn set_organization(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<OrganizationConfig>,
    ) -> Result<()> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }
        state
            .set_dynamic_config(DynamicConfigEntry {
                enabled: true,
                config: req.0,
            })
            .await?;
        Ok(())
    }

    /// Upload the organization logo
    #[oai(path = "/organization/logo", method = "post")]
    async fn upload_organization_logo(
        &self,
        state: Data<&State>,
        token: Token,
        logo: UploadLogoRequest,
    ) -> Result<()> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let UploadLogoRequest::Image(data) = logo;
        let logo = image::load_from_memory(&data).map_err(InternalServerError)?;
        let logo = logo.thumbnail(240, 240);
        let path = state.config.system.data_dir.join("organization.png");
        logo.save_with_format(path, ImageFormat::Png)
            .map_err(InternalServerError)?;
        Ok(())
    }

    /// Send email(only for test)
    #[oai(path = "/send_mail", method = "post")]
    async fn send_mail(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<SendMailRequest>,
    ) -> Result<()> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let smtp_config = state
            .get_dynamic_config_instance::<SmtpConfig>()
            .await
            .ok_or_else(|| Error::from_status(StatusCode::SERVICE_UNAVAILABLE))?;
        Ok(send_mail(&smtp_config, &req.to, &req.subject, &req.content).await?)
    }

    /// Get the secret for third-party authentication
    #[oai(path = "/third_party_secret", method = "get")]
    async fn third_party_secret(
        &self,
        state: Data<&State>,
        token: Token,
    ) -> Result<PlainText<String>> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }
        let key_config = state.key_config.read().await;
        Ok(PlainText(key_config.third_party_secret.clone()))
    }

    /// Update third-party secret
    #[oai(path = "/third_party_secret", method = "post")]
    async fn update_third_party_secret(
        &self,
        state: Data<&State>,
        token: Token,
    ) -> Result<PlainText<String>> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let mut key_config = state.key_config.write().await;
        let new_third_party_secret = create_random_str(32);
        key_config.third_party_secret = new_third_party_secret.clone();

        let key_config_path = state.config.system.data_dir.join("key.json");
        std::fs::write(
            key_config_path,
            serde_json::to_vec(&*key_config).map_err(InternalServerError)?,
        )
        .map_err(InternalServerError)?;

        Ok(PlainText(new_third_party_secret))
    }

    /// Get the frontend url
    #[oai(path = "/frontend_url", method = "get")]
    async fn get_frontend_url(
        &self,
        state: Data<&State>,
        token: Token,
    ) -> Result<PlainText<String>> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        Ok(PlainText(
            state
                .get_dynamic_config_instance::<FrontendUrlConfig>()
                .await
                .and_then(|config| config.url.clone())
                .unwrap_or_default(),
        ))
    }

    /// Update the frontend url
    #[oai(path = "/update_frontend_url", method = "post")]
    async fn update_frontend_url(
        &self,
        state: Data<&State>,
        token: Token,
        frontend_url: PlainText<String>,
    ) -> Result<()> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let frontend_url = frontend_url.0.trim_end_matches('/');
        let re = regex::Regex::new(r#"^https?://[\w\-\.]+(:\d+)?$"#).unwrap();
        if !re.is_match(frontend_url) {
            return Err(Error::from_string(
                "Bad url format!",
                StatusCode::BAD_REQUEST,
            ));
        }

        state
            .set_dynamic_config(DynamicConfigEntry {
                enabled: true,
                config: FrontendUrlConfig {
                    url: Some(frontend_url.to_string()),
                },
            })
            .await?;
        Ok(())
    }
}

#[test]
fn test_frontend_url() {
    let re = regex::Regex::new(r#"^https?://[\w\-\.]+(:\d+)?$"#).unwrap();
    assert!(re.is_match("http://1.2.3.4:4000"));
    assert!(re.is_match("http://domain.com"));
    assert!(re.is_match("http://domain.com:3000"));
    assert!(re.is_match("https://domain.com:3000"));
    assert!(re.is_match("http://127.0.0.1"));
    assert!(re.is_match("http://127.0.0.1:3000"));
    assert!(re.is_match("https://127.0.0.1:3000"));
    assert!(!re.is_match("ftp://127.0.0.1:3000"));
}

#[test]
fn test_replace_config() {
    let a = r#"frontend_url = "http://a.com/""#;
    let re = regex::Regex::new(r#"frontend_url\s*=\s*".*?""#).unwrap();
    let b = re.replace(a, format!(r#"frontend_url = "{}""#, "http://b.com/"));
    assert_eq!(b, r#"frontend_url = "http://b.com/""#);
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::test_harness::TestServer;

    #[tokio::test]
    async fn set_organization() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        let resp = server.get("/api/admin/system/organization").send().await;
        resp.assert_status_is_ok();
        resp.assert_json(&json!({
            "name": "unknown",
            "description": null,
        }))
        .await;

        server
            .post("/api/admin/system/organization")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "abc",
                "description": "def"
            }))
            .send()
            .await
            .assert_status_is_ok();

        let resp = server.get("/api/admin/system/organization").send().await;
        resp.assert_status_is_ok();
        resp.assert_json(&json!({
            "name": "abc",
            "description": "def",
        }))
        .await;
    }

    #[tokio::test]
    async fn test_update_frontend_url() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        let resp = server
            .post("/api/admin/system/update_frontend_url")
            .header("X-API-Key", &admin_token)
            .content_type("text/plain")
            .body("http://1.2.3.4:4000")
            .send()
            .await;
        resp.assert_status_is_ok();
    }
}
