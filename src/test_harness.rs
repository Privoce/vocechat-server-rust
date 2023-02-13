use std::{ops::Deref, path::Path, sync::Arc};

use futures_util::{stream::BoxStream, StreamExt};
use poem::{
    endpoint::BoxEndpoint,
    test::{TestClient, TestJson},
    EndpointExt,
};
use serde_json::json;
use sqlx::{migrate::MigrateDatabase, Sqlite, SqlitePool};
use tempfile::TempDir;

use crate::{
    api::{CurrentUser, LoginConfig, WhoCanSignUp},
    config::{NetworkConfig, SystemConfig},
    create_user::{CreateUser, CreateUserBy},
    server::MIGRATOR,
    state::DynamicConfigEntry,
    Config, State,
};

pub struct TestServer {
    _tempdir: TempDir,
    state: State,
    client: TestClient<BoxEndpoint<'static>>,
}

impl Deref for TestServer {
    type Target = TestClient<BoxEndpoint<'static>>;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl TestServer {
    pub async fn new() -> Self {
        Self::new_with_config(|_| {}).await
    }

    pub async fn new_with_config<F: FnOnce(&mut Config)>(f: F) -> Self {
        let tempdir = TempDir::new().unwrap();
        init_db(tempdir.path()).await;

        // create server
        let mut cfg = Config {
            system: SystemConfig {
                data_dir: tempdir.path().to_path_buf(),
                token_expiry_seconds: 60,
                refresh_token_expiry_seconds: 60 * 60,
                magic_token_expiry_seconds: 60 * 15,
                upload_avatar_limit: 1024 * 1024,
                send_image_limit: 1024 * 1024,
                upload_timeout_seconds: 300,
                file_expiry_days: 30 * 3,
                max_favorite_archives: 100,
            },
            network: NetworkConfig {
                domain: Vec::new(),
                bind: "127.0.0.1:3000".to_string(),
                tls: None,
                frontend_url: "http://127.0.0.1:3000".to_string(),
            },
            template: Default::default(),
            users: vec![],
            webclient_url: None,
            offical_fcm_config: Default::default(),
        };
        f(&mut cfg);
        let state = crate::server::create_state(tempdir.path(), Arc::new(cfg))
            .await
            .unwrap();
        crate::license::load_license(&state).await.unwrap();
        state
            .set_dynamic_config(DynamicConfigEntry {
                enabled: true,
                config: LoginConfig {
                    who_can_sign_up: WhoCanSignUp::EveryOne,
                    guest: true,
                    password: true,
                    magic_link: true,
                    google: true,
                    github: true,
                    oidc: vec![],
                    metamask: true,
                    third_party: true,
                },
            })
            .await
            .unwrap();
        let app = crate::server::create_endpoint(state.clone()).await;

        state
            .create_user(
                CreateUser::new(
                    "admin",
                    CreateUserBy::Password {
                        email: "admin@voce.chat",
                        password: "123456",
                    },
                    false,
                )
                .gender(1)
                .set_admin(true),
            )
            .await
            .unwrap();

        Self {
            _tempdir: tempdir,
            state,
            client: TestClient::new(app.map_to_response().boxed())
                .default_content_type("application/json"),
        }
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub async fn parse_token(&self, token: impl AsRef<str>) -> CurrentUser {
        rc_token::parse_token(
            &self.state.key_config.read().await.server_key,
            token.as_ref(),
            true,
        )
        .unwrap()
        .1
    }

    pub async fn login(&self, email: impl AsRef<str>) -> String {
        self.login_with_device(email, "iphone").await
    }

    pub async fn login_with_device(
        &self,
        email: impl AsRef<str>,
        device: impl AsRef<str>,
    ) -> String {
        let resp = self
            .client
            .post("/api/token/login")
            .header("Referer", "http://localhost/")
            .body_json(&json!({
                "credential": {
                    "type": "password",
                    "email": email.as_ref(),
                    "password": "123456"
                },
                "device": device.as_ref(),
                "device_token": "test",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.json()
            .await
            .value()
            .object()
            .get("token")
            .string()
            .to_string()
    }

    pub async fn login_admin(&self) -> String {
        self.login("admin@voce.chat").await
    }

    pub async fn login_admin_with_device(&self, device: impl AsRef<str>) -> String {
        self.login_with_device("admin@voce.chat", device).await
    }

    pub async fn create_user(&self, token: impl AsRef<str>, email: impl AsRef<str>) -> i64 {
        let resp = self
            .client
            .post("/api/admin/user")
            .header("X-API-Key", token.as_ref())
            .header("Referer", "http://localhost/")
            .body_json(&json!({
                "email": email.as_ref(),
                "password": "123456",
                "name": email.as_ref(),
                "gender": 1,
                "language": "en-US",
                "is_admin": false,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.json().await.value().object().get("uid").i64()
    }

    pub async fn send_text_to_user(
        &self,
        token: impl AsRef<str>,
        uid: i64,
        text: impl Into<String>,
    ) -> i64 {
        let resp = self
            .client
            .post(format!("/api/user/{}/send", uid))
            .header("X-API-Key", token.as_ref())
            .header("Referer", "http://localhost/")
            .content_type("text/plain")
            .body(text.into())
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.json().await.value().i64()
    }

    pub async fn send_text_to_group(
        &self,
        token: impl AsRef<str>,
        gid: i64,
        text: impl Into<String>,
    ) -> i64 {
        let resp = self
            .client
            .post(format!("/api/group/{}/send", gid))
            .header("X-API-Key", token.as_ref())
            .header("Referer", "http://localhost/")
            .content_type("text/plain")
            .body(text.into())
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.json().await.value().i64()
    }

    pub async fn get_group(&self, gid: i64) -> TestJson {
        let resp = self.get(format!("/api/group/{}", gid)).send().await;
        resp.assert_status_is_ok();
        resp.json().await
    }

    async fn internal_subscribe_events(
        &self,
        token: impl AsRef<str>,
        filters: Option<&[&str]>,
        after_mid: Option<i64>,
        users_version: Option<i64>,
    ) -> BoxStream<'static, TestJson> {
        let mut builder = self
            .client
            .get("/api/user/events")
            .query("api-key", &token.as_ref())
            .header("Referer", "http://localhost/")
            .header("Connection", "keep-alive")
            .content_type("text/event-stream");
        if let Some(after_mid) = after_mid {
            builder = builder.query("after_mid", &after_mid);
        }
        if let Some(users_version) = users_version {
            builder = builder.query("users_version", &users_version);
        }
        let resp = builder.send().await;
        resp.assert_status_is_ok();
        let mut stream = resp.json_sse_stream().boxed();
        if let Some(filters) = filters {
            let filters = filters.iter().map(ToString::to_string).collect::<Vec<_>>();
            stream = stream
                .filter(move |json| {
                    futures_util::future::ready(
                        filters
                            .iter()
                            .any(|filter| filter == json.value().object().get("type").string()),
                    )
                })
                .boxed();
        }
        stream
    }

    pub async fn subscribe_events_with_users_version(
        &self,
        token: impl AsRef<str>,
        filters: Option<&[&str]>,
        users_version: i64,
    ) -> BoxStream<'static, TestJson> {
        self.internal_subscribe_events(token, filters, None, Some(users_version))
            .await
    }

    pub async fn subscribe_events(
        &self,
        token: impl AsRef<str>,
        filters: Option<&[&str]>,
    ) -> BoxStream<'static, TestJson> {
        self.internal_subscribe_events(token, filters, None, None)
            .await
    }

    pub async fn subscribe_events_after_mid(
        &self,
        token: impl AsRef<str>,
        filters: Option<&[&str]>,
        after_mid: Option<i64>,
    ) -> BoxStream<'static, TestJson> {
        self.internal_subscribe_events(token, filters, after_mid, None)
            .await
    }
}

async fn init_db(path: &Path) {
    std::fs::create_dir(path.join("db")).unwrap();
    let dsn = format!("sqlite:{}", path.join("db").join("db.sqlite").display());
    Sqlite::create_database(&dsn).await.unwrap();
    let db = SqlitePool::connect(&dsn).await.unwrap();
    MIGRATOR.run(&db).await.unwrap();
}
