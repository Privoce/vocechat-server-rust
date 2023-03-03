use std::sync::Arc;

use itertools::Itertools;
use poem::{
    error::{InternalServerError, ReadBodyError},
    http::StatusCode,
    web::Data,
    Error, Result,
};
use poem_openapi::{param::Path, payload::Json, types::Email, ApiResponse, Object, OpenApi};

use crate::{
    api::{
        tags::ApiTags,
        token::Token,
        user::{UploadAvatarApiResponse, UploadAvatarRequest},
        CreateUserConflictReason, CreateUserResponse, DateTime, KickReason, LangId, UpdateAction,
        UpdateUserResponse, UserConflict, UserUpdateLog,
    },
    api_key::create_api_key,
    create_user::{CreateUser, CreateUserBy, CreateUserError},
    state::{BotKey, BroadcastEvent, UserEvent, UserStatus},
    State,
};

pub struct ApiAdminUser;

/// User device
#[derive(Debug, Object)]
pub struct UserDevice {
    pub device: String,
    pub device_token: Option<String>,
    pub is_online: bool,
}

/// Create user request
#[derive(Debug, Object)]
pub struct CreateUserRequest {
    pub email: Email,
    pub password: String,
    #[oai(validator(max_length = 32))]
    pub name: String,
    pub gender: i32,
    pub is_admin: bool,
    #[oai(default)]
    pub language: LangId,
    pub webhook_url: Option<String>,
    #[oai(default)]
    pub is_bot: bool,
}

/// User info for admin
#[derive(Debug, Object)]
pub struct User {
    /// User id
    pub uid: i64,
    pub email: Option<String>,
    pub password: String,
    pub name: String,
    pub gender: i32,
    pub is_admin: bool,
    pub language: LangId,
    pub create_by: String,
    pub in_online: bool,
    pub online_devices: Vec<UserDevice>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub avatar_updated_at: DateTime,
    pub status: UserStatus,
    pub webhook_url: Option<String>,
    pub is_bot: bool,
}

/// Update user request
#[derive(Debug, Object)]
pub struct UpdateUserRequest {
    email: Option<String>,
    password: Option<String>,
    #[oai(validator(max_length = 32))]
    name: Option<String>,
    gender: Option<i32>,
    is_admin: Option<bool>,
    language: Option<LangId>,
    status: Option<UserStatus>,
    webhook_url: Option<String>,
}

impl UpdateUserRequest {
    fn is_empty(&self) -> bool {
        self.email.is_none()
            && self.password.is_none()
            && self.name.is_none()
            && self.gender.is_none()
            && self.is_admin.is_none()
            && self.language.is_none()
            && self.status.is_none()
            && self.webhook_url.is_none()
    }
}

/// Create bot api key request
#[derive(Debug, Object)]
pub struct CreateBotApiKeyRequest {
    name: String,
}

/// Create bot api key response
#[derive(Debug, ApiResponse)]
pub enum CreateBotApiKeyResponse {
    #[oai(status = 200)]
    Ok(Json<String>),
    /// Key name conflict
    #[oai(status = 409)]
    ConflictName,
}

/// Delete bot api key request
#[derive(Debug, Object)]
pub struct DeleteBotApiKeyRequest {
    uid: i64,
}

/// Delete bot api key response
#[derive(Debug, ApiResponse)]
pub enum DeleteBotApiKeyResponse {
    #[oai(status = 200)]
    Ok,
    /// Key not found
    #[oai(status = 404)]
    KeyNotFound,
}

#[derive(Debug, Object)]
#[oai(rename = "BotKey")]
pub struct BotKeyInfo {
    pub id: i64,
    pub name: String,
    pub key: String,
    pub created_at: DateTime,
    pub last_used: Option<DateTime>,
}

#[OpenApi(prefix_path = "/admin/user", tag = "ApiTags::AdminUser")]
impl ApiAdminUser {
    /// Create a user
    #[oai(path = "/", method = "post")]
    async fn create(
        &self,
        state: Data<&State>,
        mut req: Json<CreateUserRequest>,
        token: Token,
    ) -> Result<CreateUserResponse> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        req.email.0 = req.email.0.to_lowercase();
        let mut create_user = CreateUser::new(
            &req.name,
            CreateUserBy::Password {
                email: &req.email,
                password: &req.password,
            },
            false,
        )
        .gender(req.gender)
        .set_admin(req.is_admin)
        .language(&req.language)
        .set_bot(req.is_bot);

        if let Some(webhook_url) = &req.0.webhook_url {
            // check the webhook url
            if !matches!(
                reqwest::get(webhook_url).await.map(|resp| resp.status()),
                Ok(StatusCode::OK)
            ) {
                return Ok(CreateUserResponse::InvalidWebhookUrl);
            }

            create_user = create_user.webhook_url(webhook_url);
        }
        let res = state.create_user(create_user).await;

        match res {
            Ok((uid, user)) => Ok(CreateUserResponse::Ok(Json(user.api_user(uid)))),
            Err(CreateUserError::NameConflict) => {
                Ok(CreateUserResponse::Conflict(Json(UserConflict {
                    reason: CreateUserConflictReason::NameConflict,
                })))
            }
            Err(CreateUserError::EmailConflict) => {
                Ok(CreateUserResponse::Conflict(Json(UserConflict {
                    reason: CreateUserConflictReason::EmailConflict,
                })))
            }
            Err(CreateUserError::PoemError(err)) => Err(err),
        }
    }

    /// Get the user by id
    #[oai(path = "/:uid", method = "get")]
    async fn get(&self, state: Data<&State>, token: Token, uid: Path<i64>) -> Result<Json<User>> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let cache = state.cache.read().await;
        let user = cache
            .users
            .get(&uid.0)
            .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;
        Ok(Json(user.api_user(uid.0)))
    }

    /// Get all users
    #[oai(path = "/", method = "get")]
    async fn get_all(&self, state: Data<&State>, token: Token) -> Result<Json<Vec<User>>> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let cache = state.cache.read().await;
        let users = cache
            .users
            .iter()
            .filter(|(_, user)| !user.is_guest)
            .map(|(uid, user)| user.api_user(*uid))
            .collect();
        Ok(Json(users))
    }

    /// Delete the user by id
    #[oai(path = "/:uid", method = "delete")]
    async fn delete(&self, state: Data<&State>, token: Token, uid: Path<i64>) -> Result<()> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        if uid.0 == token.uid || uid.0 == 1 {
            // cannot delete self and founder
            return Err(poem::Error::from(StatusCode::FORBIDDEN));
        }

        state.delete_user(uid.0).await?;
        Ok(())
    }

    /// Update user by id
    #[oai(path = "/:uid", method = "put")]
    async fn update(
        &self,
        state: Data<&State>,
        token: Token,
        uid: Path<i64>,
        req: Json<UpdateUserRequest>,
    ) -> Result<UpdateUserResponse<User>> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        if req.is_empty() {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        let mut cache = state.cache.write().await;

        if let Some(email) = &req.email {
            if !cache.check_email_conflict(email) {
                return Ok(UpdateUserResponse::Conflict(Json(UserConflict {
                    reason: CreateUserConflictReason::EmailConflict,
                })));
            }
        }

        if let Some(name) = &req.name {
            if !cache.check_name_conflict(name) {
                return Ok(UpdateUserResponse::Conflict(Json(UserConflict {
                    reason: CreateUserConflictReason::NameConflict,
                })));
            }
        }

        // check webhook url
        if let Some(webhook_url) = &req.webhook_url {
            // check the webhook url
            if !matches!(
                reqwest::get(webhook_url).await.map(|resp| resp.status()),
                Ok(StatusCode::OK)
            ) {
                return Ok(UpdateUserResponse::InvalidWebhookUrl);
            }
        }

        let now = DateTime::now();
        let cached_user = cache
            .users
            .get_mut(&uid.0)
            .ok_or_else(|| Error::from(StatusCode::NOT_FOUND))?;

        // begin transaction
        let mut tx = state.db_pool.begin().await.map_err(InternalServerError)?;

        // update user table
        let sql = format!(
            "update user set {} where uid = ?",
            req.password
                .iter()
                .map(|_| "password = ?")
                .chain(req.email.iter().map(|_| "email = ?"))
                .chain(req.name.iter().map(|_| "name = ?"))
                .chain(req.gender.iter().map(|_| "gender = ?"))
                .chain(req.language.iter().map(|_| "language = ?"))
                .chain(req.is_admin.iter().map(|_| "is_admin = ?"))
                .chain(req.status.iter().map(|_| "status = ?"))
                .chain(req.webhook_url.iter().map(|_| "webhook_url = ?"))
                .chain(Some("updated_at = ?"))
                .join(", ")
        );

        let mut query = sqlx::query(&sql);
        if let Some(password) = &req.password {
            query = query.bind(password);
        }
        if let Some(email) = &req.email {
            query = query.bind(email);
        }
        if let Some(name) = &req.name {
            query = query.bind(name);
        }
        if let Some(gender) = &req.gender {
            query = query.bind(gender);
        }
        if let Some(language) = &req.language {
            query = query.bind(language);
        }
        if let Some(is_admin) = &req.is_admin {
            query = query.bind(is_admin);
        }
        if let Some(status) = &req.status {
            query = query.bind(i8::from(*status));
        }
        if let Some(webhook_url) = &req.webhook_url {
            query = query.bind(webhook_url);
        }

        query
            .bind(now)
            .bind(uid.0)
            .execute(&mut tx)
            .await
            .map_err(InternalServerError)?;

        // insert into user_log table
        let sql = "insert into user_log (uid, action, email, name, gender, is_admin, language) values (?, ?, ?, ?, ?, ?, ?)";
        let log_id = sqlx::query(sql)
            .bind(uid.0)
            .bind(UpdateAction::Update)
            .bind(&req.email)
            .bind(&req.name)
            .bind(req.gender)
            .bind(req.is_admin)
            .bind(&req.language)
            .execute(&mut tx)
            .await
            .map_err(InternalServerError)?
            .last_insert_rowid();

        // commit transaction
        tx.commit().await.map_err(InternalServerError)?;

        // update cache
        if let Some(email) = &req.0.email {
            cached_user.email = Some(email.clone());
        }
        if let Some(name) = &req.0.name {
            cached_user.name = name.clone();
        }
        if let Some(password) = &req.0.password {
            cached_user.password = Some(password.clone());
        }
        if let Some(gender) = req.0.gender {
            cached_user.gender = gender;
        }
        if let Some(language) = &req.0.language {
            cached_user.language = language.clone();
        }
        if let Some(is_admin) = req.0.is_admin {
            cached_user.is_admin = is_admin;
        }
        if let Some(status) = &req.0.status {
            cached_user.status = *status;
        }
        if let Some(webhook_url) = req.0.webhook_url {
            cached_user.webhook_url = Some(webhook_url);
        }

        if let Some(UserStatus::Frozen) = req.0.status {
            // close all subscriptions
            for device in cached_user.devices.values_mut() {
                if let Some(sender) = device.sender.take() {
                    let _ = sender.send(UserEvent::Kick {
                        reason: KickReason::Frozen,
                    });
                }
            }
        }

        // broadcast event
        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::UserLog(UserUpdateLog {
                log_id,
                action: UpdateAction::Update,
                uid: uid.0,
                email: req.0.email,
                name: req.0.name,
                gender: req.0.gender,
                language: req.0.language,
                is_admin: req.0.is_admin,
                is_bot: None,
                avatar_updated_at: None,
            })));

        Ok(UpdateUserResponse::Ok(Json(cached_user.api_user(uid.0))))
    }

    /// Upload avatar
    #[oai(path = "/:uid/avatar", method = "post")]
    async fn upload_avatar(
        &self,
        state: Data<&State>,
        token: Token,
        uid: Path<i64>,
        req: UploadAvatarRequest,
    ) -> Result<UploadAvatarApiResponse> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let mut cache = state.cache.write().await;
        let now = DateTime::now();
        let cached_user = cache
            .users
            .get_mut(&uid)
            .ok_or_else(|| Error::from(StatusCode::UNAUTHORIZED))?;

        let UploadAvatarRequest::Image(data) = req;
        let data = match data
            .0
            .into_bytes_limit(state.config.system.upload_avatar_limit)
            .await
        {
            Ok(data) => data,
            Err(ReadBodyError::PayloadTooLarge) => {
                return Ok(UploadAvatarApiResponse::PayloadTooLarge);
            }
            Err(err) => return Err(err.into()),
        };

        // write to file
        state.save_avatar(uid.0, &data)?;

        // update sqlite
        let mut tx = state.db_pool.begin().await.map_err(InternalServerError)?;

        sqlx::query("update user set avatar_updated_at = ? where uid = ?")
            .bind(now)
            .bind(uid.0)
            .execute(&mut tx)
            .await
            .map_err(InternalServerError)?;

        let log_id =
            sqlx::query("insert into user_log (uid, action, avatar_updated_at) values (?, ?, ?)")
                .bind(uid.0)
                .bind(UpdateAction::Update)
                .bind(now)
                .execute(&mut tx)
                .await
                .map_err(InternalServerError)?
                .last_insert_rowid();

        tx.commit().await.map_err(InternalServerError)?;

        // update cache
        cached_user.avatar_updated_at = now;

        // broadcast event
        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::UserLog(UserUpdateLog {
                log_id,
                action: UpdateAction::Update,
                uid: uid.0,
                email: None,
                name: None,
                gender: None,
                language: None,
                is_admin: None,
                is_bot: None,
                avatar_updated_at: Some(now),
            })));

        Ok(UploadAvatarApiResponse::Ok)
    }

    /// Create a bot api-key
    #[oai(path = "/bot-api-key/:uid", method = "post")]
    async fn create_bot_api_key(
        &self,
        state: Data<&State>,
        token: Token,
        uid: Path<i64>,
        req: Json<CreateBotApiKeyRequest>,
    ) -> Result<CreateBotApiKeyResponse> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let mut cache = state.cache.write().await;
        let user = cache
            .users
            .get_mut(&uid)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;

        if user
            .bot_keys
            .values()
            .any(|bot_key| bot_key.name == req.name)
        {
            return Ok(CreateBotApiKeyResponse::ConflictName);
        }

        let api_key = create_api_key(uid.0, &state.0.key_config.read().await.server_key);

        // update sqlite
        let now = DateTime::now();
        let key_id =
            sqlx::query("insert into `bot_key` (uid, name, key, created_at) values (?, ?, ?, ?)")
                .bind(uid.0)
                .bind(&req.name)
                .bind(&api_key)
                .bind(now)
                .execute(&state.db_pool)
                .await
                .map_err(InternalServerError)?
                .last_insert_rowid();

        // update cache
        user.bot_keys.insert(
            key_id,
            BotKey {
                name: req.0.name,
                key: api_key.clone(),
                created_at: now,
                last_used: None,
            },
        );

        Ok(CreateBotApiKeyResponse::Ok(Json(api_key)))
    }

    /// Delete a bot api-key
    #[oai(path = "/bot-api-key/:uid/:kid", method = "delete")]
    async fn delete_bot_api_key(
        &self,
        state: Data<&State>,
        token: Token,
        uid: Path<i64>,
        kid: Path<i64>,
    ) -> Result<DeleteBotApiKeyResponse> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let mut cache = state.cache.write().await;
        let user = cache
            .users
            .get_mut(&uid)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;

        if !user.bot_keys.contains_key(&kid) {
            return Ok(DeleteBotApiKeyResponse::KeyNotFound);
        }

        // update sqlite
        sqlx::query("delete from `bot_key` where id = ?")
            .bind(kid.0)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;

        // update cache
        user.bot_keys.remove(&kid);
        Ok(DeleteBotApiKeyResponse::Ok)
    }

    /// List bot api-key
    #[oai(path = "/bot-api-key/:uid", method = "get")]
    async fn list_bot_api_key(
        &self,
        state: Data<&State>,
        token: Token,
        uid: Path<i64>,
    ) -> Result<Json<Vec<BotKeyInfo>>> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let cache = state.cache.read().await;
        let user = cache
            .users
            .get(&uid)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;

        Ok(Json(
            user.bot_keys
                .iter()
                .map(|(kid, bot_key)| BotKeyInfo {
                    id: *kid,
                    name: bot_key.name.clone(),
                    key: bot_key.key.clone(),
                    created_at: bot_key.created_at,
                    last_used: bot_key.last_used,
                })
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use poem::http::StatusCode;
    use serde_json::{json, Value};

    use crate::test_harness::TestServer;

    #[tokio::test]
    async fn test_create_user() {
        let server = TestServer::new().await;

        let admin_token = server.login_admin().await;
        let uid = server.create_user(&admin_token, "test1@voce.chat").await;
        let token = server.login("test1@voce.chat").await;
        let current_user = server.parse_token(token).await;
        assert_eq!(uid, current_user.uid);
    }

    #[tokio::test]
    async fn test_create_name_conflict() {
        let server = TestServer::new().await;

        let admin_token = server.login_admin().await;
        let resp = server
            .post("/api/admin/user")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "email": "user1@voce.chat",
                "password": "123456",
                "name": "admin",
                "gender": 1,
                "language": "en-US",
                "is_admin": false,
            }))
            .send()
            .await;
        resp.assert_status(StatusCode::CONFLICT);
        resp.assert_json(json!({
            "reason": "name_conflict"
        }))
        .await;
    }

    #[tokio::test]
    async fn test_create_email_conflict() {
        let server = TestServer::new().await;

        let admin_token = server.login_admin().await;
        let resp = server
            .post("/api/admin/user")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "email": "admin@voce.chat",
                "password": "123456",
                "name": "test1",
                "gender": 1,
                "language": "en-US",
                "is_admin": false,
            }))
            .send()
            .await;
        resp.assert_status(StatusCode::CONFLICT);
        resp.assert_json(json!({
            "reason": "email_conflict"
        }))
        .await;
    }

    #[tokio::test]
    async fn test_delete_user() {
        let server = TestServer::new().await;

        let admin_token = server.login_admin().await;
        let uid = server.create_user(&admin_token, "test1@voce.chat").await;

        let resp = server
            .delete(format!("/api/admin/user/{}", uid))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();

        server
            .get(format!("/api/admin/user/{}", uid))
            .header("X-API-Key", &admin_token)
            .send()
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_user_info() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "test1@voce.chat").await;

        let resp = server
            .put(format!("/api/admin/user/{}", uid1))
            .header("X-API-Key", &admin_token)
            .body_json(&json!({ "email": "test2@voce.chat", "name": "test1", "gender": 2 }))
            .send()
            .await;
        resp.assert_status_is_ok();

        let resp = server
            .get(format!("/api/admin/user/{}", uid1))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        json.value()
            .object()
            .get("email")
            .assert_string("test2@voce.chat");
        json.value().object().get("name").assert_string("test1");
        json.value().object().get("gender").assert_i64(2);
    }

    #[tokio::test]
    async fn test_update_user_password() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "test1@voce.chat").await;

        fn make_login_body(password: &str) -> Value {
            json!({
                "credential": {
                    "type": "password",
                    "email": "test1@voce.chat",
                    "password": password,
                },
                "device": "iphone",
                "device_token": "test",
            })
        }

        server
            .post("/api/token/login")
            .body_json(&make_login_body("123456"))
            .send()
            .await
            .assert_status_is_ok();

        let resp = server
            .put(format!("/api/admin/user/{}", uid1))
            .header("X-API-Key", &admin_token)
            .body_json(&json!({ "password": "654321" }))
            .send()
            .await;
        resp.assert_status_is_ok();

        server
            .post("/api/token/login")
            .body_json(&make_login_body("123456"))
            .send()
            .await
            .assert_status(StatusCode::UNAUTHORIZED);

        server
            .post("/api/token/login")
            .body_json(&make_login_body("654321"))
            .send()
            .await
            .assert_status_is_ok();
    }

    #[tokio::test]
    async fn test_delete_user_then_delete_owned_private_group() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "test1@voce.chat").await;
        let token1 = server.login("test1@voce.chat").await;
        let mut gid_list = Vec::new();

        for _ in 0..10 {
            // create group
            let resp = server
                .post("/api/group")
                .header("X-API-Key", &token1)
                .body_json(&json!({
                    "name": "test",
                }))
                .send()
                .await;
            resp.assert_status_is_ok();
            gid_list.push(resp.json().await.value().object().get("gid").i64());
        }

        server
            .delete(format!("/api/admin/user/{}", uid1))
            .header("X-API-Key", &admin_token)
            .send()
            .await
            .assert_status_is_ok();

        for gid in gid_list {
            // check group
            let resp = server
                .get(format!("/api/group/{}", gid))
                .header("X-API-Key", &token1)
                .send()
                .await;
            resp.assert_status(StatusCode::NOT_FOUND)
        }
    }
}
