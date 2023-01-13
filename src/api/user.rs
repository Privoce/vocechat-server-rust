use std::sync::Arc;

use futures_util::{stream::BoxStream, StreamExt};
use itertools::Itertools;
use poem::{
    error::{InternalServerError, ReadBodyError},
    http::StatusCode,
    web::Data,
    Body, Error, Request, Result,
};
use poem_openapi::{
    param::{Header, Path, Query},
    payload::{Binary, EventStream, Json, PlainText},
    types::{Email, ToJSON},
    ApiRequest, ApiResponse, Enum, Object, OpenApi,
};
use rc_magic_link::MagicLinkToken;
use rc_msgdb::MsgDb;
use tokio::{
    sync::{
        broadcast::Receiver,
        mpsc::{self, UnboundedReceiver, UnboundedSender},
    },
    time::{Duration, Instant},
};

use crate::{
    api::{
        admin_login::WhoCanSignUp,
        group::get_related_groups,
        message::{
            decode_messages, parse_properties_from_base64, send_message, JoinedGroupMessage,
            KickFromGroupMessage, KickReason, MessageTargetGroup, MessageTargetUser,
            PinnedMessageUpdated, RelatedGroupsMessage, SendMessageRequest, SessionReadyMessage,
            UserJoinedGroupMessage, UserLeavedGroupMessage, UserState, UsersSnapshotMessage,
            UsersStateMessage,
        },
        tags::ApiTags,
        token::{Token, TokenInQuery},
        BurnAfterReadingGroup, BurnAfterReadingUser, ChatMessage, ChatMessagePayload, CurrentUser,
        DateTime, HeartbeatMessage, KickMessage, LangId, LoginConfig, Message, MessageTarget,
        MuteGroup, MuteUser, ReadIndexGroup, ReadIndexUser, UpdateAction, User,
        UserSettingsChangedMessage, UserSettingsMessage, UserStateChangedMessage, UserUpdateLog,
        UsersUpdateLogMessage,
    },
    create_user::{CreateUser, CreateUserBy, CreateUserError},
    middleware::guest_forbidden,
    state::{BroadcastEvent, Cache, CacheDevice, CacheUser, UserEvent},
    SqlitePool, State,
};

const MAX_NEWEST_MESSAGES: usize = 5000;

/// User info
#[derive(Debug, Object, Clone)]
pub struct UserInfo {
    #[oai(read_only)]
    pub uid: i64,
    pub email: Option<String>,
    pub name: String,
    pub gender: i32,
    pub language: LangId,
    #[oai(read_only)]
    pub is_admin: bool,
    #[oai(read_only)]
    pub is_bot: bool,
    #[oai(read_only)]
    pub avatar_updated_at: DateTime,
    #[oai(read_only)]
    pub create_by: String,
}

/// Change password request
#[derive(Debug, Object)]
struct ChangePasswordRequest {
    old_password: String,
    new_password: String,
}

/// Update user info request
#[derive(Debug, Object)]
struct UpdateUserInfoRequest {
    name: Option<String>,
    gender: Option<i32>,
    language: Option<LangId>,
}

impl UpdateUserInfoRequest {
    fn is_empty(&self) -> bool {
        self.name.is_none() && self.gender.is_none() && self.language.is_none()
    }
}

#[derive(Debug, ApiResponse)]
pub enum UpdateUserResponse<T: ToJSON> {
    #[oai(status = 200)]
    Ok(Json<T>),
    /// Invalid webhook url
    #[oai(status = 406)]
    InvalidWebhookUrl,
    /// User conflict
    #[oai(status = 409)]
    Conflict(Json<UserConflict>),
}

#[derive(ApiRequest)]
pub enum UploadAvatarRequest {
    #[oai(content_type = "image/png")]
    Image(Binary<Body>),
}

/// Mute request user
#[derive(Debug, Object)]
struct MuteRequestUser {
    /// User id
    uid: i64,
    /// Seconds
    expired_in: Option<u32>,
}

/// Mute request group
#[derive(Debug, Object)]
struct MuteRequestGroup {
    /// Group id
    gid: i64,
    /// Seconds
    expired_in: Option<u32>,
}

/// Mute request
#[derive(Debug, Object)]
struct MuteRequest {
    #[oai(default)]
    add_users: Vec<MuteRequestUser>,
    #[oai(default)]
    add_groups: Vec<MuteRequestGroup>,
    #[oai(default)]
    remove_users: Vec<i64>,
    #[oai(default)]
    remove_groups: Vec<i64>,
}

/// Update read index request user
#[derive(Debug, Object)]
struct UpdateReadIndexRequestUser {
    /// User id
    uid: i64,
    /// Message id
    mid: i64,
}

/// Update read index request group
#[derive(Debug, Object)]
struct UpdateReadIndexRequestGroup {
    /// Group id
    gid: i64,
    /// Message id
    mid: i64,
}

/// Update read index request
#[derive(Debug, Object)]
struct UpdateReadIndexRequest {
    #[oai(default)]
    users: Vec<UpdateReadIndexRequestUser>,
    #[oai(default)]
    groups: Vec<UpdateReadIndexRequestGroup>,
}

/// Update read index request user
#[derive(Debug, Object)]
struct UpdateBurnAfterReadingRequestUser {
    /// User id
    uid: i64,
    /// Expires in seconds
    expires_in: i64,
}

/// Update read index request group
#[derive(Debug, Object)]
struct UpdateBurnAfterReadingRequestGroup {
    /// Group id
    gid: i64,
    /// Expires in seconds
    expires_in: i64,
}

/// Update read after reading request
#[derive(Debug, Object)]
struct UpdateBurnAfterReadingRequest {
    #[oai(default)]
    users: Vec<UpdateBurnAfterReadingRequestUser>,
    #[oai(default)]
    groups: Vec<UpdateBurnAfterReadingRequestGroup>,
}

#[derive(ApiResponse)]
pub enum UploadAvatarApiResponse {
    /// Success
    #[oai(status = 200)]
    Ok,
    /// Payload too large
    #[oai(status = 413)]
    PayloadTooLarge,
}

#[derive(Debug, Object)]
struct CheckMagicTokenRequest {
    magic_token: String,
}

#[derive(Debug, Object)]
struct RegisterRequest {
    magic_token: Option<String>,
    email: Option<Email>,
    password: Option<String>,
    #[oai(validator(max_length = 32))]
    name: Option<String>,
    #[oai(default)]
    gender: i32,
    #[oai(default)]
    language: LangId,
    /// Device id
    #[oai(default = "default_device")]
    device: String,
    /// FCM device token
    device_token: Option<String>,
}

fn default_device() -> String {
    "unknown".to_string()
}

// #[derive(Debug, Enum)]
// #[oai(rename_all = "snake_case")]
// enum CodeUseFor {
//     Register,
// }

#[derive(Debug, Enum)]
#[oai(rename_all = "snake_case")]
pub enum CreateUserConflictReason {
    NameConflict,
    EmailConflict,
}

#[derive(Debug, Object)]
pub struct UserConflict {
    pub reason: CreateUserConflictReason,
}

#[derive(Debug, ApiResponse)]
pub enum CreateUserResponse {
    #[oai(status = 200)]
    Ok(Json<User>),
    /// Invalid webhook url
    #[oai(status = 406)]
    InvalidWebhookUrl,
    /// User conflict
    #[oai(status = 409)]
    Conflict(Json<UserConflict>),
}

#[derive(Debug, ApiResponse)]
pub enum RegisterUserResponse {
    #[oai(status = 200)]
    Ok(Json<super::token::LoginResponse>),
    #[oai(status = 409)]
    Conflict(Json<UserConflict>),
    /// Magic token has been expired.
    #[oai(status = 412)]
    MagicTokenExpired,
    #[oai(status = 413)]
    OkButLoginFailed,
}

/// Change password request
#[derive(Debug, Object)]
struct SendRegMagicTokenRequest {
    magic_token: String,
    email: Email,
    password: String,
}

// #[derive(Debug, ApiResponse)]
// pub enum SendRegMagicTokenResponse {
//     #[oai(status = 200)]
//     Ok(Json<SendRegMagicTokenResponseInner>),
//     #[oai(status = 409)]
//     Conflict(Json<UserConflict>),
//     /// Magic token has been expired.
//     #[oai(status = 412)]
//     MagicTokenExpired,
// }

#[derive(Debug, Object)]
pub struct SendRegMagicTokenResponse {
    new_magic_token: String,
    mail_is_sent: bool,
}

pub struct ApiUser;

#[OpenApi(prefix_path = "/user", tag = "ApiTags::User")]
impl ApiUser {
    /// Check the invite magic token is valid
    #[oai(path = "/check_magic_token", method = "post")]
    async fn check_magic_token(
        &self,
        state: Data<&State>,
        req: Json<CheckMagicTokenRequest>,
    ) -> Result<Json<bool>> {
        let key_config = state.key_config.read().await;
        Ok(Json(
            MagicLinkToken::parse(&key_config.server_key, &req.magic_token).is_some(),
        ))
    }

    /// Register a new user with the magic token
    #[oai(path = "/register", method = "post")]
    async fn register(
        &self,
        state: Data<&State>,
        req: Json<RegisterRequest>,
    ) -> Result<RegisterUserResponse> {
        let key_config = state.key_config.read().await;
        let login_config = state
            .get_dynamic_config_instance::<LoginConfig>()
            .await
            .unwrap_or_default();

        let can_register = match login_config.who_can_sign_up {
            WhoCanSignUp::EveryOne => true,
            WhoCanSignUp::InvitationOnly if req.magic_token.is_some() => true,
            _ => false,
        };
        if !can_register {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let (mt_gid, extra_email, extra_password) = if let Some(magic_token) = &req.magic_token {
            let mt = match MagicLinkToken::parse(&key_config.server_key, magic_token) {
                Some(magic_token) => magic_token,
                None => return Ok(RegisterUserResponse::MagicTokenExpired),
            };
            let (is_confirmed, mt_gid, extra_email, extra_password) = match mt {
                MagicLinkToken::Register {
                    is_confirmed,
                    gid,
                    extra_email,
                    extra_password,
                    ..
                } => (is_confirmed, gid, extra_email, extra_password),
                _ => return Ok(RegisterUserResponse::MagicTokenExpired),
            };

            // check magic token is validated by email.
            let smtp_on = state
                .load_dynamic_config::<crate::api::SmtpConfig>()
                .await?
                .enabled;
            if smtp_on && !is_confirmed {
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }
            (mt_gid, extra_email, extra_password)
        } else {
            (None, None, None)
        };
        let email = if req.email.is_some() {
            req.email.as_ref().unwrap().0.clone()
        } else {
            extra_email.unwrap_or_default()
        };
        let password = if req.password.is_some() {
            req.password.as_ref().cloned().unwrap_or_default()
        } else {
            extra_password.unwrap_or_default()
        };
        let name = state
            .cache
            .read()
            .await
            .assign_username(req.name.as_deref(), Some(email.as_str()));

        let create_user = CreateUser::new(
            &name,
            CreateUserBy::Password {
                email: &email,
                password: &password,
            },
            false,
        )
        .gender(req.gender)
        .language(&req.language);

        let (uid, res) = match state.create_user(create_user).await {
            Ok((uid, user)) => (
                uid,
                // Ok::<_, poem::Error>(RegisterUserResponse::Ok(Json(user.api_user_info(uid)))),
                Ok::<_, poem::Error>({
                    drop(user);
                    if let Ok(super::token::LoginApiResponse::Ok(Json(login_resp))) =
                        super::token::do_login(
                            &state,
                            uid,
                            &req.0.device,
                            req.0.device_token.as_deref(),
                        )
                        .await
                    {
                        RegisterUserResponse::Ok(Json(login_resp))
                    } else {
                        RegisterUserResponse::OkButLoginFailed
                    }
                }),
            ),
            Err(CreateUserError::NameConflict) => {
                return Ok(RegisterUserResponse::Conflict(Json(UserConflict {
                    reason: CreateUserConflictReason::NameConflict,
                })));
            }
            Err(CreateUserError::EmailConflict) => {
                return Ok(RegisterUserResponse::Conflict(Json(UserConflict {
                    reason: CreateUserConflictReason::EmailConflict,
                })));
            }
            Err(CreateUserError::PoemError(err)) => return Err(err),
        };
        let res = res?;
        if let Some(gid) = mt_gid {
            let mut cache = state.cache.write().await;
            if let Some(group) = cache.groups.get_mut(&gid) {
                if !group.ty.is_public() {
                    // update sqlite
                    sqlx::query("insert into group_user (gid, uid) values (?, ?)")
                        .bind(gid)
                        .bind(uid)
                        .execute(&state.db_pool)
                        .await
                        .map_err(InternalServerError)?;

                    // update cache
                    group.members.insert(uid);
                }
                // broadcast event
                let _ = state
                    .event_sender
                    .send(Arc::new(BroadcastEvent::UserJoinedGroup {
                        targets: group
                            .members
                            .iter()
                            .copied()
                            .filter(|x| *x != uid)
                            .collect(),
                        gid,
                        uid: vec![uid],
                    }));
            }
        }
        Ok(res)
    }

    /// Check the specified email address is available.
    #[oai(path = "/check_email", method = "get")]
    async fn check_email(&self, state: Data<&State>, email: Query<Email>) -> Result<Json<bool>> {
        let cache = state.cache.read().await;
        Ok(Json(cache.check_email_conflict(&email)))
    }

    /// Send register magic link to email
    /// return the new magic token
    #[oai(path = "/send_reg_magic_link", method = "post")]
    async fn send_reg_magic_link(
        &self,
        state: Data<&State>,
        post: Json<SendRegMagicTokenRequest>,
        req: &Request,
    ) -> Result<Json<SendRegMagicTokenResponse>> {
        use poem::http::StatusCode;
        let url = crate::state::get_frontend_url(&state, req).await;
        let key_config = state.key_config.read().await;

        let smtp_on = state
            .load_dynamic_config::<crate::api::SmtpConfig>()
            .await?
            .enabled;

        let (new_magic_token, gid) = if smtp_on {
            let mt = MagicLinkToken::parse(&key_config.server_key, &post.magic_token).ok_or_else(
                || Error::from_status(StatusCode::from_u16(1000).unwrap_or_default()),
            )?;

            let (gid, code, expired_at) = match mt {
                MagicLinkToken::Register {
                    gid,
                    code,
                    expired_at,
                    ..
                } => Ok((gid, code, expired_at)),
                _ => Err(Error::from_status(
                    StatusCode::from_u16(1001).unwrap_or_default(),
                )),
            }?;

            if !state.magic_code_check_code(&code).await {
                return Err(poem::Error::from_status(StatusCode::BAD_REQUEST));
            }

            let expired_at = {
                let naive = chrono::NaiveDateTime::from_timestamp_opt(expired_at, 0).unwrap();
                chrono::DateTime::from_utc(naive, chrono::Utc)
            };

            (
                MagicLinkToken::gen_reg_magic_token(
                    &code,
                    &state.key_config.read().await.server_key,
                    expired_at,
                    true,
                    gid,
                    Some(post.email.0.clone()),
                    Some(post.password.clone()),
                ),
                gid,
            )
        } else {
            let code = rc_magic_link::gen_code();
            let expired_at = chrono::Utc::now() + chrono::Duration::seconds(86400);
            let gid = None;
            (
                MagicLinkToken::gen_reg_magic_token(
                    &code,
                    &state.key_config.read().await.server_key,
                    expired_at,
                    true,
                    gid,
                    Some(post.email.0.clone()),
                    Some(post.password.clone()),
                ),
                gid,
            )
        };

        if smtp_on {
            let email = post.email.clone();
            let template = state
                .templates
                .register_by_email
                .as_ref()
                .ok_or_else(|| poem::Error::from_status(StatusCode::FORBIDDEN))?;

            let uid = {
                let cache = state.cache.read().await;
                cache
                    .users
                    .iter()
                    .find(|(_, user)| user.email.as_deref() == Some(&email))
                    .map(|(uid, _)| *uid)
            };
            if uid.is_some() {
                return Err(poem::Error::from_status(StatusCode::CONFLICT));
            }

            let content = template
                .template
                .render(&liquid::object!({
                    "magic_token": &new_magic_token,
                    "email": email.0,
                    "gid": gid,
                    "url": url,
                }))
                .map_err(InternalServerError)?;

            tokio::spawn({
                let state = state.clone();
                let subject = template.subject.clone();
                let email = email.to_string();
                async move {
                    let smtp_config = state
                        .get_dynamic_config_instance::<crate::api::SmtpConfig>()
                        .await;
                    if let Some(smtp_config) = smtp_config {
                        if let Err(err) =
                            crate::state::send_mail(&smtp_config, email, subject, content).await
                        {
                            tracing::error!(error = %err, "failed to send mail");
                        }
                    }
                }
            });

            Ok(Json(SendRegMagicTokenResponse {
                new_magic_token: if cfg!(test) {
                    new_magic_token
                } else {
                    "".to_string()
                },
                mail_is_sent: true,
            }))
        } else {
            Ok(Json(SendRegMagicTokenResponse {
                new_magic_token,
                mail_is_sent: false,
            }))
        }
    }

    /// Send login magic link
    /// login magic link only can be used once.
    #[oai(path = "/send_login_magic_link", method = "post")]
    async fn send_login_magic_link(
        &self,
        state: Data<&State>,
        email: Query<Email>,
        req: &Request,
    ) -> Result<PlainText<String>> {
        crate::license::check_license_wrap!(&state, req);

        let login_config = state
            .get_dynamic_config_instance::<LoginConfig>()
            .await
            .unwrap_or_default();
        if !login_config.magic_link {
            return Err(Error::from_status(StatusCode::NOT_ACCEPTABLE));
        }

        let url = crate::state::get_frontend_url(&state, req).await;
        let code = rc_magic_link::gen_code();
        let expired_at = chrono::Utc::now()
            + chrono::Duration::seconds(state.config.system.magic_token_expiry_seconds);
        let magic_token = state
            .send_login_magic_link(&code, &url, expired_at, &email)
            .await?;

        if cfg!(test) {
            Ok(PlainText(magic_token))
        } else {
            Ok(PlainText(
                "Magic token has been sent to the email。".to_string(),
            ))
        }
    }

    /// Get the current user information
    #[oai(path = "/me", method = "get")]
    async fn me(&self, state: Data<&State>, token: Token) -> Result<Json<UserInfo>> {
        let cache = state.cache.read().await;
        let user = cache
            .users
            .get(&token.uid)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
        Ok(Json(user.api_user_info(token.uid)))
    }

    /// Get the specified user information
    #[oai(path = "/:uid", method = "get")]
    async fn get_user(&self, state: Data<&State>, uid: Path<i64>) -> Result<Json<UserInfo>> {
        let cache = state.cache.read().await;
        let user = cache
            .users
            .get(&uid.0)
            .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;
        Ok(Json(user.api_user_info(uid.0)))
    }

    #[oai(
        path = "/change_password",
        method = "post",
        transform = "guest_forbidden"
    )]
    async fn change_password(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<ChangePasswordRequest>,
    ) -> Result<()> {
        let mut cache = state.cache.write().await;
        let cached_user = cache
            .users
            .get_mut(&token.uid)
            .ok_or_else(|| Error::from(StatusCode::UNAUTHORIZED))?;

        if cached_user.password.as_deref().unwrap_or_default() != &*req.old_password {
            return Err(Error::from(StatusCode::FORBIDDEN));
        }

        // update database
        let sql = "update user set password = ? where uid = ?";
        sqlx::query(sql)
            .bind(&req.new_password)
            .bind(token.uid)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;

        // update cache
        cached_user.password = Some(req.0.new_password);
        Ok(())
    }

    /// Update the current user information
    #[oai(path = "/", method = "put", transform = "guest_forbidden")]
    async fn update_user(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<UpdateUserInfoRequest>,
    ) -> Result<UpdateUserResponse<UserInfo>> {
        if req.is_empty() {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        let mut cache = state.cache.write().await;
        if let Some(name) = &req.name {
            if !cache.check_name_conflict(name) {
                return Ok(UpdateUserResponse::Conflict(Json(UserConflict {
                    reason: CreateUserConflictReason::NameConflict,
                })));
            }
        }

        let now = DateTime::now();
        let cached_user = cache
            .users
            .get_mut(&token.uid)
            .ok_or_else(|| Error::from(StatusCode::UNAUTHORIZED))?;

        // begin transaction
        let mut tx = state.db_pool.begin().await.map_err(InternalServerError)?;

        // update user table
        let sql = format!(
            "update user set {} where uid = ?",
            req.name
                .iter()
                .map(|_| "name = ?")
                .chain(req.gender.iter().map(|_| "gender = ?"))
                .chain(req.language.iter().map(|_| "language = ?"))
                .chain(Some("updated_at = ?"))
                .join(", ")
        );

        let mut query = sqlx::query(&sql);
        if let Some(name) = &req.name {
            query = query.bind(name);
        }
        if let Some(gender) = &req.gender {
            query = query.bind(gender);
        }
        if let Some(language) = &req.language {
            query = query.bind(language);
        }

        query
            .bind(now)
            .bind(token.uid)
            .execute(&mut tx)
            .await
            .map_err(InternalServerError)?;

        // insert into user_log table
        let log_id = if req.name.is_some() || req.gender.is_some() && req.language.is_some() {
            Some(sqlx::query(
                "insert into user_log (uid, action, name, gender, language) values (?, ?, ?, ?, ?)",
            )
                .bind(token.uid)
                .bind(UpdateAction::Update)
                .bind(&req.name)
                .bind(req.gender)
                .bind(&req.language)
                .execute(&mut tx)
                .await
                .map_err(InternalServerError)?.last_insert_rowid())
        } else {
            None
        };

        // commit transaction
        tx.commit().await.map_err(InternalServerError)?;

        // update cache
        if let Some(name) = &req.0.name {
            cached_user.name = name.clone();
        }
        if let Some(gender) = req.0.gender {
            cached_user.gender = gender;
        }
        if let Some(language) = &req.0.language {
            cached_user.language = language.clone();
        }

        // broadcast event
        if let Some(log_id) = log_id {
            let _ = state
                .event_sender
                .send(Arc::new(BroadcastEvent::UserLog(UserUpdateLog {
                    log_id,
                    action: UpdateAction::Update,
                    uid: token.uid,
                    email: None,
                    name: req.0.name,
                    gender: req.0.gender,
                    language: req.0.language,
                    is_admin: None,
                    is_bot: None,
                    avatar_updated_at: None,
                })));
        }

        Ok(UpdateUserResponse::Ok(Json(
            cached_user.api_user_info(token.uid),
        )))
    }

    /// Upload avatar
    #[oai(path = "/avatar", method = "post", transform = "guest_forbidden")]
    async fn upload_avatar(
        &self,
        state: Data<&State>,
        token: Token,
        req: UploadAvatarRequest,
    ) -> Result<UploadAvatarApiResponse> {
        let mut cache = state.cache.write().await;
        let now = DateTime::now();
        let cached_user = cache
            .users
            .get_mut(&token.uid)
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
        state.save_avatar(token.uid, &data)?;

        // update sqlite
        let mut tx = state.db_pool.begin().await.map_err(InternalServerError)?;

        sqlx::query("update user set avatar_updated_at = ? where uid = ?")
            .bind(now)
            .bind(token.uid)
            .execute(&mut tx)
            .await
            .map_err(InternalServerError)?;

        let log_id =
            sqlx::query("insert into user_log (uid, action, avatar_updated_at) values (?, ?, ?)")
                .bind(token.uid)
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
                uid: token.uid,
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

    /// Get all users
    #[oai(path = "/", method = "get")]
    async fn get_all_users(&self, state: Data<&State>) -> Json<Vec<UserInfo>> {
        Json(
            state
                .cache
                .read()
                .await
                .users
                .iter()
                .filter(|(_, user)| !user.is_guest)
                .map(|(id, user)| user.api_user_info(*id))
                .collect(),
        )
    }

    /// Send message to the specified user
    #[oai(path = "/:uid/send", method = "post", transform = "guest_forbidden")]
    async fn send(
        &self,
        state: Data<&State>,
        token: Token,
        uid: Path<i64>,
        #[oai(name = "X-Properties")] properties: Header<Option<String>>,
        req: SendMessageRequest,
    ) -> Result<Json<i64>> {
        let properties = parse_properties_from_base64(properties.0);
        let payload = req
            .into_chat_message_payload(&state, token.uid, MessageTarget::user(uid.0), properties)
            .await?;
        let mid = send_message(&state, payload).await?;
        Ok(Json(mid))
    }

    /// Get history messages
    #[oai(path = "/:uid/history", method = "get")]
    async fn get_history_messages(
        &self,
        state: Data<&State>,
        token: Token,
        uid: Path<i64>,
        before: Query<Option<i64>>,
        #[oai(default = "default_get_history_messages_limit")] limit: Query<usize>,
    ) -> Result<Json<Vec<ChatMessage>>> {
        let msgs = state
            .msg_db
            .messages()
            .fetch_dm_messages_before(token.uid, uid.0, before.0, limit.0)
            .map_err(InternalServerError)?;
        Ok(Json(decode_messages(msgs)))
    }

    /// Subscribe events
    #[oai(path = "/events", method = "get")]
    async fn events(
        &self,
        state: Data<&State>,
        token: TokenInQuery,
        after_mid: Query<Option<i64>>,
        users_version: Query<Option<i64>>,
    ) -> Result<EventStream<BoxStream<'static, Message>>> {
        let uid = token.uid;
        let mut cache = state.cache.write().await;
        let related_groups = get_related_groups(&cache.groups, uid, false);
        let user = cache
            .users
            .get_mut(&token.uid)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
        let user_settings_msg = get_user_settings_msg(user);
        let rx_user_event = create_user_event_receiver(&state, &token.0, user)?;
        let receiver = state.event_sender.subscribe();
        let users_log_msg = fetch_user_log(&cache, &state.db_pool, users_version.0).await?;
        let users_state_msg = get_users_state(&cache, uid);
        let newest_messages = fetch_newest_messages(&cache, &state.msg_db, uid, after_mid.0)?;
        let push_start_id = newest_messages.last().map(|msg| msg.mid);
        let messages = users_log_msg
            .into_iter()
            .chain(Some(Message::UsersState(users_state_msg)))
            .chain(Some(Message::RelatedGroups(RelatedGroupsMessage {
                groups: related_groups,
            })))
            .chain(Some(Message::UserSettings(user_settings_msg)))
            .chain(newest_messages.into_iter().map(Message::Chat))
            .chain(Some(Message::Ready(SessionReadyMessage {})));

        tracing::info!(
            uid = uid,
            device = token.device.as_str(),
            "subscribe events"
        );

        let (tx_msg, rx_msg) = mpsc::unbounded_channel();
        for message in messages {
            let _ = tx_msg.send(message);
        }
        tokio::spawn(events_loop(
            state.0.clone(),
            rx_user_event,
            receiver,
            push_start_id,
            token.uid,
            token.0.device,
            tx_msg,
        ));

        Ok(
            EventStream::new(tokio_stream::wrappers::UnboundedReceiverStream::new(rx_msg).boxed())
                .keep_alive(Duration::from_secs(5)),
        )
    }

    /// Get all devices of the current user
    #[oai(path = "/devices", method = "get")]
    async fn get_devices(&self, state: Data<&State>, token: Token) -> Result<Json<Vec<String>>> {
        let cache = state.cache.read().await;
        let user = cache
            .users
            .get(&token.uid)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
        Ok(Json(user.devices.keys().cloned().collect()))
    }

    /// Delete current user's specified device
    #[oai(
        path = "/devices/:device",
        method = "delete",
        transform = "guest_forbidden"
    )]
    async fn delete_device(
        &self,
        state: Data<&State>,
        token: Token,
        device: Path<String>,
    ) -> Result<()> {
        let mut cache = state.cache.write().await;

        let rows_affected = sqlx::query("delete from device where uid = ? and device = ?")
            .bind(token.uid)
            .bind(&device.0)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?
            .rows_affected();
        if rows_affected == 0 {
            return Err(Error::from_status(StatusCode::UNAUTHORIZED));
        }

        let user = cache
            .users
            .get_mut(&token.uid)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
        let cached_device = user
            .devices
            .remove(&device.0)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
        if let Some(sender) = cached_device.sender {
            let _ = sender.send(UserEvent::Kick {
                reason: KickReason::DeleteDevice,
            });
        }

        Ok(())
    }

    /// Change the mute settings
    #[oai(path = "/mute", method = "post")]
    async fn mute(&self, state: Data<&State>, token: Token, req: Json<MuteRequest>) -> Result<()> {
        let mut cache = state.cache.write().await;

        if req
            .add_users
            .iter()
            .any(|item| item.uid == token.uid || !cache.users.contains_key(&item.uid))
        {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        if req
            .add_groups
            .iter()
            .any(|item| !cache.groups.contains_key(&item.gid))
        {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        if req
            .remove_users
            .iter()
            .any(|uid| !cache.users.contains_key(uid))
        {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        if req
            .remove_groups
            .iter()
            .any(|gid| !cache.groups.contains_key(gid))
        {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        let user = cache
            .users
            .get_mut(&token.uid)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;

        let now = DateTime::now();
        let add_user_list = req
            .0
            .add_users
            .into_iter()
            .map(|item| MuteUser {
                uid: item.uid,
                expired_at: item.expired_in.map(|seconds| {
                    DateTime::from(now.0 + chrono::Duration::seconds(seconds as i64))
                }),
            })
            .collect_vec();
        let add_group_list = req
            .0
            .add_groups
            .into_iter()
            .map(|item| MuteGroup {
                gid: item.gid,
                expired_at: item.expired_in.map(|seconds| {
                    DateTime::from(now.0 + chrono::Duration::seconds(seconds as i64))
                }),
            })
            .collect_vec();
        let remove_user_list = req.0.remove_users;
        let remove_group_list = req.0.remove_groups;

        // update sqlite
        let mut tx = state.db_pool.begin().await.map_err(InternalServerError)?;

        for item in &add_user_list {
            let sql = r#"
                    insert into mute (uid, mute_uid, expired_at) values (?, ?, ?)
                        on conflict (uid, mute_uid) do update set expired_at = excluded.expired_at
                    "#;
            sqlx::query(sql)
                .bind(token.uid)
                .bind(item.uid)
                .bind(item.expired_at)
                .execute(&mut tx)
                .await
                .map_err(InternalServerError)?;
        }

        for item in &add_group_list {
            let sql = r#"
                    insert into mute (uid, mute_gid, expired_at) values (?, ?, ?)
                        on conflict (uid, mute_gid) do update set expired_at = excluded.expired_at
                    "#;
            sqlx::query(sql)
                .bind(token.uid)
                .bind(item.gid)
                .bind(item.expired_at)
                .execute(&mut tx)
                .await
                .map_err(InternalServerError)?;
        }

        for uid in &remove_user_list {
            let sql = "delete from mute where uid = ? and mute_uid = ?";
            sqlx::query(sql)
                .bind(token.uid)
                .bind(uid)
                .execute(&mut tx)
                .await
                .map_err(InternalServerError)?;
        }

        for gid in &remove_group_list {
            let sql = "delete from mute where uid = ? and mute_gid = ?";
            sqlx::query(sql)
                .bind(token.uid)
                .bind(gid)
                .execute(&mut tx)
                .await
                .map_err(InternalServerError)?;
        }

        tx.commit().await.map_err(InternalServerError)?;

        // update cache
        for item in &add_user_list {
            user.mute_user.insert(item.uid, item.expired_at);
        }
        for item in &add_group_list {
            user.mute_group.insert(item.gid, item.expired_at);
        }
        for uid in &remove_user_list {
            user.mute_user.remove(uid);
        }
        for gid in &remove_group_list {
            user.mute_group.remove(gid);
        }

        // broadcast event
        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::UserSettingsChanged {
                uid: token.0.uid,
                message: UserSettingsChangedMessage {
                    from_device: token.0.device,
                    add_mute_users: add_user_list,
                    add_mute_groups: add_group_list,
                    remove_mute_users: remove_user_list,
                    remove_mute_groups: remove_group_list,
                    ..Default::default()
                },
            }));

        Ok(())
    }

    /// Change the burn after reading settings
    #[oai(path = "/burn-after-reading", method = "post")]
    async fn update_burn_after_reading(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<UpdateBurnAfterReadingRequest>,
    ) -> Result<()> {
        let mut cache = state.cache.write().await;

        if req.users.iter().any(|item| {
            item.uid == token.uid || !cache.users.contains_key(&item.uid) || item.expires_in < 0
        }) {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        if req
            .groups
            .iter()
            .any(|item| !cache.groups.contains_key(&item.gid) || item.expires_in < 0)
        {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        let user = cache
            .users
            .get_mut(&token.uid)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;

        let burn_after_reading_users = req
            .0
            .users
            .into_iter()
            .map(|item| BurnAfterReadingUser {
                uid: item.uid,
                expires_in: item.expires_in,
            })
            .collect_vec();
        let burn_after_reading_groups = req
            .0
            .groups
            .into_iter()
            .map(|item| BurnAfterReadingGroup {
                gid: item.gid,
                expires_in: item.expires_in,
            })
            .collect_vec();

        // update sqlite
        let mut tx = state.db_pool.begin().await.map_err(InternalServerError)?;

        for item in &burn_after_reading_users {
            if item.expires_in > 0 {
                let sql = r#"
                    insert into burn_after_reading (uid, target_uid, expires_in) values (?, ?, ?)
                        on conflict (uid, target_uid) do update set expires_in = excluded.expires_in
                    "#;
                sqlx::query(sql)
                    .bind(token.uid)
                    .bind(item.uid)
                    .bind(item.expires_in)
                    .execute(&mut tx)
                    .await
                    .map_err(InternalServerError)?;
            } else {
                let sql = "delete from burn_after_reading where uid = ? and target_uid = ?";
                sqlx::query(sql)
                    .bind(token.uid)
                    .bind(item.uid)
                    .execute(&mut tx)
                    .await
                    .map_err(InternalServerError)?;
            }
        }

        for item in &burn_after_reading_groups {
            if item.expires_in > 0 {
                let sql = r#"
                    insert into burn_after_reading (uid, target_gid, expires_in) values (?, ?, ?)
                        on conflict (uid, target_gid) do update set expires_in = excluded.expires_in
                    "#;
                sqlx::query(sql)
                    .bind(token.uid)
                    .bind(item.gid)
                    .bind(item.expires_in)
                    .execute(&mut tx)
                    .await
                    .map_err(InternalServerError)?;
            } else {
                let sql = "delete from burn_after_reading where uid = ? and target_gid = ?";
                sqlx::query(sql)
                    .bind(token.uid)
                    .bind(item.gid)
                    .execute(&mut tx)
                    .await
                    .map_err(InternalServerError)?;
            }
        }

        tx.commit().await.map_err(InternalServerError)?;

        // update cache
        for item in &burn_after_reading_users {
            if item.expires_in > 0 {
                user.burn_after_reading_user
                    .insert(item.uid, item.expires_in);
            } else {
                user.burn_after_reading_user.remove(&item.uid);
            }
        }

        for item in &burn_after_reading_groups {
            if item.expires_in > 0 {
                user.burn_after_reading_group
                    .insert(item.gid, item.expires_in);
            } else {
                user.burn_after_reading_group.remove(&item.gid);
            }
        }

        // broadcast event
        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::UserSettingsChanged {
                uid: token.0.uid,
                message: UserSettingsChangedMessage {
                    from_device: token.0.device,
                    burn_after_reading_users,
                    burn_after_reading_groups,
                    ..Default::default()
                },
            }));

        Ok(())
    }

    /// Update read index
    #[oai(path = "/read-index", method = "post")]
    async fn update_read_index(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<UpdateReadIndexRequest>,
    ) -> Result<()> {
        let mut cache = state.cache.write().await;

        if req
            .users
            .iter()
            .any(|item| item.uid == token.uid || !cache.users.contains_key(&item.uid))
        {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        if req
            .groups
            .iter()
            .any(|item| !cache.groups.contains_key(&item.gid))
        {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        let user = cache
            .users
            .get_mut(&token.uid)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
        let read_index_users = req
            .0
            .users
            .into_iter()
            .filter_map(|item| match user.read_index_user.get(&item.uid) {
                Some(prev_mid) if item.mid > *prev_mid => Some(ReadIndexUser {
                    uid: item.uid,
                    mid: item.mid,
                }),
                None => Some(ReadIndexUser {
                    uid: item.uid,
                    mid: item.mid,
                }),
                _ => None,
            })
            .collect_vec();
        let read_index_groups = req
            .0
            .groups
            .into_iter()
            .filter_map(|item| match user.read_index_group.get(&item.gid) {
                Some(prev_mid) if item.mid > *prev_mid => Some(ReadIndexGroup {
                    gid: item.gid,
                    mid: item.mid,
                }),
                None => Some(ReadIndexGroup {
                    gid: item.gid,
                    mid: item.mid,
                }),
                _ => None,
            })
            .collect_vec();

        if read_index_users.is_empty() && read_index_groups.is_empty() {
            return Ok(());
        }

        // update sqlite
        let mut tx = state.db_pool.begin().await.map_err(InternalServerError)?;

        for item in &read_index_users {
            let sql = r#"
                    insert into read_index (uid, target_uid, mid) values (?, ?, ?)
                        on conflict (uid, target_uid) do update set mid = excluded.mid
                    "#;
            sqlx::query(sql)
                .bind(token.uid)
                .bind(item.uid)
                .bind(item.mid)
                .execute(&mut tx)
                .await
                .map_err(InternalServerError)?;
        }

        for item in &read_index_groups {
            let sql = r#"
                    insert into read_index (uid, target_gid, mid) values (?, ?, ?)
                        on conflict (uid, target_gid) do update set mid = excluded.mid
                    "#;
            sqlx::query(sql)
                .bind(token.uid)
                .bind(item.gid)
                .bind(item.mid)
                .execute(&mut tx)
                .await
                .map_err(InternalServerError)?;
        }

        tx.commit().await.map_err(InternalServerError)?;

        // update cache
        for item in &read_index_users {
            user.read_index_user.insert(item.uid, item.mid);
        }
        for item in &read_index_groups {
            user.read_index_group.insert(item.gid, item.mid);
        }

        // broadcast event
        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::UserSettingsChanged {
                uid: token.0.uid,
                message: UserSettingsChangedMessage {
                    from_device: token.0.device,
                    read_index_users,
                    read_index_groups,
                    ..Default::default()
                },
            }));

        Ok(())
    }

    /// Delete current user
    #[oai(path = "/delete", method = "delete")]
    async fn delete_current_user(&self, state: Data<&State>, token: Token) -> Result<()> {
        state.delete_user(token.uid).await?;
        Ok(())
    }

    /// Register a new user with the magic token
    #[oai(path = "/update_fcm_token", method = "put")]
    async fn update_fcm_token(
        &self,
        state: Data<&State>,
        token: Token,
        device: Query<String>,
        fcm_token: PlainText<String>,
    ) -> Result<()> {
        let mut cache = state.cache.write().await;
        let uid = token.uid;
        let cached_user = match cache.users.get_mut(&uid) {
            Some(cached_user) => cached_user,
            None => return Err(Error::from_status(StatusCode::UNAUTHORIZED)),
        };

        // update device token
        sqlx::query(
            r#"
        insert into device (uid, device, device_token) values (?, ?, ?)
            on conflict (uid, device) do update set device_token = excluded.device_token
        "#,
        )
        .bind(uid)
        .bind(&device.0)
        .bind(&fcm_token.0)
        .execute(&state.db_pool)
        .await
        .map_err(InternalServerError)?;

        cached_user
            .devices
            .entry(device.to_string())
            .and_modify(|device| {
                device.device_token = Some(fcm_token.0.clone());
            })
            .or_insert_with(|| CacheDevice {
                device_token: Some(fcm_token.0),
                sender: None,
            });

        Ok(())
    }
}

const fn default_get_history_messages_limit() -> usize {
    300
}

async fn fetch_user_log(
    cache: &Cache,
    db_pool: &SqlitePool,
    users_version: Option<i64>,
) -> Result<Option<Message>> {
    match users_version {
        Some(users_version) => {
            let sql = "select id, uid, action, email, name, gender, language, is_admin, is_bot, avatar_updated_at from user_log where id > ?";
            let mut stream = sqlx::query_as::<
                _,
                (
                    i64,
                    i64,
                    UpdateAction,
                    Option<String>,
                    Option<String>,
                    Option<i32>,
                    Option<LangId>,
                    Option<bool>,
                    Option<bool>,
                    Option<DateTime>,
                ),
            >(sql)
            .bind(users_version)
            .fetch(db_pool);

            let mut logs = Vec::new();
            while let Some(res) = stream.next().await {
                let (
                    id,
                    uid,
                    action,
                    email,
                    name,
                    gender,
                    language,
                    is_admin,
                    is_bot,
                    avatar_updated_at,
                ) = res.map_err(InternalServerError)?;
                let log = UserUpdateLog {
                    log_id: id,
                    action,
                    uid,
                    email,
                    name,
                    gender,
                    language,
                    is_admin,
                    is_bot,
                    avatar_updated_at,
                };
                logs.push(log);
            }

            if !logs.is_empty() {
                Ok(Some(Message::UsersUpdateLog(UsersUpdateLogMessage {
                    logs,
                })))
            } else {
                Ok(None)
            }
        }
        None => {
            let version = sqlx::query_as::<_, (i64,)>("select max(id) from user_log")
                .fetch_optional(db_pool)
                .await
                .map_err(InternalServerError)?
                .map(|(version,)| version);
            let users = cache
                .users
                .iter()
                .filter(|user| !user.1.is_guest)
                .map(|(uid, user)| user.api_user_info(*uid))
                .collect_vec();
            if !users.is_empty() {
                Ok(Some(Message::UsersSnapshot(UsersSnapshotMessage {
                    users,
                    version: version.expect("user log version"),
                })))
            } else {
                Ok(None)
            }
        }
    }
}

fn get_users_state(cache: &Cache, current_uid: i64) -> UsersStateMessage {
    UsersStateMessage {
        users: cache
            .users
            .iter()
            .filter_map(|(uid, user)| {
                if *uid != current_uid && !user.is_guest {
                    Some(UserState {
                        uid: *uid,
                        online: user.is_online(),
                    })
                } else {
                    None
                }
            })
            .collect(),
    }
}

fn get_user_settings_msg(user: &CacheUser) -> UserSettingsMessage {
    let now = DateTime::now();

    UserSettingsMessage {
        mute_users: user
            .mute_user
            .iter()
            .filter_map(|(uid, expired_in)| {
                if matches!(expired_in, Some(expired_in) if now.0 > expired_in.0) {
                    return None;
                }
                Some(MuteUser {
                    uid: *uid,
                    expired_at: *expired_in,
                })
            })
            .collect(),
        mute_groups: user
            .mute_group
            .iter()
            .filter_map(|(gid, expired_in)| {
                if matches!(expired_in, Some(expired_in) if now.0 > expired_in.0) {
                    return None;
                }
                Some(MuteGroup {
                    gid: *gid,
                    expired_at: *expired_in,
                })
            })
            .collect(),
        read_index_users: user
            .read_index_user
            .iter()
            .map(|(uid, mid)| ReadIndexUser {
                uid: *uid,
                mid: *mid,
            })
            .collect(),
        read_index_groups: user
            .read_index_group
            .iter()
            .map(|(gid, mid)| ReadIndexGroup {
                gid: *gid,
                mid: *mid,
            })
            .collect(),
        burn_after_reading_users: user
            .burn_after_reading_user
            .iter()
            .map(|(uid, expires_in)| BurnAfterReadingUser {
                uid: *uid,
                expires_in: *expires_in,
            })
            .collect(),
        burn_after_reading_groups: user
            .burn_after_reading_group
            .iter()
            .map(|(gid, expires_in)| BurnAfterReadingGroup {
                gid: *gid,
                expires_in: *expires_in,
            })
            .collect(),
    }
}

fn create_user_event_receiver(
    state: &State,
    current_user: &CurrentUser,
    user: &mut CacheUser,
) -> Result<UnboundedReceiver<UserEvent>> {
    let is_online = user.is_online();

    if let Some(device) = user.devices.get_mut(&current_user.device) {
        if let Some(sender) = device.sender.take() {
            let _ = sender.send(UserEvent::Kick {
                reason: KickReason::LoginFromOtherDevice,
            });
        }

        let (tx_user_event, rx_user_event) = mpsc::unbounded_channel();
        device.sender = Some(tx_user_event);

        if !is_online && user.is_online() && !user.is_guest {
            let _ = state
                .event_sender
                .send(Arc::new(BroadcastEvent::UserStateChanged(
                    UserStateChangedMessage {
                        uid: current_user.uid,
                        online: Some(true),
                    },
                )));
        }

        Ok(rx_user_event)
    } else {
        Err(Error::from_status(StatusCode::FORBIDDEN))
    }
}

fn fetch_newest_messages(
    cache: &Cache,
    msg_db: &MsgDb,
    uid: i64,
    after_mid: Option<i64>,
) -> Result<Vec<ChatMessage>> {
    Ok(msg_db
        .messages()
        .fetch_user_messages_after(uid, after_mid, MAX_NEWEST_MESSAGES)
        .map_err(InternalServerError)?
        .into_iter()
        .filter_map(|(id, data)| {
            Some(id).zip(serde_json::from_slice::<ChatMessagePayload>(&data).ok())
        })
        .map(|(id, payload)| ChatMessage { mid: id, payload })
        .filter(|msg| match &msg.payload.target {
            MessageTarget::User(MessageTargetUser { .. }) => true,
            MessageTarget::Group(MessageTargetGroup { gid }) => cache.groups.contains_key(gid),
        })
        .collect::<Vec<_>>())
}

#[allow(clippy::too_many_arguments)]
async fn events_loop(
    state: State,
    mut rx_user_event: UnboundedReceiver<UserEvent>,
    mut receiver: Receiver<Arc<BroadcastEvent>>,
    mut push_start_id: Option<i64>,
    current_uid: i64,
    current_device: String,
    tx_msg: UnboundedSender<Message>,
) {
    let mut heartbeat = tokio::time::interval_at(
        Instant::now() + Duration::from_secs(15),
        Duration::from_secs(15),
    );

    loop {
        tokio::select! {
            res = receiver.recv() => {
                match res {
                    Ok(event) => {
                        match &*event {
                            BroadcastEvent::Chat { targets, message } => {
                                if !targets.contains(&current_uid) {
                                    continue;
                                }

                                if let Some(id) = push_start_id {
                                    if message.mid <= id {
                                        continue;
                                    }
                                    push_start_id = None;
                                }

                                if tx_msg.send(Message::Chat(message.clone())).is_err() {
                                    break;
                                }
                            }
                            BroadcastEvent::UserLog(update_log) => {
                                if tx_msg.send(Message::UsersUpdateLog(UsersUpdateLogMessage {
                                    logs: vec![update_log.clone()],
                                })).is_err() {
                                    break;
                                }
                            }
                            BroadcastEvent::UserJoinedGroup { targets, gid, uid } => {
                                if !targets.contains(&current_uid) {
                                    continue;
                                }
                                if tx_msg.send(Message::UserJoinedGroup(UserJoinedGroupMessage { gid: *gid, uid: uid.clone() })).is_err() {
                                    break;
                                }
                            }
                            BroadcastEvent::UserLeavedGroup { targets, gid, uid } => {
                                if !targets.contains(&current_uid) {
                                    continue;
                                }
                                if tx_msg.send(Message::UserLeavedGroup(UserLeavedGroupMessage { gid: *gid, uid: uid.clone() })).is_err() {
                                    break;
                                }
                            }
                            BroadcastEvent::JoinedGroup { targets, group } => {
                                if !targets.contains(&current_uid) {
                                    continue;
                                }
                                if tx_msg.send(Message::JoinedGroup(JoinedGroupMessage { group: group.clone() })).is_err() {
                                    break;
                                }
                            }
                            BroadcastEvent::KickFromGroup { targets, gid, reason } => {
                                if !targets.contains(&current_uid) {
                                    continue;
                                }
                                if tx_msg.send(Message::KickFromGroup(KickFromGroupMessage { gid: *gid, reason: *reason })).is_err() {
                                    break;
                                }
                            }
                            BroadcastEvent::UserStateChanged(msg) => {
                                if current_uid == msg.uid {
                                    continue;
                                }
                                if tx_msg.send(Message::UserStateChanged(msg.clone())).is_err() {
                                    break;
                                }
                            }
                            BroadcastEvent::UserSettingsChanged { uid, message } => {
                                if current_uid != *uid {
                                    continue;
                                }
                                if message.from_device == current_device {
                                    continue;
                                }
                                if tx_msg.send(Message::UserSettingsChanged(message.clone())).is_err() {
                                    break;
                                }
                            }
                            BroadcastEvent::GroupChanged { targets, msg } => {
                                if targets.contains(&current_uid) && tx_msg.send(Message::GroupChanged(msg.clone())).is_err() {
                                    break;
                                }
                            }
                            BroadcastEvent::PinnedMessageUpdated { targets, gid, mid, msg } => {
                                if targets.contains(&current_uid) {
                                    let msg = Message::PinnedMessageUpdated(PinnedMessageUpdated {
                                        gid: *gid,
                                        mid: *mid,
                                        msg: msg.clone(),
                                    });
                                    if tx_msg.send(msg).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            res = rx_user_event.recv() => {
                match res {
                    Some(UserEvent::Kick { reason }) => {
                        if tx_msg.send(Message::Kick(KickMessage { reason })).is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            _ = heartbeat.tick() => {
                if tx_msg.send(Message::Heartbeat(HeartbeatMessage {
                    time: DateTime::now(),
                })).is_err() {
                    break;
                }
            }
        }
    }

    let mut cache = state.cache.write().await;
    if let Some(user) = cache.users.get_mut(&current_uid) {
        if let Some(device) = user.devices.get_mut(&current_device) {
            device.sender = None;
        }
        if !user.is_online() && !user.is_guest {
            let _ = state
                .event_sender
                .send(Arc::new(BroadcastEvent::UserStateChanged(
                    UserStateChangedMessage {
                        uid: current_uid,
                        online: Some(false),
                    },
                )));
        }
    }

    tracing::info!(
        uid = current_uid,
        device = current_device.as_str(),
        "unsubscribe events"
    );
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use futures_util::StreamExt;
    use itertools::Itertools;
    use poem::http::Uri;
    use serde::Deserialize;
    use serde_json::json;

    use crate::{
        api::{LoginConfig, SmtpConfig},
        config::TemplateConfig,
        state::DynamicConfigEntry,
        test_harness::TestServer,
    };

    #[tokio::test]
    async fn test_events_after_mid() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;
        let mut seq = None;

        for i in 0..10 {
            server
                .send_text_to_user(&token1, uid2, format!("hello, {}", i))
                .await;
        }

        let mut msg_stream = server
            .subscribe_events_after_mid(&token2, Some(&["chat"]), seq)
            .await;
        for i in 0..10 {
            let msg = msg_stream.next().await.unwrap();
            let msg = msg.value().object();
            assert_eq!(msg.get("from_uid").i64(), uid1);
            let detail = msg.get("detail").object();
            detail
                .get("content")
                .assert_string(&format!("hello, {}", i));
            seq = Some(msg.get("mid").i64());
        }

        server
            .send_text_to_user(&token1, uid2, format!("hello, {}", 11))
            .await;

        let mut msg_stream = server
            .subscribe_events_after_mid(&token2, Some(&["chat"]), seq)
            .await;
        let msg = msg_stream.next().await.unwrap();
        let msg = msg.value().object();
        assert_eq!(msg.get("from_uid").i64(), uid1);
        let detail = msg.get("detail").object();
        detail
            .get("content")
            .assert_string(&format!("hello, {}", 11));
    }

    #[tokio::test]
    async fn test_send() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;

        for i in 0..10 {
            server
                .send_text_to_user(&token1, uid2, format!("hello, {}", i))
                .await;
        }

        let mut events1 = server.subscribe_events(&token1, Some(&["chat"])).await;
        let mut events2 = server.subscribe_events(&token2, Some(&["chat"])).await;

        for events in [&mut events1, &mut events2] {
            for i in 0..10 {
                let msg = events.next().await.unwrap();
                let msg = msg.value().object();
                msg.get("from_uid").assert_i64(uid1);
                msg.get("target").object().get("uid").assert_i64(uid2);
                let detail = msg.get("detail").object();
                detail.get("type").assert_string("normal");
                detail
                    .get("content")
                    .assert_string(&format!("hello, {}", i));
            }
        }

        for i in 10..20 {
            server
                .send_text_to_user(&token1, uid2, format!("hello, {}", i))
                .await;
        }

        for events in [&mut events1, &mut events2] {
            for i in 10..20 {
                let msg = events.next().await.unwrap();
                let msg = msg.value().object();
                msg.get("from_uid").assert_i64(uid1);
                msg.get("target").object().get("uid").assert_i64(uid2);
                let detail = msg.get("detail").object();
                detail.get("type").assert_string("normal");
                detail
                    .get("content")
                    .assert_string(&format!("hello, {}", i));
            }
        }
    }

    #[tokio::test]
    async fn test_send_with_properties() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let mut events1 = server.subscribe_events(&token1, Some(&["chat"])).await;

        let resp = server
            .post(format!("/api/user/{}/send", uid1))
            .header("X-API-Key", &admin_token)
            .header(
                "X-Properties",
                base64::encode(
                    serde_json::to_string(&json!({
                        "a": 10,
                        "b": "abc",
                    }))
                    .unwrap(),
                ),
            )
            .content_type("text/plain")
            .body("hello")
            .send()
            .await;
        resp.assert_status_is_ok();
        let mid = resp.json().await.value().i64();

        let msg = events1.next().await.unwrap();
        let msg = msg.value().object();
        msg.get("mid").assert_i64(mid);
        msg.get("from_uid").assert_i64(1);
        msg.get("target").object().get("uid").assert_i64(uid1);
        let detail = msg.get("detail").object();
        detail.get("type").assert_string("normal");
        let content = detail.get("content");
        content.assert_string("hello");
        let properties = detail.get("properties").object();
        properties.get("a").assert_i64(10);
        properties.get("b").assert_string("abc");
    }

    #[tokio::test]
    async fn kick_by_login_from_other_device() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        let mut msg_stream1 = server.subscribe_events(&admin_token, Some(&["kick"])).await;
        let mut _msg_stream2 = server.subscribe_events(&admin_token, None).await;

        let msg = msg_stream1.next().await.unwrap();
        assert_eq!(
            msg.value().object().get("reason").string(),
            "login_from_other_device"
        );
    }

    #[tokio::test]
    async fn kick_by_delete_user() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;

        let mut events1 = server.subscribe_events(&token1, Some(&["kick"])).await;

        let resp = server
            .delete(format!("/api/admin/user/{}", uid1))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();

        let msg = events1.next().await.unwrap();
        assert_eq!(msg.value().object().get("reason").string(), "delete_user");
    }

    #[tokio::test]
    async fn test_get_devices() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        let resp = server
            .get("/api/user/devices")
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        json.value().assert_string_array(&["iphone"]);
    }

    #[tokio::test]
    async fn kick_by_delete_device() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        let mut resp_events = server.subscribe_events(&admin_token, Some(&["kick"])).await;

        let resp = server
            .delete("/api/user/devices/iphone")
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();

        let msg = resp_events.next().await.unwrap();
        let obj = msg.value().object();
        assert_eq!(obj.get("reason").string(), "delete_device");

        let resp = server
            .get("/api/user/devices")
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        json.value().assert_string_array(&[]);
    }

    #[tokio::test]
    async fn kick_by_logout() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        let mut resp_events = server.subscribe_events(&admin_token, Some(&["kick"])).await;

        let resp = server
            .get("/api/token/logout")
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();

        let msg = resp_events.next().await.unwrap();
        let obj = msg.value().object();
        assert_eq!(obj.get("reason").string(), "logout");
    }

    #[tokio::test]
    async fn test_user_log() {
        let filters = &["users_snapshot", "users_log"];
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        // create user1
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let mut events1 = server.subscribe_events(&token1, Some(filters)).await;

        let json = events1.next().await.unwrap();
        json.value()
            .object()
            .get("type")
            .assert_string("users_snapshot");
        json.value().object().get("version").assert_i64(2);
        assert_eq!(
            json.value().object().get("users").array(),
            vec![
                json!({
                    "uid": 1,
                    "email": "admin@voce.chat",
                    "name": "admin",
                    "gender": 1,
                    "language": "en-US",
                    "is_admin": true,
                    "is_bot": false,
                    "avatar_updated_at": 0,
                    "create_by": "password",
                }),
                json!({
                    "uid": uid1,
                    "email": "user1@voce.chat",
                    "name": "user1@voce.chat",
                    "gender": 1,
                    "language": "en-US",
                    "is_admin": false,
                    "is_bot": false,
                    "create_by": "password",
                    "avatar_updated_at": 0,
                }),
            ]
        );

        // create user2
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;
        let mut events2 = server.subscribe_events(&token2, Some(filters)).await;

        let json = events2.next().await.unwrap();
        json.value()
            .object()
            .get("type")
            .assert_string("users_snapshot");
        json.value().object().get("version").assert_i64(3);
        assert_eq!(
            json.value().object().get("users").array(),
            vec![
                json!({
                    "uid": 1,
                    "email": "admin@voce.chat",
                    "name": "admin",
                    "gender": 1,
                    "language": "en-US",
                    "is_admin": true,
                    "is_bot": false,
                    "avatar_updated_at": 0,
                    "create_by": "password",
                }),
                json!({
                    "uid": uid1,
                    "email": "user1@voce.chat",
                    "name": "user1@voce.chat",
                    "gender": 1,
                    "language": "en-US",
                    "is_admin": false,
                    "is_bot": false,
                    "avatar_updated_at": 0,
                    "create_by": "password",
                }),
                json!({
                    "uid": uid2,
                    "email": "user2@voce.chat",
                    "name": "user2@voce.chat",
                    "gender": 1,
                    "language": "en-US",
                    "is_admin": false,
                    "is_bot": false,
                    "avatar_updated_at": 0,
                    "create_by": "password",
                }),
            ]
        );

        // create user2 event
        let json = events1.next().await.unwrap();
        json.value().object().get("type").assert_string("users_log");
        assert_eq!(
            json.value().object().get("logs").array(),
            vec![json!({
                "log_id": 3,
                "action": "create",
                "uid": uid2,
                "email": "user2@voce.chat",
                "name": "user2@voce.chat",
                "gender": 1,
                "language": "en-US",
                "is_admin": false,
                "is_bot": false,
                "avatar_updated_at": 0,
            })]
        );

        // update user2 name
        let resp = server
            .put("/api/user")
            .header("X-API-Key", &token2)
            .body_json(&json!({
                "name": "test22"
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut events1, &mut events2] {
            let json = events.next().await.unwrap();
            json.value().object().get("type").assert_string("users_log");
            assert_eq!(
                json.value().object().get("logs").array(),
                vec![json!({
                    "log_id": 4,
                    "action": "update",
                    "uid": uid2,
                    "email": null,
                    "name": "test22",
                    "gender": null,
                    "language": null,
                    "is_admin": null,
                    "is_bot": null,
                    "avatar_updated_at": null,
                })]
            );
        }

        // delete user2
        let resp = server
            .delete(format!("/api/admin/user/{}", uid2))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();

        let json = events1.next().await.unwrap();
        json.value().object().get("type").assert_string("users_log");
        assert_eq!(
            json.value().object().get("logs").array(),
            vec![json!({
                "log_id": 5,
                "action": "delete",
                "uid": uid2,
                "email": null,
                "name": null,
                "gender": null,
                "language": null,
                "is_admin": null,
                "is_bot": null,
                "avatar_updated_at": null,
            })]
        );

        // create user3
        let uid3 = server.create_user(&admin_token, "user3@voce.chat").await;
        let token3 = server.login("user3@voce.chat").await;
        let mut events3 = server.subscribe_events(&token3, Some(filters)).await;

        let json = events3.next().await.unwrap();
        json.value()
            .object()
            .get("type")
            .assert_string("users_snapshot");
        json.value().object().get("version").assert_i64(6);
        assert_eq!(
            json.value().object().get("users").array(),
            vec![
                json!({
                    "uid": 1,
                    "email": "admin@voce.chat",
                    "name": "admin",
                    "gender": 1,
                    "language": "en-US",
                    "is_admin": true,
                    "is_bot": false,
                    "avatar_updated_at": 0,
                    "create_by": "password",
                }),
                json!({
                    "uid": uid1,
                    "email": "user1@voce.chat",
                    "name": "user1@voce.chat",
                    "gender": 1,
                    "language": "en-US",
                    "is_admin": false,
                    "is_bot": false,
                    "avatar_updated_at": 0,
                    "create_by": "password",
                }),
                json!({
                    "uid": uid3,
                    "email": "user3@voce.chat",
                    "name": "user3@voce.chat",
                    "gender": 1,
                    "language": "en-US",
                    "is_admin": false,
                    "is_bot": false,
                    "avatar_updated_at": 0,
                    "create_by": "password",
                }),
            ]
        );

        let json = events1.next().await.unwrap();
        json.value().object().get("type").assert_string("users_log");
        assert_eq!(
            json.value().object().get("logs").array(),
            vec![json!({
                "log_id": 6,
                "action": "create",
                "uid": uid3,
                "email": "user3@voce.chat",
                "name": "user3@voce.chat",
                "gender": 1,
                "language": "en-US",
                "is_admin": false,
                "is_bot": false,
                "avatar_updated_at": 0,
            })]
        );

        // update user3 avatar
        let resp = server
            .post("/api/user/avatar")
            .header("X-API-Key", &token3)
            .content_type("image/png")
            .body(include_bytes!("assets/poem.png").to_vec())
            .send()
            .await;
        resp.assert_status_is_ok();

        let json = events1.next().await.unwrap();
        json.value().object().get("type").assert_string("users_log");
        let obj = json.value().object().get("logs").array().get(0).object();
        let avatar_updated_at = obj.get("avatar_updated_at").i64();

        // skip snapshot
        let mut events3 = server
            .subscribe_events_with_users_version(&token3, Some(filters), 3)
            .await;
        let json = events3.next().await.unwrap();
        json.value().object().get("type").assert_string("users_log");
        assert_eq!(
            json.value().object().get("logs").array(),
            vec![
                json!({
                    "log_id": 4,
                    "action": "update",
                    "uid": uid2,
                    "email": null,
                    "name": "test22",
                    "gender": null,
                    "language": null,
                    "is_admin": null,
                    "is_bot": null,
                    "avatar_updated_at": null,
                }),
                json!({
                    "log_id": 5,
                    "action": "delete",
                    "uid": uid2,
                    "email": null,
                    "name": null,
                    "gender": null,
                    "language": null,
                    "is_admin": null,
                    "is_bot": null,
                    "avatar_updated_at": null,
                }),
                json!({
                    "log_id": 6,
                    "action": "create",
                    "uid": uid3,
                    "email": "user3@voce.chat",
                    "name": "user3@voce.chat",
                    "gender": 1,
                    "language": "en-US",
                    "is_admin": false,
                    "is_bot": false,
                    "avatar_updated_at": 0,
                }),
                json!({
                    "log_id": 7,
                    "action": "update",
                    "uid": uid3,
                    "email": null,
                    "name": null,
                    "gender": null,
                    "language": null,
                    "is_admin": null,
                    "is_bot": null,
                    "avatar_updated_at": avatar_updated_at,
                }),
            ]
        );
    }

    #[tokio::test]
    async fn test_subscribe_with_different_devices_1() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let token1 = server.login_with_device("user1@voce.chat", "a1").await;
        let token2 = server.login_with_device("user1@voce.chat", "a2").await;

        let mut events1 = server.subscribe_events(&token1, Some(&["chat"])).await;
        let mut events2 = server.subscribe_events(&token2, Some(&["chat"])).await;

        for i in 0..10 {
            server
                .send_text_to_user(&admin_token, uid1, format!("hello {}", i))
                .await;
        }

        for events in [&mut events1, &mut events2] {
            for i in 0..10 {
                let msg = events.next().await.unwrap();
                let msg = msg.value().object();
                assert_eq!(msg.get("from_uid").i64(), 1);
                let detail = msg.get("detail").object();
                detail.get("content").assert_string(&format!("hello {}", i));
            }
        }
    }

    #[tokio::test]
    async fn received_chat_messages_from_myself() {
        let server = TestServer::new().await;
        let admin_token_ios = server.login_admin_with_device("ios").await;
        let admin_token_android = server.login_admin_with_device("android").await;
        let uid1 = server
            .create_user(&admin_token_ios, "user1@voce.chat")
            .await;
        let uid1_token = server.login("user1@voce.chat").await;

        let mut admin_events_ios = server
            .subscribe_events(&admin_token_ios, Some(&["chat"]))
            .await;
        let mut admin_events_android = server
            .subscribe_events(&admin_token_android, Some(&["chat"]))
            .await;
        let mut uid1_events = server.subscribe_events(&uid1_token, Some(&["chat"])).await;

        let mid = server
            .send_text_to_user(&admin_token_ios, uid1, "hello")
            .await;

        for events in [
            &mut admin_events_ios,
            &mut admin_events_android,
            &mut uid1_events,
        ] {
            let msg = events.next().await.unwrap();
            let msg = msg.value().object();
            msg.get("mid").assert_i64(mid);
            msg.get("from_uid").assert_i64(1);
            let detail = msg.get("detail").object();
            detail.get("type").assert_string("normal");
            detail.get("content").assert_string("hello");
        }
    }

    #[tokio::test]
    async fn received_joined_group_when_create_private_group() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;

        let mut events_admin = server
            .subscribe_events(&admin_token, Some(&["joined_group"]))
            .await;
        let mut events1 = server
            .subscribe_events(&token1, Some(&["joined_group"]))
            .await;
        let mut events2 = server
            .subscribe_events(&token2, Some(&["joined_group"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "members": [uid1, uid2]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        for events in [&mut events_admin, &mut events1, &mut events2] {
            let msg = events.next().await.unwrap();
            let group = msg.value().object().get("group").object();
            group.get("gid").assert_i64(gid);
            group.get("is_public").assert_bool(false);
        }
    }

    #[tokio::test]
    async fn received_joined_group_when_create_public_group() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let _uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let _uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;

        let mut events_admin = server
            .subscribe_events(&admin_token, Some(&["joined_group"]))
            .await;
        let mut events1 = server
            .subscribe_events(&token1, Some(&["joined_group"]))
            .await;
        let mut events2 = server
            .subscribe_events(&token2, Some(&["joined_group"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "is_public": true,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        for events in [&mut events_admin, &mut events1, &mut events2] {
            let msg = events.next().await.unwrap();
            let group = msg.value().object().get("group").object();
            group.get("gid").assert_i64(gid);
            group.get("is_public").assert_bool(true);
        }
    }

    #[tokio::test]
    async fn received_kick_from_group_when_delete_private_group_by_owner() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let _uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;

        let mut events1 = server
            .subscribe_events(&token1, Some(&["kick_from_group"]))
            .await;
        let mut events2 = server
            .subscribe_events(&token2, Some(&["kick_from_group"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &token1)
            .body_json(&json!({
                "name": "test",
                "members": [uid2]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        // delete group by owner
        let resp = server
            .delete(format!("/api/group/{}", gid))
            .header("X-API-Key", &token1)
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut events1, &mut events2] {
            let msg = events.next().await.unwrap();
            msg.value().object().get("gid").assert_i64(gid);
            msg.value()
                .object()
                .get("reason")
                .assert_string("group_deleted");
        }
    }

    #[tokio::test]
    async fn received_kick_from_group_when_delete_public_group_by_admin() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let _uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let _uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;

        let mut admin_events = server
            .subscribe_events(&admin_token, Some(&["kick_from_group"]))
            .await;
        let mut events1 = server
            .subscribe_events(&token1, Some(&["kick_from_group"]))
            .await;
        let mut events2 = server
            .subscribe_events(&token2, Some(&["kick_from_group"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "is_public": true,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        // delete group by admin
        let resp = server
            .delete(format!("/api/group/{}", gid))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut admin_events, &mut events1, &mut events2] {
            let msg = events.next().await.unwrap();
            msg.value().object().get("gid").assert_i64(gid);
            msg.value()
                .object()
                .get("reason")
                .assert_string("group_deleted");
        }
    }

    #[tokio::test]
    async fn received_joined_group_when_add_member() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;

        let mut events1 = server
            .subscribe_events(&token1, Some(&["joined_group"]))
            .await;
        let mut events2 = server
            .subscribe_events(&token2, Some(&["joined_group"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        // add uid1, uid2
        let resp = server
            .post(format!("/api/group/{}/members/add", gid))
            .header("X-API-Key", &admin_token)
            .body_json(&json!([uid1, uid2]))
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut events1, &mut events2] {
            let msg = events.next().await.unwrap();
            let group = msg.value().object().get("group").object();
            group.get("gid").assert_i64(gid);
        }
    }

    #[tokio::test]
    async fn received_kick_from_group_when_remove_members() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;

        let mut events2 = server
            .subscribe_events(&token2, Some(&["kick_from_group"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &token1)
            .body_json(&json!({
                "name": "test",
                "members": [uid1, uid2]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        // remove uid2 from group
        let resp = server
            .post(format!("/api/group/{}/members/remove", gid))
            .header("X-API-Key", &token1)
            .body_json(&json!([uid2]))
            .send()
            .await;
        resp.assert_status_is_ok();

        let msg = events2.next().await.unwrap();
        msg.value().object().get("gid").assert_i64(gid);
        msg.value().object().get("reason").assert_string("kick");
    }

    #[tokio::test]
    async fn received_kick_from_group_when_delete_owner_user() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;

        let mut events2 = server
            .subscribe_events(&token2, Some(&["kick_from_group"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &token1)
            .body_json(&json!({
                "name": "test",
                "members": [uid2]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        // delete user1
        let resp = server
            .delete(format!("/api/admin/user/{}", uid1))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();

        let msg = events2.next().await.unwrap();
        msg.value().object().get("gid").assert_i64(gid);
        msg.value()
            .object()
            .get("reason")
            .assert_string("group_deleted");
    }

    #[tokio::test]
    async fn received_user_joined_private_group_when_add_member() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;

        let mut events_admin = server
            .subscribe_events(&admin_token, Some(&["user_joined_group"]))
            .await;
        let mut events1 = server
            .subscribe_events(&token1, Some(&["user_joined_group"]))
            .await;
        let mut events2 = server
            .subscribe_events(&token2, Some(&["joined_group"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "members": [uid1]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        // add uid2
        let resp = server
            .post(format!("/api/group/{}/members/add", gid))
            .header("X-API-Key", &admin_token)
            .body_json(&json!([uid2]))
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut events_admin, &mut events1] {
            let msg = events.next().await.unwrap();
            msg.value().object().get("gid").assert_i64(gid);
            msg.value().object().get("uid").assert_i64_array(&[uid2]);
        }

        let msg = events2.next().await.unwrap();
        msg.value()
            .object()
            .get("group")
            .object()
            .get("gid")
            .assert_i64(gid);
    }

    #[tokio::test]
    async fn received_user_joined_public_group_when_create_user() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let _uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;

        let mut events_admin = server
            .subscribe_events(&admin_token, Some(&["user_joined_group"]))
            .await;
        let mut events1 = server
            .subscribe_events(&token1, Some(&["user_joined_group"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "is_public": true,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        // create user2
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;

        for events in [&mut events_admin, &mut events1] {
            let msg = events.next().await.unwrap();
            msg.value().object().get("gid").assert_i64(gid);
            msg.value().object().get("uid").assert_i64_array(&[uid2]);
        }
    }

    #[tokio::test]
    async fn received_user_leaved_private_group_when_remove_member() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;

        let mut events_admin = server
            .subscribe_events(&admin_token, Some(&["user_leaved_group"]))
            .await;
        let mut events1 = server
            .subscribe_events(&token1, Some(&["user_leaved_group"]))
            .await;
        let mut events2 = server
            .subscribe_events(&token2, Some(&["kick_from_group"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "members": [uid1, uid2]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        // remove uid2
        let resp = server
            .post(format!("/api/group/{}/members/remove", gid))
            .header("X-API-Key", &admin_token)
            .body_json(&json!([uid2]))
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut events_admin, &mut events1] {
            let msg = events.next().await.unwrap();
            msg.value().object().get("gid").assert_i64(gid);
            msg.value().object().get("uid").assert_i64_array(&[uid2]);
        }

        let msg = events2.next().await.unwrap();
        msg.value().object().get("gid").assert_i64(gid);
    }

    #[tokio::test]
    async fn received_user_leaved_public_group_when_delete_user() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let _uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let _token2 = server.login("user2@voce.chat").await;

        let mut events_admin = server
            .subscribe_events(&admin_token, Some(&["user_leaved_group"]))
            .await;
        let mut events1 = server
            .subscribe_events(&token1, Some(&["user_leaved_group"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "is_public": true,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        // delete user2
        let resp = server
            .delete(format!("/api/admin/user/{}", uid2))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut events_admin, &mut events1] {
            let msg = events.next().await.unwrap();
            msg.value().object().get("gid").assert_i64(gid);
            msg.value().object().get("uid").assert_i64_array(&[uid2]);
        }
    }

    #[tokio::test]
    async fn received_related_groups_on_subscribe() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;

        // create public group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "a",
                "is_public": true,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid1 = json.value().object().get("gid").i64();

        // create private group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "a",
                "members": [uid1],
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid2 = json.value().object().get("gid").i64();

        let mut events1 = server
            .subscribe_events(&token1, Some(&["related_groups"]))
            .await;

        let resp = events1.next().await.unwrap();
        let array = resp.value().object().get("groups").object_array();
        array[0].get("gid").assert_i64(gid1);
        array[1].get("gid").assert_i64(gid2);
    }

    #[tokio::test]
    async fn received_user_leaved_private_group_when_leave() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;

        let mut events_admin = server
            .subscribe_events(&admin_token, Some(&["user_leaved_group"]))
            .await;
        let mut events1 = server
            .subscribe_events(&token1, Some(&["user_leaved_group"]))
            .await;
        let mut events2 = server
            .subscribe_events(&token2, Some(&["user_leaved_group"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "members": [uid1, uid2]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        // user2 leave the group
        let resp = server
            .get(format!("/api/group/{}/leave", gid))
            .header("X-API-Key", &token2)
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut events_admin, &mut events1, &mut events2] {
            let msg = events.next().await.unwrap();
            msg.value().object().get("gid").assert_i64(gid);
            msg.value().object().get("uid").assert_i64_array(&[uid2]);
        }
    }

    #[tokio::test]
    async fn received_mute_list() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;

        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "members": [uid1]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        // mute uid1 and gid
        let resp = server
            .post("/api/user/mute")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "add_users": [{
                    "uid": uid1,
                    "expired_in": 6,
                }],
                "add_groups": [{
                    "gid": gid,
                    "expired_in": 3,
                }]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        let mut events = server
            .subscribe_events(&admin_token, Some(&["user_settings"]))
            .await;
        let msg = events.next().await.unwrap();

        let mute_users = msg.value().object().get("mute_users").array();
        mute_users.assert_len(1);
        mute_users.get(0).object().get("uid").assert_i64(uid1);

        let mute_groups = msg.value().object().get("mute_groups").array();
        mute_groups.assert_len(1);
        mute_groups.get(0).object().get("gid").assert_i64(gid);
    }

    #[tokio::test]
    async fn received_mute_changed() {
        let server = TestServer::new().await;
        let admin_token_ios = server.login_with_device("admin@voce.chat", "ios").await;
        let admin_token_android = server.login_with_device("admin@voce.chat", "android").await;
        let mut events_admin_ios = server
            .subscribe_events(&admin_token_ios, Some(&["user_settings_changed"]))
            .await;
        let mut events_admin_android = server
            .subscribe_events(&admin_token_android, Some(&["user_settings_changed"]))
            .await;
        let uid1 = server
            .create_user(&admin_token_ios, "user1@voce.chat")
            .await;

        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token_ios)
            .body_json(&json!({
                "name": "test",
                "members": [uid1]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        // mute uid1
        let resp = server
            .post("/api/user/mute")
            .header("X-API-Key", &admin_token_ios)
            .body_json(&json!({
                "add_users": [{
                    "uid": uid1,
                    "expired_in": 6,
                }]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        // mute gid
        let resp = server
            .post("/api/user/mute")
            .header("X-API-Key", &admin_token_ios)
            .body_json(&json!({
                "add_groups": [{
                    "gid": gid,
                    "expired_in": 3,
                }]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        let msg = events_admin_android.next().await.unwrap();
        msg.value().object().get("from_device").assert_string("ios");
        msg.value()
            .object()
            .get("add_mute_users")
            .array()
            .get(0)
            .object()
            .get("uid")
            .assert_i64(uid1);
        let msg = events_admin_android.next().await.unwrap();
        msg.value().object().get("from_device").assert_string("ios");
        msg.value()
            .object()
            .get("add_mute_groups")
            .array()
            .get(0)
            .object()
            .get("gid")
            .assert_i64(gid);

        assert!(
            tokio::time::timeout(Duration::from_secs(1), events_admin_ios.next())
                .await
                .is_err(),
        );

        // unmute uid1
        let resp = server
            .post("/api/user/mute")
            .header("X-API-Key", &admin_token_ios)
            .body_json(&json!({ "remove_users": [uid1] }))
            .send()
            .await;
        resp.assert_status_is_ok();

        let msg = events_admin_android.next().await.unwrap();
        msg.value().object().get("from_device").assert_string("ios");
        msg.value()
            .object()
            .get("remove_mute_users")
            .array()
            .get(0)
            .assert_i64(uid1);
    }

    #[tokio::test]
    async fn received_mute_list_exclude_expired_items() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;

        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "members": [uid1]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        // mute uid1 and gid
        let resp = server
            .post("/api/user/mute")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "add_users": [{
                    "uid": uid1,
                    "expired_in": 6,
                }],
                "add_groups": [{
                    "gid": gid,
                    "expired_in": 3,
                }]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        async fn check_items(
            server: &TestServer,
            token: &str,
            mut expect_uids: Vec<i64>,
            mut expect_gids: Vec<i64>,
        ) {
            let mut events = server
                .subscribe_events(&token, Some(&["user_settings"]))
                .await;
            let msg = events.next().await.unwrap();
            let mute_users = msg.value().object().get("mute_users").array();
            let mut mute_users = mute_users
                .iter()
                .map(|item| item.object().get("uid").i64())
                .collect_vec();
            let mute_groups = msg.value().object().get("mute_groups").array();
            let mut mute_groups = mute_groups
                .iter()
                .map(|item| item.object().get("gid").i64())
                .collect_vec();

            expect_uids.sort_unstable();
            expect_gids.sort_unstable();
            mute_users.sort_unstable();
            mute_groups.sort_unstable();

            assert_eq!(expect_uids, mute_users);
            assert_eq!(expect_gids, mute_groups);
        }

        check_items(&server, &admin_token, vec![uid1], vec![gid]).await;

        tokio::time::sleep(Duration::from_secs(4)).await;
        check_items(&server, &admin_token, vec![uid1], vec![]).await;

        tokio::time::sleep(Duration::from_secs(3)).await;
        check_items(&server, &admin_token, vec![], vec![]).await;
    }

    #[tokio::test]
    async fn received_users_state() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2_ios = server.login_with_device("user2@voce.chat", "ios").await;
        let token2_android = server.login_with_device("user2@voce.chat", "android").await;

        let mut events1 = server
            .subscribe_events(&token1, Some(&["users_state", "users_state_changed"]))
            .await;
        let mut events_admin = server
            .subscribe_events(&admin_token, Some(&["users_state", "users_state_changed"]))
            .await;

        // user1
        let msg = events1.next().await.unwrap();
        msg.value()
            .object()
            .get("type")
            .assert_string("users_state");

        let users = msg.value().object().get("users").array();
        users.assert_len(2);

        users.get(0).object().get("uid").assert_i64(1);
        users.get(0).object().get("online").assert_bool(false);

        users.get(1).object().get("uid").assert_i64(uid2);
        users.get(1).object().get("online").assert_bool(false);

        let msg = events1.next().await.unwrap();
        let obj = msg.value().object();
        obj.get("type").assert_string("users_state_changed");
        obj.get("uid").assert_i64(1);
        obj.get("online").assert_bool(true);

        // admin
        let msg = events_admin.next().await.unwrap();
        msg.value()
            .object()
            .get("type")
            .assert_string("users_state");

        let users = msg.value().object().get("users").array();
        users.assert_len(2);

        users.get(0).object().get("uid").assert_i64(uid1);
        users.get(0).object().get("online").assert_bool(true);

        users.get(1).object().get("uid").assert_i64(uid2);
        users.get(1).object().get("online").assert_bool(false);

        // user2
        let mut events2_ios = server
            .subscribe_events(&token2_ios, Some(&["users_state", "users_state_changed"]))
            .await;
        let mut events2_android = server
            .subscribe_events(
                &token2_android,
                Some(&["users_state", "users_state_changed"]),
            )
            .await;
        for events in [&mut events2_ios, &mut events2_android] {
            let msg = events.next().await.unwrap();
            msg.value()
                .object()
                .get("type")
                .assert_string("users_state");

            let users = msg.value().object().get("users").array();
            users.assert_len(2);

            users.get(0).object().get("uid").assert_i64(1);
            users.get(0).object().get("online").assert_bool(true);

            users.get(1).object().get("uid").assert_i64(uid1);
            users.get(1).object().get("online").assert_bool(true);
        }

        // user1, admin
        for events in [&mut events1, &mut events_admin] {
            let msg = events.next().await.unwrap();
            let obj = msg.value().object();
            obj.get("type").assert_string("users_state_changed");
            obj.get("uid").assert_i64(uid2);
            obj.get("online").assert_bool(true);
        }

        // user1
        drop(events2_ios);
        assert!(tokio::time::timeout(Duration::from_secs(6), events1.next())
            .await
            .is_err());

        drop(events2_android);
        tokio::time::sleep(Duration::from_secs(6)).await;

        // user1, admin
        for events in [&mut events1, &mut events_admin] {
            let msg = events.next().await.unwrap();
            let obj = msg.value().object();
            obj.get("type").assert_string("users_state_changed");
            obj.get("uid").assert_i64(uid2);
            obj.get("online").assert_bool(false);
        }
    }

    #[tokio::test]
    async fn received_read_index() {
        let server = TestServer::new().await;
        let admin_token_ios = server.login_admin_with_device("ios").await;
        let admin_token_android = server.login_admin_with_device("android").await;
        let user1 = server
            .create_user(&admin_token_ios, "user1@voce.chat")
            .await;
        let user1_token = server.login("user1@voce.chat").await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token_ios)
            .body_json(&json!({
                "name": "test",
                "members": [user1]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        let mut events_admin_ios = server
            .subscribe_events(
                &admin_token_ios,
                Some(&["chat", "user_settings", "user_settings_changed"]),
            )
            .await;
        let mut events_admin_android = server
            .subscribe_events(
                &admin_token_android,
                Some(&["chat", "user_settings", "user_settings_changed"]),
            )
            .await;

        let mid1 = server.send_text_to_user(&user1_token, 1, "a").await;
        let mid2 = server.send_text_to_group(&user1_token, gid, "b").await;

        for events in [&mut events_admin_ios, &mut events_admin_android] {
            let msg = events.next().await.unwrap();
            let msg = msg.value().object();
            msg.get("type").assert_string("user_settings");
            msg.get("read_index_users").array().assert_len(0);
            msg.get("read_index_groups").array().assert_len(0);

            let msg = events.next().await.unwrap();
            let msg = msg.value().object();
            msg.get("type").assert_string("chat");
            msg.get("mid").assert_i64(mid1);
            msg.get("from_uid").assert_i64(user1);
            let detail = msg.get("detail").object();
            detail.get("content").assert_string("a");

            let msg = events.next().await.unwrap();
            let msg = msg.value().object();
            msg.get("type").assert_string("chat");
            msg.get("mid").assert_i64(mid2);
            msg.get("from_uid").assert_i64(user1);
            msg.get("target").object().get("gid").assert_i64(gid);
            let detail = msg.get("detail").object();
            detail.get("content").assert_string("b");
        }

        // update read index
        server
            .post("/api/user/read-index")
            .header("X-API-Key", &admin_token_ios)
            .body_json(&json!({
                "users": [{"uid": user1, "mid": mid1}],
                "groups": [{"gid": gid, "mid": mid2}],
            }))
            .send()
            .await
            .assert_status_is_ok();

        let msg = events_admin_android.next().await.unwrap();
        let msg = msg.value().object();
        msg.get("type").assert_string("user_settings_changed");
        let read_index_users = msg.get("read_index_users").array();
        let read_index_groups = msg.get("read_index_groups").array();

        read_index_users.assert_len(1);
        let item = read_index_users.get(0).object();
        item.get("uid").assert_i64(user1);
        item.get("mid").assert_i64(mid1);

        read_index_groups.assert_len(1);
        let item = read_index_groups.get(0).object();
        item.get("gid").assert_i64(gid);
        item.get("mid").assert_i64(mid2);

        let mid3 = server.send_text_to_user(&user1_token, 1, "c").await;

        for events in [&mut events_admin_ios, &mut events_admin_android] {
            let msg = events.next().await.unwrap();
            let msg = msg.value().object();
            msg.get("type").assert_string("chat");
            msg.get("mid").assert_i64(mid3);
            msg.get("from_uid").assert_i64(user1);
            let detail = msg.get("detail").object();
            detail.get("content").assert_string("c");
        }

        // update read index
        server
            .post("/api/user/read-index")
            .header("X-API-Key", &admin_token_ios)
            .body_json(&json!({
                "users": [{"uid": user1, "mid": 0}],
                "groups": [{"gid": gid, "mid": 0}],
            }))
            .send()
            .await
            .assert_status_is_ok();

        // update read index
        server
            .post("/api/user/read-index")
            .header("X-API-Key", &admin_token_ios)
            .body_json(&json!({
                "users": [{"uid": user1, "mid": mid3}]
            }))
            .send()
            .await
            .assert_status_is_ok();

        let msg = events_admin_android.next().await.unwrap();
        let msg = msg.value().object();
        msg.get("type").assert_string("user_settings_changed");
        let read_index_users = msg.get("read_index_users").array();
        read_index_users.assert_len(1);
        let item = read_index_users.get(0).object();
        item.get("uid").assert_i64(user1);
        item.get("mid").assert_i64(mid3);

        let admin_token_web = server.login_admin_with_device("web").await;
        let mut events_admin_web = server
            .subscribe_events(&admin_token_web, Some(&["user_settings"]))
            .await;

        let msg = events_admin_web.next().await.unwrap();
        let msg = msg.value().object();
        msg.get("type").assert_string("user_settings");
        let read_index_users = msg.get("read_index_users").array();
        let read_index_groups = msg.get("read_index_groups").array();

        read_index_users.assert_len(1);
        let item = read_index_users.get(0).object();
        item.get("uid").assert_i64(user1);
        item.get("mid").assert_i64(mid3);

        read_index_groups.assert_len(1);
        let item = read_index_groups.get(0).object();
        item.get("gid").assert_i64(gid);
        item.get("mid").assert_i64(mid2);
    }

    #[tokio::test]
    async fn received_burn_after_reading() {
        let server = TestServer::new().await;
        let admin_token_ios = server.login_admin_with_device("ios").await;
        let admin_token_android = server.login_admin_with_device("android").await;
        let user1 = server
            .create_user(&admin_token_ios, "user1@voce.chat")
            .await;
        let user1_token = server.login("user1@voce.chat").await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token_ios)
            .body_json(&json!({
                "name": "test",
                "members": [user1]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().object().get("gid").i64();

        let mut events_admin_ios = server
            .subscribe_events(
                &admin_token_ios,
                Some(&["chat", "user_settings", "user_settings_changed"]),
            )
            .await;
        let mut events_admin_android = server
            .subscribe_events(
                &admin_token_android,
                Some(&["chat", "user_settings", "user_settings_changed"]),
            )
            .await;

        let resp = server
            .post("/api/user/burn-after-reading")
            .header("X-API-Key", &admin_token_ios)
            .body_json(&json!({
                "users": [{
                    "uid": user1,
                    "expires_in": 15,
                }],
                "groups": [{
                    "gid": gid,
                    "expires_in": 30,
                }]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        let mid1 = server.send_text_to_user(&admin_token_ios, user1, "a").await;
        let mid2 = server.send_text_to_group(&admin_token_ios, gid, "b").await;

        for events in [&mut events_admin_ios, &mut events_admin_android] {
            let msg = events.next().await.unwrap();
            let msg = msg.value().object();
            msg.get("type").assert_string("user_settings");
            msg.get("burn_after_reading_users").array().assert_len(0);
            msg.get("burn_after_reading_groups").array().assert_len(0);
        }

        let msg = events_admin_android.next().await.unwrap();
        let msg = msg.value().object();
        msg.get("type").assert_string("user_settings_changed");
        msg.get("burn_after_reading_users").array().assert_len(1);
        let item = msg.get("burn_after_reading_users").array().get(0).object();
        item.get("uid").assert_i64(user1);
        item.get("expires_in").assert_i64(15);
        msg.get("burn_after_reading_groups").array().assert_len(1);
        let item = msg.get("burn_after_reading_groups").array().get(0).object();
        item.get("gid").assert_i64(gid);
        item.get("expires_in").assert_i64(30);

        let mut events_user1 = server.subscribe_events(&user1_token, Some(&["chat"])).await;
        let msg = events_user1.next().await.unwrap();
        let msg = msg.value().object();
        msg.get("type").assert_string("chat");
        msg.get("mid").assert_i64(mid1);
        msg.get("from_uid").assert_i64(1);
        msg.get("target").object().get("uid").assert_i64(user1);
        let detail = msg.get("detail").object();
        detail.get("content").assert_string("a");
        detail.get("expires_in").assert_i64(15);

        let msg = events_user1.next().await.unwrap();
        let msg = msg.value().object();
        msg.get("type").assert_string("chat");
        msg.get("mid").assert_i64(mid2);
        msg.get("from_uid").assert_i64(1);
        msg.get("target").object().get("gid").assert_i64(gid);
        let detail = msg.get("detail").object();
        detail.get("content").assert_string("b");
        detail.get("expires_in").assert_i64(30);
    }

    #[tokio::test]
    async fn check_reg_magic_token() {
        let server = TestServer::new().await;
        let code = rc_magic_link::gen_code();
        let expired_at = chrono::Utc::now() + chrono::Duration::seconds(86400);
        let reg_magic_token = rc_magic_link::MagicLinkToken::gen_reg_magic_token(
            &code,
            &server.state().key_config.read().await.server_key,
            expired_at,
            false,
            None,
            None,
            None,
        );

        // check reg magic token
        let resp = server
            .post("/api/user/check_magic_token")
            .body_json(&json!({
                "magic_token": &reg_magic_token,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.json().await.value().assert_bool(true);

        // invalid magic token
        let resp = server
            .post("/api/user/check_magic_token")
            .body_json(&json!({
                "magic_token": "abc",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.json().await.value().assert_bool(false);
    }

    #[tokio::test]
    async fn check_login_magic_token() {
        let server = TestServer::new().await;
        let code = rc_magic_link::gen_code();
        let expired_at = chrono::Utc::now() + chrono::Duration::seconds(86400);
        let email = "user1@mail.com";
        let login_magic_token = rc_magic_link::MagicLinkToken::gen_login_magic_token(
            &code,
            &server.state().key_config.read().await.server_key,
            expired_at,
            email,
            None,
        );

        // check login magic token
        let resp = server
            .post("/api/user/check_magic_token")
            .body_json(&json!({
                "magic_token": &login_magic_token,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.json().await.value().assert_bool(true);
    }

    #[tokio::test]
    async fn reg_magic_link_without_smtp() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        server.create_user(&admin_token, "user1@voce.chat").await;
        let user1_token = server.login("user1@voce.chat").await;

        // create invite link, gid = None, global server
        let resp = server
            .get("/api/group/create_reg_magic_link?expired_in=600&max_times=10000")
            .header("X-API-Key", &user1_token)
            .send()
            .await;
        resp.assert_status_is_ok();

        let url = resp.0.into_body().into_string().await.unwrap();
        let uri = Uri::from_str(&url).unwrap();

        #[derive(Deserialize)]
        struct Params {
            magic_token: String,
        }
        let params = serde_urlencoded::from_str::<Params>(uri.query().unwrap()).unwrap();
        assert!(!params.magic_token.is_empty());

        let email1 = "user2@voce.chat";
        let resp = server
            .post("/api/user/register")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "magic_token": params.magic_token,
                "email": email1,
                "password": "123456",
                "gender": 1,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        // resp.assert_text("xxx").await;
        let json = resp.json().await;
        assert_eq!(
            email1,
            json.value()
                .object()
                .get("user")
                .object()
                .get("email")
                .string()
        );
    }

    #[tokio::test]
    async fn reg_magic_link_with_smtp() {
        let server = TestServer::new_with_config(|cfg| {
            cfg.template.register_by_email = Some(TemplateConfig {
                subject: "Register".to_string(),
                file: concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/config/templates/register_by_email.html"
                )
                .to_string(),
            });
        })
        .await;
        server
            .state()
            .set_dynamic_config(DynamicConfigEntry {
                enabled: true,
                config: SmtpConfig {
                    host: "localhost:1111".to_string(),
                    port: None,
                    from: "aaa".to_string(),
                    username: "aaa".to_string(),
                    password: "aaa".to_string(),
                },
            })
            .await
            .unwrap();
        let admin_token = server.login_admin().await;
        server.create_user(&admin_token, "user1@voce.chat").await;
        let user1_token = server.login("user1@voce.chat").await;

        // create invite link
        let resp = server
            .get("/api/group/create_reg_magic_link")
            .header("X-API-Key", &user1_token)
            .send()
            .await;
        resp.assert_status_is_ok();
        let url = resp.0.into_body().into_string().await.unwrap();
        let uri = Uri::from_str(&url).unwrap();

        #[derive(Deserialize)]
        struct Params {
            magic_token: String,
        }
        let params = serde_urlencoded::from_str::<Params>(uri.query().unwrap()).unwrap();
        assert!(!params.magic_token.is_empty());

        // send magic link
        let resp = server
            .post("/api/user/send_reg_magic_link")
            .body_json(&json!({
                "magic_token": &params.magic_token,
                "email": "user3@voce.chat",
                "password": "1",
            }))
            .send()
            .await;
        // resp.assert_text("").await;
        resp.assert_status_is_ok();

        // resp.assert_text(params.magic_token).await;
        let json = resp.json().await;
        let new_magic_token = json.value().object().get("new_magic_token").string();
        // let new_magic_token = resp.0.into_body().into_string().await.unwrap();
        dbg!(&new_magic_token);

        let resp = server
            .post("/api/user/register")
            .body_json(&json!({
                "magic_token": new_magic_token,
                "gender": 1,
            }))
            .send()
            .await;
        // resp.assert_text("").await;
        resp.assert_status_is_ok();

        let json = resp.json().await;
        json.value()
            .object()
            .get("user")
            .object()
            .get("email")
            .assert_string("user3@voce.chat");
    }

    #[tokio::test]
    async fn login_magic_link_with_smtp() {
        let server = TestServer::new_with_config(|cfg| {
            cfg.template.login_by_email = Some(TemplateConfig {
                subject: "Login".to_string(),
                file: concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/config/templates/login_by_email.html"
                )
                .to_string(),
            });
        })
        .await;
        let state = server.state();
        state
            .set_dynamic_config(DynamicConfigEntry {
                enabled: true,
                config: SmtpConfig {
                    host: "localhost:1111".to_string(),
                    port: None,
                    from: "aaa".to_string(),
                    username: "aaa".to_string(),
                    password: "aaa".to_string(),
                },
            })
            .await
            .unwrap();
        state
            .set_dynamic_config(DynamicConfigEntry {
                enabled: true,
                config: LoginConfig {
                    magic_link: true,
                    ..Default::default()
                },
            })
            .await
            .unwrap();

        let email1 = "user@email.com";
        let resp = server
            .post("/api/user/send_login_magic_link")
            .query("email", &email1)
            .send()
            .await;
        resp.assert_status_is_ok();
        let magic_token = resp.0.into_body().into_string().await.unwrap();
        assert!(!magic_token.is_empty());

        let resp = server
            .post("/api/token/login")
            .body_json(&json!({
                "credential": {
                    "type": "magiclink",
                    "magic_token": &magic_token,
                    "extra_name": "jack"
                },
                "device": "web",
                "device_token": "device token",
            }))
            .send()
            .await;
        // resp.assert_text("").await;
        // resp.assert_status_is_ok();

        let json = resp.json().await;
        assert!(!json
            .value()
            .object()
            .get("refresh_token")
            .string()
            .is_empty());
    }

    #[tokio::test]
    async fn check_email() {
        let server = TestServer::new().await;

        let resp = server
            .get("/api/user/check_email")
            .query("email", &"admin@voce.chat")
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.json().await.value().assert_bool(false);

        let resp = server
            .get("/api/user/check_email")
            .query("email", &"user1@voce.chat")
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.json().await.value().assert_bool(true);
    }

    #[tokio::test]
    async fn user_frozen() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let user1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let user1_token = server.login("user1@voce.chat").await;

        let resp = server
            .get(format!("/api/admin/user/{}", user1))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        json.value().object().get("status").assert_string("normal");

        let mut events = server.subscribe_events(&user1_token, Some(&["kick"])).await;

        let resp = server
            .put(format!("/api/admin/user/{}", user1))
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "status": "frozen"
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        let resp = server
            .get(format!("/api/admin/user/{}", user1))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        json.value().object().get("status").assert_string("frozen");

        let msg = events.next().await.unwrap();
        msg.value().object().get("type").assert_string("kick");
        msg.value().object().get("reason").assert_string("frozen");

        assert!(events.next().await.is_none());
    }

    #[tokio::test]
    async fn test_history_messages() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let user1_token = server.login("user1@voce.chat").await;

        let id1 = server.send_text_to_user(&admin_token, uid1, "a").await;
        let id2 = server.send_text_to_user(&user1_token, 1, "b").await;
        let id3 = server.send_text_to_user(&admin_token, uid1, "c").await;

        async fn check(
            server: &TestServer,
            token: &str,
            to_uid: i64,
            before_mid: Option<i64>,
            expect: Vec<(i64, &str)>,
        ) {
            let mut builder = server
                .get(format!("/api/user/{}/history", to_uid))
                .header("X-API-Key", token);
            if let Some(before_mid) = before_mid {
                builder = builder.query("before", &before_mid);
            }
            let resp = builder.send().await;
            resp.assert_status_is_ok();
            let json = resp.json().await;
            let array = json.value().array();
            array.assert_len(expect.len());
            for (row, (id, content)) in array.iter().zip(expect) {
                let row = row.object();
                row.get("mid").assert_i64(id);
                let detail = row.get("detail").object();
                detail.get("type").assert_string("normal");
                detail.get("content").assert_string(content);
            }
        }

        check(
            &server,
            &admin_token,
            uid1,
            None,
            vec![(id1, "a"), (id2, "b"), (id3, "c")],
        )
        .await;

        check(
            &server,
            &admin_token,
            uid1,
            Some(id3),
            vec![(id1, "a"), (id2, "b")],
        )
        .await;
        check(
            &server,
            &user1_token,
            1,
            Some(id3),
            vec![(id1, "a"), (id2, "b")],
        )
        .await;

        check(&server, &admin_token, uid1, Some(id1), vec![]).await;
    }

    #[tokio::test]
    async fn test_change_password() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        server.create_user(&admin_token, "user1@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;

        server
            .post("/api/user/change_password")
            .header("X-API-Key", &token1)
            .body_json(&json!({
                "old_password": "123456",
                "new_password": "654321",
            }))
            .send()
            .await
            .assert_status_is_ok();

        let resp = server
            .post("/api/token/login")
            .body_json(&json!({
                "credential": {
                    "type": "password",
                    "email": "user1@voce.chat",
                    "password": "654321"
                },
                "device": "web",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.json()
            .await
            .value()
            .object()
            .get("token")
            .assert_not_null();
    }
}
