use std::{collections::HashMap, ops::Deref, time::Duration};

use bytes::Bytes;
use chrono::Utc;
use futures_util::TryFutureExt;
use hmac::{Mac, NewMac};
use openidconnect::{
    core::{
        CoreAuthenticationFlow, CoreClient, CoreClientRegistrationRequest, CoreIdTokenClaims,
        CoreIdTokenVerifier, CoreJwsSigningAlgorithm, CoreProviderMetadata,
    },
    registration::EmptyAdditionalClientMetadata,
    AuthorizationCode, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl, Scope,
};
use poem::{
    error::{BadRequest, InternalServerError, ServiceUnavailable},
    http::StatusCode,
    web::Data,
    Error, Request, Result,
};
use poem_openapi::{
    auth::ApiKey,
    param::{Header, Query},
    payload::Json,
    types::Example,
    ApiResponse, Object, OpenApi, SecurityScheme, Union,
};
use rc_magic_link::MagicLinkToken;
use rc_token::{parse_token, TokenType};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    api::{
        admin_login::{LoginConfig, WhoCanSignUp},
        tags::ApiTags,
        user::UserInfo,
        DateTime, KickReason,
    },
    create_user::{CreateUser, CreateUserBy, CreateUserError},
    state::{CacheDevice, OAuth2State, UserEvent, UserStatus},
    State,
};

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct CurrentUser {
    pub uid: i64,
    pub device: String,
    pub is_admin: bool,
}

/// ApiKey authorization
#[derive(SecurityScheme)]
#[oai(
    type = "api_key",
    key_name = "X-API-Key",
    in = "header",
    checker = "api_checker"
)]
pub struct Token(pub CurrentUser);

impl Deref for Token {
    type Target = CurrentUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// ApiKey authorization
#[derive(SecurityScheme)]
#[oai(
    type = "api_key",
    key_name = "api-key",
    in = "query",
    checker = "api_checker"
)]
pub struct TokenInQuery(pub CurrentUser);

impl Deref for TokenInQuery {
    type Target = CurrentUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

async fn api_checker(req: &Request, api_key: ApiKey) -> Option<CurrentUser> {
    let state = req.extensions().get::<State>().unwrap();
    let key_config = state.key_config.read().await;
    let (token_type, current_user): (_, CurrentUser) =
        parse_token(&key_config.server_key, &api_key.key, true).ok()?;
    if token_type != TokenType::AccessToken {
        return None;
    }
    Some(current_user)
}

#[derive(Debug, Object)]
struct LoginCredentialPassword {
    /// Email
    email: String,

    /// Password
    password: String,
}

#[derive(Debug, Object)]
struct LoginCredentialMagicLink {
    /// Login magic token
    magic_token: String,

    /// Register directly through login magic link
    #[oai(default)]
    extra_name: String,
}

#[derive(Debug, Object)]
struct LoginCredentialGoogleIdToken {
    /// Google id token
    id_token: String,
    #[oai(default)]
    magic_token: String,
}

#[derive(Debug, Object)]
struct LoginCredentialGithubCode {
    /// Github code
    code: String,
    #[oai(default)]
    magic_token: String,
}

#[derive(Debug, Object)]
struct LoginCredentialOpenIdConnect {
    code: String,
    #[oai(rename = "state")]
    oidc_state: String,
    #[oai(default)]
    magic_token: String,
}

#[derive(Debug, Object)]
struct LoginCredentialMetaMask {
    public_address: String,
    nonce: String,
    signature: String,
    #[oai(default)]
    magic_token: String,
}

#[derive(Debug, Object)]
struct LoginCredentialThirdParty {
    key: String,
}

/// Login credential
#[derive(Debug, Union)]
#[oai(discriminator_name = "type")]
enum LoginCredential {
    #[oai(mapping = "password")]
    Password(LoginCredentialPassword),
    #[oai(mapping = "magiclink")]
    MagicLink(LoginCredentialMagicLink),
    #[oai(mapping = "google")]
    GoogleIdToken(LoginCredentialGoogleIdToken),
    #[oai(mapping = "github")]
    GithubCode(LoginCredentialGithubCode),
    #[oai(mapping = "oidc")]
    OpenIdConnect(LoginCredentialOpenIdConnect),
    #[oai(mapping = "metamask")]
    MetaMask(LoginCredentialMetaMask),
    #[oai(mapping = "thirdparty")]
    ThirdParty(LoginCredentialThirdParty),
}

impl LoginCredential {
    fn magic_token(&self) -> Option<&str> {
        match self {
            LoginCredential::Password(_) => None,
            LoginCredential::MagicLink(LoginCredentialMagicLink { magic_token, .. }) => {
                Some(magic_token.as_str())
            }
            LoginCredential::GoogleIdToken(LoginCredentialGoogleIdToken {
                magic_token, ..
            }) => Some(magic_token.as_str()),
            LoginCredential::GithubCode(LoginCredentialGithubCode { magic_token, .. }) => {
                Some(magic_token.as_str())
            }
            LoginCredential::OpenIdConnect(LoginCredentialOpenIdConnect {
                magic_token, ..
            }) => Some(magic_token.as_str()),
            LoginCredential::MetaMask(LoginCredentialMetaMask { magic_token, .. }) => {
                Some(magic_token.as_str())
            }
            LoginCredential::ThirdParty(_) => None,
        }
    }
}

/// Login request
#[derive(Debug, Object)]
#[oai(example)]
struct LoginRequest {
    /// Credential
    credential: LoginCredential,

    /// Device id
    #[oai(default = "default_device")]
    device: String,

    /// FCM device token
    device_token: Option<String>,
}

impl Example for LoginRequest {
    fn example() -> Self {
        LoginRequest {
            credential: LoginCredential::Password(LoginCredentialPassword {
                email: "admin@voce.chat".to_string(),
                password: "123456".to_string(),
            }),
            device: "web".to_string(),
            device_token: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct GoogleIdTokenPayload {
    email: String,
    name: Option<String>,
    picture: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct GithubTokenPayload {
    username: String,
    name: Option<String>,
    picture: Option<String>,
}

fn default_device() -> String {
    "unknown".to_string()
}

/// Token response
#[derive(Debug, Object)]
pub struct LoginResponse {
    /// Server id
    server_id: String,
    /// Access token
    token: String,
    /// Refresh token
    refresh_token: String,
    /// The access token expired in seconds
    expired_in: i64,
    /// User info
    user: UserInfo,
}

#[derive(ApiResponse)]
pub enum LoginApiResponse {
    /// Login success
    #[oai(status = 200)]
    Ok(Json<LoginResponse>),
    /// Login method does not supported
    #[oai(status = 403)]
    LoginMethodNotSupported,
    /// Invalid account or password
    #[oai(status = 401)]
    InvalidAccount,
    /// User does not exists
    #[oai(status = 404)]
    UserDoesNotExist,
    /// User has been frozen
    #[oai(status = 423)]
    Frozen,
    /// Email collision
    #[oai(status = 409)]
    EmailConflict,
    /// Account not associated
    #[oai(status = 410)]
    AccountNotAssociated,
}

/// Bind credential
#[derive(Debug, Union)]
#[oai(discriminator_name = "type")]
enum BindCredential {
    #[oai(mapping = "google")]
    GoogleIdToken(LoginCredentialGoogleIdToken),
    #[oai(mapping = "github")]
    GithubCode(LoginCredentialGithubCode),
    #[oai(mapping = "oidc")]
    OpenIdConnect(LoginCredentialOpenIdConnect),
    #[oai(mapping = "metamask")]
    MetaMask(LoginCredentialMetaMask),
}

/// Bind request
#[derive(Debug, Object)]
struct BindRequest {
    /// Credential
    credential: BindCredential,
}

#[derive(ApiResponse)]
enum BindApiResponse {
    /// Login success
    #[oai(status = 200)]
    Ok,
    /// Login method does not supported
    #[oai(status = 403)]
    LoginMethodNotSupported,
    /// Invalid credential
    #[oai(status = 401)]
    InvalidCredential,
    #[oai(status = 409)]
    Exists,
}

/// Credentials response
#[derive(Debug, Object)]
struct CredentialsResponse {
    password: bool,
    google: Option<String>,
    metamask: Option<String>,
    oidc: Vec<String>,
}

/// Renew token request
#[derive(Debug, Object)]
struct RenewTokenRequest {
    token: String,
    refresh_token: String,
}

/// Renew token response
#[derive(Debug, Object)]
struct RenewTokenResponse {
    /// Access token
    token: String,
    /// Refresh token
    refresh_token: String,
    /// The access token expired in seconds
    expired_in: i64,
}

#[derive(ApiResponse)]
enum RenewTokenApiResponse {
    /// Renew success
    #[oai(status = 200)]
    Ok(Json<RenewTokenResponse>),
    /// Illegal token
    #[oai(status = 401)]
    IllegalToken,
}

#[derive(ApiResponse)]
enum LogoutApiResponse {
    /// Logout success
    #[oai(status = 200)]
    Ok,
    /// Illegal token
    #[oai(status = 401)]
    IllegalToken,
}

#[derive(Debug, Object)]
struct OpenIdAuthorizeRequest {
    issuer: String,
    redirect_uri: String,
}

#[derive(Debug, Object)]
struct OpenIdAuthorizeResponse {
    url: String,
}

#[derive(Debug, Object)]
struct CreateThirdPartyKeyRequest {
    userid: String,
    username: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ThirdPartyLoginInfo {
    userid: String,
    username: String,
    expired_at: chrono::DateTime<Utc>,
}

/// Update device token request
#[derive(Debug, Object)]
struct UpdateDeviceTokenRequest {
    device_token: Option<String>,
}

pub struct ApiToken;

#[OpenApi(prefix_path = "/token", tag = "ApiTags::Token")]
impl ApiToken {
    /// OpenId authorize
    #[oai(path = "/openid/authorize", method = "post")]
    async fn openid_authorize(
        &self,
        state: Data<&State>,
        req: Json<OpenIdAuthorizeRequest>,
    ) -> Result<Json<OpenIdAuthorizeResponse>> {
        let mut provider_metadata = None;
        let login_cfg = state
            .get_dynamic_config_instance::<LoginConfig>()
            .await
            .unwrap_or_default();
        if !login_cfg
            .oidc
            .iter()
            .any(|oidc| oidc.domain == req.issuer && oidc.enable)
        {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        for url in [
            format!("https://{}", req.0.issuer),
            format!("https://{}/", req.0.issuer),
        ] {
            let issuer_url = IssuerUrl::new(url).map_err(BadRequest)?;
            if let Ok(metadata) = CoreProviderMetadata::discover_async(
                issuer_url.clone(),
                openidconnect::reqwest::async_http_client,
            )
            .await
            {
                provider_metadata = Some((issuer_url, metadata));
                break;
            }
        }

        let (issuer_url, provider_metadata) =
            provider_metadata.ok_or_else(|| Error::from_status(StatusCode::SERVICE_UNAVAILABLE))?;
        let redirect_uri = RedirectUrl::new(req.0.redirect_uri).map_err(BadRequest)?;

        let registration_endpoint = provider_metadata
            .registration_endpoint()
            .ok_or_else(|| Error::from_status(StatusCode::SERVICE_UNAVAILABLE))?;
        tracing::debug!(
            issuer_url = issuer_url.as_str(),
            redirect_uri = redirect_uri.as_str(),
            registration_endpoint = registration_endpoint.as_str(),
            "registration endpoint",
        );

        let registration_response = CoreClientRegistrationRequest::new(
            vec![redirect_uri.clone()],
            EmptyAdditionalClientMetadata::default(),
        )
        .register_async(
            registration_endpoint,
            openidconnect::reqwest::async_http_client,
        )
        .await
        .map_err(ServiceUnavailable)?;

        tracing::debug!(
            issuer_url = issuer_url.as_str(),
            redirect_uri = redirect_uri.as_str(),
            "openid authorize",
        );

        let client = CoreClient::new(
            registration_response.client_id().clone(),
            registration_response.client_secret().cloned(),
            provider_metadata.issuer().clone(),
            provider_metadata.authorization_endpoint().clone(),
            provider_metadata.token_endpoint().cloned(),
            provider_metadata.userinfo_endpoint().cloned(),
            provider_metadata.jwks().clone(),
        )
        .set_redirect_uri(redirect_uri);

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        tracing::debug!(
            authorize_url = auth_url.as_str(),
            "authorization url generated"
        );

        state.pending_oidc.lock().await.insert(
            csrf_token.secret().to_string(),
            OAuth2State {
                client,
                issuer: req.0.issuer,
                pkce_verifier,
                csrf_token: csrf_token.clone(),
                nonce,
            },
        );

        tokio::spawn({
            let state = state.clone();
            async move {
                // timeout
                tokio::time::sleep(Duration::from_secs(150)).await;
                state.pending_oidc.lock().await.remove(csrf_token.secret());
            }
        });

        Ok(Json(OpenIdAuthorizeResponse {
            url: auth_url.to_string(),
        }))
    }

    /// Get the nonce for MetaMask login
    #[oai(path = "/metamask/nonce", method = "get")]
    async fn metamask_nonce(
        &self,
        state: Data<&State>,
        public_address: Query<String>,
    ) -> Result<Json<String>> {
        let public_address = public_address.0.to_lowercase();
        let nonce = textnonce::TextNonce::new();
        let sql = r#"
        insert into metamask_nonce (public_address, nonce) values (?, ?)
            on conflict (public_address) do update set nonce = excluded.nonce
            "#;
        sqlx::query(sql)
            .bind(&public_address)
            .bind(&nonce.0)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;
        Ok(Json(nonce.0))
    }

    /// Create a key for third-party user login.
    #[oai(method = "post", path = "/create_third_party_key")]
    async fn create_third_party_key(
        &self,
        state: Data<&State>,
        req: Json<CreateThirdPartyKeyRequest>,
        #[oai(name = "X-SECRET")] secret: Header<String>,
    ) -> Result<Json<String>> {
        let key_config = state.key_config.read().await;
        if secret.0 != key_config.third_party_secret {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let info = ThirdPartyLoginInfo {
            userid: req.0.userid,
            username: req.0.username,
            expired_at: chrono::Utc::now() + chrono::Duration::seconds(60 * 2),
        };
        let key_content = serde_json::to_vec(&info).unwrap();
        let mut buf_sig = {
            let mut mac =
                hmac::Hmac::<Sha256>::new_from_slice(key_config.server_key.as_bytes()).unwrap();
            mac.update(&key_content);
            mac.finalize().into_bytes().to_vec()
        };
        buf_sig.extend_from_slice(&key_content);
        Ok(Json(hex::encode(&buf_sig)))
    }

    /// Login
    #[oai(path = "/login", method = "post")]
    async fn login(
        &self,
        state: Data<&State>,
        req: Json<LoginRequest>,
        request: &Request,
    ) -> Result<LoginApiResponse> {
        // let smtp_on = state
        //     .load_dynamic_config::<crate::api::SmtpConfig>()
        //     .await?
        //     .enabled;

        crate::license::check_license_wrap!(&state, request);

        let login_cfg = state
            .get_dynamic_config_instance::<LoginConfig>()
            .await
            .unwrap_or_default();
        let key_config = state.key_config.read().await;
        let magic_token = match req.credential.magic_token() {
            Some(s) if !s.is_empty() => match MagicLinkToken::parse(&key_config.server_key, s) {
                Some(mt) => Some(mt),
                None => {
                    return Err(Error::from_status(StatusCode::BAD_REQUEST));
                }
            },
            _ => None,
        };
        if magic_token.is_some() {
            let code = magic_token.as_ref().unwrap().get_code();
            if !state.magic_code_check_code(code).await {
                return Err(poem::Error::from_status(StatusCode::BAD_REQUEST));
            }
        }

        const MAX_USER_NUMBER: usize = 1000;
        let can_register = if state.cache.read().await.users.len() >= MAX_USER_NUMBER {
            false
        } else {
            match login_cfg.who_can_sign_up {
                WhoCanSignUp::InvitationOnly => magic_token.is_some(),
                _ => true,
            }
        };

        let uid = match req.0.credential {
            // login with password
            LoginCredential::Password(LoginCredentialPassword { email, password })
                if login_cfg.password =>
            {
                let cache = state.cache.read().await;
                let uid = match cache
                    .users
                    .iter()
                    .find(|(_, user)| user.email.as_ref() == Some(&email))
                {
                    Some((uid, cached_user)) => {
                        if cached_user.password.as_ref() != Some(&password) {
                            return Ok(LoginApiResponse::InvalidAccount);
                        }
                        *uid
                    }
                    None => return Ok(LoginApiResponse::UserDoesNotExist),
                };
                uid
            }

            // login with magic link
            LoginCredential::MagicLink(LoginCredentialMagicLink {
                magic_token,
                extra_name,
            }) => {
                let (email, uid, code, _expired_at) = match MagicLinkToken::parse(
                    &state.key_config.read().await.server_key,
                    &magic_token,
                ) {
                    Some(MagicLinkToken::Login {
                        email,
                        uid,
                        code,
                        expired_at,
                    }) => (email, uid, code, expired_at),
                    _ => return Ok(LoginApiResponse::InvalidAccount),
                };

                {
                    /* let smtp_on = true;
                    let cache = state.cache.read().await;
                    let r = cache.codes.codes.get(&code);*/
                    if !state.magic_code_check_code(&code).await {
                        state.login_magic_code_remove(&code).await;
                        return Err(Error::from_string("Bad code.", StatusCode::BAD_REQUEST));
                    }
                }

                let username = if extra_name.is_empty() {
                    None
                } else {
                    Some(extra_name)
                };
                let uid = match (uid, username.as_ref()) {
                    (Some(uid), None) => uid,
                    (None, Some(username)) => {
                        // create a new user
                        if !can_register {
                            return Ok(LoginApiResponse::AccountNotAssociated);
                        }

                        let name = state
                            .cache
                            .write()
                            .await
                            .assign_username(Some(username), Some(username))
                            .into_owned();
                        let create_user = CreateUser::new(
                            &name,
                            CreateUserBy::MagicLink { email: &email },
                            false,
                        );
                        match state.create_user(create_user).await {
                            Ok((uid, _)) => uid,
                            Err(_) => return Ok(LoginApiResponse::InvalidAccount),
                        }
                    }
                    _ => return Ok(LoginApiResponse::InvalidAccount),
                };
                // state.magic_code_check_update_by_email(email);
                uid
            }
            // login with google id token
            LoginCredential::GoogleIdToken(LoginCredentialGoogleIdToken { id_token, .. })
                if login_cfg.google =>
            {
                let payload = parse_google_id_token(&id_token)
                    .await
                    .map_err(|err| poem::Error::from((StatusCode::BAD_REQUEST, err)))?;
                let sql = "select uid from google_auth where email = ?";
                match sqlx::query_as::<_, (i64,)>(sql)
                    .bind(&payload.email)
                    .fetch_optional(&state.db_pool)
                    .await
                    .map_err(InternalServerError)?
                {
                    Some((uid,)) => uid,
                    // create a new user
                    None => {
                        if !can_register {
                            return Ok(LoginApiResponse::AccountNotAssociated);
                        }

                        // bind same email.
                        let uid = state
                            .cache
                            .read()
                            .await
                            .users
                            .iter()
                            .find(|(_, user)| user.email.as_ref() == Some(&payload.email))
                            .map(|(uid, _)| *uid);

                        if let Some(uid) = uid {
                            let sql = "insert into google_auth (email, uid) values (?, ?)";
                            sqlx::query(sql)
                                .bind(&payload.email)
                                .bind(uid)
                                .execute(&state.db_pool)
                                .await
                                .map_err(InternalServerError)?;
                            uid
                        } else {
                            // download avatar
                            let avatar = match &payload.picture {
                                Some(url) => download_avatar(url).await.ok(),
                                None => None,
                            };

                            let name = state
                                .cache
                                .write()
                                .await
                                .assign_username(payload.name.as_deref(), Some(&payload.email))
                                .into_owned();

                            let mut create_user = CreateUser::new(
                                &name,
                                CreateUserBy::Google {
                                    email: &payload.email,
                                },
                                false,
                            );
                            if let Some(avatar) = &avatar {
                                create_user = create_user.avatar(avatar);
                            }

                            match state.create_user(create_user).await {
                                Ok((uid, _)) => uid,
                                Err(CreateUserError::EmailConflict) => {
                                    return Ok(LoginApiResponse::EmailConflict)
                                }
                                Err(_) => return Ok(LoginApiResponse::InvalidAccount),
                            }
                        }
                    }
                }
            }
            // login with github code
            LoginCredential::GithubCode(LoginCredentialGithubCode { code, .. })
                if login_cfg.github =>
            {
                // fetch id_token by code
                let token = github_fetch_token(&code, &state)
                    .await
                    .map_err(|err| poem::Error::from((StatusCode::BAD_REQUEST, err)))?;
                let (username, avatar_url) = github_fetch_user_info(&token)
                    .await
                    .map_err(|err| poem::Error::from((StatusCode::BAD_REQUEST, err)))?;
                let sql = "select uid from github_auth where username = ?";
                match sqlx::query_as::<_, (i64,)>(sql)
                    .bind(&username)
                    .fetch_optional(&state.db_pool)
                    .await
                    .map_err(InternalServerError)?
                {
                    Some((uid,)) => uid,
                    // create a new user
                    None => {
                        if !can_register {
                            return Ok(LoginApiResponse::AccountNotAssociated);
                        }

                        let uid = state
                            .cache
                            .read()
                            .await
                            .users
                            .iter()
                            .find(|(_, user)| user.name.as_str() == username.as_str())
                            .map(|(uid, _)| *uid);
                        if let Some(uid) = uid {
                            let sql = "insert into github_auth (username, uid) values (?, ?)";
                            sqlx::query(sql)
                                .bind(&username)
                                .bind(uid)
                                .execute(&state.db_pool)
                                .await
                                .map_err(InternalServerError)?;
                            uid
                        } else {
                            // download avatar
                            let avatar = download_avatar(&avatar_url).await.ok();

                            let name = state
                                .cache
                                .write()
                                .await
                                .assign_username(Some(&username), None);

                            let mut create_user = CreateUser::new(
                                &name,
                                CreateUserBy::Github {
                                    username: username.as_str(),
                                },
                                false,
                            );
                            if let Some(avatar) = &avatar {
                                create_user = create_user.avatar(avatar);
                            }

                            match state.create_user(create_user).await {
                                Ok((uid, _)) => uid,
                                Err(CreateUserError::EmailConflict) => {
                                    return Ok(LoginApiResponse::EmailConflict)
                                }
                                Err(_) => return Ok(LoginApiResponse::InvalidAccount),
                            }
                        }
                    }
                }
            }
            // login with open id connect
            LoginCredential::OpenIdConnect(LoginCredentialOpenIdConnect {
                code,
                oidc_state,
                ..
            }) => {
                let item = {
                    let mut pending_oidc = state.pending_oidc.lock().await;
                    match pending_oidc.remove(&oidc_state) {
                        Some(item) => item,
                        None => {
                            tracing::debug!("oidc id does not exist");
                            return Ok(LoginApiResponse::InvalidAccount);
                        }
                    }
                };

                tracing::debug!("wait for oauth2 response");

                let issuer = item.issuer.clone();
                let id_token = match oidc_get_id_token(item, code, oidc_state).await {
                    Ok(id_token) => id_token,
                    Err(_) => return Ok(LoginApiResponse::InvalidAccount),
                };

                let subject = id_token.subject().to_string();
                let email = if id_token.email_verified().unwrap_or_default() {
                    id_token.email().map(|email| email.to_string())
                } else {
                    None
                };
                let name = id_token
                    .name()
                    .and_then(|name| name.iter().next().map(|(_, name)| name.to_string()));
                let picture = id_token.picture().and_then(|picture| {
                    picture
                        .iter()
                        .next()
                        .map(|(_, picture)| picture.to_string())
                });

                let sql = "select uid from openid_connect where issuer = ? and subject = ?";
                match sqlx::query_as::<_, (i64,)>(sql)
                    .bind(&issuer)
                    .bind(&subject)
                    .fetch_optional(&state.db_pool)
                    .await
                    .map_err(InternalServerError)?
                {
                    Some((uid,)) => uid,
                    // create a new user
                    None => {
                        if !can_register {
                            return Ok(LoginApiResponse::AccountNotAssociated);
                        }

                        // download avatar
                        let avatar = match &picture {
                            Some(url) => download_avatar(url).await.ok(),
                            None => None,
                        };

                        let name = state
                            .cache
                            .write()
                            .await
                            .assign_username(name.as_deref(), email.as_deref());

                        let mut create_user = CreateUser::new(
                            &name,
                            CreateUserBy::OpenIdConnect {
                                issuer: &issuer,
                                subject: &subject,
                                email: email.as_deref(),
                            },
                            false,
                        );
                        if let Some(avatar) = &avatar {
                            create_user = create_user.avatar(avatar);
                        }

                        match state.create_user(create_user).await {
                            Ok((uid, _)) => uid,
                            Err(_) => return Ok(LoginApiResponse::InvalidAccount),
                        }
                    }
                }
            }
            LoginCredential::MetaMask(LoginCredentialMetaMask {
                public_address,
                nonce,
                signature,
                ..
            }) if login_cfg.metamask => {
                // Reference: https://github.com/MetaMask/test-dapp
                // https://metamask.github.io/test-dapp/

                let public_address = public_address.to_lowercase();
                if !check_metamask_public_address(&state, &public_address, &nonce, &signature)
                    .await?
                {
                    return Ok(LoginApiResponse::InvalidAccount);
                }

                let sql = "select uid from metamask_auth where public_address = ?";
                match sqlx::query_as::<_, (i64,)>(sql)
                    .bind(&public_address)
                    .fetch_optional(&state.db_pool)
                    .await
                    .map_err(InternalServerError)?
                {
                    Some((uid,)) => uid,
                    // create a new user
                    None => {
                        if !can_register {
                            return Ok(LoginApiResponse::AccountNotAssociated);
                        }

                        let name = state.cache.write().await.assign_username(None, None);
                        let create_user = CreateUser::new(
                            &name,
                            CreateUserBy::MetaMask {
                                public_address: &public_address,
                            },
                            false,
                        );
                        match state.create_user(create_user).await {
                            Ok((uid, _)) => uid,
                            Err(_) => return Ok(LoginApiResponse::InvalidAccount),
                        }
                    }
                }
            }
            LoginCredential::ThirdParty(LoginCredentialThirdParty { key })
                if login_cfg.third_party =>
            {
                let data = match hex::decode(&key) {
                    Ok(data) => data,
                    Err(_) => return Ok(LoginApiResponse::InvalidAccount),
                };
                let key_config = state.key_config.read().await;
                let mut mac =
                    hmac::Hmac::<Sha256>::new_from_slice(key_config.server_key.as_bytes()).unwrap();
                mac.update(&data[32..]);
                if mac.verify(&data[..32]).is_err() {
                    return Ok(LoginApiResponse::InvalidAccount);
                }
                let info: ThirdPartyLoginInfo = match serde_json::from_slice(&data[32..]) {
                    Ok(info) => info,
                    Err(_) => return Ok(LoginApiResponse::InvalidAccount),
                };
                if info.expired_at < Utc::now() {
                    return Ok(LoginApiResponse::InvalidAccount);
                }

                let sql = "select uid from third_party_users where userid = ?";
                match sqlx::query_as::<_, (i64,)>(sql)
                    .bind(&info.userid)
                    .fetch_optional(&state.db_pool)
                    .await
                    .map_err(InternalServerError)?
                {
                    Some((uid,)) => uid,
                    // create a new user
                    None => {
                        let name = state
                            .cache
                            .write()
                            .await
                            .assign_username(Some(&info.username), None);
                        let create_user = CreateUser::new(
                            &name,
                            CreateUserBy::ThirdParty {
                                username: &info.username,
                            },
                            false,
                        );
                        match state.create_user(create_user).await {
                            Ok((uid, _)) => uid,
                            Err(_) => return Ok(LoginApiResponse::InvalidAccount),
                        }
                    }
                }
            }
            _ => return Ok(LoginApiResponse::LoginMethodNotSupported),
        };

        do_login(&state, uid, &req.0.device, req.0.device_token.as_deref()).await
    }

    /// Bind credential
    #[oai(path = "/bind", method = "post")]
    async fn bind(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<BindRequest>,
    ) -> Result<BindApiResponse> {
        let login_cfg = state
            .get_dynamic_config_instance::<LoginConfig>()
            .await
            .unwrap_or_default();

        match req.0.credential {
            BindCredential::GoogleIdToken(id_token) if login_cfg.google => {
                if get_credential_google(&state, token.uid).await?.is_some() {
                    return Ok(BindApiResponse::Exists);
                }
                match parse_google_id_token(&id_token.id_token).await {
                    Ok(GoogleIdTokenPayload { email, .. }) => {
                        let sql = "insert into google_auth (email, uid) values (?, ?)";
                        sqlx::query(sql)
                            .bind(email)
                            .bind(token.uid)
                            .execute(&state.db_pool)
                            .await
                            .map_err(InternalServerError)?;
                    }
                    Err(_) => return Ok(BindApiResponse::InvalidCredential),
                }
            }
            BindCredential::GithubCode(code) if login_cfg.github => {
                if get_credential_github(&state, token.uid).await?.is_some() {
                    return Ok(BindApiResponse::Exists);
                }
                let github_token = github_fetch_token(&code.code, &state).await?;
                match github_fetch_user_info(&github_token).await {
                    Ok((username, _avatar_url)) => {
                        let sql = "insert into github_auth (username, uid) values (?, ?)";
                        sqlx::query(sql)
                            .bind(username)
                            .bind(token.uid)
                            .execute(&state.db_pool)
                            .await
                            .map_err(InternalServerError)?;
                    }
                    Err(_) => return Ok(BindApiResponse::InvalidCredential),
                };
            }
            BindCredential::OpenIdConnect(LoginCredentialOpenIdConnect {
                code,
                oidc_state,
                ..
            }) => {
                let item = {
                    let mut pending_oidc = state.pending_oidc.lock().await;
                    match pending_oidc.remove(&oidc_state) {
                        Some(item) => item,
                        None => {
                            tracing::debug!("oidc id does not exist");
                            return Ok(BindApiResponse::InvalidCredential);
                        }
                    }
                };

                if get_credentials_openid(&state, token.uid)
                    .await?
                    .iter()
                    .any(|issuer| &item.issuer == issuer)
                {
                    return Ok(BindApiResponse::Exists);
                }

                tracing::debug!("wait for oauth2 response");

                let issuer = item.issuer.clone();
                let id_token = match oidc_get_id_token(item, code, oidc_state).await {
                    Ok(id_token) => id_token,
                    Err(_) => return Ok(BindApiResponse::InvalidCredential),
                };

                let sql = "insert into openid_connect (issuer, subject, uid) values (?, ?, ?)";
                sqlx::query(sql)
                    .bind(&issuer)
                    .bind(id_token.subject().as_str())
                    .bind(token.uid)
                    .execute(&state.db_pool)
                    .await
                    .map_err(InternalServerError)?;
            }
            BindCredential::MetaMask(LoginCredentialMetaMask {
                public_address,
                nonce,
                signature,
                ..
            }) if login_cfg.metamask => {
                if get_credential_metamask(&state, token.uid).await?.is_some() {
                    return Ok(BindApiResponse::Exists);
                }

                let public_address = public_address.to_lowercase();
                if !check_metamask_public_address(&state, &public_address, &nonce, &signature)
                    .await?
                {
                    return Ok(BindApiResponse::InvalidCredential);
                }

                let sql = "insert into metamask_auth (public_address, uid) values (?, ?)";
                sqlx::query(sql)
                    .bind(public_address)
                    .bind(token.uid)
                    .execute(&state.db_pool)
                    .await
                    .map_err(InternalServerError)?;
            }
            _ => return Ok(BindApiResponse::LoginMethodNotSupported),
        }

        Ok(BindApiResponse::Ok)
    }

    /// Get the credentials of current user
    #[oai(path = "/credentials", method = "get")]
    async fn credentials(
        &self,
        state: Data<&State>,
        token: Token,
    ) -> Result<Json<CredentialsResponse>> {
        let cache = state.cache.read().await;
        let cached_user = cache
            .users
            .get(&token.uid)
            .ok_or_else(|| Error::from(StatusCode::UNAUTHORIZED))?;

        Ok(Json(CredentialsResponse {
            password: cached_user.password.is_some(),
            google: get_credential_google(&state, token.uid).await?,
            metamask: get_credential_metamask(&state, token.uid).await?,
            oidc: get_credentials_openid(&state, token.uid).await?,
        }))
    }

    /// Renew the refresh token
    #[oai(path = "/renew", method = "post")]
    async fn renew(
        &self,
        state: Data<&State>,
        req: Json<RenewTokenRequest>,
    ) -> Result<RenewTokenApiResponse> {
        let key_config = state.key_config.read().await;
        let (token_type1, current_user1): (TokenType, CurrentUser) =
            match rc_token::parse_token(&key_config.server_key, &req.token, false) {
                Ok(res) => res,
                Err(_) => return Ok(RenewTokenApiResponse::IllegalToken),
            };
        if token_type1 != TokenType::AccessToken {
            return Ok(RenewTokenApiResponse::IllegalToken);
        }

        let (token_type2, current_user2): (TokenType, CurrentUser) =
            match rc_token::parse_token(&key_config.server_key, &req.refresh_token, true) {
                Ok(res) => res,
                Err(_) => return Ok(RenewTokenApiResponse::IllegalToken),
            };
        if token_type2 != TokenType::RefreshToken {
            return Ok(RenewTokenApiResponse::IllegalToken);
        }

        if current_user1 != current_user2 {
            return Ok(RenewTokenApiResponse::IllegalToken);
        }

        let (prev_refresh_token,) = match sqlx::query_as::<_, (String,)>(
            "select token from refresh_token where uid = ? and device = ?",
        )
        .bind(current_user1.uid)
        .bind(&current_user1.device)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(InternalServerError)?
        {
            Some(res) => res,
            None => return Ok(RenewTokenApiResponse::IllegalToken),
        };

        if prev_refresh_token != req.refresh_token {
            return Ok(RenewTokenApiResponse::IllegalToken);
        }

        let (refresh_token, token) = rc_token::create_token_pair(
            &key_config.server_key,
            current_user1.clone(),
            state.config.system.refresh_token_expiry_seconds,
            state.config.system.token_expiry_seconds,
        )
        .map_err(InternalServerError)?;

        sqlx::query("update refresh_token set token = ? where uid = ? and device = ?")
            .bind(&refresh_token)
            .bind(current_user1.uid)
            .bind(current_user1.device)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;

        Ok(RenewTokenApiResponse::Ok(Json(RenewTokenResponse {
            token,
            refresh_token,
            expired_in: state.config.system.token_expiry_seconds,
        })))
    }

    /// Logout
    #[oai(path = "/logout", method = "get")]
    async fn logout(&self, state: Data<&State>, token: Token) -> Result<LogoutApiResponse> {
        let mut cache = state.cache.write().await;
        let cached_user = match cache.users.get_mut(&token.uid) {
            Some(cached_user) => cached_user,
            None => return Ok(LogoutApiResponse::IllegalToken),
        };

        sqlx::query("delete from refresh_token where uid = ? and device = ?")
            .bind(token.uid)
            .bind(&token.device)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;

        // close events connection
        if let Some(sender) = cached_user
            .devices
            .get_mut(&token.device)
            .and_then(|device| device.sender.take())
        {
            let _ = sender.send(UserEvent::Kick {
                reason: KickReason::Logout,
            });
        }

        Ok(LogoutApiResponse::Ok)
    }

    /// Update FCM device token
    #[oai(path = "/device_token", method = "put")]
    async fn update_device_token(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<UpdateDeviceTokenRequest>,
    ) -> Result<()> {
        let mut cache = state.cache.write().await;
        let cached_user = match cache.users.get_mut(&token.uid) {
            Some(cached_user) => cached_user,
            None => return Err(Error::from_status(StatusCode::NOT_FOUND)),
        };

        // update sqlite
        let sql = "update device set device_token = ?, updated_at = ? where uid = ? and device = ?";
        sqlx::query(sql)
            .bind(&req.device_token)
            .bind(DateTime::now())
            .bind(token.uid)
            .bind(&token.device)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;

        // update cache
        if let Some(cache_device) = cached_user.devices.get_mut(&token.device) {
            cache_device.device_token = req.0.device_token;
        }

        Ok(())
    }
}

pub async fn do_login(
    state: &State,
    uid: i64,
    device: &str,
    device_token: Option<&str>,
) -> Result<LoginApiResponse> {
    let mut cache = state.cache.write().await;
    let cached_user = match cache.users.get_mut(&uid) {
        Some(cached_user) => cached_user,
        None => return Ok(LoginApiResponse::UserDoesNotExist),
    };

    if cached_user.status == UserStatus::Frozen {
        return Ok(LoginApiResponse::Frozen);
    }

    // update refresh token
    let key_config = state.key_config.read().await;
    let (refresh_token, token) = rc_token::create_token_pair(
        &key_config.server_key,
        CurrentUser {
            uid,
            device: device.to_string(),
            is_admin: cached_user.is_admin,
        },
        state.config.system.refresh_token_expiry_seconds,
        state.config.system.token_expiry_seconds,
    )
    .map_err(InternalServerError)?;

    let mut tx = state.db_pool.begin().await.map_err(InternalServerError)?;

    sqlx::query(
        r#"
        insert into refresh_token (uid, device, token) values (?, ?, ?)
            on conflict (uid, device) do update set token = excluded.token
        "#,
    )
    .bind(uid)
    .bind(device)
    .bind(&refresh_token)
    .execute(&mut tx)
    .await
    .map_err(InternalServerError)?;

    // update device token
    sqlx::query(
        r#"
        insert into device (uid, device, device_token) values (?, ?, ?)
            on conflict (uid, device) do update set device_token = excluded.device_token
        "#,
    )
    .bind(uid)
    .bind(device)
    .bind(device_token)
    .execute(&mut tx)
    .await
    .map_err(InternalServerError)?;

    tx.commit().await.map_err(InternalServerError)?;

    cached_user
        .devices
        .entry(device.to_string())
        .and_modify(|device| {
            device.device_token = device_token.map(ToString::to_string);
        })
        .or_insert_with(|| CacheDevice {
            device_token: device_token.map(ToString::to_string),
            sender: None,
        });

    Ok(LoginApiResponse::Ok(Json(LoginResponse {
        server_id: key_config.server_id.clone(),
        token,
        refresh_token,
        expired_in: state.config.system.token_expiry_seconds,
        user: cached_user.api_user_info(uid),
    })))
}

async fn download_avatar(url: &str) -> anyhow::Result<Bytes> {
    Ok(reqwest::get(url)
        .and_then(|resp| async move { resp.error_for_status() })
        .and_then(|resp| resp.bytes())
        .await?)
}

#[cfg(not(test))]
async fn parse_google_id_token(token: &str) -> anyhow::Result<GoogleIdTokenPayload> {
    use jsonwebtoken::{
        decode_header,
        jwk::{AlgorithmParameters, JwkSet},
        DecodingKey, Validation,
    };

    let jwks = reqwest::get("https://www.googleapis.com/oauth2/v3/certs")
        .await?
        .error_for_status()?
        .json::<JwkSet>()
        .await?;
    let header = decode_header(token)?;
    let kid = header
        .kid
        .ok_or_else(|| anyhow::anyhow!("Token doesn't have a `kid` header field"))?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| anyhow::anyhow!("No matching JWK found for the given kid"))?;
    match &jwk.algorithm {
        AlgorithmParameters::RSA(rsa) => {
            let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e)?;
            let mut validation = Validation::new(jwk.common.algorithm.unwrap());
            validation.iss = Some(
                vec![
                    "accounts.google.com".to_string(),
                    "https://accounts.google.com".to_string(),
                ]
                .into_iter()
                .collect(),
            );
            let token =
                jsonwebtoken::decode::<GoogleIdTokenPayload>(token, &decoding_key, &validation)?;
            Ok(token.claims)
        }
        _ => anyhow::bail!("Not supported"),
    }
}

// curl -d "client_id=xxxxx&client_secret=xxxxx&code=xxxx&redirect_uri=http://localhost:3000/" https://github.com/login/oauth/access_token
async fn github_fetch_token(code: &str, state: &State) -> anyhow::Result<String> {
    use crate::api::admin_github_auth::GithubAuthConfig;
    let entry = state.load_dynamic_config::<GithubAuthConfig>().await?;

    let params = [
        ("client_id", entry.config.client_id),
        ("client_secret", entry.config.client_secret),
        ("code", code.to_string()),
    ]; // , ("redirect_uri", "")
    let client = reqwest::Client::new();
    let res = client
        .post("https://github.com/login/oauth/access_token")
        .header("User-Agent", "Vocechat")
        .form(&params)
        .send()
        .await?;
    // access_token=xxxxx&scope=user&token_type=bearer
    // error=bad_verification_code&
    // error_description=The+code+passed+is+incorrect+or+expired.&error_uri=https%
    // 3A%2F%2Fdocs.github.com%2Fapps%2Fmanaging-oauth
    let body = res.text().await?;
    tracing::debug!(body = body.as_str());
    let pairs = serde_urlencoded::from_str::<HashMap<String, String>>(&body)?;
    let access_token = pairs.get("access_token").cloned().unwrap_or_default();
    Ok(access_token)
}

// curl -H "Authorization: token xxxxxxxx" https://api.github.com/user
// {
// "login": "RustChater",
// "id": 123456,
// "node_id": "ADQ6GXNlcjg3NDU7NzQw",
// "avatar_url": "https://avatars.githubusercontent.com/u/87459740?v=4",
// "gravatar_id": "",
// "url": "https://api.github.com/users/RustChater",
// "html_url": "https://github.com/RustChater",
// "followers_url": "https://api.github.com/users/RustChater/followers",
// "following_url": "https://api.github.com/users/RustChater/following{/other_user}",
// "gists_url": "https://api.github.com/users/RustChater/gists{/gist_id}",
// "starred_url": "https://api.github.com/users/RustChater/starred{/owner}{/repo}",
// "subscriptions_url": "https://api.github.com/users/RustChater/subscriptions",
// "organizations_url": "https://api.github.com/users/RustChater/orgs",
// "repos_url": "https://api.github.com/users/RustChater/repos",
// "events_url": "https://api.github.com/users/RustChater/events{/privacy}",
// "received_events_url": "https://api.github.com/users/RustChater/received_events",
// "type": "User",
// "site_admin": false,
// "name": null,
// "company": null,
// "blog": "",
// "location": null,
// "email": null,
// "hireable": null,
// "bio": null,
// "twitter_username": null,
// "public_repos": 15,
// "public_gists": 0,
// "followers": 0,
// "following": 0,
// "created_at": "2021-07-15T03:44:12Z",
// "updated_at": "2022-05-21T07:18:06Z",
// "private_gists": 0,
// "total_private_repos": 4,
// "owned_private_repos": 4,
// "disk_usage": 3812,
// "collaborators": 0,
// "two_factor_authentication": false,
// "plan": {
// "name": "free",
// "space": 976562499,
// "collaborators": 0,
// "private_repos": 10000
// }
// }
async fn github_fetch_user_info(token: &str) -> anyhow::Result<(String, String)> {
    let client = reqwest::Client::new();
    let res = client
        .get("https://api.github.com/user")
        .header("User-Agent", "Vocechat")
        .header("Authorization", format!("token {}", token))
        .send()
        .await?;
    // access_token=xxxxx&scope=user&token_type=bearer
    let body = res.text().await?;
    tracing::debug!(body = body.as_str());
    let pairs: serde_json::Value = serde_json::from_str(&body)?;
    let username = pairs
        .get("login")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let avatar_url = pairs
        .get("avatar_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    // let pairs = serde_urlencoded::from_str::<Vec(String, String)>(&body)?;
    // let username = pairs.get("login").cloned().ok_or(anyhow::anyhow!("expect
    // username"))?; let avatar_url =
    // pairs.get("avatar_url").cloned().ok_or(anyhow::anyhow!("expect
    // avatar_url"))?;
    Ok((username, avatar_url))
}

async fn oidc_get_id_token(
    item: OAuth2State,
    code: String,
    state: String,
) -> anyhow::Result<CoreIdTokenClaims> {
    let code = AuthorizationCode::new(code);

    anyhow::ensure!(&state == item.csrf_token.secret(), "invalid csrf token");

    // Exchange the code with a token.
    let token_response = match item
        .client
        .exchange_code(code)
        .set_pkce_verifier(item.pkce_verifier)
        .request_async(openidconnect::reqwest::async_http_client)
        .await
    {
        Ok(token_response) => token_response,
        Err(err) => {
            tracing::debug!(error = %err, "failed to exchange the code with a token");
            return Err(err.into());
        }
    };

    let id_token_verifier: CoreIdTokenVerifier = item
        .client
        .id_token_verifier()
        .set_other_audience_verifier_fn(|aud| aud.as_str() == "solid")
        .set_allowed_algs(vec![
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            CoreJwsSigningAlgorithm::EcdsaP256Sha256,
        ]);
    let id_token = match token_response.extra_fields().id_token() {
        Some(id_token) => id_token,
        None => {
            tracing::debug!("id token does not exist");
            anyhow::bail!("expect id token");
        }
    };
    let id_token_claims: &CoreIdTokenClaims = match id_token.claims(&id_token_verifier, &item.nonce)
    {
        Ok(id_token_claims) => id_token_claims,
        Err(err) => {
            tracing::debug!(error = %err, "failed to verify claims");
            return Err(err.into());
        }
    };

    tracing::debug!("success get id token");
    Ok(id_token_claims.clone())
}

#[cfg(test)]
async fn parse_google_id_token(_token: &str) -> anyhow::Result<GoogleIdTokenPayload> {
    Ok(GoogleIdTokenPayload {
        email: "test@gmail.com".to_string(),
        name: Some("test".to_string()),
        picture: None,
    })
}

async fn check_metamask_public_address(
    state: &State,
    public_address: &str,
    nonce: &str,
    signature: &str,
) -> anyhow::Result<bool> {
    if !signature.starts_with("0x") {
        return Ok(false);
    }
    let signature = hex::decode(&signature[2..])?;
    if signature.len() < 64 {
        return Ok(false);
    }
    let sql = "select nonce from metamask_nonce where public_address = ?";
    let db_nonce = sqlx::query_as::<_, (String,)>(sql)
        .bind(&public_address)
        .fetch_optional(&state.db_pool)
        .await?
        .map(|(nonce,)| nonce);
    if db_nonce.as_deref() != Some(nonce) {
        return Ok(false);
    }
    let message = web3::signing::hash_message(&nonce);
    let recovery = web3::types::Recovery::from_raw_signature(message.as_bytes(), &signature)?;
    let address = web3::signing::recover(
        message.as_bytes(),
        &signature[..64],
        recovery.recovery_id().unwrap_or_default(),
    )?;
    Ok(format!("0x{}", hex::encode(&address)) == public_address)
}

async fn get_credential_google(state: &State, uid: i64) -> anyhow::Result<Option<String>> {
    let sql = "select email from google_auth where uid = ?";
    Ok(sqlx::query_as::<_, (String,)>(sql)
        .bind(uid)
        .fetch_optional(&state.db_pool)
        .await?
        .map(|(email,)| email))
}

async fn get_credential_github(state: &State, uid: i64) -> anyhow::Result<Option<String>> {
    let sql = "select username from github_auth where uid = ?";
    Ok(sqlx::query_as::<_, (String,)>(sql)
        .bind(uid)
        .fetch_optional(&state.db_pool)
        .await?
        .map(|(username,)| username))
}

async fn get_credential_metamask(state: &State, uid: i64) -> anyhow::Result<Option<String>> {
    let sql = "select public_address from metamask_auth where uid = ?";
    Ok(sqlx::query_as::<_, (String,)>(sql)
        .bind(uid)
        .fetch_optional(&state.db_pool)
        .await?
        .map(|(public_address,)| public_address))
}

async fn get_credentials_openid(state: &State, uid: i64) -> anyhow::Result<Vec<String>> {
    let sql = "select issuer from openid_connect where uid = ?";
    Ok(sqlx::query_as::<_, (String,)>(sql)
        .bind(uid)
        .fetch_all(&state.db_pool)
        .await?
        .into_iter()
        .map(|(issuer,)| issuer)
        .collect())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use poem::http::StatusCode;
    use serde_json::json;

    use crate::test_harness::TestServer;

    async fn login(server: &TestServer) -> String {
        let resp = server
            .post("/api/token/login")
            .body_json(&json!({
                "credential": {
                    "type": "password",
                    "email": "admin@voce.chat",
                    "password": "123456",
                },
                "device": "iphone",
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

    #[tokio::test]
    async fn test_login() {
        let server = TestServer::new().await;

        let resp = server
            .post("/api/token/login")
            .body_json(&json!({
                "credential": {
                    "type": "password",
                    "email": "admin@voce.chat",
                    "password": "123456",
                },
                "device": "iphone",
                "device_token": "test",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let obj = json.value().object();
        assert_eq!(server.parse_token(obj.get("token").string()).await.uid, 1);
        assert_eq!(
            server
                .parse_token(obj.get("refresh_token").string())
                .await
                .uid,
            1
        );
    }

    #[tokio::test]
    async fn test_login_with_google_id_token() {
        let server = TestServer::new().await;

        server
            .post("/api/token/login")
            .body_json(&json!({
                "credential": {
                    "type": "google",
                    "id_token": "abc",
                    "magic_token": "",
                },
                "device": "iphone",
                "device_token": "test",
            }))
            .send()
            .await
            .assert_status_is_ok();
    }

    // #[tokio::test]
    // async fn test_login_with_google_id_token_conflict_email() {
    //     let server = TestServer::new().await;
    //     let admin_token = server.login_admin().await;
    //     server.create_user(&admin_token, "test@gmail.com").await;
    //
    //     server
    //         .post("/api/token/login")
    //         .body_json(&json!({
    //             "credential": {
    //                 "type": "google",
    //                 "id_token": "abc",
    //             },
    //             "device": "iphone",
    //             "device_token": "test",
    //         }))
    //         .send()
    //         .await
    //         .assert_status(StatusCode::CONFLICT);
    // }

    #[tokio::test]
    async fn test_renew() {
        let server = TestServer::new().await;

        // login
        let resp = server
            .post("/api/token/login")
            .body_json(&json!({
                "credential": {
                    "type": "password",
                    "email": "admin@voce.chat",
                    "password": "123456",
                },
                "device": "iphone",
                "device_token": "test",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let obj = json.value().object();
        let token = obj.get("token").string();
        let refresh_token = obj.get("refresh_token").string();

        // renew
        let resp = server
            .post("/api/token/renew")
            .body_json(&json!({
                "token": token,
                "refresh_token": refresh_token,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
    }

    #[tokio::test]
    async fn test_logout() {
        let server = TestServer::new().await;

        // login
        let token = login(&server).await;

        // logout
        let resp = server
            .get("/api/token/logout")
            .header("X-API-Key", &token)
            .send()
            .await;
        resp.assert_status_is_ok();
    }

    #[tokio::test]
    async fn test_renew_with_expired_token() {
        let server = TestServer::new_with_config(|cfg| {
            cfg.system.token_expiry_seconds = 3;
        })
        .await;

        // login
        let resp = server
            .post("/api/token/login")
            .body_json(&json!({
                "credential": {
                    "type": "password",
                    "email": "admin@voce.chat",
                    "password": "123456",
                },
                "device": "iphone",
                "device_token": "test",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let obj = json.value().object();
        let token = obj.get("token").string();
        let refresh_token = obj.get("refresh_token").string();

        tokio::time::sleep(Duration::from_secs(5)).await;

        // use the old token
        let resp = server
            .get("/api/user/me")
            .header("X-API-Key", token)
            .send()
            .await;
        resp.assert_status(StatusCode::UNAUTHORIZED);

        // renew
        let resp = server
            .post("/api/token/renew")
            .body_json(&json!({
                "token": token,
                "refresh_token": refresh_token,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let obj = json.value().object();
        let new_token = obj.get("token").string();

        // use the new token
        let resp = server
            .get("/api/user/me")
            .header("X-API-Key", new_token)
            .send()
            .await;
        resp.assert_status_is_ok();
    }

    #[tokio::test]
    async fn test_login_with_metamask() {
        let server = TestServer::new().await;
        let public_address = "0x203911a828e486e9c6464e70084ae9a53f855d26";
        let nonce = "Example `personal_sign` message";
        let signature = "0x73043b9af49b11c504962664991020c6a2a7d88a022fc9917e1ec05fa3ea35b75b193cd6e54dfbb8840508908feee688f7bc9fd408fc6c479d0706568acd5df11c";

        sqlx::query("insert into metamask_nonce (public_address, nonce) values (?, ?)")
            .bind(public_address)
            .bind(nonce)
            .execute(&server.state().db_pool)
            .await
            .unwrap();

        // login
        let resp = server
            .post("/api/token/login")
            .body_json(&json!({
                "credential": {
                    "type": "metamask",
                    "public_address": public_address,
                    "nonce": nonce,
                    "signature": signature,
                }
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
    }

    #[tokio::test]
    async fn test_update_device_token() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin_with_device("web").await;

        let resp = server
            .put("/api/token/device_token")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "device_token": "abc"
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        assert_eq!(
            server
                .state()
                .cache
                .read()
                .await
                .users
                .get(&1)
                .unwrap()
                .devices
                .get("web")
                .unwrap()
                .device_token
                .as_deref(),
            Some("abc")
        );

        let device_token2 = sqlx::query_as::<_, (Option<String>,)>(
            "select device_token from device where uid = ? and device = ?",
        )
        .bind(1)
        .bind("web")
        .fetch_one(&server.state().db_pool)
        .await
        .map(|(t,)| t)
        .unwrap();
        assert_eq!(device_token2.as_deref(), Some("abc"));

        let resp = server
            .put("/api/token/device_token")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({ "device_token": null }))
            .send()
            .await;
        resp.assert_status_is_ok();

        assert!(server
            .state()
            .cache
            .read()
            .await
            .users
            .get(&1)
            .unwrap()
            .devices
            .get("web")
            .unwrap()
            .device_token
            .is_none());

        let device_token2 = sqlx::query_as::<_, (Option<String>,)>(
            "select device_token from device where uid = ? and device = ?",
        )
        .bind(1)
        .bind("web")
        .fetch_one(&server.state().db_pool)
        .await
        .map(|(t,)| t)
        .unwrap();
        assert_eq!(device_token2, None);
    }

    #[tokio::test]
    async fn test_login_with_third_party() {
        let server = TestServer::new().await;

        let resp = server
            .post("/api/token/create_third_party_key")
            .body_json(&json!({
                "userid": "u1",
                "username": "usertest"
            }))
            .header(
                "X-SECRET",
                &server.state().key_config.read().await.third_party_secret,
            )
            .send()
            .await;
        resp.assert_status_is_ok();
        let key = resp.json().await.value().string().to_string();

        let resp = server
            .post("/api/token/login")
            .body_json(&json!({
                "credential": {
                    "type": "thirdparty",
                    "key": key,
                }
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let obj = json.value().object();
        let user = obj.get("user").object();
        user.get("name").assert_string("usertest");
    }
}
