use std::sync::Arc;

use poem::error::InternalServerError;
use reqwest::StatusCode;
use tokio::sync::{RwLockMappedWriteGuard, RwLockWriteGuard};

use crate::{
    api::{DateTime, LangId, UpdateAction, UserUpdateLog},
    state::{BroadcastEvent, CacheUser, UserStatus},
    State,
};

#[derive(Debug)]
pub enum CreateUserBy<'a> {
    Guest,
    Password {
        email: &'a str,
        password: &'a str,
    },
    MagicLink {
        email: &'a str,
    },
    Google {
        email: &'a str,
    },
    Github {
        username: &'a str,
    },
    OpenIdConnect {
        issuer: &'a str,
        subject: &'a str,
        email: Option<&'a str>,
    },
    MetaMask {
        public_address: &'a str,
    },
    ThirdParty {
        thirdparty_uid: &'a str,
        username: &'a str,
    },
}

impl<'a> CreateUserBy<'a> {
    fn type_name(&self) -> &'static str {
        match self {
            CreateUserBy::Guest => "guest",
            CreateUserBy::Password { .. } => "password",
            CreateUserBy::MagicLink { .. } => "magiclink",
            CreateUserBy::Google { .. } => "google",
            CreateUserBy::Github { .. } => "github",
            CreateUserBy::OpenIdConnect { .. } => "oidc",
            CreateUserBy::MetaMask { .. } => "metamask",
            CreateUserBy::ThirdParty { .. } => "thirdparty",
        }
    }

    fn email(&self) -> Option<&'a str> {
        match self {
            CreateUserBy::Guest => None,
            CreateUserBy::Password { email, .. } => Some(*email),
            CreateUserBy::MagicLink { email } => Some(*email),
            CreateUserBy::Google { email } => Some(*email),
            CreateUserBy::Github { username } => Some(*username),
            CreateUserBy::OpenIdConnect { email, .. } => *email,
            CreateUserBy::MetaMask { .. } => None,
            CreateUserBy::ThirdParty { .. } => None,
        }
    }

    fn password(&self) -> Option<&'a str> {
        match self {
            CreateUserBy::Guest => None,
            CreateUserBy::Password { password, .. } => Some(*password),
            CreateUserBy::MagicLink { .. } => None,
            CreateUserBy::Google { .. } => None,
            CreateUserBy::Github { .. } => None,
            CreateUserBy::OpenIdConnect { .. } => None,
            CreateUserBy::MetaMask { .. } => None,
            CreateUserBy::ThirdParty { .. } => None,
        }
    }
}

#[derive(Debug)]
pub struct CreateUser<'a> {
    name: &'a str,
    gender: i32,
    is_admin: bool,
    language: Option<&'a LangId>,
    avatar: Option<&'a [u8]>,
    create_by: CreateUserBy<'a>,
    webhook_url: Option<&'a str>,
    is_bot: bool,
}

impl<'a> CreateUser<'a> {
    pub fn new(name: &'a str, create_by: CreateUserBy<'a>, is_admin: bool) -> Self {
        Self {
            name,
            gender: 0,
            is_admin,
            language: None,
            avatar: None,
            create_by,
            webhook_url: None,
            is_bot: false,
        }
    }

    pub fn gender(self, gender: i32) -> Self {
        Self { gender, ..self }
    }

    pub fn set_admin(self, is_admin: bool) -> Self {
        Self { is_admin, ..self }
    }

    pub fn set_bot(self, is_bot: bool) -> Self {
        Self { is_bot, ..self }
    }

    pub fn language(self, language: &'a LangId) -> Self {
        Self {
            language: Some(language),
            ..self
        }
    }

    pub fn avatar(self, avatar: &'a [u8]) -> Self {
        Self {
            avatar: Some(avatar),
            ..self
        }
    }

    pub fn webhook_url(self, webhook_url: &'a str) -> Self {
        Self {
            webhook_url: Some(webhook_url),
            ..self
        }
    }
}

#[derive(Debug)]
pub enum CreateUserError {
    NameConflict,
    EmailConflict,
    PoemError(poem::Error),
}

impl From<poem::Error> for CreateUserError {
    fn from(err: poem::Error) -> Self {
        CreateUserError::PoemError(err)
    }
}

impl State {
    pub async fn create_user(
        &self,
        create_user: CreateUser<'_>,
    ) -> Result<(i64, RwLockMappedWriteGuard<'_, CacheUser>), CreateUserError> {
        let email = create_user.create_by.email();
        let password = create_user.create_by.password();
        let language = create_user.language.cloned().unwrap_or_default();
        let mut cache = self.cache.write().await;
        let is_guest = matches!(&create_user.create_by, CreateUserBy::Guest);

        // check license
        {
            if cache
                .users
                .iter()
                .filter(|(_, user)| !user.is_guest)
                .count()
                >= crate::license::G_LICENSE.lock().await.user_limit as usize
            {
                return Err(CreateUserError::PoemError(poem::Error::from_string(
                    "License error: Users reached limit.",
                    StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                )));
            }
        }

        if !cache.check_name_conflict(create_user.name) {
            return Err(CreateUserError::NameConflict);
        }
        if let Some(email) = email {
            if !cache.check_email_conflict(email) {
                return Err(CreateUserError::EmailConflict);
            }
        }

        let now = DateTime::now();

        // update sqlite
        let mut tx = self.db_pool.begin().await.map_err(InternalServerError)?;

        // insert into user table
        let avatar_updated_at = if create_user.avatar.is_some() {
            now
        } else {
            DateTime::zero()
        };
        let sql = "insert into user (name, password, email, gender, language, is_admin, create_by, avatar_updated_at, status, created_at, updated_at, is_guest, webhook_url, is_bot) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        let uid = sqlx::query(sql)
            .bind(create_user.name)
            .bind(password)
            .bind(email)
            .bind(create_user.gender)
            .bind(&language)
            .bind(create_user.is_admin)
            .bind(create_user.create_by.type_name())
            .bind(avatar_updated_at)
            .bind(i8::from(UserStatus::Normal))
            .bind(now)
            .bind(now)
            .bind(is_guest)
            .bind(create_user.webhook_url)
            .bind(create_user.is_bot)
            .execute(&mut tx)
            .await
            .map_err(InternalServerError)?
            .last_insert_rowid();

        if let Some(avatar) = create_user.avatar {
            let _ = self.save_avatar(uid, avatar);
        }

        match &create_user.create_by {
            CreateUserBy::Google { email } => {
                // insert into google_auth
                let sql = "insert into google_auth (email, uid) values (?, ?)";
                sqlx::query(sql)
                    .bind(email)
                    .bind(uid)
                    .execute(&mut tx)
                    .await
                    .map_err(InternalServerError)?;
            }
            CreateUserBy::Github { username } => {
                // insert into google_auth
                let sql = "insert into github_auth (username, uid) values (?, ?)";
                sqlx::query(sql)
                    .bind(username)
                    .bind(uid)
                    .execute(&mut tx)
                    .await
                    .map_err(InternalServerError)?;
            }
            CreateUserBy::OpenIdConnect {
                issuer, subject, ..
            } => {
                // insert into openid_connect
                let sql = "insert into openid_connect (issuer, subject, uid) values (?, ?, ?)";
                sqlx::query(sql)
                    .bind(issuer)
                    .bind(subject)
                    .bind(uid)
                    .execute(&mut tx)
                    .await
                    .map_err(InternalServerError)?;
            }
            CreateUserBy::MetaMask { public_address } => {
                // insert into metamask_auth
                let sql = "insert into metamask_auth (public_address, uid) values (?, ?)";
                sqlx::query(sql)
                    .bind(public_address)
                    .bind(uid)
                    .execute(&mut tx)
                    .await
                    .map_err(InternalServerError)?;
            }
            CreateUserBy::ThirdParty { thirdparty_uid, .. } => {
                let sql = "insert into third_party_users (userid, uid) values (?, ?)";
                sqlx::query(sql)
                    .bind(thirdparty_uid)
                    .bind(uid)
                    .execute(&mut tx)
                    .await
                    .map_err(InternalServerError)?;
            }
            _ => {}
        }

        let log_id = if !is_guest {
            // insert into user_log table
            let sql = "insert into user_log (uid, action, email, name, gender, language, avatar_updated_at, is_admin) values (?, ?, ?, ?, ?, ?, ?, ?)";
            let log_id = sqlx::query(sql)
                .bind(uid)
                .bind(UpdateAction::Create)
                .bind(email)
                .bind(create_user.name)
                .bind(create_user.gender)
                .bind(&language)
                .bind(avatar_updated_at)
                .bind(create_user.is_admin)
                .execute(&mut tx)
                .await
                .map_err(InternalServerError)?
                .last_insert_rowid();
            Some(log_id)
        } else {
            None
        };

        tx.commit().await.map_err(InternalServerError)?;

        // update cache
        cache.users.insert(
            uid,
            CacheUser {
                email: email.map(ToString::to_string),
                name: create_user.name.to_string(),
                password: password.map(ToString::to_string),
                gender: create_user.gender,
                is_admin: create_user.is_admin,
                language: language.clone(),
                create_by: create_user.create_by.type_name().to_string(),
                created_at: now,
                updated_at: now,
                avatar_updated_at,
                devices: Default::default(),
                mute_user: Default::default(),
                mute_group: Default::default(),
                burn_after_reading_user: Default::default(),
                burn_after_reading_group: Default::default(),
                read_index_user: Default::default(),
                read_index_group: Default::default(),
                status: UserStatus::Normal,
                is_guest,
                webhook_url: None,
                is_bot: create_user.is_bot,
            },
        );

        if let Some(log_id) = log_id {
            // broadcast event
            let _ = self
                .event_sender
                .send(Arc::new(BroadcastEvent::UserLog(UserUpdateLog {
                    log_id,
                    action: UpdateAction::Create,
                    uid,
                    email: email.map(ToString::to_string),
                    name: Some(create_user.name.to_string()),
                    gender: create_user.gender.into(),
                    language: Some(language.clone()),
                    is_admin: Some(create_user.is_admin),
                    is_bot: Some(create_user.is_bot),
                    avatar_updated_at: Some(avatar_updated_at),
                })));

            for (gid, group) in cache.groups.iter() {
                if group.ty.is_public() {
                    let _ = self
                        .event_sender
                        .send(Arc::new(BroadcastEvent::UserJoinedGroup {
                            targets: cache.users.keys().copied().collect(),
                            gid: *gid,
                            uid: vec![uid],
                        }));
                }
            }
        }

        Ok((
            uid,
            RwLockWriteGuard::map(cache, |cache| cache.users.get_mut(&uid).unwrap()),
        ))
    }
}
