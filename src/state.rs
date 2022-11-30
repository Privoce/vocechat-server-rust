use std::path::PathBuf;
use std::{
    any::Any,
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime},
};

use chrono::{NaiveDate, Utc};
use futures_util::StreamExt;
use itertools::Itertools;
use num_enum::{FromPrimitive, IntoPrimitive};
use openidconnect::{core::CoreClient, CsrfToken, Nonce, PkceCodeVerifier};
use poem::{
    error::{BadRequest, InternalServerError},
    http::StatusCode,
    Request,
};

use poem_openapi::Enum;
use rc_magic_link::MagicLinkToken;
use rc_msgdb::MsgDb;
use serde::{de::DeserializeOwned, Serialize};
use sqlx::SqlitePool;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use walkdir::WalkDir;

use crate::api::{FrontendUrlConfig, UpdateAction};
use crate::{
    api::{
        get_merged_message, ChatMessage, DateTime, Group, GroupChangedMessage, KickFromGroupReason,
        KickReason, LangId, PinnedMessage, SmtpConfig, User, UserDevice, UserInfo,
        UserSettingsChangedMessage, UserStateChangedMessage, UserUpdateLog,
    },
    config::KeyConfig,
    Config,
};

#[derive(Debug, Copy, Clone)]
pub enum GroupType {
    Public,
    Private { owner: i64 },
}

impl GroupType {
    pub fn is_public(&self) -> bool {
        matches!(self, GroupType::Public)
    }

    pub fn owner(&self) -> Option<i64> {
        match self {
            GroupType::Public => None,
            GroupType::Private { owner } => Some(*owner),
        }
    }
}

pub struct CacheGroup {
    pub ty: GroupType,
    pub name: String,
    pub description: String,
    pub members: BTreeSet<i64>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub avatar_updated_at: DateTime,
    pub pinned_messages: Vec<PinnedMessage>,
}

impl CacheGroup {
    pub fn contains_user(&self, uid: i64) -> bool {
        self.ty.is_public() || self.members.contains(&uid)
    }

    pub fn description_opt(&self) -> Option<String> {
        if !self.description.is_empty() {
            Some(self.description.clone())
        } else {
            None
        }
    }

    pub fn api_group(&self, gid: i64) -> Group {
        Group {
            gid,
            owner: self.ty.owner(),
            name: self.name.clone(),
            description: self.description_opt(),
            members: self.members.iter().copied().collect(),
            is_public: self.ty.is_public(),
            avatar_updated_at: self.avatar_updated_at,
            pinned_messages: self.pinned_messages.clone(),
        }
    }
}

#[derive(Debug)]
pub struct CacheDevice {
    pub device_token: Option<String>,
    pub sender: Option<mpsc::UnboundedSender<UserEvent>>,
}

#[derive(Debug, Copy, Clone, FromPrimitive, IntoPrimitive, Enum, Eq, PartialEq)]
#[oai(rename_all = "lowercase")]
#[repr(i8)]
pub enum UserStatus {
    Normal = 0,
    #[num_enum(default)]
    Frozen = -1,
}

#[derive(Debug)]
pub struct CacheUser {
    pub email: Option<String>,
    pub name: String,
    pub password: Option<String>,
    pub gender: i32,
    pub is_admin: bool,
    pub language: LangId,
    pub create_by: String,
    pub devices: HashMap<String, CacheDevice>,
    pub mute_user: HashMap<i64, Option<DateTime>>,
    pub mute_group: HashMap<i64, Option<DateTime>>,
    pub burn_after_reading_user: HashMap<i64, i64>,
    pub burn_after_reading_group: HashMap<i64, i64>,
    pub read_index_user: HashMap<i64, i64>,
    pub read_index_group: HashMap<i64, i64>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub avatar_updated_at: DateTime,
    pub status: UserStatus,
    pub is_guest: bool,
}

impl CacheUser {
    pub fn is_online(&self) -> bool {
        self.devices.values().any(|device| device.sender.is_some())
    }

    pub fn api_user_info(&self, uid: i64) -> UserInfo {
        UserInfo {
            uid,
            email: self.email.clone(),
            name: self.name.clone(),
            gender: self.gender,
            language: self.language.clone(),
            is_admin: self.is_admin,
            avatar_updated_at: self.avatar_updated_at,
            create_by: self.create_by.clone(),
        }
    }

    pub fn api_user(&self, uid: i64) -> User {
        User {
            uid,
            email: self.email.clone(),
            password: Default::default(),
            name: self.name.clone(),
            gender: self.gender,
            is_admin: self.is_admin,
            language: self.language.clone(),
            create_by: self.create_by.clone(),
            in_online: self.is_online(),
            online_devices: self
                .devices
                .iter()
                .map(|(device, cached_device)| UserDevice {
                    device: device.clone(),
                    device_token: cached_device.device_token.clone(),
                    is_online: cached_device.sender.is_some(),
                })
                .collect(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            avatar_updated_at: self.avatar_updated_at,
            status: self.status,
        }
    }

    pub fn is_user_muted(&self, uid: i64) -> bool {
        let now = DateTime::now();
        match self.mute_user.get(&uid) {
            Some(Some(expired_at)) if expired_at.0 < now.0 => true,
            Some(None) => true,
            _ => false,
        }
    }

    pub fn is_group_muted(&self, gid: i64) -> bool {
        let now = DateTime::now();
        match self.mute_group.get(&gid) {
            Some(Some(expired_at)) if expired_at.0 < now.0 => true,
            Some(None) => true,
            _ => false,
        }
    }

    pub fn burn_after_reading_to_user_expires_in(&self, uid: i64) -> Option<i64> {
        self.burn_after_reading_user.get(&uid).copied()
    }

    pub fn burn_after_reading_to_group_expires_in(&self, gid: i64) -> Option<i64> {
        self.burn_after_reading_group.get(&gid).copied()
    }
}

#[derive(Debug, Clone)]
pub enum BroadcastEvent {
    /// Chat message
    Chat {
        targets: BTreeSet<i64>,
        message: ChatMessage,
    },
    /// Users update log
    UserLog(UserUpdateLog),
    /// Other users joined group
    UserJoinedGroup {
        targets: BTreeSet<i64>,
        gid: i64,
        uid: Vec<i64>,
    },
    /// Other users leaved group
    UserLeavedGroup {
        targets: BTreeSet<i64>,
        gid: i64,
        uid: Vec<i64>,
    },
    /// Join the group
    JoinedGroup {
        targets: BTreeSet<i64>,
        group: Group,
    },
    /// Kick from group
    KickFromGroup {
        targets: BTreeSet<i64>,
        gid: i64,
        reason: KickFromGroupReason,
    },
    /// User state changed
    UserStateChanged(UserStateChangedMessage),
    /// User settings changed
    UserSettingsChanged {
        uid: i64,
        message: UserSettingsChangedMessage,
    },
    /// Group changed
    GroupChanged {
        targets: BTreeSet<i64>,
        msg: GroupChangedMessage,
    },
    /// Pinned message updated
    PinnedMessageUpdated {
        targets: BTreeSet<i64>,
        gid: i64,
        mid: i64,
        msg: Option<PinnedMessage>,
    },
}

#[derive(Debug, Clone)]
pub enum UserEvent {
    /// Kick by other device
    Kick { reason: KickReason },
}

pub struct CodeValue {
    remain_times: i32,
    expired_at: chrono::DateTime<Utc>,
    email: String,
}

#[derive(Default)]
pub struct CodeCache {
    // All sent codes, gc in tokio::spawn()
    pub codes: HashMap<String, CodeValue>,
    // Last code sent to email
    // HashMap<email, code>
    pub email_code: HashMap<String, String>,
}

#[derive(Default)]
pub struct Cache {
    pub dynamic_config: HashMap<&'static str, Box<dyn Any + Send + Sync>>,
    pub groups: BTreeMap<i64, CacheGroup>,
    pub users: BTreeMap<i64, CacheUser>,
    pub codes: CodeCache,
}

impl Cache {
    fn assign_username_by_name<'a>(&self, name: &'a str) -> Cow<'a, str> {
        if self.check_name_conflict(name) {
            return Cow::Borrowed(name);
        }

        loop {
            let new_name = format!("{}{}", name, fastrand::u32(1111..9999));
            if self.check_name_conflict(&new_name) {
                break Cow::Owned(new_name);
            }
        }
    }

    fn assign_username_by_email<'a>(&self, email: &'a str) -> Cow<'a, str> {
        match email.find('@') {
            Some(idx) if idx > 0 => self.assign_username_by_name(&email[..idx]),
            _ => self.assign_username_by_name(email),
        }
    }

    pub fn assign_username<'a>(
        &self,
        name: Option<&'a str>,
        email: Option<&'a str>,
    ) -> Cow<'a, str> {
        if let Some(name) = name {
            self.assign_username_by_name(name)
        } else if let Some(email) = email {
            self.assign_username_by_email(email)
        } else {
            loop {
                let new_name = format!("User{}", fastrand::u32(1111..9999));
                if self.check_name_conflict(&new_name) {
                    break Cow::Owned(new_name);
                }
            }
        }
    }

    pub fn check_name_conflict(&self, name: &str) -> bool {
        !self
            .users
            .values()
            .any(|user| user.name.eq_ignore_ascii_case(name))
    }

    pub fn check_email_conflict(&self, email: &str) -> bool {
        !self.users.values().any(|user| {
            if let Some(user_email) = &user.email {
                user_email.eq_ignore_ascii_case(email)
            } else {
                false
            }
        })
    }
}

pub struct Template {
    pub subject: String,
    pub template: liquid::Template,
}

#[derive(Default)]
pub struct Templates {
    pub register_by_email: Option<Template>,
    pub login_by_email: Option<Template>,
}

pub struct OAuth2State {
    pub client: CoreClient,
    pub issuer: String,
    pub pkce_verifier: PkceCodeVerifier,
    pub csrf_token: CsrfToken,
    pub nonce: Nonce,
}

pub trait DynamicConfig: Serialize + DeserializeOwned + Default {
    type Instance: Send + Sync + 'static;

    fn name() -> &'static str;

    fn create_instance(self) -> Self::Instance;
}

pub struct DynamicConfigEntry<T: DynamicConfig> {
    pub enabled: bool,
    pub config: T,
}

#[derive(Clone)]
pub struct State {
    pub key_config: Arc<RwLock<KeyConfig>>,
    pub config: Arc<Config>,
    pub config_path: PathBuf,
    pub db_pool: SqlitePool,
    pub msg_db: Arc<MsgDb>,
    pub cache: Arc<RwLock<Cache>>,
    pub event_sender: Arc<broadcast::Sender<Arc<BroadcastEvent>>>,
    pub templates: Arc<Templates>,
    pub pending_oidc: Arc<Mutex<HashMap<String, OAuth2State>>>,
    pub msg_updated_channel: Arc<mpsc::UnboundedSender<i64>>,
}

impl State {
    pub async fn load_users_cache(db: &SqlitePool) -> sqlx::Result<BTreeMap<i64, CacheUser>> {
        let mut users = BTreeMap::new();
        let sql = "select uid, email, name, password, gender, is_admin, language, create_by, created_at, updated_at, avatar_updated_at, status, is_guest from user";
        let mut stream = sqlx::query_as::<
            _,
            (
                i64,
                Option<String>,
                String,
                Option<String>,
                i32,
                bool,
                LangId,
                String,
                DateTime,
                DateTime,
                DateTime,
                i8,
                bool,
            ),
        >(sql)
        .fetch(db);
        while let Some(res) = stream.next().await {
            let (
                uid,
                email,
                name,
                password,
                gender,
                is_admin,
                language,
                create_by,
                created_at,
                updated_at,
                avatar_updated_at,
                status,
                is_guest,
            ) = res?;

            let devices = sqlx::query_as::<_, (String, Option<String>)>(
                "select device, device_token from device where uid = ?",
            )
            .bind(uid)
            .fetch_all(db)
            .await?;
            let devices = devices
                .into_iter()
                .map(|(device, device_token)| {
                    (
                        device,
                        CacheDevice {
                            device_token,
                            sender: None,
                        },
                    )
                })
                .collect();

            let sql = "select mute_uid, mute_gid, expired_at from mute where uid = ?";
            let mute = sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<DateTime>)>(sql)
                .bind(uid)
                .fetch_all(db)
                .await?;
            let mut mute_user = HashMap::new();
            let mut mute_group = HashMap::new();
            for (uid, gid, expired_at) in mute {
                match (uid, gid) {
                    (Some(uid), None) => {
                        mute_user.insert(uid, expired_at);
                    }
                    (None, Some(gid)) => {
                        mute_group.insert(gid, expired_at);
                    }
                    _ => {}
                }
            }

            let sql =
                "select target_uid, target_gid, expires_in from burn_after_reading where uid = ?";
            let burn_after_reading = sqlx::query_as::<_, (Option<i64>, Option<i64>, i64)>(sql)
                .bind(uid)
                .fetch_all(db)
                .await?;
            let mut burn_after_reading_user = HashMap::new();
            let mut burn_after_reading_group = HashMap::new();
            for (uid, gid, expires_in) in burn_after_reading {
                match (uid, gid) {
                    (Some(uid), None) => {
                        burn_after_reading_user.insert(uid, expires_in);
                    }
                    (None, Some(gid)) => {
                        burn_after_reading_group.insert(gid, expires_in);
                    }
                    _ => {}
                }
            }

            let sql = "select target_uid, target_gid, mid from read_index where uid = ?";
            let read_index = sqlx::query_as::<_, (Option<i64>, Option<i64>, i64)>(sql)
                .bind(uid)
                .fetch_all(db)
                .await?;
            let mut read_index_user = HashMap::new();
            let mut read_index_group = HashMap::new();
            for (uid, gid, mid) in read_index {
                match (uid, gid) {
                    (Some(uid), None) => {
                        read_index_user.insert(uid, mid);
                    }
                    (None, Some(gid)) => {
                        read_index_group.insert(gid, mid);
                    }
                    _ => {}
                }
            }

            users.insert(
                uid,
                CacheUser {
                    email,
                    name,
                    password,
                    gender,
                    is_admin,
                    language,
                    create_by,
                    devices,
                    mute_user,
                    mute_group,
                    burn_after_reading_user,
                    burn_after_reading_group,
                    read_index_user,
                    read_index_group,
                    created_at,
                    updated_at,
                    avatar_updated_at,
                    status: status.into(),
                    is_guest,
                },
            );
        }

        Ok(users)
    }

    pub async fn load_groups_cache(
        msg_db: &MsgDb,
        db: &SqlitePool,
    ) -> sqlx::Result<BTreeMap<i64, CacheGroup>> {
        let mut groups = BTreeMap::new();

        let sql =
            "select gid, name, description, owner, is_public, created_at, updated_at, avatar_updated_at from `group`";
        let mut stream = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                Option<i64>,
                bool,
                DateTime,
                DateTime,
                DateTime,
            ),
        >(sql)
        .fetch(db);
        while let Some(res) = stream.next().await {
            // load pinned messages
            let sql = "select mid, created_by, created_at from pinned_message where gid = ?";
            let ids = sqlx::query_as::<_, (i64, i64, DateTime)>(sql)
                .fetch_all(db)
                .await?;
            let mut pinned_messages = Vec::new();

            for (mid, created_by, created_at) in ids {
                if let Some(merged_msg) = get_merged_message(msg_db, mid).ok().flatten() {
                    pinned_messages.push(PinnedMessage {
                        mid,
                        created_by,
                        created_at,
                        content: merged_msg.content,
                    });
                }
            }

            pinned_messages.sort_by(|a, b| a.created_at.cmp(&b.created_at));

            let (
                gid,
                name,
                description,
                owner,
                is_public,
                created_at,
                updated_at,
                avatar_updated_at,
            ) = res?;
            groups.insert(
                gid,
                CacheGroup {
                    ty: if is_public {
                        GroupType::Public
                    } else {
                        GroupType::Private {
                            owner: owner.unwrap(),
                        }
                    },
                    name,
                    description,
                    members: Default::default(),
                    created_at,
                    updated_at,
                    avatar_updated_at,
                    pinned_messages,
                },
            );
        }

        let mut stream =
            sqlx::query_as::<_, (i64, i64)>("select gid, uid from group_user").fetch(db);
        while let Some(res) = stream.next().await {
            let (gid, uid) = res?;
            if let Some(conv) = groups.get_mut(&gid) {
                conv.members.insert(uid);
            }
        }

        Ok(groups)
    }

    pub async fn send_login_magic_link(
        &self,
        code: &str,
        url: &str,
        expired_at: chrono::DateTime<Utc>,
        email: &str,
    ) -> poem::Result<String> {
        let template = self
            .templates
            .login_by_email
            .as_ref()
            .ok_or_else(|| poem::Error::from_status(StatusCode::FORBIDDEN))?;

        let uid = {
            let cache = self.cache.read().await;
            cache
                .users
                .iter()
                .find(|(_, user)| user.email.as_deref() == Some(email))
                .map(|(uid, _)| *uid)
        };

        self.login_magic_code_add(code, email, expired_at, 1).await;
        // if !self.magic_code_check_code(code, &email).await {
        //     return Err(poem::Error::from_status(StatusCode::BAD_REQUEST));
        // }

        let magic_token = MagicLinkToken::gen_login_magic_token(
            code,
            &self.key_config.read().await.server_key,
            expired_at,
            email,
            uid,
        );

        let content = template
            .template
            .render(&liquid::object!({
                "magic_token": &magic_token,
                "email": email,
                "url": url,
                "exists": if uid.is_some() { "true" } else { "false" },
            }))
            .map_err(InternalServerError)?;

        tokio::spawn({
            let state = self.clone();
            let subject = template.subject.clone();
            let email = email.to_string();
            async move {
                let smtp_config = state.get_dynamic_config_instance::<SmtpConfig>().await;
                if let Some(smtp_config) = smtp_config {
                    if let Err(err) = send_mail(&smtp_config, email, subject, content).await {
                        tracing::error!(error = %err, "failed to send mail");
                    }
                }
            }
        });

        Ok(magic_token)
    }

    pub async fn magic_code_check_code(&self, code: &str) -> bool {
        let mut cache = self.cache.write().await;
        if let Some(v) = cache.codes.codes.get_mut(code) {
            if v.expired_at < Utc::now() || v.remain_times <= 0 {
                cache.codes.codes.remove(code);
                false
            } else {
                v.remain_times -= -1;
                true
            }
        } else {
            false
        }
    }

    // pub async fn magic_code_check_email(&self, email: &str, code: &code) -> bool{
    //     let mut cache = self.cache.write().await;
    //     if let Some(code) = cache.codes.email_code.get(email) {
    //         if let Some((remain_times, expired_at, email2)) = cache.codes.codes.get_mut(code) {
    //             // if !email2.is_empty() && email2.as_str() != email {
    //             //     return false;
    //             // }
    //             if *expired_at < Utc::now() || *remain_times <= 0 {
    //                 cache.codes.codes.remove(code);
    //                 false
    //             } else {
    //                 *remain_times -= -1;
    //                 *email2 = email.to_string();
    //                 cache
    //                     .codes
    //                     .email_code
    //                     .insert(email.to_string(), code.to_string());
    //                 true
    //             }
    //         } else {
    //             false
    //         }
    //     }
    //
    // }

    pub async fn reg_magic_code_add(
        &self,
        code: &str,
        expired_at: chrono::DateTime<Utc>,
        max_times: i32,
    ) {
        let mut cache = self.cache.write().await;
        cache.codes.codes.insert(
            code.to_string(),
            CodeValue {
                remain_times: max_times,
                expired_at,
                email: "".to_string(),
            },
        );
    }

    pub async fn login_magic_code_add(
        &self,
        code: &str,
        email: &str,
        expired_at: chrono::DateTime<Utc>,
        max_times: i32,
    ) {
        let mut cache = self.cache.write().await;
        // delete last code, avoid memory leak.
        if let Some(last_code) = cache
            .codes
            .email_code
            .insert(email.to_string(), code.to_string())
        {
            cache.codes.codes.remove(&last_code);
        }
        cache.codes.codes.insert(
            code.to_string(),
            CodeValue {
                remain_times: max_times,
                expired_at,
                email: email.to_string(),
            },
        );
    }

    pub async fn login_magic_code_remove(&self, code: &str) {
        let mut cache = self.cache.write().await;
        if let Some(v) = cache.codes.codes.remove(code) {
            cache.codes.email_code.remove(&v.email);
        }
    }

    pub async fn magic_code_clean(&self) {
        let mut cache = self.cache.write().await;

        let expired_emails = cache
            .codes
            .codes
            .iter()
            .filter(|&(_k, v)| v.expired_at < Utc::now() || v.remain_times <= 0)
            .map(|(_k, v)| v.email.to_string())
            .collect::<Vec<_>>();
        for email in &expired_emails {
            cache.codes.email_code.remove(email);
        }
        cache
            .codes
            .codes
            .retain(|_, v| v.expired_at >= Utc::now() && v.remain_times > 0);
    }

    pub async fn clean_mute(&self) {
        let now = DateTime::now();

        // clean in sqlite
        if let Err(err) =
            sqlx::query("delete from mute where expired_at notnull and expired_at < ?")
                .bind(now)
                .execute(&self.db_pool)
                .await
        {
            tracing::error!(error = %err, "failed to query expired mute items");
        }

        // clean in cache
        let mut cache = self.cache.write().await;
        let mut uid_list = Vec::new();
        let mut gid_list = Vec::new();

        for user in cache.users.values_mut() {
            uid_list.clear();
            gid_list.clear();

            for (uid, expired_at) in user.mute_user.iter() {
                if matches!(expired_at, Some(expired_at) if expired_at < &now) {
                    uid_list.push(*uid);
                }
            }

            for (gid, expired_at) in user.mute_group.iter() {
                if matches!(expired_at, Some(expired_at) if expired_at < &now) {
                    gid_list.push(*gid);
                }
            }

            for uid in &uid_list {
                user.mute_user.remove(uid);
            }
            for gid in &gid_list {
                user.mute_group.remove(gid);
            }
        }
    }

    pub fn clean_temp_files(&self) {
        let now = SystemTime::now();
        let timeout_dur = Duration::from_secs(self.config.system.upload_timeout_seconds as u64);

        if let Ok(file_list) = self.config.system.tmp_dir().read_dir() {
            for entry in file_list.flatten() {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) == Some("data") {
                    let mut remove = false;

                    if let Ok(modified) = path.metadata().and_then(|md| md.modified()) {
                        remove = now > modified + timeout_dur;
                    }

                    if remove {
                        let _ = std::fs::remove_file(&path);
                        let _ = std::fs::remove_file(path.with_extension("meta"));
                    }
                }
            }
        }
    }

    pub fn clean_files(&self) {
        let now = Utc::now().date_naive();
        clean_file_dir(
            now,
            &self.config.system.thumbnail_dir(),
            self.config.system.file_expiry_days,
        );
        clean_file_dir(
            now,
            &self.config.system.file_dir(),
            self.config.system.file_expiry_days,
        );
        clean_file_dir(
            now,
            &self.config.system.archive_msg_dir(),
            self.config.system.file_expiry_days,
        );
    }

    pub fn save_avatar(&self, uid: i64, data: &[u8]) -> poem::Result<()> {
        let image = image::load_from_memory(data).map_err(BadRequest)?;
        let avatar = image.thumbnail(256, 256);
        let path = self.config.system.avatar_dir().join(format!("{}.png", uid));
        avatar
            .save_with_format(path, image::ImageFormat::Png)
            .map_err(InternalServerError)?;
        Ok(())
    }

    pub fn save_group_avatar(&self, gid: i64, data: &[u8]) -> poem::Result<()> {
        let image = image::load_from_memory(data).map_err(BadRequest)?;
        let avatar = image.thumbnail(256, 256);
        let path = self
            .config
            .system
            .group_avatar_dir()
            .join(format!("{}.png", gid));
        avatar
            .save_with_format(path, image::ImageFormat::Png)
            .map_err(InternalServerError)?;
        Ok(())
    }

    pub async fn load_dynamic_config<T: DynamicConfig>(
        &self,
    ) -> anyhow::Result<DynamicConfigEntry<T>> {
        self.load_dynamic_config_with(|| DynamicConfigEntry {
            enabled: false,
            config: T::default(),
        })
        .await
    }

    pub async fn load_dynamic_config_with<T, F>(
        &self,
        f: F,
    ) -> anyhow::Result<DynamicConfigEntry<T>>
    where
        T: DynamicConfig,
        F: FnOnce() -> DynamicConfigEntry<T>,
    {
        let sql = "select enabled, value from config where name = ?";
        match sqlx::query_as::<_, (bool, String)>(sql)
            .bind(T::name())
            .fetch_optional(&self.db_pool)
            .await?
        {
            Some((enabled, value)) => Ok(DynamicConfigEntry {
                enabled,
                config: serde_json::from_str(&value)?,
            }),
            None => Ok(f()),
        }
    }

    pub async fn set_dynamic_config<T: DynamicConfig>(
        &self,
        entry: DynamicConfigEntry<T>,
    ) -> anyhow::Result<()> {
        let sql = r#"
        insert into config (name, enabled, value) values (?, ?, ?)
            on conflict (name) do update set enabled = excluded.enabled, value = excluded.value
        "#;
        sqlx::query(sql)
            .bind(T::name())
            .bind(entry.enabled)
            .bind(serde_json::to_string(&entry.config)?)
            .execute(&self.db_pool)
            .await?;

        if entry.enabled {
            let instance = entry.config.create_instance();
            self.cache
                .write()
                .await
                .dynamic_config
                .insert(T::name(), Box::new(Arc::new(instance)));
        } else {
            self.cache.write().await.dynamic_config.remove(T::name());
        }

        Ok(())
    }

    pub async fn initialize_dynamic_config<T>(&self) -> anyhow::Result<()>
    where
        T: DynamicConfig,
    {
        self.initialize_dynamic_config_with(|| DynamicConfigEntry {
            enabled: false,
            config: T::default(),
        })
        .await
    }

    pub async fn initialize_dynamic_config_with<T, F>(&self, f: F) -> anyhow::Result<()>
    where
        T: DynamicConfig,
        F: FnOnce() -> DynamicConfigEntry<T>,
    {
        let entry = self.load_dynamic_config_with::<T, _>(f).await?;
        if entry.enabled {
            let instance = entry.config.create_instance();
            self.cache
                .write()
                .await
                .dynamic_config
                .insert(T::name(), Box::new(Arc::new(instance)));
        }
        Ok(())
    }

    pub async fn get_dynamic_config_instance<T: DynamicConfig>(&self) -> Option<Arc<T::Instance>> {
        self.cache
            .read()
            .await
            .dynamic_config
            .get(T::name())
            .and_then(|instance| {
                instance
                    .downcast_ref::<Arc<T::Instance>>()
                    .map(Clone::clone)
            })
    }

    pub async fn clean_guest(&self) {
        if let Ok(users) = sqlx::query_as::<_, (i64,)>(
            "select uid from user where is_guest = true and time('now', '-7 days') >= created_at",
        )
        .fetch_all::<_>(&self.db_pool)
        .await
        {
            for (uid,) in users {
                let _ = self.delete_user(uid).await;
            }
        }
    }

    pub async fn delete_user(&self, uid: i64) -> poem::Result<()> {
        let mut cache = self.cache.write().await;
        let is_guest = match cache.users.get(&uid) {
            Some(user) => user.is_guest,
            None => return Err(poem::Error::from(StatusCode::NOT_FOUND)),
        };

        // begin transaction
        let mut tx = self.db_pool.begin().await.map_err(InternalServerError)?;

        // delete from user table
        sqlx::query("delete from user where uid = ?")
            .bind(uid)
            .execute(&mut tx)
            .await
            .map_err(InternalServerError)?;

        let log_id = if !is_guest {
            // insert into user_log table
            let log_id = sqlx::query("insert into user_log (uid, action) values (?, ?)")
                .bind(uid)
                .bind(UpdateAction::Delete)
                .execute(&mut tx)
                .await
                .map_err(InternalServerError)?
                .last_insert_rowid();
            Some(log_id)
        } else {
            None
        };

        // commit transaction
        tx.commit().await.map_err(InternalServerError)?;

        // update cache
        if let Some(cached_user) = cache.users.remove(&uid) {
            // close all subscriptions
            for device in cached_user.devices.into_values() {
                if let Some(sender) = device.sender {
                    let _ = sender.send(UserEvent::Kick {
                        reason: KickReason::DeleteUser,
                    });
                }
            }
        }

        let mut removed_groups_id = Vec::new();
        let mut removed_groups = Vec::new();
        let mut exit_from_private_group = Vec::new();
        let mut exit_from_public_group = Vec::new();

        for (gid, group) in cache.groups.iter_mut() {
            match group.ty {
                GroupType::Public => {
                    exit_from_public_group.push(*gid);
                }
                GroupType::Private { owner } if owner == uid => {
                    removed_groups_id.push(*gid);
                }
                GroupType::Private { .. } => {
                    group.members.remove(&uid);
                    exit_from_private_group.push((*gid, group.members.clone()));
                }
            }
        }

        for gid in &removed_groups_id {
            removed_groups.extend(cache.groups.remove(gid).map(|group| (*gid, group)));
        }
        for user in cache.users.values_mut() {
            user.read_index_user.remove(&uid);
        }
        for user in cache.users.values_mut() {
            for gid in &removed_groups_id {
                user.read_index_group.remove(gid);
            }
        }

        // broadcast event
        if let Some(log_id) = log_id {
            let _ = self
                .event_sender
                .send(Arc::new(BroadcastEvent::UserLog(UserUpdateLog {
                    log_id,
                    action: UpdateAction::Delete,
                    uid,
                    email: None,
                    name: None,
                    gender: None,
                    language: None,
                    is_admin: None,
                    avatar_updated_at: None,
                })));

            for (gid, group) in removed_groups {
                let _ = self
                    .event_sender
                    .send(Arc::new(BroadcastEvent::KickFromGroup {
                        targets: group.members.iter().copied().collect(),
                        gid,
                        reason: KickFromGroupReason::GroupDeleted,
                    }));
            }

            for (gid, members) in exit_from_private_group {
                let _ = self
                    .event_sender
                    .send(Arc::new(BroadcastEvent::UserLeavedGroup {
                        targets: members,
                        gid,
                        uid: vec![uid],
                    }));
            }

            for gid in exit_from_public_group {
                let _ = self
                    .event_sender
                    .send(Arc::new(BroadcastEvent::UserLeavedGroup {
                        targets: cache.users.keys().copied().collect(),
                        gid,
                        uid: vec![uid],
                    }));
            }
        }

        Ok(())
    }
}

pub(crate) async fn send_mail(
    smtp_config: &SmtpConfig,
    to: impl AsRef<str>,
    subject: impl Into<String>,
    content: impl Into<String>,
) -> anyhow::Result<()> {
    use lettre::AsyncTransport;

    let msg = lettre::Message::builder()
        .from(smtp_config.from.parse()?)
        .reply_to(smtp_config.from.parse()?)
        .to(to.as_ref().parse()?)
        .subject(subject)
        .multipart(
            lettre::message::MultiPart::alternative().singlepart(
                lettre::message::SinglePart::builder()
                    .header(lettre::message::header::ContentType::TEXT_HTML)
                    .body(content.into()),
            ),
        )?;
    let creds = lettre::transport::smtp::authentication::Credentials::new(
        smtp_config.username.clone(),
        smtp_config.password.clone(),
    );

    let port = smtp_config.port.unwrap_or(465);
    tracing::info!(
        host = smtp_config.host.as_str(),
        port = port,
        from = smtp_config.from.as_str(),
        to = to.as_ref(),
        "send mail"
    );

    let mailer = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(&smtp_config.host)?
        .port(port)
        .credentials(creds)
        .build();

    if cfg!(not(test)) {
        mailer.send(msg).await?;
    }
    Ok(())
}

pub async fn get_frontend_url(state: &State, req: &Request) -> String {
    let frontend_url = state
        .get_dynamic_config_instance::<FrontendUrlConfig>()
        .await
        .and_then(|config| config.url.clone());

    if let Some(frontend_url) = frontend_url {
        frontend_url
    } else {
        let tls_on = state.config.network.tls.is_some();
        let host = state
            .config
            .network
            .domain
            .get(0)
            .cloned()
            .unwrap_or_else(|| {
                let mut host = req
                    .header("Authority")
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| {
                        req.header("Host")
                            .map(|v| v.to_string())
                            .unwrap_or_default()
                    });
                if host.is_empty() {
                    host = if state.config.network.domain.is_empty() {
                        state
                            .config
                            .network
                            .bind
                            .clone()
                            .replace("0.0.0.0", "localhost")
                    } else {
                        format!(
                            "{}:{}",
                            state
                                .config
                                .network
                                .domain
                                .get(0)
                                .map(|v| v.to_string())
                                .unwrap_or_default(),
                            &state.config.network.bind
                                [state.config.network.bind.find(':').unwrap_or_default() + 1..]
                        )
                    };
                }
                host
            });
        format!("{}://{}", if tls_on { "https" } else { "http" }, &host)
    }
}

fn clean_file_dir(now: NaiveDate, path: &Path, expiry_days: i64) {
    let mut remove_dirs = Vec::new();
    let mut iter = WalkDir::new(path).into_iter();

    while let Some(Ok(entry)) = iter.next() {
        let entry_path = entry.path();
        if !entry_path.is_dir() {
            continue;
        }

        if let Ok(p) = entry_path.strip_prefix(path) {
            if let Some(date) = p
                .to_str()
                .map(|name| name.split(std::path::MAIN_SEPARATOR).collect_vec())
                .filter(|s| s.len() == 3)
                .and_then(|s| {
                    let year = s[0].parse::<i32>().ok();
                    let month = s[1].parse::<u32>().ok();
                    let day = s[2].parse::<u32>().ok();
                    match (year, month, day) {
                        (Some(year), Some(month), Some(day)) => Some((year, month, day)),
                        _ => None,
                    }
                })
                .and_then(|(y, m, d)| NaiveDate::from_ymd_opt(y, m, d))
            {
                if (now - date).num_days() > expiry_days {
                    remove_dirs.push(entry_path.to_path_buf());
                }
            }
        }
    }

    for p in remove_dirs {
        let _ = std::fs::remove_dir_all(&p);
    }
}

#[cfg(test)]
mod tests {
    use std::{path::Path, time::Duration};

    use chrono::NaiveDate;
    use itertools::Itertools;
    use serde_json::json;

    use crate::{state::clean_file_dir, test_harness::TestServer, State};

    #[tokio::test]
    async fn test_clean_mute() {
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
        let gid = json.value().i64();

        // mute uid1 and token1
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

        async fn check(state: &State, mut items: Vec<(i64, Vec<i64>, Vec<i64>)>) {
            // check in cache
            let cache = state.cache.read().await;

            for (uid, users, groups) in &mut items {
                let mut exists_users = cache
                    .users
                    .get(uid)
                    .unwrap()
                    .mute_user
                    .keys()
                    .copied()
                    .collect_vec();
                let mut exists_groups = cache
                    .users
                    .get(uid)
                    .unwrap()
                    .mute_group
                    .keys()
                    .copied()
                    .collect_vec();

                users.sort_unstable();
                groups.sort_unstable();
                exists_users.sort_unstable();
                exists_groups.sort_unstable();

                assert_eq!(users, &exists_users);
                assert_eq!(groups, &exists_groups);
            }

            for (uid, users, groups) in &items {
                let mute = sqlx::query_as::<_, (Option<i64>, Option<i64>)>(
                    "select mute_uid, mute_gid from mute where uid = ?",
                )
                .bind(uid)
                .fetch_all(&state.db_pool)
                .await
                .unwrap();

                let mut exists_users = Vec::new();
                let mut exists_groups = Vec::new();

                for (uid, gid) in mute {
                    match (uid, gid) {
                        (Some(uid), None) => {
                            exists_users.push(uid);
                        }
                        (None, Some(gid)) => {
                            exists_groups.push(gid);
                        }
                        _ => {}
                    }
                }

                exists_users.sort_unstable();
                exists_groups.sort_unstable();
                assert_eq!(users, &exists_users);
                assert_eq!(groups, &exists_groups);
            }
        }

        server.state().clean_mute().await;
        check(server.state(), vec![(1, vec![uid1], vec![gid])]).await;

        tokio::time::sleep(Duration::from_secs(4)).await;
        server.state().clean_mute().await;
        check(server.state(), vec![(1, vec![uid1], vec![])]).await;

        tokio::time::sleep(Duration::from_secs(3)).await;
        server.state().clean_mute().await;
        check(server.state(), vec![]).await;
    }

    #[test]
    fn test_clear_file_dir() {
        fn create_dirs(path: &Path, dirs: &[i32]) {
            for d in dirs.iter().copied() {
                let year = d / 10000;
                let month = d / 100 % 100;
                let day = d % 100;

                let dpath = path
                    .join(format!("{}", year))
                    .join(format!("{}", month))
                    .join(format!("{}", day));
                let _ = std::fs::create_dir_all(&dpath);
            }
        }

        fn check_dirs(path: &Path, dirs: &[(i32, bool)]) {
            for (d, exists) in dirs.iter().copied() {
                let year = d / 10000;
                let month = d / 100 % 100;
                let day = d % 100;

                let dpath = path
                    .join(format!("{}", year))
                    .join(format!("{}", month))
                    .join(format!("{}", day));
                assert_eq!(
                    dpath.exists(),
                    exists,
                    "{}-{}-{} = {}",
                    year,
                    month,
                    day,
                    exists
                );
            }
        }

        let path = tempfile::tempdir().unwrap();
        let dirs = vec![
            20220101, 20220102, 20220103, 20220104, 20220105, 20220106, 20220107, 20220108,
        ];
        create_dirs(path.path(), &dirs);

        clean_file_dir(
            NaiveDate::from_ymd_opt(2022, 1, 10).unwrap(),
            path.path(),
            7,
        );
        check_dirs(
            path.path(),
            &[
                (20220101, false),
                (20220102, false),
                (20220103, true),
                (20220104, true),
                (20220105, true),
                (20220106, true),
                (20220107, true),
                (20220108, true),
            ],
        );

        clean_file_dir(
            NaiveDate::from_ymd_opt(2022, 1, 12).unwrap(),
            path.path(),
            7,
        );

        check_dirs(
            path.path(),
            &[
                (20220103, false),
                (20220104, false),
                (20220105, true),
                (20220106, true),
                (20220107, true),
                (20220108, true),
            ],
        );
    }
}
