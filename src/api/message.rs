use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use itertools::Itertools;
use poem::{
    error::{BadRequest, InternalServerError},
    http::StatusCode,
    Error, Result,
};
use poem_openapi::{
    payload::{Json, PlainText},
    ApiRequest, Enum, Object, Union,
};
use rc_msgdb::MsgDb;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    api::{
        group::Group, resource::FileMeta, user::UserInfo, DateTime, FcmConfig, LangId,
        PinnedMessage, UpdateAction,
    },
    state::{BroadcastEvent, Cache, UserStatus},
    State,
};

/// Message target user
#[derive(Debug, Object, Copy, Clone, Serialize, Deserialize)]
pub struct MessageTargetUser {
    pub uid: i64,
}

/// Message target group
#[derive(Debug, Object, Copy, Clone, Serialize, Deserialize)]
pub struct MessageTargetGroup {
    pub gid: i64,
}

/// Message target
#[derive(Debug, Union, Copy, Clone, Serialize, Deserialize)]
pub enum MessageTarget {
    User(MessageTargetUser),
    Group(MessageTargetGroup),
}

impl MessageTarget {
    #[inline]
    pub fn user(uid: i64) -> Self {
        MessageTarget::User(MessageTargetUser { uid })
    }

    #[inline]
    pub fn group(gid: i64) -> Self {
        MessageTarget::Group(MessageTargetGroup { gid })
    }
}

#[derive(Debug, Object, Clone, Serialize, Deserialize)]
pub struct ChatMessageContent {
    /// Extended attributes
    pub properties: Option<HashMap<String, Value>>,

    /// Content type
    pub content_type: String,

    /// Content
    pub content: String,
}

impl ChatMessageContent {
    fn notify_message(&self, cache: &Cache, mentions: &HashSet<i64>) -> Option<String> {
        match self.content_type.as_str() {
            "text/plain" => {
                if mentions.is_empty() {
                    Some(self.content.clone())
                } else {
                    let mut msg = self.content.clone();
                    for uid in mentions {
                        if let Some(user) = cache.users.get(uid) {
                            msg = msg.replace(&format!(" @{} ", uid), &format!(" @{} ", user.name));
                        }
                    }
                    Some(msg)
                }
            }
            "text/markdown" => Some("You have a new message".to_string()),
            "vocechat/file" => Some("You have a new file".to_string()),
            _ => None,
        }
    }
}

/// Normal message
///
/// content_type match properties as following:
/// ##### application/octet-stream
///    - id: String(UUID)
///    - name: String
///    - size: i64
///    - hash: String(SHA-256)
#[derive(Debug, Object, Clone, Serialize, Deserialize)]
pub struct MessageNormal {
    #[oai(flatten)]
    pub content: ChatMessageContent,

    /// Expires in seconds
    pub expires_in: Option<i64>,
}

#[derive(Debug, Object, Clone, Serialize, Deserialize)]
pub struct MessageReply {
    pub mid: i64,
    #[oai(flatten)]
    pub content: ChatMessageContent,
}

/// Message reaction edit
#[derive(Debug, Object, Clone, Serialize, Deserialize)]
pub struct MessageReactionEdit {
    #[oai(flatten)]
    pub content: ChatMessageContent,
}

/// Message reaction like
#[derive(Debug, Object, Clone, Serialize, Deserialize)]
pub struct MessageReactionLike {
    pub action: String,
}

const ALLOWED_EMOJI: &[&str] = &["❤️", "😄", "👀", "👍", "👎", "🎉", "🙁", "🚀"];

impl MessageReactionLike {
    pub fn check(&self) -> bool {
        ALLOWED_EMOJI.contains(&self.action.as_str())
    }
}

/// Message reaction delete
#[derive(Debug, Object, Clone, Serialize, Deserialize)]
pub struct MessageReactionDelete {}

#[derive(Debug, Union, Clone, Serialize, Deserialize)]
#[oai(discriminator_name = "type")]
pub enum MessageReactionDetail {
    #[oai(mapping = "edit")]
    Edit(MessageReactionEdit),
    #[oai(mapping = "like")]
    Like(MessageReactionLike),
    #[oai(mapping = "delete")]
    Delete(MessageReactionDelete),
}

impl MessageReactionDetail {
    pub fn can_reaction(
        &self,
        current_uid: i64,
        is_admin: bool,
        payload: &ChatMessagePayload,
    ) -> bool {
        if !matches!(
            &payload.detail,
            MessageDetail::Normal(_) | MessageDetail::Reply(_)
        ) {
            return false;
        }

        match self {
            MessageReactionDetail::Edit(_) => current_uid == payload.from_uid,
            MessageReactionDetail::Like(_) => true,
            MessageReactionDetail::Delete(_) => current_uid == payload.from_uid || is_admin,
        }
    }
}

/// Normal reaction
#[derive(Debug, Object, Clone, Serialize, Deserialize)]
pub struct MessageReaction {
    pub mid: i64,
    pub detail: MessageReactionDetail,
}

#[derive(Debug, Union, Clone, Serialize, Deserialize)]
#[oai(discriminator_name = "type")]
pub enum MessageDetail {
    #[oai(mapping = "normal")]
    Normal(MessageNormal),
    #[oai(mapping = "reaction")]
    Reaction(MessageReaction),
    #[oai(mapping = "reply")]
    Reply(MessageReply),
}

impl MessageDetail {
    pub fn as_normal_mut(&mut self) -> Option<&mut MessageNormal> {
        match self {
            MessageDetail::Normal(normal) => Some(normal),
            _ => None,
        }
    }
}

/// Chat message payload
#[derive(Debug, Object, Clone, Serialize, Deserialize)]
pub struct ChatMessagePayload {
    /// Sender id
    pub from_uid: i64,

    /// The create time of the message.
    pub created_at: DateTime,

    /// Message target
    pub target: MessageTarget,

    /// Message detail
    pub detail: MessageDetail,
}

impl ChatMessagePayload {
    pub fn notify_message(&self, cache: &Cache, mentions: &HashSet<i64>) -> Option<String> {
        match &self.detail {
            MessageDetail::Normal(MessageNormal { content, .. }) => {
                content.notify_message(cache, mentions)
            }
            MessageDetail::Reply(MessageReply { content, .. }) => {
                content.notify_message(cache, mentions)
            }
            _ => None,
        }
    }
}

/// Merged chat message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedMessagePayload {
    pub from_uid: i64,
    /// Message target
    pub target: MessageTarget,
    pub content: ChatMessageContent,
    pub created_at: DateTime,
}

/// Chat message
#[derive(Debug, Object, Clone)]
pub struct ChatMessage {
    /// Message id
    pub mid: i64,
    #[oai(flatten)]
    pub payload: ChatMessagePayload,
}

/// Kick reason
#[derive(Debug, Enum, Copy, Clone, Eq, PartialEq)]
#[oai(rename_all = "snake_case")]
pub enum KickReason {
    /// Login from other device
    LoginFromOtherDevice,

    /// User has been deleted
    DeleteUser,

    /// Device has been deleted
    DeleteDevice,

    /// Logout
    Logout,

    /// Frozen
    Frozen,
}

/// Kick message
#[derive(Debug, Object, Clone)]
pub struct KickMessage {
    pub reason: KickReason,
}

/// Session ready message
#[derive(Debug, Object, Clone)]
pub struct SessionReadyMessage {}

/// Heartbeat message
#[derive(Debug, Object, Clone)]
pub struct HeartbeatMessage {
    pub time: DateTime,
}

/// User snapshot message
#[derive(Debug, Object, Clone)]
pub struct UsersSnapshotMessage {
    /// A snapshot of all user information.
    pub users: Vec<UserInfo>,

    /// User information version.
    pub version: i64,
}

/// User state
#[derive(Debug, Object, Clone)]
pub struct UserState {
    pub uid: i64,
    pub online: bool,
}

/// User state message
#[derive(Debug, Object, Clone)]
pub struct UsersStateMessage {
    pub users: Vec<UserState>,
}

#[derive(Debug, Object, Clone)]
pub struct UserStateChangedMessage {
    pub uid: i64,
    pub online: Option<bool>,
}

/// User update log
#[derive(Debug, Object, Clone)]
pub struct UserUpdateLog {
    /// Log id(version)
    pub log_id: i64,
    pub action: UpdateAction,
    pub uid: i64,
    pub email: Option<String>,
    pub name: Option<String>,
    pub gender: Option<i32>,
    pub language: Option<LangId>,
    pub is_admin: Option<bool>,
    pub is_bot: Option<bool>,
    pub avatar_updated_at: Option<DateTime>,
}

/// User update log message
#[derive(Debug, Object, Clone)]
pub struct UsersUpdateLogMessage {
    /// Logs
    pub logs: Vec<UserUpdateLog>,
}

/// Related groups message
#[derive(Debug, Object, Clone)]
pub struct RelatedGroupsMessage {
    pub groups: Vec<Group>,
}

/// Other users joined group message
#[derive(Debug, Object, Clone)]
pub struct UserJoinedGroupMessage {
    /// Group id
    pub gid: i64,

    /// Users id
    pub uid: Vec<i64>,
}

/// Other users leaved group message
#[derive(Debug, Object, Clone)]
pub struct UserLeavedGroupMessage {
    /// Group id
    pub gid: i64,

    /// Users id
    pub uid: Vec<i64>,
}

/// Joined group message
#[derive(Debug, Object, Clone)]
pub struct JoinedGroupMessage {
    /// Group
    pub group: Group,
}

/// User leaved group reason
#[derive(Debug, Enum, Copy, Clone)]
#[oai(rename_all = "snake_case")]
pub enum KickFromGroupReason {
    /// Kick by owner or admin
    Kick,
    /// Group deleted
    GroupDeleted,
}

/// Kick from group message
#[derive(Debug, Object, Clone)]
pub struct KickFromGroupMessage {
    /// Group id
    pub gid: i64,

    /// Reason
    pub reason: KickFromGroupReason,
}

/// Group info changed message
#[derive(Debug, Object, Clone)]
pub struct GroupChangedMessage {
    /// Group id
    pub gid: i64,
    pub name: Option<String>,
    pub description: Option<String>,
    pub owner: Option<i64>,
    pub avatar_updated_at: Option<DateTime>,
    pub is_public: Option<bool>,
}

/// Pinned message updated
#[derive(Debug, Object, Clone)]
pub struct PinnedMessageUpdated {
    pub gid: i64,
    pub mid: i64,
    pub msg: Option<PinnedMessage>,
}

/// Mute user
#[derive(Debug, Object, Clone)]
pub struct MuteUser {
    /// User id
    pub uid: i64,
    /// Expired at
    pub expired_at: Option<DateTime>,
}

/// Mute group
#[derive(Debug, Object, Clone)]
pub struct MuteGroup {
    /// Group id
    pub gid: i64,
    /// Expired at
    pub expired_at: Option<DateTime>,
}

/// Read index to user
#[derive(Debug, Object, Clone)]
pub struct ReadIndexUser {
    /// User id
    pub uid: i64,
    /// Message id
    pub mid: i64,
}

/// Read index to group
#[derive(Debug, Object, Clone)]
pub struct ReadIndexGroup {
    /// Group id
    pub gid: i64,
    /// Message id
    pub mid: i64,
}

/// Burn after reading to user
#[derive(Debug, Object, Clone)]
pub struct BurnAfterReadingUser {
    /// User id
    pub uid: i64,
    /// Expires in seconds
    pub expires_in: i64,
}

/// Burn after reading to group
#[derive(Debug, Object, Clone)]
pub struct BurnAfterReadingGroup {
    /// Group id
    pub gid: i64,
    /// Expires in seconds
    pub expires_in: i64,
}

/// User settings message
#[derive(Debug, Object, Clone)]
pub struct UserSettingsMessage {
    pub mute_users: Vec<MuteUser>,
    pub mute_groups: Vec<MuteGroup>,
    pub read_index_users: Vec<ReadIndexUser>,
    pub read_index_groups: Vec<ReadIndexGroup>,
    pub burn_after_reading_users: Vec<BurnAfterReadingUser>,
    pub burn_after_reading_groups: Vec<BurnAfterReadingGroup>,
}

/// User setting changed message
#[derive(Debug, Object, Clone, Default)]
pub struct UserSettingsChangedMessage {
    pub from_device: String,
    pub add_mute_users: Vec<MuteUser>,
    pub remove_mute_users: Vec<i64>,
    pub add_mute_groups: Vec<MuteGroup>,
    pub remove_mute_groups: Vec<i64>,
    pub read_index_users: Vec<ReadIndexUser>,
    pub read_index_groups: Vec<ReadIndexGroup>,
    pub burn_after_reading_users: Vec<BurnAfterReadingUser>,
    pub burn_after_reading_groups: Vec<BurnAfterReadingGroup>,
}

/// Message
#[derive(Debug, Union, Clone)]
#[oai(discriminator_name = "type")]
pub enum Message {
    #[oai(mapping = "ready")]
    Ready(SessionReadyMessage),
    #[oai(mapping = "users_snapshot")]
    UsersSnapshot(UsersSnapshotMessage),
    #[oai(mapping = "users_log")]
    UsersUpdateLog(UsersUpdateLogMessage),
    #[oai(mapping = "users_state")]
    UsersState(UsersStateMessage),
    #[oai(mapping = "users_state_changed")]
    UserStateChanged(UserStateChangedMessage),
    #[oai(mapping = "user_settings")]
    UserSettings(UserSettingsMessage),
    #[oai(mapping = "user_settings_changed")]
    UserSettingsChanged(UserSettingsChangedMessage),
    #[oai(mapping = "related_groups")]
    RelatedGroups(RelatedGroupsMessage),
    #[oai(mapping = "chat")]
    Chat(ChatMessage),
    #[oai(mapping = "kick")]
    Kick(KickMessage),
    #[oai(mapping = "user_joined_group")]
    UserJoinedGroup(UserJoinedGroupMessage),
    #[oai(mapping = "user_leaved_group")]
    UserLeavedGroup(UserLeavedGroupMessage),
    #[oai(mapping = "joined_group")]
    JoinedGroup(JoinedGroupMessage),
    #[oai(mapping = "kick_from_group")]
    KickFromGroup(KickFromGroupMessage),
    #[oai(mapping = "group_changed")]
    GroupChanged(GroupChangedMessage),
    #[oai(mapping = "pinned_message_updated")]
    PinnedMessageUpdated(PinnedMessageUpdated),
    #[oai(mapping = "heartbeat")]
    Heartbeat(HeartbeatMessage),
}

#[derive(Debug, Object)]
pub struct FileInfo {
    pub path: String,
}

#[derive(Debug, ApiRequest)]
pub enum SendMessageRequest {
    Text(PlainText<String>),
    #[oai(content_type = "text/markdown")]
    Markdown(PlainText<String>),
    #[oai(content_type = "vocechat/file")]
    File(Json<FileInfo>),
    #[oai(content_type = "vocechat/archive")]
    Archive(PlainText<String>),
}

impl SendMessageRequest {
    pub async fn into_chat_message_content(
        self,
        state: &State,
        properties: Option<HashMap<String, Value>>,
    ) -> Result<ChatMessageContent> {
        match self {
            SendMessageRequest::Text(text) => Ok(ChatMessageContent {
                properties,
                content_type: "text/plain".to_string(),
                content: text.0,
            }),
            SendMessageRequest::Markdown(text) => Ok(ChatMessageContent {
                properties,
                content_type: "text/markdown".to_string(),
                content: text.0,
            }),
            SendMessageRequest::File(Json(file_info)) => Ok(ChatMessageContent {
                properties: Some({
                    let mut properties = properties.unwrap_or_default();
                    let base_dir = state.config.system.file_dir();
                    let path = base_dir.join(&file_info.path);
                    let path_meta = base_dir.join(&file_info.path).with_extension("meta");

                    let filesize = {
                        let metadata = tokio::fs::metadata(&path).await.map_err(BadRequest)?;
                        metadata.len()
                    };
                    let meta = tokio::fs::read(&path_meta)
                        .await
                        .ok()
                        .and_then(|data| serde_json::from_slice::<FileMeta>(&data).ok())
                        .unwrap_or_else(|| FileMeta {
                            content_type: "application/octet-stream".to_string(),
                            filename: None,
                        });

                    if let Some(filename) = meta.filename {
                        properties.insert("name".to_string(), filename.into());
                    }
                    properties.insert("content_type".to_string(), meta.content_type.into());
                    properties.insert("size".to_string(), filesize.into());
                    properties
                }),
                content_type: "vocechat/file".to_string(),
                content: file_info.path,
            }),
            SendMessageRequest::Archive(path) => Ok(ChatMessageContent {
                properties,
                content_type: "vocechat/archive".to_string(),
                content: path.0,
            }),
        }
    }

    pub async fn into_chat_message_payload(
        self,
        state: &State,
        from_uid: i64,
        target: MessageTarget,
        properties: Option<HashMap<String, Value>>,
    ) -> Result<ChatMessagePayload> {
        Ok(ChatMessagePayload {
            from_uid,
            created_at: DateTime::now(),
            target,
            detail: MessageDetail::Normal(MessageNormal {
                content: self.into_chat_message_content(state, properties).await?,
                expires_in: None,
            }),
        })
    }
}

pub fn decode_messages(rows: Vec<(i64, Vec<u8>)>) -> Vec<ChatMessage> {
    rows.into_iter()
        .filter_map(|(mid, data)| {
            serde_json::from_slice::<ChatMessagePayload>(&data)
                .ok()
                .map(|payload| ChatMessage { mid, payload })
        })
        .collect()
}

enum InternalSendMessageTarget {
    Group { gid: i64, targets: Vec<i64> },
    Dm { from_uid: i64, to_uid: i64 },
}

fn internal_send_message(
    state: &State,
    target: InternalSendMessageTarget,
    payload: ChatMessagePayload,
) -> poem::Result<i64> {
    let (msg_id, targets) = match target {
        InternalSendMessageTarget::Group { gid, targets } => {
            // send message to group
            let mid = state
                .msg_db
                .messages()
                .send_to_group(
                    gid,
                    targets.iter().copied(),
                    &serde_json::to_vec(&payload).map_err(InternalServerError)?,
                )
                .map_err(InternalServerError)?;
            (mid, targets)
        }
        InternalSendMessageTarget::Dm { from_uid, to_uid } => {
            // send message to dm
            let mid = state
                .msg_db
                .messages()
                .send_to_dm(
                    from_uid,
                    to_uid,
                    &serde_json::to_vec(&payload).map_err(InternalServerError)?,
                )
                .map_err(InternalServerError)?;
            (mid, vec![from_uid, to_uid])
        }
    };

    // update merged message
    let merged_id = match &payload.detail {
        MessageDetail::Normal(normal) => {
            let merged_payload = MergedMessagePayload {
                from_uid: payload.from_uid,
                target: payload.target,
                content: normal.content.clone(),
                created_at: payload.created_at,
            };

            state
                .msg_db
                .messages()
                .insert_merged_msg(
                    msg_id,
                    &serde_json::to_vec(&merged_payload).map_err(InternalServerError)?,
                )
                .map_err(InternalServerError)?;

            Some(msg_id)
        }
        MessageDetail::Reaction(reaction) => match &reaction.detail {
            MessageReactionDetail::Edit(edit) => {
                state
                    .msg_db
                    .messages()
                    .update_merged_msg(reaction.mid, |data| {
                        match serde_json::from_slice::<MergedMessagePayload>(data) {
                            Ok(mut merged_payload) => {
                                merged_payload.content = edit.content.clone();
                                serde_json::to_vec(&merged_payload)
                                    .unwrap_or_else(|_| data.to_vec())
                            }
                            Err(_) => data.to_vec(),
                        }
                    })
                    .map_err(InternalServerError)?;

                Some(reaction.mid)
            }
            MessageReactionDetail::Like(_) => None,
            MessageReactionDetail::Delete(_) => None,
        },
        MessageDetail::Reply(reply) => {
            let merged_payload = MergedMessagePayload {
                from_uid: payload.from_uid,
                target: payload.target,
                content: reply.content.clone(),
                created_at: payload.created_at,
            };

            state
                .msg_db
                .messages()
                .insert_merged_msg(
                    msg_id,
                    &serde_json::to_vec(&merged_payload).map_err(InternalServerError)?,
                )
                .map_err(InternalServerError)?;

            Some(msg_id)
        }
    };

    // broadcast message
    let _ = state.event_sender.send(Arc::new(BroadcastEvent::Chat {
        targets: targets.into_iter().collect(),
        message: ChatMessage {
            mid: msg_id,
            payload,
        },
    }));

    if let Some(merged_id) = merged_id {
        let _ = state.msg_updated_channel.send(merged_id);
    }
    Ok(msg_id)
}

pub async fn send_message(state: &State, mut payload: ChatMessagePayload) -> poem::Result<i64> {
    let cache = state.cache.read().await;

    // set expires_in
    if let Some(normal) = payload.detail.as_normal_mut() {
        let current_user = cache
            .users
            .get(&payload.from_uid)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
        normal.expires_in = match payload.target {
            MessageTarget::User(MessageTargetUser { uid }) => {
                current_user.burn_after_reading_to_user_expires_in(uid)
            }
            MessageTarget::Group(MessageTargetGroup { gid }) => {
                current_user.burn_after_reading_to_group_expires_in(gid)
            }
        };
    }

    let mentions = match &payload.detail {
        MessageDetail::Normal(normal) => normal
            .content
            .properties
            .as_ref()
            .and_then(|properties| properties.get("mentions")),
        MessageDetail::Reaction(_) => None,
        MessageDetail::Reply(reply) => reply
            .content
            .properties
            .as_ref()
            .and_then(|properties| properties.get("mentions")),
    };
    let mentions = mentions.and_then(|value| value.as_array());
    let mentions = match mentions {
        Some(mentions) => mentions
            .iter()
            .filter_map(|value| value.as_i64())
            .collect::<HashSet<_>>(),
        None => Default::default(),
    };

    // do send
    let from_uid = payload.from_uid;
    let mid = match payload.target {
        MessageTarget::User(MessageTargetUser { uid }) => {
            // send notify
            if let Some(user) = cache.users.get(&payload.from_uid) {
                if user.status == UserStatus::Normal {
                    if let Some(notify_message) = payload.notify_message(&cache, &mentions) {
                        let target_user = match cache.users.get(&uid) {
                            Some(user) => user,
                            None => return Err(Error::from_status(StatusCode::NOT_FOUND)),
                        };

                        let notify_tokens = if !target_user.is_user_muted(payload.from_uid) {
                            target_user
                                .devices
                                .values()
                                .filter_map(|device| device.device_token.clone())
                                .collect_vec()
                        } else {
                            vec![]
                        };

                        let key_config = state.key_config.read().await;
                        let data = serde_json::json!({
                            "vocechat_server_id": &key_config.server_id,
                            "vocechat_from_uid": from_uid.to_string(),
                            "vocechat_to_uid": uid.to_string(),
                        });

                        send_notify(
                            state.clone(),
                            notify_tokens,
                            user.name.clone(),
                            notify_message,
                            data,
                        )
                        .await;
                    }
                }
            };

            // send message
            tokio::task::spawn_blocking({
                let state = state.clone();
                move || {
                    internal_send_message(
                        &state,
                        InternalSendMessageTarget::Dm {
                            from_uid,
                            to_uid: uid,
                        },
                        payload,
                    )
                }
            })
            .await
            .map_err(InternalServerError)??
        }
        MessageTarget::Group(MessageTargetGroup { gid }) => {
            let notify_message = payload.notify_message(&cache, &mentions);

            let group = match cache.groups.get(&gid) {
                Some(group) => group,
                None => return Err(Error::from_status(StatusCode::NOT_FOUND)),
            };

            if !group.ty.is_public() && !group.members.contains(&from_uid) {
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }

            let target_users = if !group.ty.is_public() {
                group.members.iter().copied().collect::<Vec<_>>()
            } else {
                cache.users.keys().copied().collect::<Vec<_>>()
            };

            // send notify
            if let Some(user) = cache.users.get(&payload.from_uid) {
                if let Some(notify_message) = notify_message {
                    let key_config = state.key_config.read().await;
                    let data = serde_json::json!({
                        "vocechat_server_id": &key_config.server_id,
                        "vocechat_from_uid": from_uid.to_string(),
                        "vocechat_to_gid": gid.to_string(),
                    });

                    let notify_tokens = target_users
                        .iter()
                        .filter_map(|uid| match cache.users.get(uid) {
                            Some(user) if *uid != payload.from_uid => {
                                if user.status != UserStatus::Normal {
                                    return None;
                                }

                                if mentions.contains(uid) || !user.is_group_muted(gid) {
                                    Some(
                                        user.devices
                                            .values()
                                            .filter_map(|device| device.device_token.clone()),
                                    )
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        })
                        .flatten()
                        .collect::<Vec<_>>();

                    send_notify(
                        state.clone(),
                        notify_tokens,
                        group.name.clone(),
                        format!("{}: {}", user.name, notify_message),
                        data,
                    )
                    .await;
                }
            }

            // send message
            tokio::task::spawn_blocking({
                let state = state.clone();
                move || {
                    internal_send_message(
                        &state,
                        InternalSendMessageTarget::Group {
                            gid,
                            targets: target_users,
                        },
                        payload,
                    )
                }
            })
            .await
            .map_err(InternalServerError)??
        }
    };

    Ok(mid)
}

async fn send_notify(
    state: State,
    notify_tokens: Vec<String>,
    title: String,
    message: String,
    data: impl Serialize + Send + Sync + 'static,
) {
    let notify_start_time = Instant::now();
    if !notify_tokens.is_empty() {
        let fut = async move {
            if let Some(fcm_client) = state.get_dynamic_config_instance::<FcmConfig>().await {
                for token in notify_tokens {
                    if state.invalid_device_tokens.lock().contains(&token) {
                        continue;
                    }

                    if Instant::now() - notify_start_time > Duration::from_secs(60) {
                        break;
                    }

                    tracing::info!(
                        device_token = token.as_str(),
                        message = message.as_str(),
                        "send notify"
                    );
                    if let Err(err) = fcm_client.send(&token, &title, &message, &data).await {
                        if let Some(req_err) = err.downcast_ref::<reqwest::Error>() {
                            if let Some(StatusCode::BAD_REQUEST) = req_err.status() {
                                state.invalid_device_tokens.lock().insert(token);
                                continue;
                            }
                        }

                        tracing::error!(
                            device_token = token.as_str(),
                            error = %err, "failed to send notify with firebase",
                        );
                    }
                }
            }
        };
        tokio::spawn(fut);
    }
}

pub fn parse_properties_from_base64(s: Option<impl AsRef<str>>) -> Option<HashMap<String, Value>> {
    s.and_then(|s| {
        base64::decode(s.as_ref())
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok())
    })
}

pub fn get_merged_message(db: &MsgDb, mid: i64) -> poem::Result<Option<MergedMessagePayload>> {
    Ok(db
        .messages()
        .get_merged_msg(mid)
        .map_err(InternalServerError)?
        .and_then(|data| serde_json::from_slice(&data).ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_like_emoji(s: &str, r: bool) {
        assert_eq!(
            MessageReactionLike {
                action: s.to_string()
            }
            .check(),
            r
        );
    }

    #[test]
    fn like_emoji() {
        check_like_emoji("a", false);
        check_like_emoji("ab", false);
        check_like_emoji("❤️", true);
        check_like_emoji("😄", true);
        check_like_emoji("😄❤️", false);
    }
}
