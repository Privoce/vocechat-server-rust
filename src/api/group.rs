use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use chrono::Utc;
use itertools::Itertools;
use poem::{
    error::{InternalServerError, ReadBodyError},
    http::StatusCode,
    web::Data,
    Error, Result,
};
use poem_openapi::{
    param::{Header, Path, Query},
    payload::{Json, PlainText},
    Object, OpenApi,
};

use crate::{
    api::{
        get_merged_message,
        message::{
            decode_messages, parse_properties_from_base64, send_message, ChatMessageContent,
            SendMessageRequest,
        },
        tags::ApiTags,
        token::Token,
        user::{UploadAvatarApiResponse, UploadAvatarRequest},
        AgoraConfig, ChatMessage, DateTime, GroupChangedMessage, KickFromGroupReason,
        MessageTarget,
    },
    middleware::guest_forbidden,
    state::{BroadcastEvent, Cache, CacheGroup, GroupType},
    State,
};

/// Update group request
#[derive(Debug, Object)]
struct UpdateGroupRequest {
    name: Option<String>,
    description: Option<String>,
    owner: Option<i64>,
}

/// Change group type request
#[derive(Debug, Object)]
struct ChangeGroupTypeRequest {
    is_public: bool,
}

impl UpdateGroupRequest {
    fn is_empty(&self) -> bool {
        self.name.is_none() && self.owner.is_none() && self.description.is_none()
    }
}

/// Group info
#[derive(Debug, Clone, Object)]
pub struct Group {
    /// Group id
    #[oai(read_only)]
    pub gid: i64,
    /// Group owner id
    #[oai(read_only)]
    pub owner: Option<i64>,
    /// Group name
    pub name: String,
    /// Group description
    pub description: Option<String>,
    /// Members id
    #[oai(default)]
    pub members: Vec<i64>,
    /// Is public group
    #[oai(default)]
    pub is_public: bool,
    #[oai(read_only)]
    pub avatar_updated_at: DateTime,
    /// Pinned messages
    #[oai(read_only)]
    pub pinned_messages: Vec<PinnedMessage>,
}

/// Pinned message
#[derive(Debug, Clone, Object)]
pub struct PinnedMessage {
    pub mid: i64,
    pub created_by: i64,
    pub created_at: DateTime,
    #[oai(flatten)]
    pub content: ChatMessageContent,
}

/// Agora token response
#[derive(Debug, Object)]
struct AgoraTokenResponse {
    agora_token: String,
    app_id: String,
    uid: u32,
    channel_name: String,
    /// The agora token expired in seconds
    expired_in: i64,
}

/// Pin message request
#[derive(Debug, Object)]
struct PinMessageRequest {
    mid: i64,
}

/// Unpin message request
#[derive(Debug, Object)]
struct UnpinMessageRequest {
    mid: i64,
}

pub struct ApiGroup;

#[OpenApi(prefix_path = "/group", tag = "ApiTags::Group")]
impl ApiGroup {
    /// Create a new group
    #[oai(path = "/", method = "post", transform = "guest_forbidden")]
    async fn create(
        &self,
        state: Data<&State>,
        req: Json<Group>,
        token: Token,
    ) -> Result<Json<i64>> {
        let mut cache = state.cache.write().await;

        if req.is_public && !token.is_admin {
            // only admin can create public groups
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        if req.is_public && !req.members.is_empty() {
            // public groups are not allowed to specify any members.
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        let members = if !req.is_public {
            req.members
                .iter()
                .copied()
                .chain(std::iter::once(token.uid))
                .collect::<BTreeSet<i64>>()
        } else {
            Default::default()
        };

        for uid in &members {
            if !cache.users.contains_key(uid) {
                // invalid uid
                return Err(Error::from_status(StatusCode::BAD_REQUEST));
            }
        }

        // insert to sqlite
        let mut tx = state.db_pool.begin().await.map_err(InternalServerError)?;
        let now = DateTime::now();
        let owner = if req.is_public { None } else { Some(token.uid) };
        let sql = "insert into `group` (name, description, owner, is_public, created_at, updated_at) values (?, ?, ?, ?, ?, ?)";
        let gid = sqlx::query(sql)
            .bind(&req.0.name)
            .bind(req.0.description.as_deref().unwrap_or_default())
            .bind(owner)
            .bind(req.is_public)
            .bind(now)
            .bind(now)
            .execute(&mut tx)
            .await
            .map_err(InternalServerError)?
            .last_insert_rowid();

        for id in &members {
            sqlx::query("insert into group_user (gid, uid) values (?, ?)")
                .bind(gid)
                .bind(*id)
                .execute(&mut tx)
                .await
                .map_err(InternalServerError)?;
        }

        tx.commit().await.map_err(InternalServerError)?;

        // update cache
        cache.groups.insert(
            gid,
            CacheGroup {
                ty: if req.is_public {
                    GroupType::Public
                } else {
                    GroupType::Private { owner: token.uid }
                },
                name: req.0.name.clone(),
                description: req.0.description.clone().unwrap_or_default(),
                members: members.clone(),
                created_at: now,
                updated_at: now,
                avatar_updated_at: DateTime::zero(),
                pinned_messages: Vec::new(),
            },
        );

        let group = Group {
            gid,
            owner: if req.is_public { None } else { Some(token.uid) },
            name: req.0.name,
            description: req.0.description,
            members: members.clone().into_iter().collect(),
            is_public: req.0.is_public,
            avatar_updated_at: req.0.avatar_updated_at,
            pinned_messages: Vec::new(),
        };

        // broadcast event
        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::JoinedGroup {
                targets: {
                    if !req.0.is_public {
                        members
                    } else {
                        cache.users.keys().copied().collect()
                    }
                },
                group,
            }));

        Ok(Json(gid))
    }

    /// Upload group avatar
    #[oai(path = "/:gid/avatar", method = "post")]
    async fn upload_avatar(
        &self,
        state: Data<&State>,
        token: Token,
        gid: Path<i64>,
        req: UploadAvatarRequest,
    ) -> Result<UploadAvatarApiResponse> {
        let mut cache = state.cache.write().await;
        let now = DateTime::now();
        let cached_group = cache
            .groups
            .get_mut(&gid.0)
            .ok_or_else(|| Error::from(StatusCode::UNAUTHORIZED))?;

        match cached_group.ty {
            GroupType::Public if !token.is_admin => {
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }
            GroupType::Private { owner } if owner != token.uid && !token.is_admin => {
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }
            _ => {}
        }

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
        state.save_group_avatar(gid.0, &data)?;

        // update sqlite
        sqlx::query("update `group` set avatar_updated_at = ? where gid = ?")
            .bind(now)
            .bind(gid.0)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;

        // update cache
        cached_group.avatar_updated_at = now;

        // broadcast event
        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::GroupChanged {
                targets: if !cached_group.ty.is_public() {
                    cached_group.members.iter().copied().collect()
                } else {
                    cache.users.keys().copied().collect()
                },
                msg: GroupChangedMessage {
                    gid: gid.0,
                    name: None,
                    description: None,
                    owner: None,
                    avatar_updated_at: Some(now),
                    is_public: None,
                },
            }));

        Ok(UploadAvatarApiResponse::Ok)
    }

    /// Delete a exists group
    #[oai(path = "/:gid", method = "delete")]
    async fn delete(&self, state: Data<&State>, token: Token, gid: Path<i64>) -> Result<()> {
        let mut cache = state.cache.write().await;
        let group = match cache.groups.get(&gid.0) {
            Some(group) => group,
            None => return Err(Error::from_status(StatusCode::NOT_FOUND)),
        };

        match group.ty {
            GroupType::Public if !token.is_admin => {
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }
            GroupType::Private { owner } if owner != token.uid && !token.is_admin => {
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }
            _ => {}
        }

        // update sqlite
        sqlx::query("delete from `group` where gid = ?")
            .bind(gid.0)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;

        // update cache
        let cached_group = cache.groups.remove(&gid.0).unwrap();
        for user in cache.users.values_mut() {
            user.read_index_group.remove(&gid.0);
        }

        // broadcast event
        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::KickFromGroup {
                targets: {
                    if !cached_group.ty.is_public() {
                        cached_group.members
                    } else {
                        cache.users.keys().copied().collect()
                    }
                },
                reason: KickFromGroupReason::GroupDeleted,
                gid: gid.0,
            }));

        Ok(())
    }

    /// Update a exists group
    #[oai(path = "/:gid", method = "put")]
    async fn update(
        &self,
        state: Data<&State>,
        token: Token,
        gid: Path<i64>,
        req: Json<UpdateGroupRequest>,
    ) -> Result<()> {
        if req.is_empty() {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        let mut cache = state.cache.write().await;
        let group = match cache.groups.get_mut(&gid.0) {
            Some(group) => group,
            None => return Err(Error::from_status(StatusCode::NOT_FOUND)),
        };

        match group.ty {
            GroupType::Public if !token.is_admin => {
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }
            GroupType::Private { owner } if owner != token.uid && !token.is_admin => {
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }
            _ => {}
        }

        if let Some(new_owner) = req.owner {
            if group.ty.is_public() {
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }
            if !group.contains_user(new_owner) {
                return Err(Error::from_status(StatusCode::BAD_REQUEST));
            }
        }

        let now = Utc::now();

        // update sqlite
        let sql = format!(
            "update `group` set {} where gid = ?",
            req.name
                .iter()
                .map(|_| "name = ?")
                .chain(req.owner.iter().map(|_| "owner = ?"))
                .chain(req.description.iter().map(|_| "description = ?"))
                .chain(Some("updated_at = ?"))
                .join(", ")
        );

        let mut query = sqlx::query(&sql);
        if let Some(name) = &req.name {
            query = query.bind(name);
        }
        if let Some(owner) = &req.owner {
            query = query.bind(owner);
        }
        if let Some(description) = &req.description {
            query = query.bind(description);
        }

        query
            .bind(now)
            .bind(gid.0)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;

        let mut broadcast_event = GroupChangedMessage {
            gid: gid.0,
            name: None,
            description: None,
            owner: None,
            avatar_updated_at: None,
            is_public: None,
        };

        // update cache
        if let Some(name) = req.0.name {
            broadcast_event.name = Some(name.clone());
            group.name = name;
        }
        if let Some(description) = req.0.description {
            broadcast_event.description = Some(description.clone());
            group.description = description;
        }
        if let Some(new_owner) = req.0.owner {
            if let GroupType::Private { owner } = &mut group.ty {
                broadcast_event.owner = Some(new_owner);
                *owner = new_owner;
            }
        }

        // broadcast event
        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::GroupChanged {
                targets: if !group.ty.is_public() {
                    group.members.iter().copied().collect()
                } else {
                    cache.users.keys().copied().collect()
                },
                msg: broadcast_event,
            }));

        Ok(())
    }

    #[oai(path = "/:gid/change_type", method = "post")]
    async fn change_type(
        &self,
        state: Data<&State>,
        token: Token,
        gid: Path<i64>,
        req: Json<ChangeGroupTypeRequest>,
    ) -> Result<()> {
        let mut cache = state.cache.write().await;
        let Cache { groups, users, .. } = &mut *cache;
        let group = match groups.get_mut(&gid.0) {
            Some(group) => group,
            None => return Err(Error::from_status(StatusCode::NOT_FOUND)),
        };

        match group.ty {
            GroupType::Public if !token.is_admin => {
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }
            GroupType::Private { owner } if owner != token.uid && !token.is_admin => {
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }
            _ => {}
        }

        let mut tx = state.db_pool.begin().await.map_err(InternalServerError)?;

        match (group.ty.is_public(), req.is_public) {
            (true, false) => {
                // public to private
                sqlx::query("update `group` set is_public = ?, owner = ? where gid = ?")
                    .bind(false)
                    .bind(token.uid)
                    .bind(gid.0)
                    .execute(&mut tx)
                    .await
                    .map_err(InternalServerError)?;

                for uid in users
                    .iter()
                    .filter(|(_, user)| !user.is_guest)
                    .map(|(id, _)| *id)
                {
                    sqlx::query("insert into group_user (gid, uid) values (?, ?)")
                        .bind(gid.0)
                        .bind(uid)
                        .execute(&mut tx)
                        .await
                        .map_err(InternalServerError)?;
                }
            }
            (false, true) => {
                // private to public
                sqlx::query("update `group` set is_public = ?, owner = ? where gid = ?")
                    .bind(true)
                    .bind(None::<i32>)
                    .bind(gid.0)
                    .execute(&mut tx)
                    .await
                    .map_err(InternalServerError)?;

                sqlx::query("delete from group_user where gid = ?")
                    .bind(gid.0)
                    .execute(&mut tx)
                    .await
                    .map_err(InternalServerError)?;
            }
            _ => {}
        }

        tx.commit().await.map_err(InternalServerError)?;

        // update cache
        match (group.ty.is_public(), req.is_public) {
            (true, false) => {
                group.ty = GroupType::Private { owner: token.uid };
                group.members = users
                    .iter()
                    .filter(|(_, user)| !user.is_guest)
                    .map(|(id, _)| *id)
                    .collect();

                let _ = state
                    .event_sender
                    .send(Arc::new(BroadcastEvent::GroupChanged {
                        targets: users.keys().copied().collect(),
                        msg: GroupChangedMessage {
                            gid: gid.0,
                            name: None,
                            description: None,
                            owner: Some(gid.0),
                            avatar_updated_at: None,
                            is_public: Some(false),
                        },
                    }));
            }
            (false, true) => {
                let origin_members = std::mem::take(&mut group.members);
                let all_users: BTreeSet<_> = users
                    .iter()
                    .filter(|(_, user)| !user.is_guest)
                    .map(|(id, _)| *id)
                    .collect();
                let new_members = all_users
                    .difference(&origin_members)
                    .copied()
                    .collect::<BTreeSet<_>>();

                group.ty = GroupType::Public;

                let _ = state
                    .event_sender
                    .send(Arc::new(BroadcastEvent::GroupChanged {
                        targets: users.keys().copied().collect(),
                        msg: GroupChangedMessage {
                            gid: gid.0,
                            name: None,
                            description: None,
                            owner: None,
                            avatar_updated_at: None,
                            is_public: Some(true),
                        },
                    }));

                let _ = state
                    .event_sender
                    .send(Arc::new(BroadcastEvent::UserJoinedGroup {
                        targets: origin_members,
                        gid: gid.0,
                        uid: new_members.iter().copied().collect(),
                    }));

                let _ = state
                    .event_sender
                    .send(Arc::new(BroadcastEvent::JoinedGroup {
                        targets: new_members,
                        group: group.api_group(gid.0),
                    }));
            }
            _ => {}
        }

        Ok(())
    }

    /// Let the current user leave the specified group.
    #[oai(path = "/:gid/leave", method = "get")]
    async fn leave(&self, state: Data<&State>, token: Token, gid: Path<i64>) -> Result<()> {
        let mut cache = state.cache.write().await;
        let group = match cache.groups.get_mut(&gid.0) {
            Some(group) => group,
            None => return Err(Error::from_status(StatusCode::NOT_FOUND)),
        };

        match group.ty {
            GroupType::Public => return Err(Error::from_status(StatusCode::FORBIDDEN)),
            GroupType::Private { owner } => {
                // the current user is not in this group
                if !group.contains_user(token.uid) {
                    return Err(Error::from_status(StatusCode::FORBIDDEN));
                }
                if owner == token.uid {
                    // the current user is owner
                    return Err(Error::from_status(StatusCode::FORBIDDEN));
                }
            }
        }

        // update sqlite
        sqlx::query("delete from group_user where gid = ? and uid = ?")
            .bind(gid.0)
            .bind(token.uid)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;

        // update cache
        let members = group.members.clone();
        group.members.remove(&token.uid);

        // broadcast event
        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::UserLeavedGroup {
                targets: members,
                gid: gid.0,
                uid: vec![token.uid],
            }));

        Ok(())
    }

    /// Get a group by id
    #[oai(path = "/:gid", method = "get")]
    async fn get(&self, state: Data<&State>, gid: Path<i64>) -> Result<Json<Group>> {
        let cache = state.cache.read().await;
        Ok(Json(
            cache
                .groups
                .get(&gid.0)
                .map(|group| group.api_group(gid.0))
                .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?,
        ))
    }

    /// Get all groups related to the current user.
    #[oai(path = "/", method = "get")]
    async fn get_related_groups(
        &self,
        state: Data<&State>,
        token: Token,
        public_only: Query<Option<bool>>,
    ) -> Result<Json<Vec<Group>>> {
        let cache = state.cache.read().await;
        Ok(Json(get_related_groups(
            &cache.groups,
            token.uid,
            public_only.0.unwrap_or_default(),
        )))
    }

    /// Add some new members to the specified group
    #[oai(path = "/:gid/members/add", method = "post")]
    async fn add_members(
        &self,
        state: Data<&State>,
        token: Token,
        gid: Path<i64>,
        members: Json<Vec<i64>>,
    ) -> Result<()> {
        let mut cache = state.cache.write().await;

        if !members.iter().all(|uid| cache.users.contains_key(uid)) {
            // invalid uid
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        let group = cache
            .groups
            .get_mut(&gid.0)
            .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;

        match group.ty {
            GroupType::Public => return Err(Error::from_status(StatusCode::FORBIDDEN)),
            GroupType::Private { .. } if !group.members.contains(&token.uid) && !token.is_admin => {
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }
            _ => {}
        }

        for uid in members.iter() {
            if group.contains_user(*uid) {
                // already in the group
                return Err(Error::from_status(StatusCode::BAD_REQUEST));
            }
        }

        // update sqlite
        let mut tx = state.db_pool.begin().await.map_err(InternalServerError)?;
        for uid in members.iter() {
            sqlx::query("insert into group_user (gid, uid) values (?, ?)")
                .bind(gid.0)
                .bind(uid)
                .execute(&mut tx)
                .await
                .map_err(InternalServerError)?;
        }
        tx.commit().await.map_err(InternalServerError)?;

        // update cache
        let original_members = group.members.clone();
        group.members.extend(members.0.clone());

        // broadcast event
        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::JoinedGroup {
                targets: members.0.clone().into_iter().collect(),
                group: group.api_group(gid.0),
            }));

        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::UserJoinedGroup {
                targets: original_members,
                gid: gid.0,
                uid: members.0.clone(),
            }));

        Ok(())
    }

    /// Remove some members from the specified group
    #[oai(path = "/:gid/members/remove", method = "post")]
    async fn remove_members(
        &self,
        state: Data<&State>,
        token: Token,
        gid: Path<i64>,
        members: Json<Vec<i64>>,
    ) -> Result<()> {
        let mut cache = state.cache.write().await;
        let group = cache
            .groups
            .get_mut(&gid.0)
            .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;

        let owner = match group.ty {
            GroupType::Public => return Err(Error::from_status(StatusCode::FORBIDDEN)),
            GroupType::Private { owner } if owner != token.uid && !token.is_admin => {
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }
            GroupType::Private { owner } => owner,
        };

        for uid in members.iter() {
            if owner == *uid {
                // can't remove the owner of group
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }

            if !group.contains_user(*uid) {
                // this user is not in the group
                return Err(Error::from_status(StatusCode::NOT_FOUND));
            }
        }

        // update sqlite
        let mut tx = state.db_pool.begin().await.map_err(InternalServerError)?;
        for uid in members.iter() {
            sqlx::query("delete from group_user where gid = ? and uid = ?")
                .bind(gid.0)
                .bind(uid)
                .execute(&mut tx)
                .await
                .map_err(InternalServerError)?;
        }
        tx.commit().await.map_err(InternalServerError)?;

        // update cache
        for uid in &members.0 {
            group.members.remove(uid);
        }

        // broadcast event
        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::KickFromGroup {
                targets: members.0.clone().into_iter().collect(),
                gid: gid.0,
                reason: KickFromGroupReason::Kick,
            }));

        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::UserLeavedGroup {
                targets: group.members.clone(),
                gid: gid.0,
                uid: members.0.clone(),
            }));

        Ok(())
    }

    /// Send message to the specified group
    #[oai(path = "/:gid/send", method = "post", transform = "guest_forbidden")]
    async fn send(
        &self,
        state: Data<&State>,
        token: Token,
        gid: Path<i64>,
        #[oai(name = "X-Properties")] properties: Header<Option<String>>,
        req: SendMessageRequest,
    ) -> Result<Json<i64>> {
        let properties = parse_properties_from_base64(properties.0);
        let payload = req
            .into_chat_message_payload(&state, token.uid, MessageTarget::group(gid.0), properties)
            .await?;
        let mid = send_message(&state, payload).await?;
        Ok(Json(mid))
    }

    /// Create a register magic link to invit user to join group
    /// format: https://domain.com/?magic_token=xxx#/register
    #[oai(path = "/create_reg_magic_link", method = "get")]
    async fn create_reg_magic_link(
        &self,
        state: Data<&State>,
        token: Token,
        gid: Query<Option<i64>>,
        expired_in: Query<Option<i64>>,
        max_times: Query<Option<i32>>,
        req: &poem::Request,
    ) -> Result<PlainText<String>> {
        if gid.0.is_some() {
            let mut cache = state.cache.write().await;
            let group = cache
                .groups
                .get_mut(&gid.0.unwrap())
                .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;
            if !group.ty.is_public() && !group.members.contains(&token.uid) && !token.is_admin {
                return Err(Error::from_status(StatusCode::FORBIDDEN));
            }
        }
        let url = crate::state::get_frontend_url(&state, req).await;
        let code = rc_magic_link::gen_code();
        let expired_at = chrono::Utc::now()
            + chrono::Duration::seconds(
                expired_in
                    .0
                    .unwrap_or(state.config.system.magic_token_expiry_seconds),
            );
        let magic_link = {
            let key_config = state.key_config.read().await;
            let magic_token = rc_magic_link::MagicLinkToken::gen_reg_magic_token(
                &code,
                &key_config.server_key,
                expired_at,
                false,
                gid.0,
                None,
                None,
            );
            format!("{}/?magic_token={}#/register", url, magic_token)
        };
        state
            .reg_magic_code_add(&code, expired_at, max_times.0.unwrap_or(10000))
            .await;
        Ok(PlainText(magic_link))
    }

    /// Get history messages
    #[oai(path = "/:gid/history", method = "get")]
    async fn get_history_messages(
        &self,
        state: Data<&State>,
        token: Token,
        gid: Path<i64>,
        before: Query<Option<i64>>,
        #[oai(default = "default_get_history_messages_limit")] limit: Query<usize>,
    ) -> Result<Json<Vec<ChatMessage>>> {
        let cache = state.cache.read().await;
        let group = cache
            .groups
            .get(&gid.0)
            .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;
        if !group.contains_user(token.uid) {
            // this user is not in the group
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let msgs = state
            .msg_db
            .messages()
            .fetch_group_messages_before(gid.0, before.0, limit.0)
            .map_err(InternalServerError)?;
        Ok(Json(decode_messages(msgs)))
    }

    /// Generates a Agora token
    #[oai(path = "/:gid/agora_token", method = "get")]
    async fn generate_agora_token(
        &self,
        state: Data<&State>,
        gid: Path<i64>,
        token: Token,
    ) -> Result<Json<AgoraTokenResponse>> {
        let agora = state
            .get_dynamic_config_instance::<AgoraConfig>()
            .await
            .ok_or_else(|| Error::from_status(StatusCode::SERVICE_UNAVAILABLE))?;
        let cache = state.cache.read().await;
        let group = cache
            .groups
            .get(&gid.0)
            .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;

        if !group.contains_user(token.uid) {
            // this user is not in the group
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let channel_name = format!("vocechat:group:{}", gid.0);
        let agora_token = agora_token::create_rtc_token(
            &agora.app_id,
            &agora.app_certificate,
            &channel_name,
            token.uid as u32,
        );
        Ok(Json(AgoraTokenResponse {
            agora_token,
            app_id: agora.app_id.clone(),
            uid: token.uid as u32,
            channel_name,
            expired_in: 24 * 3600,
        }))
    }

    /// Pin a message
    #[oai(path = "/:gid/pin", method = "post")]
    async fn pin_message(
        &self,
        state: Data<&State>,
        gid: Path<i64>,
        token: Token,
        req: Json<PinMessageRequest>,
    ) -> Result<()> {
        let mut cache = state.cache.write().await;
        let group = cache
            .groups
            .get_mut(&gid.0)
            .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;

        let check_permission = match group.ty {
            GroupType::Public if token.is_admin => true,
            GroupType::Private { owner } if owner == token.uid || token.is_admin => true,
            _ => false,
        };

        if !check_permission {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        if group.pinned_messages.iter().any(|msg| msg.mid == req.mid) {
            return Err(Error::from_status(StatusCode::CONFLICT));
        }

        let merged_msg = get_merged_message(&state.msg_db, req.mid)?
            .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;

        // update database
        let now = DateTime::now();
        let sql =
            "insert into pinned_message (gid, mid, created_by, created_at) values (?, ?, ?, ?)";
        sqlx::query(sql)
            .bind(gid.0)
            .bind(req.mid)
            .bind(token.uid)
            .bind(now)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;

        // update cache
        let pinned_msg = PinnedMessage {
            mid: req.mid,
            created_by: token.uid,
            created_at: now,
            content: merged_msg.content,
        };
        group.pinned_messages.push(pinned_msg.clone());
        group
            .pinned_messages
            .sort_by(|a, b| a.created_at.cmp(&b.created_at));

        // broadcast event
        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::PinnedMessageUpdated {
                targets: if group.ty.is_public() {
                    cache.users.iter().map(|(uid, _)| *uid).collect()
                } else {
                    group.members.clone()
                },
                gid: gid.0,
                mid: req.mid,
                msg: Some(pinned_msg),
            }));

        Ok(())
    }

    /// Unpin a message
    #[oai(path = "/:gid/unpin", method = "post")]
    async fn unpin_message(
        &self,
        state: Data<&State>,
        gid: Path<i64>,
        token: Token,
        req: Json<UnpinMessageRequest>,
    ) -> Result<()> {
        let mut cache = state.cache.write().await;
        let group = cache
            .groups
            .get_mut(&gid.0)
            .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;

        let check_permission = match group.ty {
            GroupType::Public if token.is_admin => true,
            GroupType::Private { owner } if owner == token.uid || token.is_admin => true,
            _ => false,
        };

        if !check_permission {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }

        let idx = match group
            .pinned_messages
            .iter()
            .enumerate()
            .find(|(_, msg)| msg.mid == req.mid)
        {
            Some((idx, _)) => idx,
            None => return Err(Error::from_status(StatusCode::NOT_FOUND)),
        };

        // update database
        let sql = "delete from pinned_message where gid = ? and mid = ?";
        sqlx::query(sql)
            .bind(gid.0)
            .bind(req.mid)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;

        // update cache
        group.pinned_messages.remove(idx);

        // broadcast event
        let _ = state
            .event_sender
            .send(Arc::new(BroadcastEvent::PinnedMessageUpdated {
                targets: if group.ty.is_public() {
                    cache.users.iter().map(|(uid, _)| *uid).collect()
                } else {
                    group.members.clone()
                },
                gid: gid.0,
                mid: req.mid,
                msg: None,
            }));

        Ok(())
    }
}

const fn default_get_history_messages_limit() -> usize {
    300
}

pub fn get_related_groups(
    groups_cache: &BTreeMap<i64, CacheGroup>,
    uid: i64,
    public_only: bool,
) -> Vec<Group> {
    groups_cache
        .iter()
        .filter(|(_, group)| group.ty.is_public() || (!public_only && group.contains_user(uid)))
        .map(|(id, group)| group.api_group(*id))
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tokio_stream::StreamExt;

    use super::*;
    use crate::test_harness::TestServer;

    #[tokio::test]
    async fn test_crud() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "test1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "test2@voce.chat").await;
        let uid3 = server.create_user(&admin_token, "test3@voce.chat").await;
        let token1 = server.login("test1@voce.chat").await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "description": "abc",
                "members": [uid1, uid2]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().i64();
        let json = server.get_group(gid).await;
        let group = json.value().object();
        group.get("gid").assert_i64(gid);
        group.get("owner").assert_i64(1);
        group.get("name").assert_string("test");
        group.get("description").assert_string("abc");
        group.get("members").assert_i64_array(&[1, uid1, uid2]);
        group.get("is_public").assert_bool(false);

        // update group name
        let resp = server
            .put(format!("/api/group/{}", gid))
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test2",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        assert_eq!(
            server
                .get_group(gid)
                .await
                .value()
                .object()
                .get("name")
                .string(),
            "test2"
        );

        // update group description
        let resp = server
            .put(format!("/api/group/{}", gid))
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "description": "iop",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        assert_eq!(
            server
                .get_group(gid)
                .await
                .value()
                .object()
                .get("description")
                .string(),
            "iop"
        );

        // update group owner
        let resp = server
            .put(format!("/api/group/{}", gid))
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "owner": uid1,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        assert_eq!(
            server
                .get_group(gid)
                .await
                .value()
                .object()
                .get("owner")
                .i64(),
            uid1
        );

        // add members
        let resp = server
            .post(format!("/api/group/{}/members/add", gid))
            .header("X-API-Key", &token1)
            .body_json(&json!([uid3]))
            .send()
            .await;
        resp.assert_status_is_ok();
        assert_eq!(
            server
                .get_group(gid)
                .await
                .value()
                .object()
                .get("members")
                .i64_array(),
            &[1, uid1, uid2, uid3]
        );

        // remove members
        let resp = server
            .post(format!("/api/group/{}/members/remove", gid))
            .header("X-API-Key", &token1)
            .body_json(&json!([uid2]))
            .send()
            .await;
        resp.assert_status_is_ok();

        assert_eq!(
            server
                .get_group(gid)
                .await
                .value()
                .object()
                .get("members")
                .i64_array(),
            &[1, uid1, uid3]
        );

        // delete group
        let resp = server
            .delete(format!("/api/group/{}", gid))
            .header("X-API-Key", &token1)
            .send()
            .await;
        resp.assert_status_is_ok();

        let resp = server.get(format!("/api/group/{}", gid)).send().await;
        resp.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn only_admin_can_create_public_group() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        server.create_user(&admin_token, "user1@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;

        // create group with normal user
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &token1)
            .body_json(&json!({
                "name": "test",
                "is_public": true,
            }))
            .send()
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);

        // create group with admin user
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
    }

    #[tokio::test]
    async fn only_admin_can_update_public_group() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        server.create_user(&admin_token, "user1@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;

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
        let gid = json.value().i64();

        // update group with normal user
        let resp = server
            .put(format!("/api/group/{}", gid))
            .header("X-API-Key", &token1)
            .body_json(&json!({
                "name": "test1",
            }))
            .send()
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);

        // update group with admin user
        let resp = server
            .put(format!("/api/group/{}", gid))
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test1",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
    }

    #[tokio::test]
    async fn cannot_change_the_public_group_owner() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;

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
        let gid = json.value().i64();

        // change the owner
        let resp = server
            .put(format!("/api/group/{}", gid))
            .header("X-API-Key", &admin_token)
            .body_json(&json!(  {
                "owner": uid1,
            }))
            .send()
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn only_admin_can_delete_public_group() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        server.create_user(&admin_token, "user1@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;

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
        let gid = json.value().i64();

        // delete group with normal user
        let resp = server
            .delete(format!("/api/group/{}", gid))
            .header("X-API-Key", &token1)
            .send()
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);

        // delete group with admin user
        let resp = server
            .delete(format!("/api/group/{}", gid))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();
    }

    #[tokio::test]
    async fn test_send_to_private_group() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let mut ids = Vec::new();
        let mut tokens = Vec::new();

        for i in 1..10 {
            ids.push(
                server
                    .create_user(&admin_token, format!("test{}@voce.chat", i))
                    .await,
            );
            tokens.push(server.login(format!("test{}@voce.chat", i)).await);
        }

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &tokens[0])
            .body_json(&json!({
                "name": "test",
                "members": ids[1..].iter().copied().collect_vec(),
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let gid = resp.json().await.value().i64();

        // send text
        for i in 0..10 {
            server
                .send_text_to_group(&tokens[0], gid, format!("hello {}", i))
                .await;
        }

        // subscribe
        let mut streams = Vec::new();
        for token in &tokens {
            let stream = server.subscribe_events(token, Some(&["chat"])).await;
            streams.push(stream);
        }

        for stream in &mut streams {
            for j in 0..10 {
                let event = stream.next().await.unwrap();
                let event = event.value().object();
                event.get("target").object().get("gid").assert_i64(gid);
                let detail = event.get("detail").object();
                detail.get("content").assert_string(&format!("hello {}", j));
            }
        }

        // send text
        for i in 10..20 {
            server
                .send_text_to_group(&tokens[0], gid, format!("hello {}", i))
                .await;
        }

        for stream in &mut streams {
            for j in 10..20 {
                let event = stream.next().await.unwrap();
                let event = event.value().object();
                event.get("target").object().get("gid").assert_i64(gid);
                let detail = event.get("detail").object();
                detail.get("content").assert_string(&format!("hello {}", j));
            }
        }
    }

    #[tokio::test]
    async fn test_send_to_public_group() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        server.create_user(&admin_token, "user1@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        server.create_user(&admin_token, "user2@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;

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
        let gid = json.value().i64();

        // subscribe events
        let mut events1 = server.subscribe_events(&token1, Some(&["chat"])).await;
        let mut events2 = server.subscribe_events(&token2, Some(&["chat"])).await;

        // send message
        let id1 = server.send_text_to_group(&token1, gid, "a").await;
        let id2 = server.send_text_to_group(&token2, gid, "b").await;
        let id3 = server.send_text_to_group(&token1, gid, "c").await;

        // check messages
        for events in [&mut events1, &mut events2] {
            let msg = events.next().await.unwrap();
            assert_eq!(msg.value().object().get("mid").i64(), id1);
            let msg = events.next().await.unwrap();
            assert_eq!(msg.value().object().get("mid").i64(), id2);
            let msg = events.next().await.unwrap();
            assert_eq!(msg.value().object().get("mid").i64(), id3);
        }
    }

    #[tokio::test]
    async fn test_related_groups() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let uid3 = server.create_user(&admin_token, "user3@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;
        let token3 = server.login("user3@voce.chat").await;

        // create public group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "public",
                "is_public": true,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let public_gid = json.value().i64();

        // create group1
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
        let gid1 = json.value().i64();

        // create group2
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "members": [uid2, uid3]
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid2 = json.value().i64();

        // get related groups
        async fn check_groups(server: &TestServer, token: &str, mut groups: Vec<i64>) {
            let resp = server
                .get("/api/group")
                .header("X-API-Key", token)
                .send()
                .await;
            resp.assert_status_is_ok();
            let json = resp.json().await;

            let mut res = json
                .value()
                .array()
                .iter()
                .map(|group| group.object().get("gid").i64())
                .collect_vec();
            res.sort_unstable();
            groups.sort_unstable();
            assert_eq!(res, groups);
        }

        check_groups(&server, &admin_token, vec![public_gid, gid1, gid2]).await;
        check_groups(&server, &token1, vec![public_gid, gid1]).await;
        check_groups(&server, &token2, vec![public_gid, gid1, gid2]).await;
        check_groups(&server, &token3, vec![public_gid, gid2]).await;
    }

    #[tokio::test]
    async fn test_history_messages() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

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
        let gid = json.value().i64();

        let id1 = server.send_text_to_group(&admin_token, gid, "a").await;
        let id2 = server.send_text_to_group(&admin_token, gid, "b").await;
        let id3 = server.send_text_to_group(&admin_token, gid, "c").await;

        async fn check(
            server: &TestServer,
            token: &str,
            gid: i64,
            before_mid: Option<i64>,
            expect: Vec<(i64, &str)>,
        ) {
            let mut builder = server
                .get(format!("/api/group/{}/history", gid))
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
            gid,
            None,
            vec![(id1, "a"), (id2, "b"), (id3, "c")],
        )
        .await;

        check(
            &server,
            &admin_token,
            gid,
            Some(id3),
            vec![(id1, "a"), (id2, "b")],
        )
        .await;

        check(&server, &admin_token, gid, Some(id1), vec![]).await;
    }

    #[tokio::test]
    async fn test_leave_group() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "members": [uid1],
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().i64();

        assert_eq!(
            server
                .get_group(gid)
                .await
                .value()
                .object()
                .get("members")
                .i64_array(),
            vec![1, uid1]
        );

        // uid1 leave the group
        let resp = server
            .get(format!("/api/group/{}/leave", gid))
            .header("X-API-Key", &token1)
            .send()
            .await;
        resp.assert_status_is_ok();

        assert_eq!(
            server
                .get_group(gid)
                .await
                .value()
                .object()
                .get("members")
                .i64_array(),
            vec![1]
        );

        // owner leave the group
        let resp = server
            .get(format!("/api/group/{}/leave", gid))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status(StatusCode::FORBIDDEN)
    }

    #[tokio::test]
    async fn received_update_group_msg() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        server.create_user(&admin_token, "user1@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;

        let mut admin_events = server
            .subscribe_events(&admin_token, Some(&["group_changed"]))
            .await;
        let mut user1_events = server
            .subscribe_events(&token1, Some(&["group_changed"]))
            .await;
        let mut user2_events = server
            .subscribe_events(&token2, Some(&["group_changed"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test1",
                "is_public": true,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let public_gid = json.value().i64();

        let resp = server
            .post("/api/group")
            .header("X-API-Key", &token1)
            .body_json(&json!({
                "name": "test2",
                "members": [uid2],
                "is_public": false,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let private_gid = json.value().i64();

        // update public group
        let resp = server
            .put(format!("/api/group/{}", public_gid))
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test3",
                "description": "abc",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut user1_events, &mut user2_events, &mut admin_events] {
            let msg = events.next().await.unwrap();
            let obj = msg.value().object();
            obj.get("type").assert_string("group_changed");
            obj.get("gid").assert_i64(public_gid);
            obj.get("name").assert_string("test3");
            obj.get("description").assert_string("abc");
            obj.get("owner").assert_null();
            obj.get("avatar_updated_at").assert_null();
        }

        // update private group
        let resp = server
            .put(format!("/api/group/{}", private_gid))
            .header("X-API-Key", &token1)
            .body_json(&json!({
                "name": "test4",
                "description": "def",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut user2_events, &mut user1_events] {
            let msg = events.next().await.unwrap();
            let obj = msg.value().object();
            obj.get("type").assert_string("group_changed");
            obj.get("gid").assert_i64(private_gid);
            obj.get("name").assert_string("test4");
            obj.get("description").assert_string("def");
            obj.get("owner").assert_null();
            obj.get("avatar_updated_at").assert_null();
        }

        // update public group avatar
        let resp = server
            .post(format!("/api/group/{}/avatar", public_gid))
            .header("X-API-Key", &admin_token)
            .content_type("image/png")
            .body(include_bytes!("assets/poem.png").to_vec())
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut user1_events, &mut user2_events, &mut admin_events] {
            let msg = events.next().await.unwrap();
            let obj = msg.value().object();
            obj.get("type").assert_string("group_changed");
            obj.get("gid").assert_i64(public_gid);
            obj.get("avatar_updated_at").assert_not_null();
        }
    }

    // #[tokio::test]
    // async fn invite_to_group() {
    //     let server = TestServer::new_with_config(|cfg| {
    //         let url = "http://localhost:3000/web/invite?code={{ code|url_encode }}&token={{ token|url_encode }}";
    //         cfg.link.reg_magic_url_tpl =
    //             Some(url.to_string());
    //     })
    //     .await;
    //     let admin_token = server.login_admin().await;
    //
    //     // create group
    //     let resp = server
    //         .post("/api/group")
    //         .header("X-API-Key", &admin_token)
    //         .body_json(&json!({
    //             "name": "test",
    //             "description": "abc",
    //             "is_public": false,
    //             "members": [],
    //         }))
    //         .send()
    //         .await;
    //     resp.assert_status_is_ok();
    //     let json = resp.json().await;
    //     let gid = json.value().i64();
    //
    //     // create invite link
    //     let resp = server
    //         .get(format!("/api/group/create_reg_magic_link/gid={}", gid))
    //         .header("X-API-Key", &admin_token)
    //         .send()
    //         .await;
    //     resp.assert_status_is_ok();
    //     let url = resp.0.into_body().into_string().await.unwrap();
    //     let uri = Uri::from_str(&url).unwrap();
    //
    //     #[derive(Deserialize)]
    //     struct Params {
    //         code: bool,
    //         token: String,
    //     }
    //     let params = serde_urlencoded::from_str::<Params>(uri.query().unwrap()).unwrap();
    //     assert!(!params.code);
    //
    //     // register user
    //     let resp = server
    //         .post("/api/user/register")
    //         .header("X-API-Key", &admin_token)
    //         .body_json(&json!({
    //             "magic_token": params.token,
    //             "email": "user1@voce.chat",
    //             "password": "123456",
    //             "name": "user1",
    //             "gender": 1,
    //         }))
    //         .send()
    //         .await;
    //     resp.assert_status_is_ok();
    //     let uid = resp.json().await.value().object().get("uid").i64();
    //
    //     let resp = server
    //         .get(format!("/api/group/{}", gid))
    //         .header("X-API-Key", &admin_token)
    //         .send()
    //         .await;
    //     let json = resp.json().await;
    //     json.value()
    //         .object()
    //         .get("members")
    //         .array()
    //         .assert_contains(|value| value.i64() == uid);
    //
    //     // create invite link by group member
    //     let user1_token = server.login("user1@voce.chat").await;
    //
    //     let resp = server
    //         .get(format!("/api/group/create_reg_magic_link?gid=", gid))
    //         .header("X-API-Key", &user1_token)
    //         .send()
    //         .await;
    //     resp.assert_status_is_ok();
    //
    //     // create invite link by a user not in the group
    //     server.create_user(&admin_token, "user2@voce.chat").await;
    //     let user2_token = server.login("user2@voce.chat").await;
    //
    //     let resp = server
    //         .get(format!("/api/group/create_reg_magic_link?gid=", gid))
    //         .header("X-API-Key", &user2_token)
    //         .send()
    //         .await;
    //     resp.assert_status(StatusCode::FORBIDDEN);
    // }

    #[tokio::test]
    async fn pin_messsage() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "description": "abc",
                "is_public": false,
                "members": [],
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().i64();

        let mid1 = server.send_text_to_group(&admin_token, gid, "a").await;
        let mid2 = server.send_text_to_group(&admin_token, gid, "b").await;
        let mid3 = server.send_text_to_group(&admin_token, gid, "c").await;

        // pin
        for mid in [mid1, mid2] {
            let resp = server
                .post(format!("/api/group/{}/pin", gid))
                .header("X-API-Key", &admin_token)
                .body_json(&json!({
                    "mid": mid,
                }))
                .send()
                .await;
            resp.assert_status_is_ok();
        }

        let resp = server.get(format!("/api/group/{}", gid)).send().await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let json = json.value().object();

        let pinned_msgs = json.get("pinned_messages").array();
        pinned_msgs.assert_len(2);

        let m1 = pinned_msgs.get(0).object();
        m1.get("mid").assert_i64(mid1);
        m1.get("content").assert_string("a");

        let m2 = pinned_msgs.get(1).object();
        m2.get("mid").assert_i64(mid2);
        m2.get("content").assert_string("b");

        // unpin
        let resp = server
            .post(format!("/api/group/{}/unpin", gid))
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "mid": mid3,
            }))
            .send()
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);

        let resp = server
            .post(format!("/api/group/{}/unpin", gid))
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "mid": mid1,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        let resp = server.get(format!("/api/group/{}", gid)).send().await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let json = json.value().object();

        let pinned_msgs = json.get("pinned_messages").array();
        pinned_msgs.assert_len(1);

        let m1 = pinned_msgs.get(0).object();
        m1.get("mid").assert_i64(mid2);
        m1.get("content").assert_string("b");
    }

    #[tokio::test]
    async fn received_pinned_message_updated_private_group() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let mut events_admin = server
            .subscribe_events(&admin_token, Some(&["pinned_message_updated"]))
            .await;
        let uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let user1_token = server.login("user1@voce.chat").await;
        let mut events_user1 = server
            .subscribe_events(&user1_token, Some(&["pinned_message_updated"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "description": "abc",
                "is_public": false,
                "members": [uid1],
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().i64();

        let mid1 = server.send_text_to_group(&admin_token, gid, "a").await;
        let mid2 = server.send_text_to_group(&admin_token, gid, "b").await;

        for mid in [mid1, mid2] {
            let resp = server
                .post(format!("/api/group/{}/pin", gid))
                .header("X-API-Key", &admin_token)
                .body_json(&json!({
                    "mid": mid,
                }))
                .send()
                .await;
            resp.assert_status_is_ok();
        }

        for events in [&mut events_admin, &mut events_user1] {
            let msg = events.next().await.unwrap();
            let obj = msg.value().object();
            obj.get("gid").assert_i64(gid);
            obj.get("mid").assert_i64(mid1);
            let msg = obj.get("msg").object();
            msg.get("content").assert_string("a");

            let msg = events.next().await.unwrap();
            let obj = msg.value().object();
            obj.get("gid").assert_i64(gid);
            obj.get("mid").assert_i64(mid2);
            let msg = obj.get("msg").object();
            msg.get("content").assert_string("b");
        }

        let resp = server
            .put(format!("/api/message/{}/edit", mid1))
            .header("X-API-Key", &admin_token)
            .content_type("text/plain")
            .body("c")
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut events_admin, &mut events_user1] {
            let msg = events.next().await.unwrap();
            let obj = msg.value().object();
            obj.get("gid").assert_i64(gid);
            obj.get("mid").assert_i64(mid1);
            let msg = obj.get("msg").object();
            msg.get("content").assert_string("c");
        }

        let resp = server
            .delete(format!("/api/message/{}", mid1))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut events_admin, &mut events_user1] {
            let msg = events.next().await.unwrap();
            let obj = msg.value().object();
            obj.get("gid").assert_i64(gid);
            obj.get("mid").assert_i64(mid1);
            obj.get("msg").assert_null();
        }
    }

    #[tokio::test]
    async fn received_pinned_message_updated_public_group() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let mut events_admin = server
            .subscribe_events(&admin_token, Some(&["pinned_message_updated"]))
            .await;
        server.create_user(&admin_token, "user1@voce.chat").await;
        let user1_token = server.login("user1@voce.chat").await;
        let mut events_user1 = server
            .subscribe_events(&user1_token, Some(&["pinned_message_updated"]))
            .await;

        // create group
        let resp = server
            .post("/api/group")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": "test",
                "description": "abc",
                "is_public": true,
                "members": [],
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let gid = json.value().i64();

        let mid1 = server.send_text_to_group(&admin_token, gid, "a").await;
        let mid2 = server.send_text_to_group(&admin_token, gid, "b").await;

        for mid in [mid1, mid2] {
            let resp = server
                .post(format!("/api/group/{}/pin", gid))
                .header("X-API-Key", &admin_token)
                .body_json(&json!({
                    "mid": mid,
                }))
                .send()
                .await;
            resp.assert_status_is_ok();
        }

        for events in [&mut events_admin, &mut events_user1] {
            let msg = events.next().await.unwrap();
            let obj = msg.value().object();
            obj.get("gid").assert_i64(gid);
            obj.get("mid").assert_i64(mid1);
            let msg = obj.get("msg").object();
            msg.get("content").assert_string("a");

            let msg = events.next().await.unwrap();
            let obj = msg.value().object();
            obj.get("gid").assert_i64(gid);
            obj.get("mid").assert_i64(mid2);
            let msg = obj.get("msg").object();
            msg.get("content").assert_string("b");
        }

        let resp = server
            .put(format!("/api/message/{}/edit", mid1))
            .header("X-API-Key", &admin_token)
            .content_type("text/plain")
            .body("c")
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut events_admin, &mut events_user1] {
            let msg = events.next().await.unwrap();
            let obj = msg.value().object();
            obj.get("gid").assert_i64(gid);
            obj.get("mid").assert_i64(mid1);
            let msg = obj.get("msg").object();
            msg.get("content").assert_string("c");
        }

        let resp = server
            .delete(format!("/api/message/{}", mid1))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();

        for events in [&mut events_admin, &mut events_user1] {
            let msg = events.next().await.unwrap();
            let obj = msg.value().object();
            obj.get("gid").assert_i64(gid);
            obj.get("mid").assert_i64(mid1);
            obj.get("msg").assert_null();
        }
    }
}
