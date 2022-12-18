use poem::{http::StatusCode, web::Data, Error, Result};
use poem_openapi::{
    param::{Header, Path, Query},
    payload::Json,
    OpenApi,
};

use crate::{
    api::{
        group::get_related_groups,
        message::{parse_properties_from_base64, send_message, SendMessageRequest},
        tags::ApiTags,
        DateTime, Group, MessageTarget,
    },
    api_key::parse_api_key,
    state::State,
};

async fn check_api_key(state: &State, uid: i64, key: &str) -> Result<()> {
    let mut cache = state.cache.write().await;
    let bot_key = cache
        .users
        .get_mut(&uid)
        .and_then(|user| {
            user.bot_keys
                .values_mut()
                .find(|bot_key| bot_key.key == key)
        })
        .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
    bot_key.last_used = Some(DateTime::now());
    Ok(())
}

pub struct ApiBot;

#[OpenApi(prefix_path = "/bot", tag = "ApiTags::Bot")]
impl ApiBot {
    /// Get all groups related to the current user.
    #[oai(path = "/", method = "get")]
    async fn get_related_groups(
        &self,
        state: Data<&State>,
        #[oai(name = "x-api-key")] api_key: Header<String>,
        public_only: Query<Option<bool>>,
    ) -> Result<Json<Vec<Group>>> {
        let current_uid = parse_api_key(&api_key, &state.0.key_config.read().await.server_key)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
        check_api_key(&state, current_uid, &api_key).await?;
        let cache = state.cache.read().await;
        Ok(Json(get_related_groups(
            &cache.groups,
            current_uid,
            public_only.0.unwrap_or_default(),
        )))
    }

    /// Send message to the specified user
    #[oai(path = "/send_to_user/:uid", method = "post")]
    async fn send_to_user(
        &self,
        state: Data<&State>,
        #[oai(name = "x-api-key")] api_key: Header<String>,
        uid: Path<i64>,
        #[oai(name = "X-Properties")] properties: Header<Option<String>>,
        req: SendMessageRequest,
    ) -> Result<Json<i64>> {
        let current_uid = parse_api_key(&api_key, &state.0.key_config.read().await.server_key)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
        check_api_key(&state, current_uid, &api_key).await?;
        let properties = parse_properties_from_base64(properties.0);
        let payload = req
            .into_chat_message_payload(&state, current_uid, MessageTarget::user(uid.0), properties)
            .await?;
        let mid = send_message(&state, payload).await?;
        Ok(Json(mid))
    }

    /// Send message to the specified group
    #[oai(path = "/send_to_group/:gid", method = "post")]
    async fn send_to_group(
        &self,
        state: Data<&State>,
        #[oai(name = "x-api-key")] api_key: Header<String>,
        gid: Path<i64>,
        #[oai(name = "X-Properties")] properties: Header<Option<String>>,
        req: SendMessageRequest,
    ) -> Result<Json<i64>> {
        let current_uid = parse_api_key(&api_key, &state.0.key_config.read().await.server_key)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
        check_api_key(&state, current_uid, &api_key).await?;
        let properties = parse_properties_from_base64(properties.0);
        let payload = req
            .into_chat_message_payload(&state, current_uid, MessageTarget::group(gid.0), properties)
            .await?;
        let mid = send_message(&state, payload).await?;
        Ok(Json(mid))
    }
}
