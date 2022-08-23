use poem::{error::InternalServerError, http::StatusCode, web::Data, Error, Result};
use poem_openapi::{
    param::{Header, Path},
    payload::Json,
    ApiResponse, Object, OpenApi,
};

use crate::{
    api::{
        message::{
            parse_properties_from_base64, send_message, MessageDetail, MessageReaction,
            MessageReactionDelete, MessageReactionDetail, MessageReactionEdit, MessageReactionLike,
            MessageReply, SendMessageRequest,
        },
        tags::ApiTags,
        token::Token,
        ChatMessagePayload, DateTime, MessageTarget, MessageTargetGroup, MessageTargetUser,
    },
    middleware::guest_forbidden,
    State,
};

pub struct ApiMessage;

#[derive(Debug, Object)]
struct LikeMessageRequest {
    action: String,
}

#[derive(ApiResponse)]
enum ReactionApiResponse {
    /// Success
    #[oai(status = 200)]
    Ok(Json<i64>),
    /// Target user does not exist
    #[oai(status = 404)]
    MessageDoesNotExist,
    #[oai(status = 403)]
    Forbidden,
}

#[OpenApi(prefix_path = "/message", tag = "ApiTags::Message")]
impl ApiMessage {
    /// Edit message
    #[oai(path = "/:mid/edit", method = "put", transform = "guest_forbidden")]
    async fn edit(
        &self,
        state: Data<&State>,
        token: Token,
        mid: Path<i64>,
        #[oai(name = "X-Properties")] properties: Header<Option<String>>,
        req: SendMessageRequest,
    ) -> Result<ReactionApiResponse> {
        let properties = parse_properties_from_base64(properties.0);
        let content = req.into_chat_message_content(&state, properties).await?;
        do_reaction(
            &state,
            token,
            mid.0,
            MessageReactionDetail::Edit(MessageReactionEdit { content }),
        )
        .await
    }

    /// Edit message
    #[oai(path = "/:mid/like", method = "put", transform = "guest_forbidden")]
    async fn like(
        &self,
        state: Data<&State>,
        token: Token,
        mid: Path<i64>,
        req: Json<LikeMessageRequest>,
    ) -> Result<ReactionApiResponse> {
        let like = MessageReactionLike {
            action: req.0.action,
        };
        if !like.check() {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        do_reaction(&state, token, mid.0, MessageReactionDetail::Like(like)).await
    }

    /// Delete message
    #[oai(path = "/:mid", method = "delete", transform = "guest_forbidden")]
    async fn delete(
        &self,
        state: Data<&State>,
        token: Token,
        mid: Path<i64>,
    ) -> Result<ReactionApiResponse> {
        do_reaction(
            &state,
            token,
            mid.0,
            MessageReactionDetail::Delete(MessageReactionDelete {}),
        )
        .await
    }

    /// Reply message
    #[oai(path = "/:mid/reply", method = "post", transform = "guest_forbidden")]
    async fn reply(
        &self,
        state: Data<&State>,
        token: Token,
        mid: Path<i64>,
        #[oai(name = "X-Properties")] properties: Header<Option<String>>,
        req: SendMessageRequest,
    ) -> Result<ReactionApiResponse> {
        let properties = parse_properties_from_base64(properties.0);
        let content = req.into_chat_message_content(&state, properties).await?;

        let msg_data = match state
            .msg_db
            .messages()
            .get(mid.0)
            .map_err(InternalServerError)?
        {
            Some(data) => data,
            None => return Ok(ReactionApiResponse::MessageDoesNotExist),
        };
        let payload =
            serde_json::from_slice::<ChatMessagePayload>(&msg_data).map_err(InternalServerError)?;

        if !matches!(
            &payload.detail,
            MessageDetail::Normal(_) | MessageDetail::Reply(_)
        ) {
            return Ok(ReactionApiResponse::Forbidden);
        }

        match payload.target {
            MessageTarget::User(MessageTargetUser { uid }) => {
                if uid != token.uid && payload.from_uid != token.uid {
                    return Ok(ReactionApiResponse::Forbidden);
                }
            }
            MessageTarget::Group(MessageTargetGroup { gid }) => {
                let cache = state.cache.read().await;
                let group = match cache.groups.get(&gid) {
                    Some(group) => group,
                    None => return Ok(ReactionApiResponse::Forbidden),
                };
                if !group.contains_user(token.uid) {
                    return Ok(ReactionApiResponse::Forbidden);
                }
            }
        }

        let new_payload = ChatMessagePayload {
            from_uid: token.uid,
            created_at: DateTime::now(),
            target: get_target(token.uid, &payload),
            detail: MessageDetail::Reply(MessageReply {
                mid: mid.0,
                content,
            }),
        };
        let new_mid = send_message(&state, new_payload).await?;
        Ok(ReactionApiResponse::Ok(Json(new_mid)))
    }
}

fn get_target(current_uid: i64, payload: &ChatMessagePayload) -> MessageTarget {
    match payload.target {
        MessageTarget::User(MessageTargetUser { uid }) => {
            MessageTarget::user(if uid == current_uid {
                payload.from_uid
            } else {
                uid
            })
        }
        MessageTarget::Group(MessageTargetGroup { gid }) => MessageTarget::group(gid),
    }
}

async fn do_reaction(
    state: &State,
    token: Token,
    mid: i64,
    detail: MessageReactionDetail,
) -> Result<ReactionApiResponse> {
    let msg_data = match state
        .msg_db
        .messages()
        .get(mid)
        .map_err(InternalServerError)?
    {
        Some(data) => data,
        None => return Ok(ReactionApiResponse::MessageDoesNotExist),
    };
    let payload =
        serde_json::from_slice::<ChatMessagePayload>(&msg_data).map_err(InternalServerError)?;
    if !detail.can_reaction(token.uid, token.is_admin, &payload) {
        return Ok(ReactionApiResponse::Forbidden);
    }

    let new_payload = ChatMessagePayload {
        from_uid: token.uid,
        created_at: DateTime::now(),
        target: get_target(token.uid, &payload),
        detail: MessageDetail::Reaction(MessageReaction { mid, detail }),
    };
    let new_mid = send_message(state, new_payload).await?;
    Ok(ReactionApiResponse::Ok(Json(new_mid)))
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;
    use serde_json::json;

    use crate::test_harness::TestServer;

    #[tokio::test]
    async fn test_reaction_edit() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let user1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let user1_token = server.login("user1@voce.chat").await;
        let mut user1_events = server.subscribe_events(&user1_token, Some(&["chat"])).await;

        let mid1 = server.send_text_to_user(&admin_token, user1, "a").await;

        let resp = server
            .put(format!("/api/message/{}/edit", mid1))
            .header("X-API-Key", &admin_token)
            .content_type("text/plain")
            .body("b")
            .send()
            .await;
        resp.assert_status_is_ok();
        let mid2 = resp.json().await.value().i64();

        let msg = user1_events.next().await.unwrap();
        let msg = msg.value().object();
        msg.get("mid").assert_i64(mid1);
        msg.get("from_uid").assert_i64(1);
        msg.get("target").object().get("uid").assert_i64(user1);
        let detail = msg.get("detail").object();
        detail.get("type").assert_string("normal");
        detail.get("content_type").assert_string("text/plain");
        detail.get("content").assert_string("a");

        let msg = user1_events.next().await.unwrap();
        let msg = msg.value().object();
        msg.get("mid").assert_i64(mid2);
        msg.get("from_uid").assert_i64(1);
        msg.get("target").object().get("uid").assert_i64(user1);
        let detail = msg.get("detail").object();
        detail.get("type").assert_string("reaction");
        detail.get("mid").assert_i64(mid1);
        let reaction_detail = detail.get("detail").object();
        reaction_detail.get("type").assert_string("edit");
        reaction_detail.get("content").assert_string("b");
    }

    #[tokio::test]
    async fn test_reaction_like() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let user1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let user1_token = server.login("user1@voce.chat").await;
        let mut admin_events = server.subscribe_events(&admin_token, Some(&["chat"])).await;
        let mut user1_events = server.subscribe_events(&user1_token, Some(&["chat"])).await;

        let mid1 = server.send_text_to_user(&admin_token, user1, "a").await;

        for events in [&mut admin_events, &mut user1_events] {
            let msg = events.next().await.unwrap();
            let msg = msg.value().object();
            msg.get("mid").assert_i64(mid1);
            msg.get("from_uid").assert_i64(1);
            msg.get("target").object().get("uid").assert_i64(user1);
        }

        let resp = server
            .put(format!("/api/message/{}/like", mid1))
            .header("X-API-Key", &admin_token)
            .content_type("application/json")
            .body_json(&json!({
                "action": "❤️"
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let mid2 = resp.json().await.value().i64();

        let resp = server
            .put(format!("/api/message/{}/like", mid1))
            .header("X-API-Key", &user1_token)
            .content_type("application/json")
            .body_json(&json!({
                "action": "🚀"
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let mid3 = resp.json().await.value().i64();

        for events in [&mut admin_events, &mut user1_events] {
            let msg = events.next().await.unwrap();
            let msg = msg.value().object();
            msg.get("mid").assert_i64(mid2);
            msg.get("from_uid").assert_i64(1);
            msg.get("target").object().get("uid").assert_i64(user1);
            let detail = msg.get("detail").object();
            detail.get("type").assert_string("reaction");
            detail.get("mid").assert_i64(mid1);
            let reaction_detail = detail.get("detail").object();
            reaction_detail.get("type").assert_string("like");
            reaction_detail.get("action").assert_string("❤️");

            let msg = events.next().await.unwrap();
            let msg = msg.value().object();
            msg.get("mid").assert_i64(mid3);
            msg.get("from_uid").assert_i64(user1);
            msg.get("target").object().get("uid").assert_i64(1);
            let detail = msg.get("detail").object();
            detail.get("type").assert_string("reaction");
            detail.get("mid").assert_i64(mid1);
            let reaction_detail = detail.get("detail").object();
            reaction_detail.get("type").assert_string("like");
            reaction_detail.get("action").assert_string("🚀");
        }
    }

    #[tokio::test]
    async fn test_reply() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let user1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let user1_token = server.login("user1@voce.chat").await;
        let mut user1_events = server.subscribe_events(&user1_token, Some(&["chat"])).await;

        let mid1 = server.send_text_to_user(&admin_token, user1, "a").await;

        let msg = user1_events.next().await.unwrap();
        let msg = msg.value().object();
        msg.get("mid").assert_i64(mid1);
        let detail = msg.get("detail").object();
        detail.get("type").assert_string("normal");
        detail.get("content_type").assert_string("text/plain");
        detail.get("content").assert_string("a");

        let resp = server
            .post(format!("/api/message/{}/reply", mid1))
            .content_type("text/plain")
            .header("X-API-Key", &admin_token)
            .body("b")
            .send()
            .await;
        resp.assert_status_is_ok();
        let mid2 = resp.json().await.value().i64();

        let msg = user1_events.next().await.unwrap();
        let msg = msg.value().object();
        msg.get("mid").assert_i64(mid2);
        let detail = msg.get("detail").object();
        detail.get("type").assert_string("reply");
        detail.get("mid").assert_i64(mid1);
        detail.get("content_type").assert_string("text/plain");
        detail.get("content").assert_string("b");

        let resp = server
            .post(format!("/api/message/{}/reply", mid1))
            .content_type("text/plain")
            .header("X-API-Key", &user1_token)
            .body("c")
            .send()
            .await;
        resp.assert_status_is_ok();
        let mid3 = resp.json().await.value().i64();

        let msg = user1_events.next().await.unwrap();
        let msg = msg.value().object();
        msg.get("mid").assert_i64(mid3);
        let detail = msg.get("detail").object();
        detail.get("type").assert_string("reply");
        detail.get("mid").assert_i64(mid1);
        detail.get("content_type").assert_string("text/plain");
        detail.get("content").assert_string("c");

        let resp = server
            .post(format!("/api/message/{}/reply", mid3))
            .content_type("text/plain")
            .header("X-API-Key", &user1_token)
            .body("d")
            .send()
            .await;
        resp.assert_status_is_ok();
        let mid4 = resp.json().await.value().i64();

        let msg = user1_events.next().await.unwrap();
        let msg = msg.value().object();
        msg.get("mid").assert_i64(mid4);
        let detail = msg.get("detail").object();
        detail.get("type").assert_string("reply");
        detail.get("mid").assert_i64(mid3);
        detail.get("content_type").assert_string("text/plain");
        detail.get("content").assert_string("d");
    }
}
