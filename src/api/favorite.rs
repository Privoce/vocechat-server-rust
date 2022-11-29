use poem::{
    error::InternalServerError,
    http::{header, StatusCode},
    web::Data,
    Error, Result,
};
use poem_openapi::{
    param::{Path, Query},
    payload::{Binary, Json, Response},
    ApiResponse, Object, OpenApi,
};

use crate::{
    api::{
        archive::{create_message_archive, extract_archive, extract_archive_attachment},
        tags::ApiTags,
        token::Token,
        Archive, DateTime,
    },
    middleware::guest_forbidden,
    state::State,
};

#[derive(Debug, Object)]
struct FavoriteArchive {
    id: String,
    created_at: DateTime,
}

#[derive(Debug, Object)]
struct CreateFavoriteRequest {
    mid_list: Vec<i64>,
}

#[derive(Debug, ApiResponse)]
enum CreateFavoriteResponse {
    #[oai(status = 200)]
    Ok(Json<FavoriteArchive>),
    /// Too many favorite archives
    #[oai(status = 429)]
    TooManyFavorites,
}

pub struct ApiFavorite;

#[OpenApi(prefix_path = "/favorite", tag = "ApiTags::Favorite")]
impl ApiFavorite {
    /// Create favorite archive
    #[oai(path = "/", method = "post", transform = "guest_forbidden")]
    async fn create(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<CreateFavoriteRequest>,
    ) -> Result<CreateFavoriteResponse> {
        let sql = "select count(*) from favorite_archive where uid = ?";
        let count = sqlx::query_as::<_, (i64,)>(sql)
            .fetch_one(&state.db_pool)
            .await
            .map(|(count,)| count)
            .map_err(InternalServerError)?;
        if count >= state.config.system.max_favorite_archives as i64 {
            return Ok(CreateFavoriteResponse::TooManyFavorites);
        }

        let data = create_message_archive(&state, req.0.mid_list, token.uid).await?;
        let path = state.config.system.favorite_dir(token.uid);
        let uuid = uuid::Uuid::new_v4().to_string();

        let _ = std::fs::create_dir_all(&path);
        tokio::fs::write(path.join(&uuid), data)
            .await
            .map_err(InternalServerError)?;

        let now = DateTime::now();
        let sql = "insert into favorite_archive (uid, archive_id, created_at) values (?, ?, ?)";
        sqlx::query(sql)
            .bind(token.uid)
            .bind(&uuid)
            .bind(now)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;

        Ok(CreateFavoriteResponse::Ok(Json(FavoriteArchive {
            id: uuid,
            created_at: now,
        })))
    }

    /// List all favorite archives
    #[oai(path = "/", method = "get")]
    async fn list(&self, state: Data<&State>, token: Token) -> Result<Json<Vec<FavoriteArchive>>> {
        let sql = "select archive_id, created_at from favorite_archive where uid = ?";
        let mut archives = sqlx::query_as::<_, (String, DateTime)>(sql)
            .bind(token.uid)
            .fetch_all(&state.db_pool)
            .await
            .map_err(InternalServerError)?
            .into_iter()
            .map(|(archive_id, created_at)| FavoriteArchive {
                id: archive_id,
                created_at,
            })
            .collect::<Vec<_>>();
        archives.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(Json(archives))
    }

    /// Delete a favorite archive
    #[oai(path = "/:id", method = "delete", transform = "guest_forbidden")]
    async fn delete(&self, state: Data<&State>, token: Token, id: Path<String>) -> Result<()> {
        let path = state.config.system.favorite_dir(token.uid).join(&id.0);
        if !path.exists() {
            return Err(Error::from_status(StatusCode::NOT_FOUND));
        }

        sqlx::query("delete from favorite_archive where uid = ? and archive_id = ?")
            .bind(token.uid)
            .bind(&id.0)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;

        tokio::fs::remove_file(&path)
            .await
            .map_err(InternalServerError)?;

        Ok(())
    }

    /// Get favorite archive info
    #[oai(path = "/:id", method = "get")]
    async fn get_index(
        &self,
        state: Data<&State>,
        token: Token,
        id: Path<String>,
    ) -> Result<Response<Json<Archive>>> {
        if id.contains('.') {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }
        let path = state.config.system.favorite_dir(token.uid).join(&id.0);
        let archive = extract_archive(path).await?;
        Ok(Response::new(Json(archive)).header(header::CACHE_CONTROL, "public, max-age=31536000"))
    }

    /// Get attachment in the archive
    #[oai(path = "/attachment/:uid/:id/:attachment_id", method = "get")]
    async fn get_archive_attachment(
        &self,
        state: Data<&State>,
        uid: Path<i64>,
        id: Path<String>,
        attachment_id: Path<usize>,
        #[oai(default)] download: Query<bool>,
    ) -> Result<Response<Binary<Vec<u8>>>> {
        if id.contains('.') {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }
        let path = state.config.system.favorite_dir(uid.0).join(&id.0);
        let archive_file = extract_archive_attachment(path, attachment_id.0).await?;

        let mut resp = Response::new(Binary(archive_file.content));
        let ty = if download.0 { "attachment" } else { "inline" };
        resp = resp
            .header(header::CONTENT_TYPE, archive_file.content_type)
            .header(header::CACHE_CONTROL, "public, max-age=31536000");
        if let Some(filename) = archive_file.filename {
            resp = resp.header(
                header::CONTENT_DISPOSITION,
                format!(r#"{}; filename="{}""#, ty, filename),
            );
        }

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::test_harness::TestServer;

    #[tokio::test]
    async fn test_crud() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        let user1 = server.create_user(&admin_token, "user1@voce.chat").await;
        server.login("user1@voce.chat").await;

        let mid1 = server.send_text_to_user(&admin_token, user1, "a").await;
        let mid2 = server.send_text_to_user(&admin_token, user1, "b").await;
        let mid3 = server.send_text_to_user(&admin_token, user1, "c").await;

        let resp = server
            .post("/api/favorite")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "mid_list": [mid1, mid2],
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let archive1 = json.value().object().get("id").string().to_string();

        let resp = server
            .post("/api/favorite")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "mid_list": [mid2, mid3],
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let archive2 = json.value().object().get("id").string().to_string();

        let resp = server
            .get("/api/favorite")
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let archives = json.value().array();

        archives.assert_len(2);
        archives.get(0).object().get("id").assert_string(&archive1);
        archives.get(1).object().get("id").assert_string(&archive2);

        let resp = server
            .get(format!("/api/favorite/{}", archive1))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let json = json.value().object();

        let users = json.get("users").array();
        users.assert_len(1);
        users.get(0).object().get("name").assert_string("admin");

        let messages = json.get("messages").array();
        messages.assert_len(2);

        let message = messages.get(0).object();
        message.get("from_user").assert_i64(0);
        message.get("content_type").assert_string("text/plain");
        message.get("content").assert_string("a");

        let message = messages.get(1).object();
        message.get("from_user").assert_i64(0);
        message.get("content_type").assert_string("text/plain");
        message.get("content").assert_string("b");

        json.get("num_attachments").assert_i64(0);

        let resp = server
            .delete(format!("/api/favorite/{}", archive1))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();

        let resp = server
            .get("/api/favorite")
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        json.value().array().assert_len(1);
    }
}
