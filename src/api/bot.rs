use std::str::FromStr;

use chrono::Datelike;
use futures_util::TryFutureExt;
use mime_guess::{mime, Mime};
use poem::{
    error::{BadRequest, InternalServerError},
    http::StatusCode,
    web::Data,
    Error, Result,
};
use poem_openapi::{
    param::{Header, Path, Query},
    payload::Json,
    OpenApi,
};
use tokio::io::AsyncWriteExt;

use crate::{
    api::{
        group::get_related_groups,
        message::{parse_properties_from_base64, send_message, SendMessageRequest},
        resource::{
            sha256_file, ImageProperties, PrepareUploadFileRequest, UploadFileRequest,
            UploadFileResponse,
        },
        tags::ApiTags,
        DateTime, FileMeta, Group, MessageTarget, UserInfo,
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

    /// Get user info by id
    #[oai(path = "/user/:uid", method = "get")]
    async fn user_info(
        &self,
        state: Data<&State>,
        #[oai(name = "x-api-key")] api_key: Header<String>,
        uid: Query<i64>,
    ) -> Result<Json<UserInfo>> {
        let current_uid = parse_api_key(&api_key, &state.0.key_config.read().await.server_key)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
        check_api_key(&state, current_uid, &api_key).await?;
        let cache = state.cache.read().await;
        let user = cache
            .users
            .get(&uid.0)
            .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;
        Ok(Json(user.api_user_info(uid.0)))
    }

    /// Get group info by id
    #[oai(path = "/group/:gid", method = "get")]
    async fn group_info(
        &self,
        state: Data<&State>,
        #[oai(name = "x-api-key")] api_key: Header<String>,
        gid: Query<i64>,
    ) -> Result<Json<Group>> {
        let current_uid = parse_api_key(&api_key, &state.0.key_config.read().await.server_key)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
        check_api_key(&state, current_uid, &api_key).await?;
        let cache = state.cache.read().await;
        let group = cache
            .groups
            .get(&gid.0)
            .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;
        Ok(Json(group.api_group(gid.0)))
    }

    /// Prepare for uploading file
    #[oai(path = "/file/prepare", method = "post")]
    async fn upload_file_prepare(
        &self,
        state: Data<&State>,
        req: Json<PrepareUploadFileRequest>,
        #[oai(name = "x-api-key")] api_key: Header<String>,
    ) -> Result<Json<String>> {
        let current_uid = parse_api_key(&api_key, &state.0.key_config.read().await.server_key)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
        check_api_key(&state, current_uid, &api_key).await?;

        let uuid = uuid::Uuid::new_v4().to_string();

        let tmp_file_path = state
            .config
            .system
            .tmp_dir()
            .join(&uuid)
            .with_extension("data");
        let tmp_file_path_meta = tmp_file_path.with_extension("meta");

        tokio::fs::write(&tmp_file_path, &[])
            .await
            .map_err(InternalServerError)?;

        let meta = FileMeta {
            content_type: match req.0.content_type {
                Some(content_type) => content_type,
                None => match &req.filename {
                    Some(filename) => mime_guess::from_path(filename)
                        .first()
                        .map(|mime| mime.to_string())
                        .unwrap_or_else(|| "application/octet-stream".to_string()),
                    None => "application/octet-stream".to_string(),
                },
            },
            filename: req.0.filename,
        };
        tokio::fs::write(
            &tmp_file_path_meta,
            serde_json::to_vec(&meta).map_err(InternalServerError)?,
        )
        .await
        .map_err(InternalServerError)?;

        Ok(Json(uuid))
    }

    /// Upload file
    #[oai(path = "/file/upload", method = "post")]
    async fn upload_file(
        &self,
        state: Data<&State>,
        #[oai(name = "x-api-key")] api_key: Header<String>,
        req: UploadFileRequest,
    ) -> Result<Json<Option<UploadFileResponse>>> {
        let current_uid = parse_api_key(&api_key, &state.0.key_config.read().await.server_key)
            .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;
        check_api_key(&state, current_uid, &api_key).await?;

        if req.file_id.is_empty() {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        // open the file, append data.
        let tmp_file_path = state
            .config
            .system
            .tmp_dir()
            .join(&req.file_id)
            .with_extension("data");
        let tmp_file_path_meta = tmp_file_path.with_extension("meta");

        if tmp_file_path.exists() {
            let mut f = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&tmp_file_path)
                .await
                .map_err(InternalServerError)?;
            f.write_all(req.chunk_data.as_slice())
                .await
                .map_err(InternalServerError)?;
            f.flush().await.map_err(InternalServerError)?;
        } else {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        if req.chunk_is_last {
            let file_meta = serde_json::from_slice::<FileMeta>(
                &std::fs::read(&tmp_file_path_meta).map_err(InternalServerError)?,
            )
            .map_err(InternalServerError)?;
            let is_image = Mime::from_str(&file_meta.content_type)
                .map(|mime| mime.type_() == mime::IMAGE)
                .unwrap_or_default();

            let file_size = tokio::fs::metadata(&tmp_file_path)
                .await
                .map_err(InternalServerError)?
                .len() as i64;
            let file_hash = sha256_file(&tmp_file_path)
                .await
                .map_err(|_| Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?;

            //  move tmp to dir
            let now = DateTime::now();
            let year = now.year();
            let month = now.month();
            let day = now.day();
            // ./data/file/{year}/{month}/{day}/{file_uuid}
            // ./data/file/2021/01/30/123-456-789
            let save_path = state
                .config
                .system
                .file_dir()
                .join(year.to_string())
                .join(month.to_string())
                .join(day.to_string());
            if !save_path.exists() {
                tokio::fs::create_dir_all(&save_path)
                    .await
                    .map_err(InternalServerError)?;
            }

            tokio::fs::rename(&tmp_file_path, save_path.join(&req.file_id))
                .and_then(|_| {
                    tokio::fs::rename(
                        &tmp_file_path_meta,
                        save_path.join(&req.file_id).with_extension("meta"),
                    )
                })
                .await
                .map_err(InternalServerError)?;

            // create the thumbnail
            let mut image_properties = None;
            if is_image {
                let src_path = save_path.join(&req.file_id);
                let src_meta_path = src_path.with_extension("meta");
                let thumbnail_dir_path = state
                    .config
                    .system
                    .thumbnail_dir()
                    .join(year.to_string())
                    .join(month.to_string())
                    .join(day.to_string());
                let thumbnail_file_path = thumbnail_dir_path.join(&req.file_id);
                let thumbnail_meta_path = thumbnail_file_path.with_extension("meta");

                tracing::info!(
                    src_path = %src_path.display(),
                    thumbnail_path = %thumbnail_file_path.display(),
                    "create thumbnail",
                );

                image_properties = Some(
                    tokio::task::spawn_blocking(move || {
                        let image_data = std::fs::read(src_path).map_err(InternalServerError)?;
                        let image = image::load_from_memory(&image_data).map_err(BadRequest)?;
                        let thumbnail = image.thumbnail(480, 480);
                        let _ = std::fs::create_dir_all(&thumbnail_dir_path);

                        if thumbnail.color().has_alpha() {
                            thumbnail
                                .save_with_format(thumbnail_file_path, image::ImageFormat::Png)
                                .map_err(InternalServerError)?;
                        } else {
                            thumbnail
                                .save_with_format(thumbnail_file_path, image::ImageFormat::Jpeg)
                                .map_err(InternalServerError)?;
                        }

                        std::fs::copy(&src_meta_path, &thumbnail_meta_path)
                            .map_err(InternalServerError)?;
                        Ok::<_, poem::Error>(ImageProperties {
                            width: image.width(),
                            height: image.height(),
                        })
                    })
                    .await
                    .map_err(InternalServerError)??,
                );
            }

            // return the file url path, the client assembles the payload and sends it.
            // {year}/{month}/{day}/{file_uuid}
            // 2021/01/30/123-456-789
            let file_url_path = format!("{}/{}/{}/{}", year, month, day, &req.file_id);
            return Ok(Json(Some(UploadFileResponse {
                path: file_url_path,
                size: file_size,
                hash: file_hash.to_string(),
                image_properties,
            })));
        }
        Ok(Json(None))
    }
}
