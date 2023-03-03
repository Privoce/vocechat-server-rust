use std::str::FromStr;

use chrono::Datelike;
use futures_util::TryFutureExt;
use mime_guess::{mime, Mime};
// use open_graph::Object;
use poem::{
    error::{BadRequest, InternalServerError},
    http::{header, HeaderMap, StatusCode},
    web::{Data, StaticFileRequest, StaticFileResponse},
    Body, Error, Result,
};
use poem_openapi::{
    param::Query,
    payload::{Binary, Json, Response},
    ApiRequest, Multipart, Object, OpenApi,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::io::AsyncWriteExt;

use crate::{
    api::{
        archive::{create_message_archive, extract_archive, extract_archive_attachment},
        tags::ApiTags,
        token::Token,
        Archive, DateTime,
    },
    State,
};

/// Upload image request
#[derive(Debug, ApiRequest)]
pub enum UploadImageRequest {
    #[oai(content_type = "image/png")]
    Image(Binary<Body>),
}

/// Prepare upload file request
#[derive(Debug, Object)]
pub struct PrepareUploadFileRequest {
    pub content_type: Option<String>,
    pub filename: Option<String>,
}

/// Upload file request
#[derive(Debug, Multipart)]
pub struct UploadFileRequest {
    #[oai(default)]
    /// file_id: uuid that return by prepare uploading file API
    pub file_id: String,
    pub chunk_data: poem_openapi::types::Binary<Vec<u8>>,
    #[oai(default)]
    pub chunk_is_last: bool,
}

#[derive(Serialize, Deserialize)]
pub struct FileMeta {
    pub content_type: String,
    pub filename: Option<String>,
}

/// Download file request
#[derive(Debug, Object)]
struct DownloadFileRequest {
    #[oai(default)]
    file_id: String,
    #[oai(default)]
    chunk_start: i64,
    #[oai(default)]
    chunk_len: i64,
}

/// Image properties
#[derive(Debug, Object)]
pub struct ImageProperties {
    pub width: u32,
    pub height: u32,
}

/// Download file request
#[derive(Debug, Object)]
pub struct UploadFileResponse {
    pub path: String,
    pub size: i64,
    pub hash: String,
    pub image_properties: Option<ImageProperties>,
}

#[derive(Debug, Object)]
struct CreateArchiveMsgRequest {
    mid_list: Vec<i64>,
}

pub struct ApiResource;

#[OpenApi(prefix_path = "/resource", tag = "ApiTags::Resource")]
impl ApiResource {
    /// Get the organization logo
    #[oai(path = "/organization/logo", method = "get")]
    async fn get_organization_logo(
        &self,
        state: Data<&State>,
        req: StaticFileRequest,
    ) -> Result<StaticFileResponse> {
        let path = state.config.system.data_dir.join("organization.png");
        if path.exists() {
            Ok(req.create_response(path, false)?)
        } else {
            Ok(req
                .create_response_from_data(include_bytes!("assets/organization-logo.png"))?
                .with_content_type("image/png"))
        }
    }

    /// Get user avatar by id
    #[oai(path = "/avatar", method = "get")]
    async fn get_avatar(
        &self,
        state: Data<&State>,
        uid: Query<i64>,
        req: StaticFileRequest,
    ) -> Result<StaticFileResponse> {
        let path = state
            .config
            .system
            .avatar_dir()
            .join(format!("{}.png", uid.0));
        Ok(req.create_response(path, false)?)
    }

    /// Get group avatar by id
    #[oai(path = "/group_avatar", method = "get")]
    async fn get_group_avatar(
        &self,
        state: Data<&State>,
        gid: Query<i64>,
        req: StaticFileRequest,
    ) -> Result<StaticFileResponse> {
        let path = state
            .config
            .system
            .group_avatar_dir()
            .join(format!("{}.png", gid.0));
        Ok(req.create_response(path, false)?)
    }

    /// Prepare for uploading file
    #[oai(path = "/file/prepare", method = "post")]
    async fn upload_file_prepare(
        &self,
        state: Data<&State>,
        req: Json<PrepareUploadFileRequest>,
        _token: Token,
    ) -> Result<Json<String>> {
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
        _token: Token,
        req: UploadFileRequest,
    ) -> Result<Json<Option<UploadFileResponse>>> {
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

    /// Download file
    #[oai(path = "/file", method = "get")]
    async fn download_file(
        &self,
        state: Data<&State>,
        file_path: Query<String>,
        #[oai(default)] thumbnail: Query<bool>,
        #[oai(default)] download: Query<bool>,
        req: StaticFileRequest,
    ) -> Result<Response<StaticFileResponse>> {
        if file_path.is_empty() || file_path.contains('.') {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }
        let base_dir = if !thumbnail.0 {
            state.config.system.file_dir()
        } else {
            state.config.system.thumbnail_dir()
        };
        let path = base_dir.join(file_path.as_str());
        let path_meta = base_dir.join(file_path.as_str()).with_extension("meta");

        let meta = tokio::fs::read(&path_meta)
            .await
            .ok()
            .and_then(|data| serde_json::from_slice::<FileMeta>(&data).ok())
            .unwrap_or_else(|| FileMeta {
                content_type: "application/octet-stream".to_string(),
                filename: None,
            });

        let mut resp = Response::new(req.create_response(path, false)?);
        let ty = if download.0 { "attachment" } else { "inline" };
        resp = resp.header(header::CONTENT_TYPE, meta.content_type);
        if let Some(filename) = meta.filename {
            resp = resp.header(
                header::CONTENT_DISPOSITION,
                format!(r#"{}; filename="{}""#, ty, filename),
            );
        }

        Ok(resp)
    }

    /// Create messages archive
    #[oai(path = "/archive", method = "post")]
    async fn create_archive(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<CreateArchiveMsgRequest>,
    ) -> Result<Json<String>> {
        let data = create_message_archive(&state, req.0.mid_list, token.uid).await?;

        let now = DateTime::now();
        let year = now.year();
        let month = now.month();
        let day = now.day();
        let save_path = state
            .config
            .system
            .archive_msg_dir()
            .join(year.to_string())
            .join(month.to_string())
            .join(day.to_string());
        let _ = std::fs::create_dir_all(&save_path);
        let uuid = uuid::Uuid::new_v4().to_string();

        let file_path = save_path.join(&uuid);
        std::fs::write(file_path, data).map_err(InternalServerError)?;

        Ok(Json(format!("{}/{}/{}/{}", year, month, day, &uuid)))
    }

    /// Get archive info
    #[oai(path = "/archive", method = "get")]
    async fn get_archive_index(
        &self,
        state: Data<&State>,
        file_path: Query<String>,
    ) -> Result<Response<Json<Archive>>> {
        if file_path.is_empty() || file_path.contains('.') {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }
        let path = state
            .config
            .system
            .archive_msg_dir()
            .join(file_path.as_str());
        let archive = extract_archive(path).await?;
        Ok(Response::new(Json(archive)).header(header::CACHE_CONTROL, "public, max-age=31536000"))
    }

    /// Get archive attachment
    #[oai(path = "/archive/attachment", method = "get")]
    async fn get_archive_attachment(
        &self,
        state: Data<&State>,
        file_path: Query<String>,
        attachment_id: Query<usize>,
        #[oai(default)] download: Query<bool>,
    ) -> Result<Response<Binary<Vec<u8>>>> {
        if file_path.is_empty() || file_path.contains('.') {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }
        let path = state
            .config
            .system
            .archive_msg_dir()
            .join(file_path.as_str());
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

    /// Parse URL with Open Graphic Protocol
    #[oai(path = "/open_graphic_parse", method = "get")]
    async fn open_graphic_parse(
        &self,
        url: Query<String>,
        header_map: &HeaderMap,
    ) -> Result<Response<Json<open_graph::Object>>> {
        if url.is_empty() {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }
        let url = url.0;
        let extra_header_map = header_map
            .get(poem::http::header::ACCEPT_LANGUAGE)
            .cloned()
            .map(|value| (poem::http::header::ACCEPT_LANGUAGE, value))
            .into_iter()
            .collect::<HeaderMap>();
        let obj = open_graph::fetch(&url, Some(extra_header_map), 0)
            .await
            .unwrap_or_default();
        Ok(Response::new(Json(obj)).header(header::CACHE_CONTROL, "public, max-age=86400"))
    }
}

pub async fn sha256_file<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<String> {
    let path = path.as_ref().to_path_buf();
    Ok(tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(path)?;
        let mut sha256 = sha2::Sha256::new();
        std::io::copy(&mut file, &mut sha256)?;
        let hash = hex::encode(sha256.finalize().as_slice());
        Ok::<_, std::io::Error>(hash)
    })
    .await??)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use futures_util::StreamExt;
    use poem::test::TestForm;
    use reqwest::StatusCode;
    use serde_json::json;

    use super::*;
    use crate::test_harness::TestServer;

    #[tokio::test]
    async fn test_sha256_file() {
        // use std::io::Write;
        let mut tmp_file = tempfile::NamedTempFile::new().unwrap();
        tmp_file.write_all(b"1").unwrap();
        let s = sha256_file(tmp_file.path()).await.unwrap();
        assert_eq!(
            "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
            s
        );
        std::fs::remove_file(tmp_file.path()).unwrap();
    }

    fn sha256_bytes(v: impl AsRef<[u8]>) -> String {
        let mut sha256 = sha2::Sha256::new();
        sha2::digest::Update::update(&mut sha256, v);
        hex::encode(sha256.finalize().as_slice())
    }

    #[test]
    fn test_sha256_bytes() {
        let s = sha256_bytes(b"1");
        assert_eq!(
            "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
            s
        );
    }

    #[tokio::test]
    async fn test_organization_logo() {
        let server = TestServer::new().await;
        let token = server.login_admin().await;

        let resp = server.get("/api/resource/organization/logo").send().await;
        resp.assert_status_is_ok();
        resp.assert_bytes(include_bytes!("assets/organization-logo.png"))
            .await;

        // upload the logo
        let resp = server
            .post("/api/admin/system/organization/logo")
            .header("X-API-Key", &token)
            .content_type("image/png")
            .body(include_bytes!("assets/poem.png").to_vec())
            .send()
            .await;
        resp.assert_status_is_ok();

        // get the logo
        let resp = server.get("/api/resource/organization/logo").send().await;
        resp.assert_status_is_ok();
    }

    #[tokio::test]
    async fn test_avatar() {
        let server = TestServer::new().await;
        let token = server.login_admin().await;

        // upload avatar
        let resp = server
            .post("/api/user/avatar")
            .header("X-API-Key", &token)
            .content_type("image/png")
            .body(include_bytes!("assets/poem.png").to_vec())
            .send()
            .await;
        resp.assert_status_is_ok();

        // get avatar
        let resp = server
            .get("/api/resource/avatar")
            .query("uid", &2i64)
            .send()
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);

        // get avatar
        let resp = server
            .get("/api/resource/avatar")
            .query("uid", &1i64)
            .send()
            .await;
        resp.assert_status_is_ok();
    }

    #[tokio::test]
    async fn test_upload_file_prepare() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        let resp = server
            .post("/api/resource/file/prepare")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "content_type": "audio/mp4",
                "filename": "test.mp4",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let id = json.value().string();
        assert_eq!(id.len(), 36);
    }

    #[tokio::test]
    async fn test_upload_file() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        let file1_name = "1.txt";
        let file1_content = b"abc";
        let file1_sh256 = sha256_bytes(file1_content);

        // upload_file_prepare
        let resp = server
            .post("/api/resource/file/prepare")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "content_type": "text/plain",
                "filename": file1_name,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let file_id = json.value().string();

        // upload file
        let resp = server
            .post("/api/resource/file/upload")
            .header("X-API-Key", &admin_token)
            .multipart(
                TestForm::new()
                    .text("file_id", file_id.to_string())
                    .text("chunk_is_last", "true")
                    .bytes("chunk_data", file1_content.to_vec()),
            )
            .send()
            .await;
        resp.assert_status_is_ok();
        let j = resp.json().await;

        let file_path = j.value().object().get("path").string();
        let file_size = j.value().object().get("size").i64();
        assert_eq!(file_size, file1_content.len() as i64);
        let file_hash = j.value().object().get("hash").string();
        assert_eq!(file_hash, &file1_sh256);

        // download file as inline
        let resp = server
            .get("/api/resource/file")
            .query("file_path", &file_path)
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.assert_header("content-type", "text/plain");
        resp.assert_header("content-disposition", r#"inline; filename="1.txt""#);
        resp.assert_bytes(file1_content).await;

        // download file as attachment
        let resp = server
            .get("/api/resource/file")
            .query("file_path", &file_path)
            .query("download", &true)
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.assert_header("content-type", "text/plain");
        resp.assert_header("content-disposition", r#"attachment; filename="1.txt""#);
        resp.assert_bytes(file1_content).await;
    }

    #[tokio::test]
    async fn test_upload_image() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        // upload_file_prepare
        let resp = server
            .post("/api/resource/file/prepare")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "content_type": "image/png",
                "filename": "poem.png",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let file_id = json.value().string();

        // upload file
        let resp = server
            .post("/api/resource/file/upload")
            .header("X-API-Key", &admin_token)
            .multipart(
                TestForm::new()
                    .text("file_id", file_id.to_string())
                    .text("chunk_is_last", "true")
                    .bytes("chunk_data", include_bytes!("assets/poem.png").to_vec()),
            )
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let obj = json.value().object();
        let image_properties = obj.get("image_properties").object();
        image_properties.get("width").assert_i64(400);
        image_properties.get("height").assert_i64(400);

        let file_path = obj.get("path").string();

        // download image
        let resp = server
            .get("/api/resource/file")
            .query("file_path", &file_path)
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.assert_header("content-type", "image/png");
        resp.assert_header("content-disposition", r#"inline; filename="poem.png""#);
        resp.assert_bytes(include_bytes!("assets/poem.png")).await;

        // download thumbnail
        let resp = server
            .get("/api/resource/file")
            .query("file_path", &file_path)
            .query("thumbnail", &true)
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.assert_header("content-type", "image/png");
        resp.assert_header("content-disposition", r#"inline; filename="poem.png""#);
    }

    #[tokio::test]
    async fn test_upload_file_with_chunk() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        let file1_content = b"12345678";
        let file1_sh256 = sha256_bytes(file1_content);
        let mut file1 = tempfile::NamedTempFile::new().unwrap();
        let file1_name = "1.txt";
        let file_path1 = file1
            .path()
            .to_str()
            .map(|v| v.to_string())
            .unwrap_or_default();
        file1.write_all(file1_content).unwrap();
        file1.flush().unwrap();

        // upload file prepare
        let resp = server
            .post("/api/resource/file/prepare")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "name": file1_name,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let file_id = json.value().string();
        assert_eq!(file_id.len(), 36);

        // upload file
        let mut file_path = String::new();
        for (i, c) in file1_content.iter().enumerate() {
            let is_last = i + 1 == file1_content.len();
            let resp = server
                .post("/api/resource/file/upload")
                .header("X-API-Key", &admin_token)
                .multipart(
                    TestForm::new()
                        .text("file_id", file_id.to_string())
                        .text("chunk_is_last", if is_last { "true" } else { "false" })
                        .bytes("chunk_data", vec![*c]),
                )
                .send()
                .await;
            resp.assert_status_is_ok();
            if is_last {
                let j = resp.json().await;
                file_path = j.value().object().get("path").string().to_string();
                assert!(file_path.len() > 36);
            }
        }
        tokio::fs::remove_file(&file_path1).await.unwrap();

        // download file
        let mut downloaded_data = vec![];
        // for i in 0..file1_content.len() + 1 {
        let mut i = 0;
        loop {
            let resp = server
                .get("/api/resource/file")
                .query("file_path", &file_path)
                .header("X-API-Key", &admin_token)
                .header("Range", format!("bytes={}-{}", i, i))
                //.typed_header(Range::bytes(i..i+1))
                .send()
                .await;
            if resp.0.status() != StatusCode::RANGE_NOT_SATISFIABLE {
                assert_eq!(resp.0.status(), StatusCode::PARTIAL_CONTENT);
            } else {
                break;
            }
            let body = resp.0.into_body().into_bytes().await.unwrap();
            downloaded_data.append(&mut body.to_vec());
            i += 1;
        }
        assert_eq!(sha256_bytes(&downloaded_data), file1_sh256);
    }

    #[tokio::test]
    async fn test_upload_file_and_send_subscribe_msg() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let _uid1 = server.create_user(&admin_token, "user1@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "user2@voce.chat").await;
        let token1 = server.login("user1@voce.chat").await;
        let token2 = server.login("user2@voce.chat").await;

        let file1_content = b"1";
        let file1_sha256 = sha256_bytes(file1_content);
        let file1_name = "1.txt";

        // upload file prepare
        let resp = server
            .post("/api/resource/file/prepare")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "filename": file1_name,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let file_id = json.value().string();
        assert_eq!(file_id.len(), 36);

        // upload file
        let resp = server
            .post("/api/resource/file/upload")
            .header("X-API-Key", &admin_token)
            .multipart(
                TestForm::new()
                    .text("file_id", file_id.to_string())
                    .text("chunk_is_last", "true")
                    .bytes("chunk_data", file1_content.to_vec()),
            )
            .send()
            .await;
        resp.assert_status_is_ok();
        let j = resp.json().await;
        let file_path = j.value().object().get("path").string().to_string();
        assert!(file_path.len() > 36);
        j.value().object().get("hash").assert_string(&file1_sha256);
        j.value()
            .object()
            .get("size")
            .assert_i64(file1_content.len() as i64);

        // send msg
        let resp = server
            .post(format!("/api/user/{}/send", uid2))
            .header("X-API-Key", &token1)
            .content_type("vocechat/file")
            .body_json(&json!({
                "path": file_path,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        let mut msg_stream = server.subscribe_events(&token2, Some(&["chat"])).await;
        let msg = msg_stream.next().await.unwrap();
        let msg = msg.value().object();

        let detail = msg.get("detail").object();
        detail.get("content_type").assert_string("vocechat/file");

        let properties = detail.get("properties").object();
        properties.get("name").assert_string(file1_name);
        properties.get("content_type").assert_string("text/plain");
        properties
            .get("size")
            .assert_i64(file1_content.len() as i64);
    }

    #[tokio::test]
    async fn test_open_graphic_parse() {
        // let server = TestServer::new().await;
        // let admin_token = server.login_admin().await;

        // let resp = server
        //     .get("/api/resource/open_graphic_parse")
        //     .header("X-API-Key", &admin_token)
        //     .query("url", &"https://www.youtube.com/watch?v=5C_HPTJg5ek")
        //     .send()
        //     .await;
        // resp.assert_status_is_ok();
        // let json = resp.json().await;
        // json.value()
        //     .object()
        //     .get("type")
        //     .assert_string("video.other");
        // // json.value().object().get("url").assert_string("https://www.youtube.com/embed/5C_HPTJg5ek");

        // let resp = server
        //     .get("/api/resource/open_graphic_parse")
        //     .header("X-API-Key", &admin_token)
        //     .query("url", &"http://baidu.com/")
        //     .send()
        //     .await;
        // resp.assert_status_is_ok();
        // let json = resp.json().await;
        // json.value()
        //     .object()
        //     .get("title")
        //     .assert_string("百度一下，你就知道");
    }

    // #[tokio::test]
    // async fn test_open_graphic_parse_directly() {
    //     let a = open_graph::fetch("https://www.youtube.com/watch?v=5C_HPTJg5ek", None).await.unwrap();
    //     dbg!(a);
    // }

    #[tokio::test]
    async fn test_archive() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        server.create_user(&admin_token, "user1@voce.chat").await;
        let user1_token = server.login("user1@voce.chat").await;

        // upload avatar
        let resp = server
            .post("/api/user/avatar")
            .header("X-API-Key", &user1_token)
            .content_type("image/png")
            .body(include_bytes!("assets/organization-logo.png").to_vec())
            .send()
            .await;
        resp.assert_status_is_ok();

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
        let gid = resp.json().await.value().object().get("gid").i64();

        let mid1 = server.send_text_to_group(&admin_token, gid, "abc").await;
        let mid2 = server.send_text_to_group(&admin_token, gid, "def").await;

        // upload_file_prepare
        let resp = server
            .post("/api/resource/file/prepare")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "content_type": "application/octet-stream",
                "filename": "poem.png",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let file_id = json.value().string();

        // upload file
        let resp = server
            .post("/api/resource/file/upload")
            .header("X-API-Key", &admin_token)
            .multipart(
                TestForm::new()
                    .text("file_id", file_id.to_string())
                    .text("chunk_is_last", "true")
                    .bytes("chunk_data", include_bytes!("assets/poem.png").to_vec()),
            )
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let obj = json.value().object();
        let file_path = obj.get("path").string().to_string();

        let resp = server
            .post(format!("/api/group/{}/send", gid))
            .header("X-API-Key", &admin_token)
            .content_type("vocechat/file")
            .body_json(&json!({
                "path": file_path,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let mid3 = resp.json().await.value().i64();

        let mid4 = server.send_text_to_group(&user1_token, gid, "ghi").await;

        // create archive
        let resp = server
            .post("/api/resource/archive")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "mid_list": [mid1, mid2, mid3, mid4],
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let archive_path = resp.json().await.value().string().to_string();

        // get archive index
        let resp = server
            .get("/api/resource/archive")
            .query("file_path", &archive_path)
            .send()
            .await;
        resp.assert_status_is_ok();
        let json = resp.json().await;
        let json = json.value().object();

        // check users
        let users = json.get("users").array();

        let user = users.get(0).object();
        user.get("name").assert_string("admin");
        user.get("avatar").assert_null();

        let user = users.get(1).object();
        user.get("name").assert_string("user1@voce.chat");
        user.get("avatar").assert_i64(1);

        // check messages
        let messages = json.get("messages").array();
        messages.assert_len(4);

        let msg = messages.get(0).object();
        msg.get("from_user").assert_i64(0);
        msg.get("content_type").assert_string("text/plain");
        msg.get("content").assert_string("abc");

        let msg = messages.get(1).object();
        msg.get("from_user").assert_i64(0);
        msg.get("content_type").assert_string("text/plain");
        msg.get("content").assert_string("def");

        let msg = messages.get(2).object();
        msg.get("from_user").assert_i64(0);
        msg.get("content_type").assert_string("vocechat/file");
        msg.get("file_id").assert_i64(0);

        let msg = messages.get(3).object();
        msg.get("from_user").assert_i64(1);
        msg.get("content_type").assert_string("text/plain");
        msg.get("content").assert_string("ghi");

        // check attachment
        let resp = server
            .get("/api/resource/archive/attachment")
            .query("file_path", &archive_path)
            .query("attachment_id", &0)
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.assert_header(
            header::CONTENT_DISPOSITION,
            r#"inline; filename="poem.png""#,
        );
        resp.assert_header(header::CONTENT_TYPE, "application/octet-stream");

        let resp = server
            .get("/api/resource/archive/attachment")
            .query("file_path", &archive_path)
            .query("attachment_id", &1)
            .send()
            .await;
        resp.assert_status_is_ok();
    }
}
