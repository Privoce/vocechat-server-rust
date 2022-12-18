use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use poem::error::{InternalServerError, NotFound};
use poem_openapi::Object;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    api::{
        get_merged_message, message::MergedMessagePayload, DateTime, FileMeta, MessageTarget,
        MessageTargetGroup, MessageTargetUser,
    },
    state::State,
};

#[derive(Debug, Object, Clone, Serialize, Deserialize)]
pub struct Archive {
    pub users: Vec<ArchiveUser>,
    pub messages: Vec<ArchiveMessage>,
    pub num_attachments: usize,
}

#[derive(Debug, Object, Clone, Serialize, Deserialize)]
pub struct ArchiveUser {
    pub name: String,
    pub avatar: Option<usize>,
}

#[derive(Debug, Object, Clone, Serialize, Deserialize)]
pub struct ArchiveMessage {
    pub from_user: usize,
    pub created_at: DateTime,
    pub mid: i64,
    pub source: MessageTarget,
    #[oai(flatten)]
    pub content: ArchiveMessageContent,
}

#[derive(Debug, Object, Clone, Serialize, Deserialize)]
pub struct ArchiveMessageContent {
    pub properties: Option<HashMap<String, Value>>,
    pub content_type: String,
    pub content: Option<String>,
    pub file_id: Option<usize>,
    pub thumbnail_id: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ArchiveFile {
    pub content_type: String,
    pub filename: Option<String>,
    #[serde(skip)]
    pub content: Vec<u8>,
}

async fn internal_create_message_archive(
    state: &State,
    mut mid_list: Vec<i64>,
    create_by_uid: i64,
) -> poem::Result<(Archive, Vec<ArchiveFile>)> {
    let cache = state.cache.read().await;
    let is_admin = cache
        .users
        .get(&create_by_uid)
        .ok_or_else(|| poem::Error::from_status(StatusCode::BAD_REQUEST))?
        .is_admin;

    let mut archive = Archive {
        users: Vec::new(),
        messages: Vec::new(),
        num_attachments: 0,
    };
    let mut files = Vec::new();
    let mut users_map: HashMap<i64, usize> = Default::default();

    mid_list.sort_unstable();

    for mid in mid_list {
        let merged_payload = get_merged_message(&state.msg_db, mid)?
            .ok_or_else(|| poem::Error::from_status(StatusCode::NOT_FOUND))?;

        if !is_admin {
            let allow = match merged_payload.target {
                MessageTarget::User(MessageTargetUser { uid })
                    if uid == create_by_uid || merged_payload.from_uid == create_by_uid =>
                {
                    true
                }
                MessageTarget::Group(MessageTargetGroup { gid }) => cache
                    .groups
                    .get(&gid)
                    .map(|group| group.contains_user(create_by_uid))
                    .unwrap_or_default(),
                _ => false,
            };

            if !allow {
                return Err(poem::Error::from_status(StatusCode::FORBIDDEN));
            }
        }

        let from_user = cache
            .users
            .get(&merged_payload.from_uid)
            .ok_or_else(|| poem::Error::from_status(StatusCode::BAD_REQUEST))?;

        let user_idx = match users_map.get(&merged_payload.from_uid) {
            Some(idx) => *idx,
            None => {
                let avatar_path = state
                    .config
                    .system
                    .avatar_dir()
                    .join(format!("{}.png", merged_payload.from_uid));
                let avatar_data = tokio::fs::read(avatar_path).await.ok();
                let avatar = avatar_data.map(|avatar_data| {
                    files.push(ArchiveFile {
                        content_type: "image/png".to_string(),
                        filename: None,
                        content: avatar_data,
                    });
                    files.len() - 1
                });

                archive.users.push(ArchiveUser {
                    name: from_user.name.clone(),
                    avatar,
                });
                users_map.insert(merged_payload.from_uid, archive.users.len() - 1);
                archive.users.len() - 1
            }
        };

        match merged_payload.content.content_type.as_str() {
            "text/plain" | "text/markdown" => {
                archive.messages.push(ArchiveMessage {
                    from_user: user_idx,
                    created_at: merged_payload.created_at,
                    mid,
                    source: get_source(create_by_uid, &merged_payload),
                    content: ArchiveMessageContent {
                        properties: merged_payload.content.properties.clone(),
                        content_type: merged_payload.content.content_type.clone(),
                        content: Some(merged_payload.content.content.clone()),
                        file_id: None,
                        thumbnail_id: None,
                    },
                });
            }
            "vocechat/file" => {
                let file_path = state
                    .config
                    .system
                    .file_dir()
                    .join(&merged_payload.content.content);
                let file_data = tokio::fs::read(&file_path).await.unwrap_or_default();

                let thumbnail_path = state
                    .config
                    .system
                    .thumbnail_dir()
                    .join(&merged_payload.content.content);
                let thumbnail_data = tokio::fs::read(&thumbnail_path).await.ok();

                let meta = tokio::fs::read(file_path.with_extension("meta"))
                    .await
                    .ok()
                    .and_then(|data| serde_json::from_slice::<FileMeta>(&data).ok())
                    .unwrap_or_else(|| FileMeta {
                        content_type: "application/octet-stream".to_string(),
                        filename: None,
                    });

                files.push(ArchiveFile {
                    content_type: meta.content_type.clone(),
                    filename: meta.filename.clone(),
                    content: file_data,
                });
                let file_idx = files.len() - 1;

                let thumbnail_id = if let Some(thumbnail_data) = thumbnail_data {
                    files.push(ArchiveFile {
                        content_type: meta.content_type,
                        filename: meta.filename,
                        content: thumbnail_data,
                    });
                    Some(files.len() - 1)
                } else {
                    None
                };

                archive.messages.push(ArchiveMessage {
                    from_user: user_idx,
                    created_at: merged_payload.created_at,
                    mid,
                    source: get_source(create_by_uid, &merged_payload),
                    content: ArchiveMessageContent {
                        properties: merged_payload.content.properties.clone(),
                        content_type: merged_payload.content.content_type.clone(),
                        content: None,
                        file_id: Some(file_idx),
                        thumbnail_id,
                    },
                });
            }
            _ => return Err(poem::Error::from_status(StatusCode::BAD_REQUEST)),
        }
    }

    archive.num_attachments = files.len();
    Ok((archive, files))
}

fn get_source(create_by_uid: i64, merged_payload: &MergedMessagePayload) -> MessageTarget {
    match merged_payload.target {
        MessageTarget::User(MessageTargetUser { uid }) => {
            if uid == create_by_uid {
                MessageTarget::User(MessageTargetUser {
                    uid: merged_payload.from_uid,
                })
            } else {
                MessageTarget::User(MessageTargetUser { uid })
            }
        }
        group @ MessageTarget::Group(MessageTargetGroup { .. }) => group,
    }
}

pub async fn create_message_archive(
    state: &State,
    mid_list: Vec<i64>,
    create_by_uid: i64,
) -> poem::Result<Vec<u8>> {
    let (archive, files) = internal_create_message_archive(state, mid_list, create_by_uid).await?;

    tokio::task::spawn_blocking(move || {
        let mut buf = Vec::new();

        let mut zip_writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));

        let options =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        zip_writer
            .start_file("index.json", options)
            .map_err(InternalServerError)?;
        let index_data = serde_json::to_vec(&archive).map_err(InternalServerError)?;
        zip_writer.write(&index_data).map_err(InternalServerError)?;

        for (idx, file) in files.into_iter().enumerate() {
            zip_writer
                .start_file(format!("attachment/{}.data", idx), options)
                .map_err(InternalServerError)?;
            zip_writer
                .write_all(&file.content)
                .map_err(InternalServerError)?;

            let meta_data = serde_json::to_vec(&file).map_err(InternalServerError)?;
            zip_writer
                .start_file(format!("attachment/{}.meta", idx), options)
                .map_err(InternalServerError)?;
            zip_writer
                .write_all(&meta_data)
                .map_err(InternalServerError)?;
        }

        zip_writer.finish().map_err(InternalServerError)?;
        drop(zip_writer);

        Ok(buf)
    })
    .await
    .map_err(InternalServerError)?
}

pub async fn extract_archive(path: impl Into<PathBuf>) -> poem::Result<Archive> {
    let path = path.into();

    tokio::task::spawn_blocking(move || {
        let file = File::open(path).map_err(NotFound)?;
        let mut zip_archive = zip::ZipArchive::new(file).map_err(InternalServerError)?;
        let mut index_file = zip_archive
            .by_name("index.json")
            .map_err(InternalServerError)?;
        let mut data = Vec::new();
        index_file
            .read_to_end(&mut data)
            .map_err(InternalServerError)?;

        serde_json::from_slice(&data).map_err(InternalServerError)
    })
    .await
    .map_err(InternalServerError)?
}

pub async fn extract_archive_attachment(
    path: impl Into<PathBuf>,
    file_idx: usize,
) -> poem::Result<ArchiveFile> {
    let path = path.into();

    tokio::task::spawn_blocking(move || {
        if !path.exists() {
            return Err(StatusCode::NOT_FOUND.into());
        }

        let file = File::open(path).map_err(NotFound)?;
        let mut zip_archive = zip::ZipArchive::new(file).map_err(InternalServerError)?;

        let mut archive_file = {
            let mut index_file = zip_archive
                .by_name(&format!("attachment/{}.meta", file_idx))
                .map_err(InternalServerError)?;
            let mut data = Vec::new();
            index_file
                .read_to_end(&mut data)
                .map_err(InternalServerError)?;

            serde_json::from_slice::<ArchiveFile>(&data).map_err(InternalServerError)?
        };

        archive_file.content = {
            let mut index_file = zip_archive
                .by_name(&format!("attachment/{}.data", file_idx))
                .map_err(InternalServerError)?;
            let mut data = Vec::new();
            index_file
                .read_to_end(&mut data)
                .map_err(InternalServerError)?;
            data
        };

        Ok(archive_file)
    })
    .await
    .map_err(InternalServerError)?
}
