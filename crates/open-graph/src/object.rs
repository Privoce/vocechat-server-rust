use crate::{Audio, Image, Video};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[cfg(feature = "poem_openapi")]
#[derive(poem_openapi::Object)]
pub struct Object {
    pub r#type: String,
    pub title: String,
    pub url: String,

    pub images: Vec<Image>,
    pub audios: Vec<Audio>,
    pub videos: Vec<Video>,

    pub favicon_url: Option<String>,
    pub description: Option<String>,
    pub locale: Option<String>,
    pub locale_alternate: Option<Vec<String>>,
    pub site_name: Option<String>,
}
