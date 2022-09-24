/// more media types: https://en.wikipedia.org/wiki/Media_type
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[cfg(feature = "poem_openapi")]
#[derive(poem_openapi::Object)]
pub struct Image {
    pub r#type: Option<String>,
    pub url: String,
    pub secure_url: Option<String>,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub alt: Option<String>,
}

impl Image {
    pub fn new(url: String) -> Self {
        Image {
            url,
            ..Default::default()
        }
    }
}
