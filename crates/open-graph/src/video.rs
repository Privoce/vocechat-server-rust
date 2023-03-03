#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[cfg(feature = "poem_openapi")]
#[derive(poem_openapi::Object)]
pub struct Video {
    pub r#type: Option<String>,
    pub url: String,
    pub secure_url: Option<String>,
    pub width: Option<i32>,
    pub height: Option<i32>,
}

impl Video {
    pub fn new(url: String) -> Video {
        Video {
            url,
            ..Default::default()
        }
    }
}
