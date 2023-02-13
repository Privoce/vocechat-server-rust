#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[cfg(feature = "poem_openapi")]
#[derive(poem_openapi::Object)]
pub struct Audio {
    pub r#type: Option<String>,
    pub url: String,
    pub secure_url: Option<String>,
}

impl Audio {
    pub fn new(url: String) -> Audio {
        Audio {
            url,
            ..Default::default()
        }
    }
}
