#[derive(Debug, Clone)]
pub struct ApplicationCredentials {
    pub project_id: String,
    pub private_key: String,
    pub client_email: String,
    pub token_uri: String,
}
