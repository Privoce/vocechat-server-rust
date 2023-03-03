use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use reqwest::Client;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::sync::Mutex;

use crate::{
    jwt::{Claims, JwtSigner},
    ApplicationCredentials,
};

const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const SCOPES: &[&str] = &["https://www.googleapis.com/auth/firebase.messaging"];

#[derive(Deserialize, Debug)]
struct Token {
    access_token: String,
    #[serde(
        deserialize_with = "deserialize_expires_in",
        rename(deserialize = "expires_in")
    )]
    expires_at: Option<DateTime<Utc>>,
}

impl Token {
    fn has_expired(&self) -> bool {
        self.expires_at
            .map(|expiration_time| expiration_time - Duration::seconds(30) <= Utc::now())
            .unwrap_or(false)
    }

    fn as_str(&self) -> &str {
        &self.access_token
    }
}

fn deserialize_expires_in<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<i64> = Deserialize::deserialize(deserializer)?;
    Ok(s.map(|seconds_from_now| Utc::now() + Duration::seconds(seconds_from_now)))
}

pub struct FcmClient {
    client: Client,
    credentials: ApplicationCredentials,
    token: Mutex<Option<Token>>,
}

impl FcmClient {
    pub fn new(credentials: ApplicationCredentials) -> Self {
        Self {
            client: Client::new(),
            credentials,
            token: Default::default(),
        }
    }

    pub fn credentials(&self) -> &ApplicationCredentials {
        &self.credentials
    }

    async fn refresh_token(&self) -> Result<Token> {
        let signer = JwtSigner::new(&self.credentials.private_key)?;
        let claims = Claims::new(&self.credentials, SCOPES, None);
        let signed = signer.sign_claims(&claims)?;
        let token = self
            .client
            .post(&self.credentials.token_uri)
            .form(&[("grant_type", GRANT_TYPE), ("assertion", signed.as_str())])
            .send()
            .await?
            .error_for_status()?
            .json::<Token>()
            .await?;
        Ok(token)
    }

    pub async fn send(
        &self,
        device_token: &str,
        title: &str,
        message: &str,
        data: &impl Serialize,
    ) -> Result<()> {
        let token = loop {
            let mut token = self.token.lock().await;
            match &*token {
                Some(token) if !token.has_expired() => break token.as_str().to_string(),
                _ => *token = Some(self.refresh_token().await?),
            }
        };

        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.credentials.project_id
        );

        let _ = reqwest::Client::new()
            .post(url)
            .bearer_auth(token)
            .json(&serde_json::json!({
                "message": {
                    "notification": {
                        "title": title,
                        "body": message,
                        "sound": "default",
                    },
                    "data": data,
                    "token": device_token,
                }
            }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn test_send() {
        let credentials = ApplicationCredentials {
            project_id: "Your project".to_string(),
            private_key: "Your key".to_string(),
            client_email: "Your client email"
                .to_string(),
            token_uri: "https://oauth2.googleapis.com/token".to_string(),
        };

        let client = FcmClient::new(credentials);
        let device_token = "Your client token";
        client
            .send(
                device_token,
                "title",
                "hello!",
                &json!({
                    "vocechat_server_id": "your server id",
                    "vocechat_from_uid": "123",
                    "vocechat_to_uid": "123123",
                }),
            )
            .await
            .unwrap();
    }
}
