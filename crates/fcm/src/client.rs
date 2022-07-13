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
            project_id: "vocechat-develop".to_string(),
            private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC99goqqoX4OyB6\ng0kOCGL7HG1cfWH0BDOjopghPl0Ja49/Fbegl+43XRpt7kSXfPawUj9bx++32CB7\nT6Z4GtW4HszZdyIpvdmNq12mGwentjH9jmEskkcJpnnQMyuoWkvbzxriF1ppdDy4\n/sTRMZbSVsRoyxoaviRL/5OfHR9dtfn/04L6tByREfj06LScQ/CMwrN2IrL/3WcX\nzGHJoAPazif8D/YGgjy5zFizvI54O8ZAryjpLpyk75hdj0GTJdPLp4AERJU9q5sw\nGSB8xeZnRcYpIHGBgEIqKYel756dY3099p2xCbXyU1hwk07fx+rQbsZYu8fNnOs9\nMaRPUrYTAgMBAAECggEACnGDX5MeaGY/w9yB4K6fWnTWolYWU4cDm8Rtnq5CCSmL\nqw3zmXWg2BRbRp3p0XZCTbFH4HDegfn01zKq0UGQbF3tHyuIikjws/Qu4tnrktHW\nb70rJHsqQqKPYd3eUZQdRYleTf3Ar7l/OSBwi5uxUgEJLUW1OrEnZ7I2WHIObmVh\nXdvUGgKGqnBMKuMxZ45vgcFpVvbxWv3JOa9bVLUf2yzoBTwZyL6jMMzB/iBqVGBA\nhVPV8EuA4WDzVzodYoR5/ZxvUZZ+LF4/we6QLqA15Nirj2C6vplLgbkYDoAgqls5\nFZg6CAU2I12qd4v9n5X7Rot9yQ5idwsCFx0rMY3HKQKBgQD4COAg0NgTmBv1J/6Y\ns4GEu0Ds/ubWQqhR4bB1xxHf0f7ZMQHH0WQD+0WjJswLoXyYVIt5TxSoMpFXiTaR\nWOtXeXfvqjJIdHFIL+EeuMyRGXdVRAxX+bHMxipQ5/3BiSl4AA0qH9JEpkvj6kKf\niQ016DqPnHvuX5PZfOnOllrd9QKBgQDED7vlDXcX5VpwbPgDssV4zquwabbCYi4I\nh9kz+yIsQVAcaEjeNssYdKLKF770m5cdCrzIrIsgyqBsKJTlnRJOIY5aIzuZGwyz\nMTjHxhPepKmtpAuix4mH3OJ0Fqzuc8yj6egOlb8j85VbkgGXkQUbnFZLlfC7Rf/k\n6J6jb//25wKBgGeIbOXFxywGpkTi+OcMptecwjErBXgSQuhK6LmA6vkeUt6eEjwy\nLylqTVsY6rtAIR4EzGNKmzjKQtjjMZ/iGfpdfa7QwER2NoMHWVTVlq5KjwFMckqW\ns5ziau9ypv2OH30zqEsZFVAKiksMkdq9/oGt+iPQEfsicjiqZ34QTMWxAoGASu5U\nekL+LBTMzsDmvMsbK4OZHHAamAnb3AjHW1V0hwNjMagtiTfZwPv6p1AR+/xm8YOE\nCRHgjmTCkPOljGfOcivi8tIaWfZ7kRSTxc4PE/1Ml/9lLw4hotopdgKgjvWU1WR0\n+vYCOiRDBd80Wo/jKt1CIdspSPmExiCdWItagSsCgYB6A1E4AbPeHszORLeVJAiO\nx4cSDaKSww/E93RZjF7QJXr2xlODTUb3kYd+TozL0P/kDmC57w3aLWkxpuAyLhqy\nQOVj7PCz2k38ZezkHZVN+soZc74/w483V1+2g4HPjbFADKThRxwlmyLqgoTPpTY5\ny8fMswj9GwiZmmS3IRqFuA==\n-----END PRIVATE KEY-----\n"
            .to_string(),
            client_email: "firebase-adminsdk-aj4n6@vocechat-develop.iam.gserviceaccount.com"
                .to_string(),
            token_uri: "https://oauth2.googleapis.com/token".to_string(),
        };

        let client = FcmClient::new(credentials);
        let device_token = "cHzY7u91OEY3oCd-uP-Wbm:APA91bEsRUfrzehskdhdjCyFQkXkE23GBdqNNDJLvwWlV7TwpWVwDEhYSntZZ9CyLwqKBMUDjDUlvarlfzHLMjXVFyB1R0Wgm4rwWFTDD65ZBsR78KJLCfUPxyeaDcBSOVWvMQ03Opw5";
        client
            .send(
                device_token,
                "title",
                "hello!",
                &json!({
                    "vocechat_server_id": "8WgMQwEnxnB0kceYhb2TYh5NZGDiwHyk",
                    "vocechat_from_uid": "123",
                    "vocechat_to_uid": "123123",
                }),
            )
            .await
            .unwrap();
    }
}
