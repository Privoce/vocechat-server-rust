mod error;

use chrono::{DateTime, Duration, Utc};
pub use error::Error;
use hmac::{Hmac, NewMac};
use jwt::{SignWithKey, VerifyWithKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum TokenType {
    AccessToken,
    RefreshToken,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenFields<T> {
    #[serde(rename = "d")]
    data: T,
    #[serde(rename = "e")]
    expire_at: DateTime<Utc>,
    #[serde(rename = "n")]
    nonce: String,
    #[serde(rename = "t")]
    token_type: TokenType,
}

pub fn create_token_pair(
    server_key: &str,
    data: impl Serialize,
    refresh_token_expiry_seconds: i64,
    token_expiry_seconds: i64,
) -> Result<(String, String), Error> {
    let refresh_token = create_token(
        server_key,
        &data,
        TokenType::RefreshToken,
        refresh_token_expiry_seconds,
    )?;
    let token = create_token(
        server_key,
        &data,
        TokenType::AccessToken,
        token_expiry_seconds,
    )?;
    Ok((refresh_token, token))
}

fn create_token(
    server_key: &str,
    data: &impl Serialize,
    token_type: TokenType,
    expiry_seconds: i64,
) -> Result<String, Error> {
    Ok(TokenFields {
        data,
        expire_at: Utc::now() + Duration::seconds(expiry_seconds),
        nonce: textnonce::TextNonce::sized(16).unwrap().to_string(),
        token_type,
    }
    .sign_with_key(&create_hmac_key(server_key))?)
}

fn create_hmac_key(server_key: &str) -> Hmac<Sha256> {
    Hmac::<Sha256>::new_from_slice(server_key.as_bytes()).expect("invalid server key")
}

pub fn parse_token<T: DeserializeOwned>(
    server_key: &str,
    token: &str,
    check_expired: bool,
) -> Result<(TokenType, T), Error> {
    let fields =
        VerifyWithKey::<TokenFields<T>>::verify_with_key(token, &create_hmac_key(server_key))?;
    if check_expired && fields.expire_at < Utc::now() {
        return Err(Error::Expired);
    }
    Ok((fields.token_type, fields.data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token() {
        let (refresh_token, token) = create_token_pair("123456", 100i32, 60 * 5, 60).unwrap();

        let (token_type, value) = parse_token::<i32>("123456", &token, true).unwrap();
        assert_eq!(token_type, TokenType::AccessToken);
        assert_eq!(value, 100);

        let (token_type, value) = parse_token::<i32>("123456", &refresh_token, true).unwrap();
        assert_eq!(token_type, TokenType::RefreshToken);
        assert_eq!(value, 100);
    }
}
