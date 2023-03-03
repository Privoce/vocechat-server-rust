extern crate core;

use chrono::{DateTime, Utc};
use hmac::{Mac, NewMac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum MagicLinkToken {
    Register {
        is_confirmed: bool,
        // in_confirmed -> is_email_confirmed
        gid: Option<i64>,
        code: String,
        expired_at: i64,
        extra_email: Option<String>,
        extra_password: Option<String>,
    },
    Login {
        email: String,
        uid: Option<i64>,
        code: String,
        expired_at: i64,
    },
}

impl MagicLinkToken {
    pub fn gen_reg_magic_token(
        code: &str,
        server_key: &str,
        expired_at: DateTime<Utc>,
        is_confirmed: bool,
        gid: Option<i64>,
        extra_email: Option<String>,
        extra_password: Option<String>,
    ) -> String {
        encode(
            server_key,
            &MagicLinkToken::Register {
                is_confirmed,
                gid,
                code: code.to_string(),
                expired_at: expired_at.timestamp(), /* : (Utc::now() + Duration::seconds(expired_in)).timestamp() */
                extra_email,
                extra_password,
            },
        )
    }

    pub fn gen_login_magic_token(
        code: &str,
        server_key: &str,
        expired_at: DateTime<Utc>,
        email: &str,
        uid: Option<i64>,
    ) -> String {
        encode(
            server_key,
            &MagicLinkToken::Login {
                email: email.to_string(),
                uid,
                code: code.to_string(),
                expired_at: expired_at.timestamp(),
            },
        )
    }

    pub fn parse(server_key: &str, s: impl AsRef<str>) -> Option<MagicLinkToken> {
        if s.as_ref().is_empty() {
            return None;
        }
        // ya29.a0ARrdaM-5RaNLVVbJQSCYlekpYmPqhUXpG4THaOOYA0kUJ8jUd_rLFEgRappLi9fdmFpvdD7keGos2jzcnl0Vivh4C3HDNbOJpqCtwEQvH8vIYGUayAeMNMKGowkAhH0zCCprUGNBdQaZ65EW8Gf3kKcPc2GH
        let data = hex::decode(s.as_ref()).ok()?;
        assert!(data.len() >= 32);
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(server_key.as_bytes()).unwrap();
        mac.update(&data[32..]);
        mac.verify(&data[..32]).ok()?;
        let magic_token = bincode::deserialize::<MagicLinkToken>(&data[32..]).ok()?;
        if magic_token.get_expired_at() < Utc::now().timestamp() {
            return None;
        }
        Some(magic_token)
    }

    pub fn get_expired_at(&self) -> i64 {
        match &self {
            MagicLinkToken::Register { expired_at, .. } => *expired_at,
            MagicLinkToken::Login { expired_at, .. } => *expired_at,
        }
    }

    pub fn get_code(&self) -> &str {
        match &self {
            MagicLinkToken::Register { code, .. } => code.as_str(),
            MagicLinkToken::Login { code, .. } => code.as_str(),
        }
    }
}

pub fn gen_code() -> String {
    (0..6)
        .map(|_| fastrand::char('0'..='9'))
        .collect::<String>()
}

fn encode(server_key: &str, magictoken: &MagicLinkToken) -> String {
    let content = bincode::serialize(&magictoken).unwrap();
    let mut buf_sig = {
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(server_key.as_bytes()).unwrap();
        mac.update(&content);
        mac.finalize().into_bytes().to_vec()
    };
    buf_sig.extend_from_slice(&content);
    hex::encode(&buf_sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_invite_to_server() {
        let server_key = "123456";
        let code = gen_code();
        let expired_at = chrono::Utc::now() + chrono::Duration::seconds(10);
        let token = MagicLinkToken::gen_reg_magic_token(
            &code, server_key, expired_at, true, None, None, None,
        );
        if let MagicLinkToken::Register {
            is_confirmed,
            gid,
            code,
            expired_at,
            extra_email,
            extra_password,
        } = MagicLinkToken::parse(server_key, token).unwrap()
        {
            assert!(is_confirmed);
            assert_eq!(gid, None);
            assert_eq!(code.len(), 6);
            assert!(expired_at > 0);
            assert_eq!(extra_email, None);
            assert_eq!(extra_password, None);
        } else {
            panic!("test failed!");
        }
    }
}
