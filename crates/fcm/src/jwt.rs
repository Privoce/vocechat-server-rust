use anyhow::Result;
use chrono::Utc;
use rustls::{sign, sign::SigningKey, PrivateKey};
use serde::Serialize;

use crate::ApplicationCredentials;

const GOOGLE_RS256_HEAD: &str = r#"{"alg":"RS256","typ":"JWT"}"#;

/// Encodes s as Base64
fn append_base64<T: AsRef<[u8]> + ?Sized>(s: &T, out: &mut String) {
    base64::encode_config_buf(s, base64::URL_SAFE, out)
}

/// Decode a PKCS8 formatted RSA key.
fn decode_rsa_key(pem_pkcs8: &str) -> Result<PrivateKey> {
    let mut private_keys = rustls_pemfile::pkcs8_private_keys(&mut pem_pkcs8.as_bytes())?;
    anyhow::ensure!(!private_keys.is_empty(), "Not enough private keys in PEM");
    Ok(PrivateKey(private_keys.remove(0)))
}

/// Permissions requested for a JWT.
/// See https://developers.google.com/identity/protocols/OAuth2ServiceAccount#authorizingrequests.
#[derive(Serialize, Debug)]
pub(crate) struct Claims<'a> {
    iss: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    subject: Option<&'a str>,
    scope: String,
}

impl<'a> Claims<'a> {
    pub(crate) fn new<T>(
        key: &'a ApplicationCredentials,
        scopes: &[T],
        subject: Option<&'a str>,
    ) -> Self
    where
        T: std::string::ToString,
    {
        let iat = Utc::now().timestamp();
        let expiry = iat + 3600 - 5; // Max validity is 1h.

        let scope: String = scopes
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        Claims {
            iss: &key.client_email,
            aud: &key.token_uri,
            exp: expiry,
            iat,
            subject,
            scope,
        }
    }
}

/// A JSON Web Token ready for signing.
pub(crate) struct JwtSigner {
    signer: Box<dyn rustls::sign::Signer>,
}

impl JwtSigner {
    pub(crate) fn new(private_key: &str) -> Result<Self> {
        let key = decode_rsa_key(private_key)?;
        let signing_key = sign::RsaSigningKey::new(&key)?;
        let signer = signing_key
            .choose_scheme(&[rustls::SignatureScheme::RSA_PKCS1_SHA256])
            .ok_or_else(|| anyhow::anyhow!("Couldn't choose signing scheme"))?;
        Ok(JwtSigner { signer })
    }

    pub(crate) fn sign_claims(&self, claims: &Claims) -> Result<String, rustls::Error> {
        let mut jwt_head = Self::encode_claims(claims);
        let signature = self.signer.sign(jwt_head.as_bytes())?;
        jwt_head.push('.');
        append_base64(&signature, &mut jwt_head);
        Ok(jwt_head)
    }

    /// Encodes the first two parts (header and claims) to base64 and assembles
    /// them into a form ready to be signed.
    fn encode_claims(claims: &Claims) -> String {
        let mut head = String::new();
        append_base64(GOOGLE_RS256_HEAD, &mut head);
        head.push('.');
        append_base64(&serde_json::to_string(&claims).unwrap(), &mut head);
        head
    }
}
