use hmac::{Mac, NewMac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Debug, Serialize, Deserialize)]
struct ApiKey {
    uid: i64,
    nonce: String,
}

pub fn create_api_key(uid: i64, server_key: &str) -> String {
    let content = serde_json::to_vec(&ApiKey {
        uid,
        nonce: textnonce::TextNonce::new().0,
    })
    .unwrap();
    let mut buf_sig = {
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(server_key.as_bytes()).unwrap();
        mac.update(&content);
        mac.finalize().into_bytes().to_vec()
    };
    buf_sig.extend_from_slice(&content);
    hex::encode(&buf_sig)
}

pub fn parse_api_key(data: &str, server_key: &str) -> Option<i64> {
    let data = hex::decode(data).ok()?;
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(server_key.as_bytes()).unwrap();
    mac.update(&data[32..]);
    mac.verify(&data[..32]).ok()?;
    let api_key = serde_json::from_slice::<ApiKey>(&data[32..]).ok()?;
    Some(api_key.uid)
}
