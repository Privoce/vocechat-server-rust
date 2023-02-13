use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Mac, NewMac};
use sha2::Sha256;

const VERSION: &str = "006";

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
enum Privileges {
    JoinChannel = 1,
    PublishAudioStream = 2,
    PublishVideoStream = 3,
    PublishDataStream = 4,
}

fn create_access_token(
    app_id: &str,
    app_certificate: &str,
    channel_name: &str,
    uid: &str,
    privileges: &[Privileges],
) -> String {
    let ts = (SystemTime::now().duration_since(UNIX_EPOCH))
        .unwrap()
        .as_secs() as u32
        + 24 * 3600;
    let salt = fastrand::u32(1..99999999);
    let mut buf_m = Vec::new();

    buf_m.extend_from_slice(&salt.to_le_bytes());
    buf_m.extend_from_slice(&ts.to_le_bytes());

    buf_m.extend_from_slice(&(privileges.len() as u16).to_le_bytes());
    let mut privileges = privileges.to_vec();
    privileges.sort();

    for k in privileges {
        buf_m.extend_from_slice(&(k as u16).to_le_bytes());
        buf_m.extend_from_slice(&ts.to_le_bytes());
    }

    let mut buf_val = Vec::new();
    buf_val.extend(format!("{}{}{}", app_id, channel_name, uid).as_bytes());
    buf_val.extend(&buf_m);

    let buf_sig = {
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(app_certificate.as_bytes())
            .expect("valid app certificate");
        mac.update(&buf_val);
        mac.finalize().into_bytes()
    };

    let crc_channel_name = crc32(channel_name.as_bytes());
    let crc_uid = crc32(uid.as_bytes());

    let mut buf_content = Vec::new();
    pack_bytes(&mut buf_content, &buf_sig);
    buf_content.extend_from_slice(&crc_channel_name.to_le_bytes());
    buf_content.extend_from_slice(&crc_uid.to_le_bytes());
    pack_bytes(&mut buf_content, &buf_m);

    format!("{}{}{}", VERSION, app_id, base64::encode(buf_content))
}

fn crc32(data: &[u8]) -> u32 {
    let mut hasher = checksum::crc32::Crc32::new();
    hasher.checksum(data)
}

fn pack_bytes(data: &mut Vec<u8>, s: &[u8]) {
    data.extend_from_slice(&(s.len() as u16).to_le_bytes());
    data.extend_from_slice(s);
}

pub fn create_rtc_token(
    app_id: &str,
    app_certificate: &str,
    channel_name: &str,
    uid: u32,
) -> String {
    let uid = if uid == 0 {
        String::new()
    } else {
        uid.to_string()
    };
    create_access_token(
        app_id,
        app_certificate,
        channel_name,
        &uid,
        &[
            Privileges::JoinChannel,
            Privileges::PublishAudioStream,
            Privileges::PublishVideoStream,
            Privileges::PublishDataStream,
        ],
    )
}
