use std::ops::Deref;

use anyhow::Result;
use chrono::Utc;
use once_cell::sync::Lazy;
use poem::Request;
use tokio::sync::Mutex;
use vc_license::License;

use crate::state::State;

pub static VOCE_LICENSE_DEFAULT: &str = "333RgyjbHG5BoTXJaHDwAwcqZD1FZo24LKyByKvM4EgRGoyZFfrDhVgNVu9PFSaUoT6funBzzHWxNJRTcXfUEhx16WoSng9hukM51nmsA6EF5bNA76UDdjxyTRqp3EdpcWZhs58oiuwun1CF5HMYGT54pD9xb35u3Aq15iHqCkWBcoU4DHJRtg9HPVqGskbmwSAYbpfgWZE9NQMxt4RZxB8arik1CCUyAxpW8tKPLdt1JzeJi1KcWXn8Vmm8Nzb7hFfpjVb8yeAGc2QXyGLkGq92BgRdA6iPpc4HZQkfDFZ69xP2YFiH5fZbmAFAX2UGYKPkFQU5jQodVTtqZXxexczPCNtZQY2K5cdLcnQEoVjSKQ3cp2m15Twyus9JFbS3dm22aeX3ZBu2unXoV6mDwDndTJ3tBU6FxVyg3zckAHj5Kh2yfAcVdqnaU3JQAZcFsQVHw319qbUywm2PenD1jnSBAtuy6N6oqzXj9n8yQFrqJLFKCg8VaVhke9fUCKGYey4iVgQsHLHK6CMcjYMGWfB3tatPn44wGNpegdm9i4vEo3729HQBu6Ba4MCrNkkX8o244WehVHSaage6UVdMQMd8uh3QBEJJQTd3Vchz9Z4W4389iW5iA2pyzXTGmKEh8NiqUQZJgoE3HZysdaHpahxbCs2ihU7M9da5DtJMxjic7fKNtTinSomQ9E8TS5mBBGJsSYsAb94kpRrT9wxmH5Am81WWaY3UWR68Kxb4DHHtU7MA1ptJuQNCuBMBGeG7tj5f3TmsxB7FR4Mh4Fz";

pub const VOCE_LICENSE_PUBLIC_KEY_PEM: &str = r#"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEApqGLPAiVzx42qRkjDGqCT4+BrS3BReJA7UAXQt3YNfw2HIB+CJSD
F22KnpqmnsaLWmxrUP1Q+ttb+fZhMZ569s5ZLs9h6pq2oTBK8kBUKz127rpwHSpG
VnuGbkPB4NUcTOYiDTLT7iD9NSN38Cr1ITTD3+4EiSiCuf9aUpggfo06fqF69ebD
C0pPSTRvIDgKrJiku93c3d1uDq1DWfYKu3GP23ie5+3WwQcsd/XG/0xyMk1hfVQJ
qTf5Z2rVdmhVGt0XjV6cmaVshJOxGeoAubPLJX4G4DLTvXKGy/WlQlQTqIBz8xUB
dnwtOymXGQpaS/Vfo0q1kGzZoXsCx3v7BQIDAQAB
-----END RSA PUBLIC KEY-----"#;

// pub static mut g_license: Lazy<License> = Lazy::new(||License::default());
pub static G_LICENSE: Lazy<Mutex<License>> = Lazy::new(|| Mutex::new(License::default()));

/// inline always, Increase the difficulty of disassembly
#[inline(always)]
pub fn get_referer_domain(req: &Request) -> Option<String> {
    let referer = req.header("Referer").unwrap_or_default();
    let u = url::Url::parse(referer).ok()?;
    u.domain()
        .map(|v| v.to_string())
        .or_else(|| u.host().map(|v| v.to_string()))
}

pub async fn load_license(state: &State) -> Result<()> {
    let mut license_path = state.config.system.data_dir.clone();
    license_path.push("license");
    if !license_path.exists() {
        tokio::fs::write(&license_path, VOCE_LICENSE_DEFAULT).await?;
    }
    let license_bs58 = tokio::fs::read_to_string(&license_path).await?;
    let license = License::from_string(license_bs58)?;

    G_LICENSE.lock().await.created_at = license.created_at;
    G_LICENSE.lock().await.expired_at = license.expired_at;
    G_LICENSE.lock().await.user_limit = license.user_limit;
    G_LICENSE.lock().await.domains = license.domains;
    G_LICENSE.lock().await.sign = license.sign;

    Ok(())
}

pub async fn update_license(state: &State, new_license: &str) -> Result<()> {
    let license = vc_license::License::from_string(new_license.to_string())?;
    let mut license_path = state.config.system.data_dir.clone();
    license_path.push("license");
    std::fs::write(license_path, new_license.as_bytes())?;

    G_LICENSE.lock().await.created_at = license.created_at;
    G_LICENSE.lock().await.expired_at = license.expired_at;
    G_LICENSE.lock().await.user_limit = license.user_limit;
    G_LICENSE.lock().await.domains = license.domains;
    G_LICENSE.lock().await.sign = license.sign;

    Ok(())
}

/// inline always, Increase the difficulty of disassembly
#[inline(always)]
pub async fn check_license(state: &State, req: &Request) -> Result<()> {
    if cfg!(test) && req.header("Referer").is_none() {
        return Ok(());
    }
    let domain = get_referer_domain(req)
        .ok_or_else(|| anyhow::anyhow!("License error: Referer is empty."))?;
    let license_guard = G_LICENSE.lock().await;
    let license = license_guard.deref();
    if domain == "localhost" {
        return Ok(());
    }
    if !license.domains.contains(&domain) && !license.domains.contains(&"*".to_string()) {
        return Err(anyhow::anyhow!("License error: Domain incorrect."));
    }
    if license.expired_at < Utc::now() {
        return Err(anyhow::anyhow!("License error: Expired."));
    }
    if vc_license::rsa_check_license(license, VOCE_LICENSE_PUBLIC_KEY_PEM).is_err() {
        return Err(anyhow::anyhow!("License error: Sign invalid."));
    }
    let cache = state.cache.read().await;
    if cache
        .users
        .iter()
        .filter(|(_, user)| !user.is_guest)
        .count()
        > license.user_limit as usize
    {
        return Err(anyhow::anyhow!("License error: Users reached limit."));
    }
    Ok(())
}

#[macro_export]
macro_rules! check_license_wrap {
    ($($tt: expr),*) => {
        $crate::license::check_license($($tt),*).await.map_err(|err| Error::from_string(err.to_string(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS))?;
    }
}
pub(crate) use check_license_wrap;
