use crate::{
    api::{tags::ApiTags, token::Token},
    State,
};
use chrono::Utc;
use poem::{web::Data, Error, Result};
use poem_openapi::{payload::Json, Object, OpenApi};
use reqwest::StatusCode;

#[derive(Debug, Object)]
struct CheckLicenseRequest {
    license: String,
}

#[derive(Debug, Object)]
struct SaveLicenseRequest {
    license: String,
}

#[derive(Debug, Object, Clone)]
pub struct LicenseReply {
    pub domain: String,
    pub user_limit: u32,
    pub created_at: chrono::DateTime<Utc>,
    pub expired_at: chrono::DateTime<Utc>,
    pub sign: bool,
}

pub struct ApiLicense;

pub const VOCE_LICENSE_PUBLIC_KEY_PEM: &str = r#"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEApqGLPAiVzx42qRkjDGqCT4+BrS3BReJA7UAXQt3YNfw2HIB+CJSD
F22KnpqmnsaLWmxrUP1Q+ttb+fZhMZ569s5ZLs9h6pq2oTBK8kBUKz127rpwHSpG
VnuGbkPB4NUcTOYiDTLT7iD9NSN38Cr1ITTD3+4EiSiCuf9aUpggfo06fqF69ebD
C0pPSTRvIDgKrJiku93c3d1uDq1DWfYKu3GP23ie5+3WwQcsd/XG/0xyMk1hfVQJ
qTf5Z2rVdmhVGt0XjV6cmaVshJOxGeoAubPLJX4G4DLTvXKGy/WlQlQTqIBz8xUB
dnwtOymXGQpaS/Vfo0q1kGzZoXsCx3v7BQIDAQAB
-----END RSA PUBLIC KEY-----"#;

#[OpenApi(prefix_path = "/license", tag = "ApiTags::License")]
impl ApiLicense {
    /// Check the license is valid
    #[oai(path = "/check", method = "post")]
    async fn check(
        &self,
        _state: Data<&State>,
        req: Json<CheckLicenseRequest>,
    ) -> Result<Json<LicenseReply>> {
        let license_bs58 = req.license.clone();
        let license = vc_license::License::from_string(license_bs58.clone())
            .map_err(|_err| Error::from_status(StatusCode::BAD_REQUEST))?;
        let sign_is_ok =
            vc_license::rsa_check_license_bs58(&license_bs58, VOCE_LICENSE_PUBLIC_KEY_PEM).is_ok();

        Ok(Json(LicenseReply {
            domain: license.domain.clone(),
            user_limit: license.user_limit,
            created_at: license.created_at,
            expired_at: license.expired_at,
            sign: sign_is_ok,
        }))
    }

    /// Save the license
    #[oai(path = "/", method = "put")]
    async fn put(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<SaveLicenseRequest>,
    ) -> Result<Json<bool>> {
        let mut license_path = state.config.system.data_dir.clone();
        license_path.push("license");
        //if !license_path.exists() || (token.is_some() && token.unwrap().is_admin) {
        if !license_path.exists() || token.is_admin {
            crate::license::update_license(&state, &req.license)
                .await
                .map_err(|_err| Error::from_status(StatusCode::BAD_REQUEST))?;
        }
        Ok(Json(true))
    }

    /// Get the license
    #[oai(path = "/", method = "get")]
    async fn get(
        &self,
        state: Data<&State>,
        //token: Token,
    ) -> Result<Json<LicenseReply>> {
        // if !token.is_admin {
        //     // return Err(Error::from_status(StatusCode::FORBIDDEN));
        // }
        let mut license_path = state.config.system.data_dir.clone();
        license_path.push("license");
        let license_bs58 = tokio::fs::read_to_string(license_path).await.map_err(|_err|Error::from_status(StatusCode::BAD_REQUEST))?;
        let license = vc_license::License::from_string(license_bs58.clone())
            .map_err(|_err| Error::from_status(StatusCode::BAD_REQUEST))?;
        let sign_is_ok =
            vc_license::rsa_check_license_bs58(&license_bs58, VOCE_LICENSE_PUBLIC_KEY_PEM).is_ok();

        Ok(Json(LicenseReply {
            domain: license.domain.clone(),
            user_limit: license.user_limit,
            created_at: license.created_at,
            expired_at: license.expired_at,
            sign: sign_is_ok,
        }))
    }
}

/*
#[cfg(test)]
mod tests {
    use reqwest::StatusCode;
    use serde_json::json;
    use crate::{test_harness::TestServer};

    #[tokio::test]
    async fn test_check_license() {
        let server = TestServer::new().await;
        let resp = server
            .post("/api/license/check")
            .body_json(&json!({
                    "license": "37w6gXBCKnuPHT6Np1QjhUDRacerHsz9eY1UKWVQyBiiHjLPJ96fBTMwKRAZW5USxkDcT73CPAejwrnoomcj2ZzC5m9hb7H2Q6rTxwzenWoJ5Va2dP3AY84NkZt15maJJcDxRnGZSURrEixFHtYfvk5neEUnxY5tDz2fjD42fWo5UnE4n8bjTgCgAFdS4AxMCmuFaVbidgnTEeNdLjwpdP3v4nQwYX9d211Zmiy81UYq2pJfrksAcP4Ew34jAgB1etAvqYnT2fGvUWtA7DfG6yMgx2Hbo52Upo8TMQNnNkAv4ZDHF1AZ8NqXScAXCK7v5MpdkfggrRepwViovnVKku5XSa794aoXtx9q8fQuKUvAShTYNA2qVm5EYZTNpMTgHAtyAuABJN3DFpT8jJiSjQ3pb31Nh5v2yDKGDhYzBgdwpQmKMp82GakMxCKFmhM7E74VEi4avFed4UdqtQzf2iFnobNs3hJyqT5zys9Yws1ff9iY2bUqP9HRNWtzamPFvWSEt7AgSqRfe1cEuJLhU1SDL2zVgydD69FEKfmrTyR43YfRz8mVjuNLcbKmwgNQk4145SpsZ59nrRdfjTo3wqhbSmoip53mhDaVpMkiWzbESy1QrD6ow75C3SNzUgxmoBWceFPgzcZbQixLWVoh2ofUf4yJqw3JqoaJFrrFUAjVafQLN4hKhrSSoNbkrFjM5rGmZ87ZVFkkLrLez6vCGbxFfK8KeiXDBeq4H1VKRmuy2G9VVDYLNvGFfNpy2YLYnsiXCY8rEyGctteU9i94jbHn1zN9vinyBcgkY",
                }))
            .send()
            .await;

        let json = resp.json().await;
        assert_eq!(json.value().object().get("domain").string(), "www.domain.com");
        assert_eq!(json.value().object().get("sign").bool(), true);

        let server = TestServer::new().await;
        let resp = server
            .post("/api/license/check")
            // .header("X-API-Key", &token1)
            .body_json(&json!({
                        "license": "bad",
                    }))
            .send()
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);

    }

    #[tokio::test]
    async fn test_save_license() {
        let server = TestServer::new().await;
        let resp = server
            .put("/api/license")
            .body_json(&json!({
                        "license": "2RvN4krfyQbvuLcXzz4PwoJfckRFptqLKKXSP7f4Np7AGqgixrfdUzZ5qk2iT2gFwCntivyYnSaumyao7QF2SfQ3TKyLAgGDYeYeJcbBri9re5esG2PMrxZBjq68eR94yYqdTg6LAP9oc5WtLAaBX25RkVu2zt59kdgRzk5CbnnmZnMAHgZEDnsVJfCQa6HKnb3p1cpZa6LTANrKh1VuvCAerdCHCoc1YHNwUipg5JJXmxJQadFShv1sYREUHHzLuPMb8xHb7GkPJ6MJpQBzHfDnTySRG7BGxNz5GKCutFp1o7YjkQqZvKBTvWQ8ic4HmbHErLHw4aJ5CAMyugX4v2GAgxS8Z4zi9tjdzRtbbqzncnXSNBTumBxobBskNAbEaQC9HgBavgcAw4wHrHSyG3v2rTdsDUJZgTtanEfxnxZhSpKtXZRFzVNdjmo66GeLhvWwMZSXKzH89uTvMcEokmbUyLz9mKXzRP9dhTJ4bC6YWNrbDueYX9pqrsmXm3Z4aYP7DjknXwPCMKZbsCXZi2YQVUjggCyRarR4eThY6gZ8iWGkvi1ybAADooh8KXSAFNGSRRTGC5La6Atug7y6e6QnFmaRndLHdCyxqyq9LM1Ly2icYAFa2ZspXyL3MyBTLFvgQeqTmL1KQVHzhjwtkTvcFsUxScYNXhVgCkyD5vkSZpcwixGJYyYtkrF27XpMcq8mR6dAyi3Zqt2w68X3xA748a8ofky1KYwHmA1U4BaDpXbbVKSu6wtonMhzvQ6xMssyWJVhrzeymPnMwM8Xiut3pZcpC77Ri",
                    }))
            .send()
            .await;
        resp.assert_status_is_ok();

    }

    #[tokio::test]
    async fn test_license_user_limit() {
        let server = TestServer::new().await;
        let state = server.state();
        crate::license::load_license(&state).await.unwrap();

        // test user limit
        let admin_token = server.login_admin().await;
        for i in 0..30 {
            server.create_user(&admin_token, format!("user{}@voce.chat", i)).await;
        }
        let resp = server
            .post("/api/user/send_login_magic_link")
            .query("email", &"xx@xx.com")
            .header("Referer", "http://domain.com:3000/")
            .send()
            .await;
        resp.assert_text("License error: Users reached limit.").await;
    }

    #[tokio::test]
    async fn test_license_invalid_sign() {
        // test sign invalid
        let server = TestServer::new().await;
        let state = server.state();
        crate::license::load_license(&state).await.unwrap();
        let invalid_sign_license = "Jym9MkwzuPBfKKPkYVKJfGeGVbpx8pHeWrLM5zPNoSf3GrrwNCowRGgowUX2LULLzMpdLUcSvrHTHLpYRhKDc5JFyPVNqoKxiWfcCwGzn";
        crate::license::update_license(&state, invalid_sign_license).await.unwrap();
        let resp = server
            .post("/api/user/send_login_magic_link")
            .query("email", &"xx@xx.com")
            .header("Referer", "http://domain.com:3000/")
            .send()
            .await;
        resp.assert_text("License error: Sign invalid.").await;
    }

    #[tokio::test]
    async fn test_license_invalid_sign2() {
        // test sign invalid
        let server = TestServer::new().await;
        let state = server.state();
        crate::license::load_license(&state).await.unwrap();
        let invalid_sign_license = "Jym9MkwzuPBfKKPkYVKJfGeGVbpx8pHeWrLM5zPNoSf3GrrwNCowRGgowUX2LULLzMpdLUcSvrHTHLpYRhKDc5JFyPVNqoKxiWfcCwGzn";
        crate::license::update_license(&state, invalid_sign_license).await.unwrap();
        let resp = server
            .post("/api/token/login")
            .body_json(&json!({
                "credential": {
                    "type": "magiclink",
                    "magic_token": "test",
                    "extra_name": "jack"
                },
                "device": "web",
                "device_token": "device token",
            }))
            .header("Referer", "http://domain.com:3000/")
            .send()
            .await;
        resp.assert_text("License error: Sign invalid.").await;
    }
}
*/
