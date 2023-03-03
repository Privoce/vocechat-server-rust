use chrono::Utc;
use poem::{web::Data, Error, Result};
use poem_openapi::{payload::Json, Object, OpenApi};
use reqwest::StatusCode;

use crate::{
    api::{tags::ApiTags, token::Token},
    State,
};

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
    pub domains: Vec<String>,
    pub user_limit: u32,
    pub created_at: chrono::DateTime<Utc>,
    pub expired_at: chrono::DateTime<Utc>,
    pub sign: bool,
    pub base58: String,
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
            domains: license.domains.clone(),
            user_limit: license.user_limit,
            created_at: license.created_at,
            expired_at: license.expired_at,
            sign: sign_is_ok,
            base58: license_bs58,
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
        // if !license_path.exists() || (token.is_some() && token.unwrap().is_admin) {
        if !license_path.exists() || token.is_admin {
            crate::license::update_license(&state, &req.license)
                .await
                .map_err(|_err| Error::from_status(StatusCode::BAD_REQUEST))?;
        }
        Ok(Json(true))
    }

    /// Get the license
    #[oai(path = "/", method = "get")]
    async fn get(&self, state: Data<&State>) -> Result<Json<LicenseReply>> {
        let mut license_path = state.config.system.data_dir.clone();
        license_path.push("license");
        let license_bs58 = tokio::fs::read_to_string(license_path)
            .await
            .map_err(|_err| Error::from_status(StatusCode::BAD_REQUEST))?;
        let license = vc_license::License::from_string(license_bs58.clone())
            .map_err(|_err| Error::from_status(StatusCode::BAD_REQUEST))?;
        let sign_is_ok =
            vc_license::rsa_check_license_bs58(&license_bs58, VOCE_LICENSE_PUBLIC_KEY_PEM).is_ok();

        Ok(Json(LicenseReply {
            domains: license.domains.clone(),
            user_limit: license.user_limit,
            created_at: license.created_at,
            expired_at: license.expired_at,
            sign: sign_is_ok,
            base58: license_bs58,
        }))
    }
}

#[cfg(test)]
mod tests {
    use reqwest::StatusCode;
    use serde_json::json;

    use crate::test_harness::TestServer;

    #[tokio::test]
    async fn test_check_license() {
        let server = TestServer::new().await;
        let resp = server
            .post("/api/license/check")
            .body_json(&json!({
                    "license": "37w6gXBCKnuPHT6Np1QjhUDRacerHsz9eY1UKWVQyBiiHjLPJ96fBTMwKRAZW5USxkDcT73CPAejwrnoomcj2ZzC5m9hb7H2Q6rTxwzenWoJ5Va2dP3AY84NkZt15maJJcDxRnGZSURrEixFHtYfvk5neEUnxY5tDz2fjD42fWo5UnE4n8bjTgCgAFdS4AxMCmuFaVbidgnTEeNdLjwpdP3v4nQwYX9d211Zmiy81UYq2pJfrksAcP4Ew34jAgB1etAvqYnT2fGvUWtA7DfG6yMgx2Hbo52Upo8TMQNnNkAv4ZDHF1AZ8NqXScAXCK7v5MpdkfggrRepwViovnVKku5XSa794aoXtx9q8fQuKUvAShTYNA2qVm5EYZTNpMTgHAtyAuABJN3DFpT8jJiSjQ3pb31Nh5v2yDKGDhYzBgdwpQmKMp82GakMxCKFmhM7E74VEi4avFed4UdqtQzf2iFnobNs3hJyqT5zys9Yws1ff9iY2bUqP9HRNWtzamPFvWSEt7AgSqRfe1cEuJLhU1SDL2zVgydD69FEKfmrTyR43YfRz8mVjuNLcbKmwgNQk4145SpsZ59nrRdfjTo3wqhbSmoip53mhDaVpMkiWzbESy1QrD6ow75C3SNzUgxmoBWceFPgzcZbQixLWVoh2ofUf4yJqw3JqoaJFrrFUAjVafQLN4hKhrSSoNbkrFjM5rGmZ87ZVFkkLrLez6vCGbxFfK8KeiXDBeq4H1VKRmuy2G9VVDYLNvGFfNpy2YLYnsiXCY8rEyGctteU9i94jbHn1zN9vinyBcgkY",
                }))
            .header("Referer", "http://localhost/")
            .send()
            .await;

        let json = resp.json().await;
        assert_eq!(
            json.value().object().get("domains").string_array()[0],
            "www.domain.com"
        );
        assert!(json.value().object().get("sign").bool());

        let server = TestServer::new().await;
        let resp = server
            .post("/api/license/check")
            // .header("X-API-Key", &token1)
            .body_json(&json!({
                "license": "bad",
            }))
            .header("Referer", "http://localhost/")
            .send()
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_save_license() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let resp = server
            .put("/api/license")
            .header("Referer", "http://localhost/")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                        "license": "2mLNGnEXac5XNmKftu2P8p9hiaqReiUTscKftwNJuKQyLLBYh7JZ6JzC4Vsehw375PfgAksxtLCFy9dLvetiN7nKDtsQGBj5VBhJ9XPtKsbbfrQSyG2bPdaEyM2KuH6YhvnhfSMbnA5deVH5C4uJ8zkwckFPqchmeDiwXobJeNKKRYzpkef5ggS7WeRnWNRrtXjEXkqsYW1aBb3bmAGR9XQzJcyvGYPAmDwRTLfiyNKCmma1ADeQAyhsooiBB4Q56XQ7cBs55VrUPHmvEisaeNnwU4Y9cihvWRz8HfdFhNs2dsCR2hSnDG6mEbtcoTVVaFonhQGKb9nMrDcFiNoidiSazpUWqVHG1SbcCNiwQweZ8VYRxMDVYXFLTXX2rg17jsY4mMvVHp5sqMjHvQRH4ueZtjVHVRYq4Ra21VUZBMcbLmD56RB1nMveWbAWuppENKtvg5MdByVC9Ah5oca34irHGoJMN2DrXCBxLrf21ushhY1gbXw5f4KETaod2EogivongR3g1UoU3FtiKzXbLMspGzJnBzZeij9UdqBNP8jnSiu667bpGYJSAMjJzPXtZ4oL5U5fFY14wQ5ssLssvQx5XyeGBRMKUphZT5EXL9VyTHYX2EU3Z9nQRNpumXkn4PPUQwZcbJbAeEkRbZDEsiG6g3fwFovfZffXkm5w8qCZ37DuaZkp4FgeLjNHgg3jyLM4VyirWgLkxQ2y7qL7hYSBQPzqpQVfkfYiZY9Tw4WG6cZrvUSmmnaLpDJBwwXxCxg1GaqoypusBMT5Mhw22PcLkmN8e8zS1NaXm3KVijukGQAaHTAc4EYDEASbjiSCavMipqd8Mbsj6j",
                    }))
            .send()
            .await;
        resp.assert_status_is_ok();
    }

    // #[tokio::test]
    // async fn test_license_user_limit() {
    //     let server = TestServer::new().await;
    //     let state = server.state();
    //     crate::license::load_license(&state).await.unwrap();
    //
    //     // test user limit
    //     let admin_token = server.login_admin().await;
    //     for i in 0..30 {
    //         // user default limit: 20
    //         server.create_user(&admin_token, format!("user{}@voce.chat",
    // i)).await;     }
    //
    //     let resp = server
    //         .post("/api/user/send_login_magic_link")
    //         .query("email", &"xx@xx.com")
    //         .header("Referer", "http://localhost/")
    //         .send()
    //         .await;
    //     // resp.assert_text("").await;
    //     resp.assert_text("License error: Users reached limit.").await;
    // }

    #[tokio::test]
    async fn test_license_invalid_sign() {
        // test sign invalid
        let server = TestServer::new().await;
        let state = server.state();
        crate::license::load_license(state).await.unwrap();
        let invalid_sign_license = "Jym9MkwzuPBfKKPkYVKJfGeGVbpx8pHeWrLM5zPNoSf3GrrwNCowRGgowUX2LULLzMpdLUcSvrHTHLpYRhKDc5JFyPVNqoKxiWfcCwGzn";
        crate::license::update_license(state, invalid_sign_license)
            .await
            .unwrap();
        let resp = server
            .post("/api/user/send_login_magic_link")
            .query("email", &"xx@xx.com")
            .header("Referer", "http://www.domain.com/")
            .send()
            .await;
        resp.assert_text("License error: Sign invalid.").await;
    }

    #[tokio::test]
    async fn test_license_invalid_sign2() {
        // test sign invalid
        let server = TestServer::new().await;
        let state = server.state();
        crate::license::load_license(state).await.unwrap();
        let invalid_sign_license = "Jym9MkwzuPBfKKPkYVKJfGeGVbpx8pHeWrLM5zPNoSf3GrrwNCowRGgowUX2LULLzMpdLUcSvrHTHLpYRhKDc5JFyPVNqoKxiWfcCwGzn";
        crate::license::update_license(state, invalid_sign_license)
            .await
            .unwrap();
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
            .header("Referer", "http://www.domain.com/")
            .send()
            .await;
        resp.assert_text("License error: Sign invalid.").await;
    }
}
