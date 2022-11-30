use poem::{http::StatusCode, web::Data, Error, Result};
use poem_openapi::{payload::Json, Object, OpenApi};
use rc_fcm::{ApplicationCredentials, FcmClient};
use serde::{Deserialize, Serialize};

use crate::{
    api::{tags::ApiTags, token::Token},
    state::{DynamicConfig, DynamicConfigEntry},
    State,
};

pub struct ApiAdminFirebase;

/// Firebase config
#[derive(Debug, Object, Serialize, Deserialize, Default)]
pub struct FcmConfig {
    #[serde(default = "default_use_offical")]
    pub use_offical: bool,
    #[oai(default = "default_token_url")]
    pub token_url: String,
    pub project_id: String,
    pub private_key: String,
    pub client_email: String,
}

fn default_use_offical() -> bool {
    true
}

fn default_token_url() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

impl DynamicConfig for FcmConfig {
    type Instance = FcmClient;

    fn name() -> &'static str {
        "fcm"
    }

    fn create_instance(self) -> Self::Instance {
        if self.use_offical {
            FcmClient::new(ApplicationCredentials {
                project_id: "vocechatdev".to_string(),
                private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCTnF6VYea6IHAM\nRysub/vjCefL9L7pKZVOMHn+2Upg6sTyYwu7q2utvdBN7jNwCMKHadzMMvCn7R+q\nVFTNqjrBwav1D5pRhsAubGNR6h3n1ycGe4HrXfeSGrxKmd8CQwcYyWP5rhtC2HyV\nNIgFRXMmQ/PUzf8YscScFZduFFUgNV1uate5jCv7hZOuymt8H7fov1MZFcgejk0+\nAr5wHG4pEW9aB6TWTcx/qqTPeP2qWhjbLBVJLMisc67TJEoV0xUmcUVWFRXhYkVR\nlBDZrsDr62jqqm1lJYTDGBW6ZvEzM/iXEK1K84NULpHhsnVmHE/savG6w6BQ4qaH\nnWfMSh9RAgMBAAECggEAASFi5OT+raHyouwI2qKMiMmJfq/5GUHXQQ9GAOYDuWRb\nRdUThZbEPky9KsdqWdpauITuou2+ygkHqGMvazi8pofiP+z0TRln931yOrhtJxQb\nijbIDBZ6GNKNkURWeNusuYBIOYG8N1XMD79OE+nBrjszg7EmtrPP6VQKpt/Faar1\nK8Oha8h8sV4bb4iqHJpNdW0aW5uhNbcQ+lWJZK8gJ9PgAA3uqfNv+UEN0fa08lb0\nspY30hdG56QuLq9nr8AigNzbprWVl1s1LtbhCzA1GMZfthu8K7ZutONvgonoIFRd\nxkEb/WMuSKhl3B/TTpEaA9C9zk9WXQbmNZINoIYAAQKBgQDO31hr502JJKz8LNmX\nqVcTwFBLWfyKw/rUxR74AKzaCygeBhOU/4C1yISnU51UeRJ/SrtaDEMmBrD/s00h\nOUhFi142ARFSDIPnMR+eEoVeSgAtCSMG1/tW9X15zjHCobgN42Y+5vq0qtYQKygM\nexwvdD5CU/1gOligInOhmKEAAQKBgQC2qkIWu94NkEVYKtOIRCP4ektyrZPW+maj\nfYsKQhso/+JhFKL1AucdkUfIcJc8Sxt430iUD0S/4nKfR1OgN1F4YL99ZbbaEbVR\njGzU1Ldg5P7y7IQ3h7YygrxBdhqwSylLoydr7Lf/cxbqNAbILagQwB4JAHG01JYi\nLyPSAlkfUQKBgH0AF72blg44Sw5VS2WIvUUB/4KIbUCsCvRl58CTJ97YvvTlVw/B\nE1TEROOWcoqIXdTsoyhWIHzprinTfdeFdVYQUGzxWDXruggIdsJdDplavaB41OFd\nwFFbJOZk4Uxpy30Y2r9HclWYpKBAc4KXIQDLjJMnjQKIPuUD7DrIrwABAoGAQlUr\nsMPCTFyiwfSzYl2UTmxir59W+49s7FvvvObqpAXgOG7dCmpmcTdLwP8Z/Hwt2sQC\nwDmXNrNN+odVV+4euL8xaqEgOKqLlLSQ5OzmNtqRtreq/9tZj5goMwFnibORqHT0\nIN4Sp0ItBRmliNYDnSmW/p/Zqtg0OO+za1UM9jECgYAL1BQr6+qbvyCaT61OoXkv\nz/0NMWDROmsbdTdyxTCU6qqIKUJjCOzET7aGahhqLaY4Y1sCnwN7PuDjdM5wvX+f\nDppfxRPxLwN5xWWHMydUcKwu+8gZuvVF73i4G3RsSGtf2IYLzshC3em+VpL46JOc\neYi8fGY6puD0XaSOZxXAKQ==\n-----END PRIVATE KEY-----\n".to_string(),
                client_email: "firebase-adminsdk-z6x67@vocechatdev.iam.gserviceaccount.com".to_string(),
                token_uri: "https://oauth2.googleapis.com/token".to_string(),
            })
        } else {
            FcmClient::new(ApplicationCredentials {
                project_id: self.project_id,
                private_key: self.private_key,
                client_email: self.client_email,
                token_uri: self.token_url,
            })
        }
    }
}

/// Firebase config
#[derive(Debug, Object)]
pub struct FcmConfigObject {
    enabled: bool,
    #[oai(flatten)]
    config: FcmConfig,
}

#[OpenApi(prefix_path = "/admin/fcm", tag = "ApiTags::AdminFirebase")]
impl ApiAdminFirebase {
    /// Set Firebase config
    #[oai(path = "/config", method = "post")]
    async fn set_config(
        &self,
        state: Data<&State>,
        token: Token,
        config: Json<FcmConfigObject>,
    ) -> Result<()> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }
        state
            .set_dynamic_config(DynamicConfigEntry {
                enabled: config.0.enabled,
                config: config.0.config,
            })
            .await?;
        Ok(())
    }

    /// Get Firebase config
    #[oai(path = "/config", method = "get")]
    async fn get_config(&self, state: Data<&State>, token: Token) -> Result<Json<FcmConfigObject>> {
        if !token.is_admin {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }
        let entry = state.load_dynamic_config::<FcmConfig>().await?;
        Ok(Json(FcmConfigObject {
            enabled: entry.enabled,
            config: entry.config,
        }))
    }
}
