use poem::{http::StatusCode, Endpoint, EndpointExt, Error};
use poem_openapi::{ApiExtractor, ExtractParamOptions};

use crate::api::Token;

pub fn guest_forbidden(ep: impl Endpoint) -> impl Endpoint {
    ep.before(|req| async move {
        let token = Token::from_request(
            &req,
            &mut Default::default(),
            ExtractParamOptions {
                name: "",
                default_value: None,
                explode: false,
            },
        )
        .await?;
        if token.is_guest {
            return Err(Error::from_status(StatusCode::FORBIDDEN));
        }
        Ok(req)
    })
}
