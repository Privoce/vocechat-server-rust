#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Jwt(#[from] jwt::Error),

    #[error("expired")]
    Expired,
}
