#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Db(#[from] sled::Error),

    #[error("invalid data")]
    InvalidData,
}

pub type Result<T, E = Error> = ::std::result::Result<T, E>;
