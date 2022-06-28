use std::{
    error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use reqwest;
use url;

#[derive(Debug)]
pub enum Error {
    NetworkError(reqwest::Error),
    UrlParseError(url::ParseError),
    IoError(std::io::Error),
    Other(String),
    Unexpected,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Error::NetworkError(ref e) => write!(f, "NetworkError:  {}", e),
            Error::UrlParseError(ref e) => write!(f, "UrlParseError:  {}", e),
            Error::IoError(ref e) => write!(f, "IoError:  {}", e),
            Error::Other(s) => write!(f, "Other Error: {}", s.as_str()),
            Error::Unexpected => write!(f, "UnexpectedError"),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error::NetworkError(err)
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Error {
        Error::UrlParseError(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IoError(err)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        ""
    }
}
