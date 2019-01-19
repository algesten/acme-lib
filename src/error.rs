//
use std::fmt;
use std::io;

/// acme-lib result.
pub type Result<T> = ::std::result::Result<T, Error>;

/// acme-lib errors.
#[derive(Debug)]
pub enum Error {
    /// An API call failed.
    Call(String),
    /// Base64 decoding failed.
    Base64Decode(base64::DecodeError),
    /// JSON serialization/deserialization error.
    Json(serde_json::Error),
    /// std::io error.
    Io(io::Error),
    /// Some other error. Notice that `Error` is
    /// `From<String>` and `From<&str>` and it becomes `Other`.
    Other(String),
}
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Call(s) => write!(f, "{}", s),
            Error::Base64Decode(e) => write!(f, "{}", e),
            Error::Json(e) => write!(f, "{}", e),
            Error::Io(e) => write!(f, "{}", e),
            Error::Other(s) => write!(f, "{}", s),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Other(s.to_string())
    }
}
