use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExposureError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("routing error: {0}")]
    Routing(String),

    #[error("access denied: {0}")]
    AccessDenied(String),

    #[error("link error: {0}")]
    Link(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ExposureError>;
