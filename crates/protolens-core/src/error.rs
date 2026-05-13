use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("unsupported operation: {0}")]
    Unsupported(String),

    #[error("capture backend {source_id} failed: {message}")]
    Capture { source_id: String, message: String },

    #[error("protocol analyzer {analyzer} failed: {message}")]
    Protocol { analyzer: String, message: String },

    #[error("event sink {sink} failed: {message}")]
    Sink { sink: String, message: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
