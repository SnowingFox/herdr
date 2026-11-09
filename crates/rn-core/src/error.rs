use thiserror::Error;

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("unknown binding namespace: {0}")]
    UnknownNamespace(String),
    #[error("binding namespace {namespace} is missing member {member}")]
    MissingMember { namespace: String, member: String },
    #[error("javascript exception escaped: {0}")]
    JsException(String),
}

pub type Result<T> = std::result::Result<T, KernelError>;
