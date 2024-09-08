use thiserror::Error;
use crate::secure::errors::SecureError;

/// RepositoryError describes all errors that can occure in repository.
///
#[derive(Error, Debug)]
pub enum RepositoryError {
    #[error("repository secure guard failed with error {0}")]
    SecureGuardFailure(#[from] SecureError),
    #[error("repository request failed with error {0}")]
    ReqwestFailure(#[from] reqwest::Error),
    #[error("repository failed with error {0}")]
    WithMessage(String)
}
