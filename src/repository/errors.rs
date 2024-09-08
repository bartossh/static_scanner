use thiserror::Error;

/// RepositoryError describes all errors that can occure in repository.
///
#[derive(Error, Debug)]
pub enum RepositoryError {
    #[error("repository request failed with error {0}")]
    ReadFailure(#[from] reqwest::Error),
    #[error("repository failed with error {0}")]
    WithMessage(String)
}
