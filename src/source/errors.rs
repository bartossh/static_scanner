use thiserror::Error;
use git2;
use std::io;

/// SourceError describes all errors that can occure in Source.
///
#[derive(Error, Debug)]
pub enum SourceError {
    #[error("failed due to file io failuer, {0}")]
    FileIoFailure(#[from] io::Error),
    #[error("failed due to git io failuer, {0}")]
    Git2IoFailure(#[from] git2::Error),
    #[error("failed due to async decomression failure, {0}")]
    AsyncDecompresionFailure(String),
    #[error("failed due to parameter is lacking, {0}")]
    ParameterFailure(String),
    #[error("failed due to source not ready, {0}")]
    GitSourceNotReady(String),
    #[error("failed due to not being able to access the {0} branch")]
    BranchNotAccessible(String),
}
