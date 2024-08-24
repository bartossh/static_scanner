use thiserror::Error;
use crate::source::errors::SourceError;
use crate::inspect::errors::InspectorError;
use std::io;
use zip::result::ZipError;

/// ExecutorError describes all errors that can occure in Executor.
///
#[derive(Error, Debug)]
pub enum ExecutorError {
    #[error("failed due to inspector failuer, {0}")]
    InspectorFailure(#[from] InspectorError),
    #[error("failed due to source io failuer, {0}")]
    GitSourceIoFailure(#[from] SourceError),
    #[error("failed due to parameter is lacking, {0}")]
    FileIoFailure(#[from] io::Error),
    #[error("failed due file io error, {0}")]
    ZipArchiveFailure(#[from] ZipError),
    #[error("failed due zip archive reading error, {0}")]
    WrongParameterFailure(String),
    #[error("filed due to unexpected error, {0}")]
    Unexpected(String),
}
