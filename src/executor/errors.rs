use thiserror::Error;
use crate::source::errors::SourceError;
use crate::inspect::errors::InspectorError;

/// ExecutorError describes all errors that can occure in Executor.
///
#[derive(Error, Debug)]
pub enum ExecutorError {
    #[error("failed due to inspector failuer: {0}")]
    InspectorFailure(#[from] InspectorError),
    #[error("failed due to source io failuer: {0}")]
    GitSourceIoFailure(#[from] SourceError),
    #[error("failed due to parameter is lacking, {0}")]
    WrongParameterFailure(String),
}
