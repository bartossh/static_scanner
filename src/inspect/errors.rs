use thiserror::Error;
use crate::detectors::errors::DetectorError;

/// InspectorError describes all errors that can occure in Inspector.
///
#[derive(Error, Debug)]
pub enum InspectorError {
    #[error("failed to build inspector, detector failed with: {0}")]
    BuildFailure(#[from] DetectorError),
}
