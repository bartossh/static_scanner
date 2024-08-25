use thiserror::Error;

/// ReporterError describes reporter error.
///
#[derive(Error, Debug)]
pub enum ReporterError {
    #[error("failed to report, {0}")]
    StatndardFailure(String)
}
