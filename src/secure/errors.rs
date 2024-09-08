use thiserror::Error;
use openssl::error::ErrorStack;
use std::str;

/// SecureError describes all errors that can occure in secure package.
///
#[derive(Error, Debug)]
pub enum SecureError {
    #[error("IO operation failed, {0}")]
    IOFailure(#[from] std::io::Error),
    #[error("failed due to string formatting, {0}")]
    StringFormattingFailed(#[from] str::Utf8Error),
    #[error("signer failed with error, {0}")]
    SignerFailureErrorStack(#[from] ErrorStack),
    #[error("repository failed with error {0}")]
    WithMessage(String)
}
