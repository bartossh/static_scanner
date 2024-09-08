use thiserror::Error;
use openssl::error::ErrorStack;

/// SecureError describes all errors that can occure in secure package.
///
#[derive(Error, Debug)]
pub enum SecureError {
    #[error("signer failed with error, {0}")]
    SignerFailureErrorStack(#[from] ErrorStack),
    #[error("repository failed with error {0}")]
    WithMessage(String)
}
