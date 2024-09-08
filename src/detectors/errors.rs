use thiserror::Error;
use std::io;
use aho_corasick::BuildError;


/// DetectorError describes all errors that can occure in detector.
///
#[derive(Error, Debug)]
pub enum DetectorError {
    #[error("failed to read from file, {0}")]
    ReadFailure(#[from] io::Error),
    #[error("failed to parse yaml, {0}")]
    YamlParsing(#[from] serde_yaml::Error),
    #[error("failed to build scanner, Aho Corasick failed with: {0}")]
    AhoCorasickFailure(#[from] BuildError),
    #[error("failed to build scanner, Regex failed with: {0}")]
    RegexBuilderFailure(#[from] regex::Error),
    #[error("failed to build scanner, {0}")]
    BuildScannerFailure(String),
    #[error("failed to convert, {0}")]
    TryIntoError(String),
}
