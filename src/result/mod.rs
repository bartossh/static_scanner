use std::fmt::{Display, Formatter, Result};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod mod_test;

/// Describes detector type.
///
#[derive(Debug, Serialize, Deserialize, Display, Clone, PartialEq, Eq, Hash)]
#[display(fmt = "{}")]
pub enum DetectorType {
    #[serde(rename = "Configured")]
    Unique(String)
}

/// Describes decoder type.
///
#[derive(Debug, Serialize, Deserialize, Display, Clone, PartialEq, Eq, Hash)]
#[display(fmt = "{}")]
pub enum DecoderType {
    #[display(fmt = "Plane")]
    #[serde(rename = "Plane")]
    Plane,
    #[display(fmt = "Base64")]
    #[serde(rename = "Nase64")]
    Base64,
    #[display(fmt = "JWT")]
    #[serde(rename = "JWT")]
    Jwt,
}

/// Result of the secret finding.
///
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Secret {
    pub detector_type: DetectorType,
    pub decoder_type: DecoderType,
    pub raw_result: String,
    pub branch: String,
    pub file: String,
    pub line: usize,
    pub author: Option<String>,
}

impl Display for Secret {
    #[inline(always)]
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "😱 Found secret:\nDetector Type [ {} ]\nDecoderType [ {} ]\nRawResult [ {} ]\nBranch [ {} ]\nFile [ {} ]\nLine [ {} ]\nAuthor [ {} ]\n",
            self.detector_type, self.decoder_type, self.raw_result,
            self.branch, self.file, self.line, self.author.clone().unwrap_or("unknown".to_string()),
        )
    }
}
