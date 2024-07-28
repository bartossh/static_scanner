use super::detectors::{Fingerprint, Json, Presenter, Scanner, Schema};
use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::path::Path;
use std::{
    collections::HashMap,
    fmt::{Display, Formatter, Result as FmtResult},
};
use tokenizers::tokenizer::pre_tokenizer::PreTokenizedString;

const EQUALS_PATTERNS: [&str; 5] = [":", "=", "=>", "->", "=="];
const DELETE_PATTERNS: [&str; 7] = ["[", "]", "{", "}", "'", "'", "\""];

/// Marks the secret to be unique.
///
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash, Clone)]
pub struct Mark {
    pub key: String,
    pub start_index: usize,
    pub end_index: usize,
}

impl Display for Mark {
    #[inline(always)]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "{}: [ {} to {} ]",
            self.key, self.start_index, self.end_index
        )
    }
}

impl Mark {
    pub fn new(key: &str, si: usize, ei: usize) -> Self {
        Self {
            key: key.to_string(),
            start_index: si,
            end_index: ei,
        }
    }
}

/// Evidence holds data proving the secret leakage.
///
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    secret_name: String,
    values: HashMap<Mark, String>,
}

impl Display for Evidence {
    #[inline(always)]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let mut secrets = "".to_string();
        for (k, v) in self.values.iter() {
            secrets.push_str(&format!("  {}: {}\n", k, v));
        }
        write!(f, "[ {} ]\n{}", self.secret_name, secrets)
    }
}

impl Evidence {
    pub fn new(name: &str, values: HashMap<Mark, String>) -> Self {
        Self {
            secret_name: name.to_string(),
            values,
        }
    }

    /// Get the clone of the secret key.
    ///
    #[inline(always)]
    pub fn get_secret(&self, k: &Mark) -> Option<String> {
        let Some(v) = self.values.get(k) else {
            return None;
        };

        Some(v.to_owned())
    }

    /// Get the clone of the secrets HashMap.
    ///
    #[inline(always)]
    pub fn get_secrets(&self) -> HashMap<Mark, String> {
        self.values.clone()
    }
}

/// Detects secrets in string.
///
pub trait Detector {
    fn detect(&self, tokens: &str) -> Vec<Evidence>;
}

/// Offers Fingerprints inspection.
/// Looks for all matching fingerprints to provide evidences of leaked secrets.
///
#[derive(Debug)]
pub struct Inspector {
    jsons: Vec<Json>,
    fingerprints: Vec<Fingerprint>,
}

impl Inspector {
    /// Ties to create a new Inspector from the path to a yaml file.
    ///
    pub fn try_new(path_to_config_yaml: &str) -> IoResult<Self> {
        let path = Path::new(path_to_config_yaml);
        let mut jsons = Vec::new();
        let mut fingerprints = Vec::new();
        for schema in Schema::read_from_yaml_file(path)?.iter() {
            let json_result: Result<Json, _> = schema.try_into();
            let Ok(json_scanner) = json_result else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "cannot crate json scanner",
                ));
            };
            jsons.push(json_scanner);

            let fingerprint_result: Result<Fingerprint, _> = schema.try_into();
            let Ok(fingerprint_scanner) = fingerprint_result else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "cannot crate fingerprint scanner",
                ));
            };
            fingerprints.push(fingerprint_scanner);
        }
        Ok(Self {
            jsons,
            fingerprints,
        })
    }

    /// Scans string of suspected crime comparing with internal prove of fingerprints.
    /// Returns vector of all found evidences of crimes of leaked secrets.
    ///
    pub fn scan(&self, suspected_crime: &str) -> Vec<Evidence> {
        let mut evidences: Vec<Evidence> = Vec::with_capacity(self.fingerprints.len() * 10); // naive memory preallocation
                                                                                             //let mut unique_secert_type = HashSet::with_capacity(self.jsons.len());
                                                                                             //for json_scanner in self.jsons.iter() {
                                                                                             //    if let Some(evidence) = json_scanner.scan(&suspected_crime) {
                                                                                             //        unique_secert_type.insert(json_scanner.name());
                                                                                             //        evidences.push(evidence);
                                                                                             //    }
                                                                                             //}
                                                                                             //'fingerprint_loop: for fingerprint_scanner in self.fingerprints.iter() {
                                                                                             //    if unique_secert_type.contains(&fingerprint_scanner.name()) {
                                                                                             //        continue 'fingerprint_loop;
                                                                                             //    }
                                                                                             //    if let Some(evidence) = fingerprint_scanner.scan(&suspected_crime) {
                                                                                             //        evidences.push(evidence);
                                                                                             //    }
                                                                                             //}
        evidences
    }
}
