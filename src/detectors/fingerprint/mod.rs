// This is prototype detector based on https://documents.trendmicro.com/assets/wp/wp-locality-sensitive-hash.pdf and fingerprinting.
// This may produce unexpected results.
// To get better results it is required to create larger population of fingerprints from redimed secrets.

use std::collections::HashMap;
use std::usize;

use super::Scanner;
use super::errors::DetectorError;
use crossbeam_channel::Sender;
use serde::{Deserialize, Serialize};
use meansd::MeanSD;
use crate::result::{DecoderType, DetectorType};
use crate::{reporter::Input, result::Secret};
use crate::lines::LinesEndsProvider;
use tlsh::{Tlsh, Version, BucketKind, ChecksumKind, TlshBuilder};

const MIN_BYTES_LEN: usize = 50;

#[inline(always)]
fn new_tlsh_hash<'a>(s: &'a str) -> Result<Tlsh, DetectorError>  {
    let mut builder = TlshBuilder::new(
       BucketKind::Bucket128,
       ChecksumKind::OneByte,
       Version::Version4,
    );
    let buf = s.as_bytes();
    if buf.len() < MIN_BYTES_LEN {
        return Err(DetectorError::FingerprintBuilderFailure(format!("expected min {} bytes, got {}", MIN_BYTES_LEN, buf.len())));
    }
    builder.update(&buf);
    match builder.build() {
        Ok(h) => Ok(h),
        Err(e) => Err(DetectorError::FingerprintBuilderFailure(e.to_string())),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretSuspectsData {
    pub name: String,
    pub secrets_for_fingerprint: Vec<String>,
    pub include_length_diff: bool,
}

#[derive(Debug)]
struct Evidence {
    name: String,
    fingerprints: Vec<Tlsh>,
    distance_mean: usize,
    distance_stdev: usize,
    size_mean: usize,
    size_stdev: usize,
    include_length_diff: bool,
}

/// Lab offers TLSH fingerprint comparsion for secrets similarity detection.
///
#[derive(Debug)]
pub struct Lab {
    evidences: Vec<Evidence>,
}

impl Lab {
    #[inline(always)]
    pub fn from_suspects(suspects: &[SecretSuspectsData]) -> Result<Self, DetectorError> {
        if suspects.len() == 0 {
            return Err(
                DetectorError::FingerprintBuilderFailure(
                    format!(
                        "shall contain at least one suspect, got {}",
                        suspects.len()
                    )
                ));
        }
        let mut evidences: Vec<Evidence> = Vec::with_capacity(suspects.len());
        for suspect in suspects.iter() {
            if suspect.secrets_for_fingerprint.len() == 0 {
                return Err(
                    DetectorError::FingerprintBuilderFailure(
                        format!(
                            "shall contain at least one secret for fingerprinting, got {}",
                            suspect.secrets_for_fingerprint.len()
                        )
                    ));
            }
            let mut size = MeanSD::default();

            let mut fingerprints: Vec<Tlsh> = Vec::with_capacity(suspect.secrets_for_fingerprint.len());
            for fingerprint_candidate in suspect.secrets_for_fingerprint.iter() {
                size.update(fingerprint_candidate.len() as f64);
                let tlsh = new_tlsh_hash(fingerprint_candidate)?;
                fingerprints.push(tlsh);
            }

            let mut dist = MeanSD::default();
            let mut position: usize = 1;
            for fingerprint_candidate in fingerprints.iter() {
                for fingerprint_compare in fingerprints[position..].iter() {
                    let distance = fingerprint_candidate.diff(fingerprint_compare, suspect.include_length_diff);
                    dist.update(distance as f64);
                }
                position+=1;
                if position == fingerprints.len() {
                    break;
                }
            }


            evidences.push(Evidence {
                name: suspect.name.clone(),
                fingerprints,
                distance_mean: dist.mean() as usize,
                distance_stdev: dist.pstdev() as usize,
                size_mean: size.mean() as usize,
                size_stdev: size.pstdev() as usize,
                include_length_diff: suspect.include_length_diff,
            })
        }

        Ok(Self{ evidences })
    }
}

impl Scanner for Lab {
    #[inline(always)]
    fn scan(
        &self,
        lines_ends: &impl LinesEndsProvider,
        s: &str,
        file: &str,
        branch: &str,
        sx:
        crossbeam_channel::Sender<Option<Input>>
    ) {
        let mut detector = Detection::new(lines_ends, self, &s, file, branch, sx);
        detector.detect();
    }
}

#[derive(Debug)]
struct Detection<'a, L: LinesEndsProvider> {
    s: &'a str,
    file: &'a str,
    branch: &'a str,
    scanner: &'a Lab,
    line_ends: &'a L,
    sx: Sender<Option<Input>>,
}
impl<'a, L> Detection<'a, L>
where
    L: LinesEndsProvider,
{
    #[inline(always)]
    fn new(line_ends: &'a L, scanner: &'a Lab, s: &'a str, file: &'a str, branch: &'a str, sx: Sender<Option<Input>>) -> Self {
        Self {s, file, branch, scanner, line_ends, sx}
    }

    #[inline(always)]
    fn detect(&'a mut self) {
        for evidance in self.scanner.evidences.iter() {
            let mut start: usize = 0;
            let mut finish: usize = evidance.size_mean + evidance.size_stdev;
            finish = if finish > self.s.len() { self.s.len() } else { finish };

            let mut unique_secrets: HashMap<String, usize> = HashMap::new();
            'slicer: while finish <= self.s.len() {
                let s = &self.s[start..finish];
                let Ok(tlsh) = new_tlsh_hash(s) else {
                    return;
                };
                let max_dist = evidance.distance_mean + evidance.distance_stdev;
                for fingerprint in evidance.fingerprints.iter() {
                    let distance = fingerprint.diff(&tlsh, evidance.include_length_diff);
                    if distance <  max_dist {
                        if let  Some(_) = unique_secrets.insert(s.to_string(), start) {
                            start += 1;
                            finish += start;
                            continue 'slicer;
                        };
                    }
                }
                start += 1;
                finish += start;
            }
            for (finding, start) in unique_secrets {
                let _ = self.sx.send(Some(Input::Finding(Secret {
                    detector_type: DetectorType::Unique(evidance.name.to_string()),
                    decoder_type: DecoderType::Plane,
                    raw_result: finding,
                    branch: self.branch.to_string(),
                    file: self.file.to_string(),
                    line: self.line_ends.get_line(start).unwrap_or_default(),
                    author: None,
                })));
            }
        }
    }
}

#[cfg(test)]
mod tests;
