pub mod errors;

use crate::detectors::{Scanner, regex::{Schema, Pattern}};
use crossbeam_channel::Sender;
use errors::InspectorError;
use crate::lines::LinesEnds;
use crate::reporter::Input;
use std::path::Path;

#[derive(Debug)]
enum ScannerWrapper {
    Regex(Pattern),
}

impl Scanner for ScannerWrapper {
    #[inline(always)]
    fn scan(&self, lines_ends: &impl crate::lines::LinesEndsProvider, s: &str, file: &str, branch: &str, sx: Sender<Option<Input>>) {
        match self {
            Self::Regex(scan) => scan.scan(lines_ends, s, file, branch, sx),
        }
    }
}

/// Inspector holds collection of detectors to be use for scanning.
/// Performs pre-processing of the given input before sending it to scanners.
///
#[derive(Debug)]
pub struct Inspector {
    scanners: Vec<ScannerWrapper>,
    sx: Sender<Option<Input>>
}

impl Inspector {
    #[inline(always)]
    pub fn try_new(path_to_config_yaml: &str, sx: Sender<Option<Input>>) -> Result<Self, InspectorError> {
        let path = Path::new(path_to_config_yaml);
        let mut scanners: Vec<ScannerWrapper> = Vec::new();
        for schema in Schema::read_from_yaml_file(path)?.iter() {
            let s: ScannerWrapper = ScannerWrapper::Regex(schema.try_into()?);
            scanners.push(s);
        }
        let _ = sx.send(Some(Input::Detectors(scanners.len())));
        Ok(Self {
            scanners,
            sx,
        })
    }

    #[inline(always)]
    pub fn inspect(&self, s: &str, file: &str, branch: &str) {
        // pre-process phase
        let line_ends = LinesEnds::from_str(s);

        // scan phase
        for scanner in self.scanners.iter() {
            scanner.scan(&line_ends, s, file, branch, self.sx.clone());
        }
    }
}
