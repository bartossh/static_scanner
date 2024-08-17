use crate::detectors::regex::{Schema, Scanner, Pattern};
use crossbeam_channel::Sender;
use crate::lines::LinesEnds;
use crate::reporter::Input;
use std::io::Result as IoResult;
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

#[derive(Debug)]
pub struct Inspector {
    scanners: Vec<ScannerWrapper>,
    sx: Sender<Option<Input>>
}

impl Inspector {
    #[inline(always)]
    pub fn try_new(path_to_config_yaml: &str, rx: Sender<Option<Input>>) -> IoResult<Self> {
        let path = Path::new(path_to_config_yaml);
        let mut scanners: Vec<ScannerWrapper> = Vec::new();
        for schema in Schema::read_from_yaml_file(path)?.iter() {
            let s: ScannerWrapper = ScannerWrapper::Regex(schema.try_into()?);
            scanners.push(s);
        }
        Ok(Self {
            scanners,
            sx: rx,
        })
    }
}

impl Inspector {
    #[inline(always)]
    pub fn inspect(&self, s: &str, file: &str, branch: &str) {
        let line_ends = LinesEnds::from_str(s);
        for scanner in self.scanners.iter() {
            scanner.scan(&line_ends, s, file, branch, self.sx.clone());
        }
    }
}
