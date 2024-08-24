pub mod errors;

use std::{collections::HashSet, path::PathBuf, sync::Arc};
use crossbeam_channel::{unbounded, Sender, Receiver};
use std::{fs::{read, read_to_string, File},  io::prelude::*};
use rayon::iter::ParallelBridge;
use rayon::prelude::ParallelIterator;
use std::thread::spawn;
use errors::ExecutorError;
use crate::{
    inspect::Inspector,
    reporter::Input,
    source::{
        BranchLevel, DataSource, DirectoryProvider, RepositoryProvider, Source,
    },
};
use zip::ZipArchive;
use tar::Archive;

const GUESS_OMIT_SIZE: usize = 64;
const FILE_SYSTEM: &str = "------ FILE SYSTEM ------";

struct DataWithInfo {
    data: String,
    file_name: String,
}

/// Config contains full configuration of Executor to run.
///
#[derive(Debug, Clone)]
pub struct Config<'a> {
    pub data_source: DataSource,
    pub path: Option<&'a PathBuf>,
    pub url: Option<&'a String>,
    pub config: Option<&'a PathBuf>,
    pub omit: Option<&'a String>,
    pub nodeps: Option<String>,
    pub branch_level: BranchLevel,
    pub branches: &'a Option<Vec<String>>,
    pub sx_input: Sender<Option<Input>>,
    pub decompress: bool,
    pub scan_binary: bool,
}

/// Executes the scanners with given setup.
///
pub struct Executor {
    source: Source,
    omit: Vec<String>,
    inspector: Arc<Inspector>,
    branch_level: BranchLevel,
    branches: Option<HashSet<String>>,
    sx_input: Sender<Option<Input>>,
    decompress: bool,
    scan_binary: bool,
}

impl Executor {
    #[inline(always)]
    pub fn new(
        cfg: &Config,
    ) -> Result<Self, ExecutorError> {
        let mut source = match cfg.data_source {
            DataSource::Git => Source::new_git(cfg.path, cfg.url)?,
            DataSource::FileSystem => Source::new_filesystem_local(cfg.path)?,
        };

        let config_path = match cfg.config {
            Some(c) => Ok(c),
            None => {
                let _ = source.flush()?;
                Err(ExecutorError::WrongParameterFailure("Config path is not specified.".to_string()))
            },
        }?;

        let mut omit_patterns: Vec<String> = Vec::with_capacity(GUESS_OMIT_SIZE);
        if let Some(patterns) = &cfg.omit {
            for pattern in patterns.split(" ") {
                omit_patterns.push(pattern.to_string())
            }
        }
        if let Some(patterns) = &cfg.nodeps {
            for pattern in patterns.split(" ") {
                omit_patterns.push(pattern.to_string())
            }
        }

        let inspector = Arc::new(Inspector::try_new(
            config_path.to_str().unwrap_or_default(),
            cfg.sx_input.clone(),
        )?);

        Ok(Self {
            source,
            omit: omit_patterns,
            inspector,
            branch_level: cfg.branch_level,
            branches: if let Some(branches) = cfg.branches { Some(branches.into_iter().map(|v| v.to_owned()).collect::<HashSet<String>>()) } else { None },
            sx_input: cfg.sx_input.clone(),
            decompress: cfg.decompress,
            scan_binary: cfg.scan_binary,
        })
    }

    #[inline(always)]
    pub fn execute(&mut self) -> Result<(), ExecutorError>{
        let mut branches_to_scan = Vec::new();
        match &self.branch_level {
           BranchLevel::Head => branches_to_scan.push(FILE_SYSTEM.to_string()),
           BranchLevel::All => {
               branches_to_scan.extend(self.source.get_local_branches().unwrap_or(Vec::new()));
               branches_to_scan.extend(self.source.get_remote_branches().unwrap_or(Vec::new()));
           },
           BranchLevel::Local => {
               branches_to_scan.extend(self.source.get_local_branches().unwrap_or(Vec::new()));
           },
           BranchLevel::Remote => {
               branches_to_scan.extend(self.source.get_remote_branches().unwrap_or(Vec::new()));
           },
        };

        for branch in branches_to_scan.iter() {
            let (sx_data, rx_data): (Sender<Option<DataWithInfo>>, Receiver<Option<DataWithInfo>>) = unbounded();
            if branch == FILE_SYSTEM {
                self.walk_dir(sx_data)?;
                self.process(rx_data, &branch);
                break;
            }
            if let Some(branches) = &self.branches {
                if !branches.contains(branch) {
                    continue;
                }
            }
            match self.source.switch_branch(branch) {
                Ok(()) => (),
                Err(_) => {
                    continue;
                },
            };
            let branch = branch.to_string().clone();
            self.walk_dir(sx_data)?;
            self.process(rx_data, &branch);
        }

        let _ = self.sx_input.send(None);
        let _ = self.source.flush();

        Ok(())
    }

    #[inline(always)]
    fn walk_dir(&self, sx: Sender<Option<DataWithInfo>>) -> Result<(), ExecutorError>{
        let Some(walk_dir) = self.source.walk_dir() else {
            let _ = self.sx_input.send(None);
            return Err(ExecutorError::Unexpected("unable to walk directory".to_string()));
        };

        let omit = self.omit.clone();
        let decompress = self.decompress;
        let read_binary = self.scan_binary;

        spawn( move || {
            'walker: for entry in walk_dir {
                let Ok(entry) = entry else {
                    continue 'walker;
                };
                if let Some(dir_name) = entry.path().to_str() {
                    for pattern in omit.iter() {
                        if dir_name.contains(pattern) {
                            continue 'walker;
                        }
                    }
                }
                if entry.file_type().is_dir() {
                    continue 'walker;
                }

                let entry = entry.into_path();
                let _ = extract_utf8_and_send(&sx, &entry, decompress, read_binary); // TODO: Introduce error channel.
            }
            let _ = sx.send(None);
        });

        Ok(())
    }

    #[inline(always)]
    fn process(&mut self, rx: Receiver<Option<DataWithInfo>>, branch: &str) {
        rx.into_iter().par_bridge().for_each( |input| {
            let Some(input) = input else {
                return;
            };
            let inspector = self.inspector.clone();
            let sx_input = self.sx_input.clone();
            let branch = branch.to_string().clone();
            let _ = sx_input.send(Some(Input::Bytes(input.data.as_bytes().len())));
            inspector.inspect(&input.data, &input.file_name, &branch);
        });
    }
}

#[inline(always)]
fn extract_utf8_and_send(sx: &Sender<Option<DataWithInfo>>, path: &PathBuf, decompress: bool, scan_binary: bool) -> Result<(), ExecutorError> {
    let file_name = path.as_path().to_str().unwrap_or_default().to_string();
    if decompress {
        return match &file_name[file_name.len()-3..file_name.len()] {
            "tar" | ".gz" => decomopress_tar_archive_and_send(sx, path, file_name),
            "zip" | "jar" | "bz2" => decomopress_zip_archive_and_send(sx, path, file_name),
            "zst" | "rar" | "iso" | ".rz" | ".7z" | "s7z" | "aar" | "apk" => Ok(()),
            _ => read_and_send(sx, path, file_name, scan_binary),
        }
    }
    read_and_send(sx, path, file_name, scan_binary)
}

#[inline(always)]
fn read_and_send(sx: &Sender<Option<DataWithInfo>>, path: &PathBuf, file_name: String, scan_binary: bool) -> Result<(), ExecutorError> {
    match scan_binary {
        true => read_binaryfile_and_send_to_channel(sx, path, file_name),
        false => read_textfile_and_send_to_channel(sx, path, file_name),
    }
}

#[inline(always)]
fn read_textfile_and_send_to_channel(sx: &Sender<Option<DataWithInfo>>, path: &PathBuf, file_name: String) -> Result<(), ExecutorError> {
    let data = read_to_string(path)?;
    let _ = sx.send(Some(DataWithInfo{data , file_name}));

    Ok(())
}

#[inline(always)]
fn read_binaryfile_and_send_to_channel(sx: &Sender<Option<DataWithInfo>>, path: &PathBuf, file_name: String) -> Result<(), ExecutorError> {
    let bytes = read(&path)?;
    let data = String::from_utf8_lossy(&bytes).to_string();
    let _ = sx.send(Some(DataWithInfo{data , file_name}));

    Ok(())
}

#[inline(always)]
fn decomopress_zip_archive_and_send(sx: &Sender<Option<DataWithInfo>>, path: &PathBuf, file_name: String) -> Result<(), ExecutorError> {
    let file = File::open(path)?;
    let mut zip = ZipArchive::new(&file)?;

    for i in 0..zip.len() {
        let mut data = String::new();
        let mut file = zip.by_index(i)?;
        let file_name = format!("{}/{}", file_name, file.name());
        let Ok(_) = file.read_to_string(&mut data) else {
            continue;
        };
        let _ = sx.send(Some(DataWithInfo{data, file_name}));
    }

    Ok(())
}

#[inline(always)]
fn decomopress_tar_archive_and_send(sx: &Sender<Option<DataWithInfo>>, path: &PathBuf, file_name: String) -> Result<(), ExecutorError> {
    let file = File::open(path)?;
    let mut t = Archive::new(&file);

    for file in t.entries()? {
        let mut file = file?;
        let mut data = String::new();
        let file_name = format!("{}/{}", file_name, file.path().unwrap_or_default().to_str().unwrap_or_default());
        let Ok(_) = file.read_to_string(&mut data) else {
            continue;
        };
        let _ = sx.send(Some(DataWithInfo{data, file_name}));
    }

    Ok(())
}
