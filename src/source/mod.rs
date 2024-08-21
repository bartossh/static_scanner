pub mod git_source;
pub mod errors;

use std::path::PathBuf;

use walkdir::WalkDir;
use crate::source::errors::SourceError;
use crate::source::git_source::GitRepo;

/// Provides source functionality like:
///  - path buffer of root directory,
///  - WalkDir,
///  - flushing the source,
///
pub trait SourceProvider {
    fn path_buf(&self) -> Option<PathBuf>;
    fn flush(&mut self) -> Result<(), SourceError>;
    fn walk_dir(&self) -> Option<WalkDir>;
    fn get_local_branches(&self) -> Result<Vec<String>, SourceError>;
    fn get_remote_branches(&self) -> Result<Vec<String>, SourceError>;
    fn switch_branch(&self, branch: &str) -> Result<(), SourceError>;
}

pub enum Source {
    FileSystem(PathBuf),
    Remote(GitRepo),
    Local(GitRepo),
}

impl Source {
    #[inline(always)]
    pub fn new_git(path: Option<&PathBuf>, url: Option<&String>) -> Result<Self, SourceError> {
        match url {
            Some(url) => {
                Ok(Source::Remote(GitRepo::remote(url)?))
            },
            None => {
                match path {
                    Some(path) => Ok(Source::Local(GitRepo::local(path)?)),
                    None => Err(SourceError::ParameterFailure("path is not specified".to_string())),
                }
            },
        }
    }

    #[inline(always)]
    pub fn new_filesystem(path: Option<&PathBuf>) -> Result<Self, SourceError> {
        match path {
            Some(path) => Ok(Source::FileSystem(path.clone())),
            None => Err(SourceError::ParameterFailure("path is not specified".to_string())),
        }
    }
}

impl SourceProvider for Source {
    #[inline(always)]
    fn path_buf(&self) -> Option<PathBuf> {
        match self {
            Self::FileSystem(l) => Some(l.to_owned()),
            Self::Remote(gr) => gr.path(),
            Self::Local(gr) => gr.path(),
        }
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<(), SourceError> {
        match self {
            Self::FileSystem(_) => Ok(()),
            Self::Remote(gr) => gr.flush(),
            Self::Local(_) => Ok(()),
        }
    }

    #[inline(always)]
    fn walk_dir(&self) -> Option<WalkDir> {
        Some(WalkDir::new(self.path_buf()?))
    }

    #[inline(always)]
    fn get_local_branches(&self) -> Result<Vec<String>, SourceError> {
        match self {
            Self::FileSystem(_) => Err(SourceError::ParameterFailure("No access to branches on filesystem".to_string())),
            Self::Remote(gr) => gr.get_local_branches(),
            Self::Local(gr) => gr.get_local_branches(),
        }
    }

    #[inline(always)]
    fn get_remote_branches(&self) -> Result<Vec<String>, SourceError> {
        match self {
            Self::FileSystem(_) => Err(SourceError::ParameterFailure("No access to branches on filesystem".to_string())),
            Self::Remote(gr) => gr.get_remote_branches(),
            Self::Local(gr) => gr.get_remote_branches(),
        }
    }

    #[inline(always)]
    fn switch_branch(&self, branch: &str) -> Result<(), SourceError> {
        match self {
            Self::FileSystem(_) => Err(SourceError::ParameterFailure("No access to branches on filesystem".to_string())),
            Self::Remote(gr) => gr.switch_branch(branch),
            Self::Local(gr) => gr.switch_branch(branch),
        }
    }
}

/// Branch level specifies the level at which Git repo is scanned.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchLevel {
    Local,
    Remote,
    All,
    Head,
}

// Source describes source of the data.
//
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataSource {
    FileSystem,
    Git,
}
