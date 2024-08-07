use git2::Repository;
use std::path::PathBuf;
use std::{fs::remove_dir_all, path::Path};
use std::str::{self, FromStr};
use std::io::{Result, Error, ErrorKind};

#[cfg(test)]
pub mod mod_test;

const TEMP_DIR: &str = "./tempdir";

pub struct GitRepo {
   repo: Option<Repository>,
}

impl GitRepo {
    #[inline(always)]
    pub fn remote(url: &str) -> Result<Self> {
        let repo = match Repository::clone(url, &Path::new(TEMP_DIR)) {
            Ok(repo) => Ok(repo),
            Err(e) => Err(Error::new(ErrorKind::ConnectionAborted, e.to_string())),
        }?;

        Ok(Self {
            repo: Some(repo),
        })
    }

    pub fn path(&self) -> Option<PathBuf> {
        let Ok(path_buf) = PathBuf::from_str(TEMP_DIR) else {
          return None;
        };
        Some(path_buf)
    }

    #[inline(always)]
    pub fn flush(&mut self) -> Result<()> {
        remove_dir_all(&Path::new(TEMP_DIR))?;
        self.repo = None;
        Ok(())
    }
}
