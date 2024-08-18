use git2::{BranchType, Repository, build::CheckoutBuilder};
use std::path::PathBuf;
use std::{fs::remove_dir_all, env::temp_dir};
use std::io::{Result, Error, ErrorKind};
use random_string::generate;

#[cfg(test)]
pub mod mod_test;

const TEMP_DIR: &str = "static_scanner";
const CHARSET: &str = "abcdefghijklmnopqrstuwxyz_";

pub struct GitRepo {
    is_local: bool, // It is immportant to be set to true for local repo so it is not be flushed.
    repo: Option<Repository>,
}

impl GitRepo {
    #[inline(always)]
    pub fn remote(url: &str) -> Result<Self> {
        let mut dir :PathBuf = PathBuf::from(temp_dir().as_path());
        dir.push(format!("{}/{}", TEMP_DIR, generate(12, CHARSET)));

        let repo = match Repository::clone(url, dir.clone()) {
            Ok(repo) => Ok(repo),
            Err(e) => Err(Error::new(ErrorKind::ConnectionAborted, e.to_string())),
        }?;

        Ok(Self {
            is_local: false,
            repo: Some(repo),
        })
    }

    #[inline(always)]
    pub fn local(path: &PathBuf) -> Result<Self> {
        let repo = match Repository::discover(path) {
            Ok(repo) => Ok(repo),
            Err(e) => Err(Error::new(ErrorKind::ConnectionAborted, e.to_string())),
        }?;

        Ok(Self {
            is_local: true,
            repo: Some(repo),
        })
    }

    #[inline(always)]
    pub fn path(&self) -> Option<PathBuf> {
        let Some(repo) = &self.repo else {
            return None;
        };
        let Some(p) = repo.workdir() else {
            return None;
        };

        Some(PathBuf::from(p))
    }

    #[inline(always)]
    pub fn get_local_branches(&self) -> Result<Vec<String>> {
        self.get_branches(BranchType::Local)
    }

    #[inline(always)]
    pub fn get_remote_branches(&self) -> Result<Vec<String>> {
        self.get_branches(BranchType::Remote)
    }

    #[inline(always)]
    pub fn switch_branch(&self, branch: &str) -> Result<()> {
        let Some(repo) = &self.repo else {
            return Err(Error::new(ErrorKind::Interrupted, "Repository is flushed or doesn't exist."));
        };
        let (object, _reference) = match repo.revparse_ext(branch) {
            Ok(a) => Ok(a),
            Err(e) => Err(Error::new(ErrorKind::Interrupted, format!("Failed to checkout to branch {branch} {e}"))),
        }?;

        match repo.checkout_tree(&object, Some(CheckoutBuilder::new().force())) {
            Ok(()) => Ok(()),
            Err(e) => Err(Error::new(ErrorKind::Interrupted, format!("Failed to checkout to branch {branch} {e}"))),
        }
    }

    #[inline(always)]
    pub fn flush(&mut self) -> Result<()> {
        if self.is_local {
            return Ok(());
        }
        let Some(path) = self.path() else {
            return Err(Error::new(ErrorKind::ConnectionAborted, "Repository is flushed or doesn't exist."));
        };
        remove_dir_all(&path)?;
        self.repo = None;
        Ok(())
    }

    #[inline(always)]
    fn get_branches(&self, bt: BranchType) -> Result<Vec<String>> {
        let Some(repo) = &self.repo else {
            return Err(Error::new(ErrorKind::Interrupted, "Repository is flushed or doesn't exist."));
        };
        let mut branches_names = Vec::new();
        let branches = match repo.branches(Some(bt)) {
            Ok(b) => Ok(b),
            Err(e) => Err(Error::new(ErrorKind::Interrupted, format!("Failed to get branches for {:?} {e}", bt))),
        }?;
        for branch in branches {
            let (b, _) = match branch {
                Ok(b) => Ok(b),
                Err(e) => Err(Error::new(ErrorKind::Interrupted, format!("Repository cannot access {:?} branch {e}", bt))),
            }?;
            let name = match b.name() {
                Ok(b) => Ok(b),
                Err(e) => Err(Error::new(ErrorKind::Interrupted, format!("Repository cannot access {:?} branch {e}", bt))),
            }?;

            let name = match name {
                Some(n) => Ok(n),
                None => Err(Error::new(ErrorKind::Interrupted, format!("Repository cannot access {:?} branch", bt))),
            }?;

            branches_names.push(name.to_string());
        }

        Ok(branches_names)
    }
}
