use git2::{BranchType, Repository};
use std::path::PathBuf;
use std::{fs::remove_dir_all, env::temp_dir};
use std::io::{Result, Error, ErrorKind};
use random_string::generate;

#[cfg(test)]
pub mod mod_test;

const TEMP_DIR: &str = "static_scanner";
const CHARSET: &str = "abcdefghijklmnopqrstuwxyz_";

pub struct GitRepo {
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
            repo: Some(repo)
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
            return Err(Error::new(ErrorKind::ConnectionAborted, "Repository is flushed or doesn't exist."));
        };
        let (object, _reference) = repo.revparse_ext(branch).expect(&format!("Branch {branch} not found"));
        repo.checkout_tree(&object, None).expect(&format!("Failed to checkout to branch {branch}"));

        Ok(())
    }

    #[inline(always)]
    pub fn flush(&mut self) -> Result<()> {
        let Some(path) = self.path() else {
            return Err(Error::new(ErrorKind::ConnectionAborted, "Repository is flushed or doesn't exist."));
        };
        remove_dir_all(&path)?;
        self.repo = None;
        Ok(())
    }

    fn get_branches(&self, bt: BranchType) -> Result<Vec<String>> {
        let Some(repo) = &self.repo else {
            return Err(Error::new(ErrorKind::ConnectionAborted, "Repository is flushed or doesn't exist."));
        };
        let mut branches_names = Vec::new();
        let branches = repo.branches(Some(bt)).expect("Repository cannot find any branches");
        for branch in branches {
            let (b, _) = branch.expect(&format!("Repository cannot access {:?} branch", bt));
            let name = b.name().expect(&format!("Repository cannot access {:?} branch", bt));
            let name = name.expect(&format!("Repository cannot access {:?} branch", bt));
            branches_names.push(name.to_string());
        }

        Ok(branches_names)
    }
}
