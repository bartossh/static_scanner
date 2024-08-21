mod tests {
    use crate::source::git_source::GitRepo;

    const TEST_URL: &str = "https://github.com/OpenSourceScannerCollective/expired-creds.git";
    #[test]
    fn it_should_fetch_repo() {
        let Ok(mut repo) = GitRepo::remote(TEST_URL) else {
            assert!(false);
            return;
        };

        let Ok(_) = repo.flush() else {
            assert!(false);
            return;
        };
    }

    #[test]
    fn it_should_list_local_branches() {
        let Ok(mut repo) = GitRepo::remote(TEST_URL) else {
            assert!(false);
            return;
        };

        let Ok(branches) = repo.get_local_branches() else {
            assert!(false);
            return;
        };

        assert!(branches.len() > 0);

        let Ok(_) = repo.flush() else {
            assert!(false);
            return;
        };
    }

    #[test]
    fn it_should_list_remote_branches() {
        let Ok(mut repo) = GitRepo::remote(TEST_URL) else {
            assert!(false);
            return;
        };

        let Ok(branches) = repo.get_remote_branches() else {
            assert!(false);
            return;
        };

        assert!(branches.len() > 0);

        let Ok(_) = repo.flush() else {
            assert!(false);
            return;
        };
    }

    #[test]
    fn it_should_switch_between_branches() {
        let Ok(mut repo) = GitRepo::remote(TEST_URL) else {
            assert!(false);
            return;
        };

        let Ok(branches) = repo.get_remote_branches() else {
            assert!(false);
            return;
        };

        for b in branches.iter() {
            let Ok(_) = repo.switch_branch(&b) else {
                assert!(false);
                return;
            };
        }

        let Ok(_) = repo.flush() else {
            assert!(false);
            return;
        };
    }
}
