mod tests {
    use crate::source;
    use git2::Repository;

    const TEST_URL: &str = "https://github.com/OpenSourceScannerCollective/expired-creds.git";
    #[test]
    fn it_should_fetch_repo() {
        let Ok(mut repo) = source::GitRepo::remote(TEST_URL) else {
            assert!(false);
            return;
        };

        let Ok(_) = repo.flush() else {
            assert!(false);
            return;
        };
    }
}
