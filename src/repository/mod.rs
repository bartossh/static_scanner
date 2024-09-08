pub mod errors;

use std::time::Duration;
use errors::RepositoryError;
use reqwest::{blocking, Certificate, blocking::Client};

const TIMEOUT_SEC: u64 = 5;

/// Http2Agent serves secure connection to external API.
///
pub struct Http2Agent {
    basic_url: String,
    client: Client,
}

impl Http2Agent {
    /// Creates a new http2 agent.
    ///
    #[inline(always)]
    pub fn new(basic_url: String, cert: &[u8]) -> Result<Self, RepositoryError> {
        let cert = Certificate::from_pem(cert)?;
        Ok(Self { basic_url, client: blocking::ClientBuilder::new()
            .timeout(Duration::from_secs(TIMEOUT_SEC))
            .add_root_certificate(cert)
            .danger_accept_invalid_certs(true)
            .build()? })
    }

    /// Reads health of the remote repository API.
    ///
    #[inline(always)]
    pub fn get_healthz(&self) -> Result<(), RepositoryError > {
        let res = self.client.get(format!("{}/healthz", self.basic_url ))
            .send()?;
        res.error_for_status()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::read;

    #[test]
    fn it_should_make_a_succesfull_request() {
        let Ok(cert) = read("./certs/ca-cert.pem") else {
            assert!(false);
            return;
        };
        let Ok(agent) = Http2Agent::new("https://127.0.0.1:8080".to_string(), &cert) else {
            assert!(false);
            return;
        };

        match agent.get_healthz() {
            Ok(()) => assert!(true),
            Err(e) => {
                println!("{:?}", e);
                assert!(false);
            }
        };
    }
}
