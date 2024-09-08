pub mod errors;
pub mod dtos;

use dtos::{
    ContributorCreateDto,
    RegexConfigurationCreateDto,
    RegexConfigurationDataDto,
    RegexConfigurationDeleteDto,
    RegexConfigurationPagginateQueryDto,
};
use serde::Serialize;
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
        let res = self.client.get(format!("{}/healthz", &self.basic_url))
            .send()?;
        res.error_for_status()?;

        Ok(())
    }

    #[inline(always)]
    pub fn create_account(&self, create_account: &ContributorCreateDto) -> Result<(), RepositoryError> {
        self.post_no_result("/account/create", create_account)
    }

    #[inline(always)]
    pub fn create_regex_config(&self, create_regex: &RegexConfigurationCreateDto) -> Result<(), RepositoryError> {
        self.post_no_result("/config/create", create_regex)
    }

    #[inline(always)]
    pub fn delete_regex_config_unverified(&self, delete_regex: &RegexConfigurationDeleteDto) -> Result<(), RepositoryError> {
        self.post_no_result("/config/delete", delete_regex)
    }


    pub fn config_pagginate(
        &self,
        config_pagginate: &RegexConfigurationPagginateQueryDto,
    ) -> Result<Vec<RegexConfigurationDataDto>, RepositoryError> {
        let res = self.client.post(format!("{}/config/pagginate", &self.basic_url))
            .json(config_pagginate)
            .send()?;

        Ok(res.json::<Vec<RegexConfigurationDataDto>>()?)
    }

    #[inline(always)]
    fn post_no_result<T>(&self, path: &str, data: &T) -> Result<(), RepositoryError>
    where T: Serialize + ?Sized,
    {
        let res = self.client.post(format!("{}{}", &self.basic_url, path))
            .json(data)
            .send()?;
        res.error_for_status()?;

        Ok(())
    }
}
