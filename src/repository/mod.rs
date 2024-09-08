pub mod errors;

use serde::{Deserialize, Serialize};
use std::time::Duration;
use errors::RepositoryError;
use reqwest::{blocking, Certificate, blocking::Client};

const TIMEOUT_SEC: u64 = 5;

/// This functionality returns bytes that are used to create a signature.
pub trait AsBytesToSigned {
    fn bytes_to_sign(&self) -> Vec<u8>;
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CreateAccountDto {
    #[serde(with = "serde_arrays")]
    pub signature: [u8;512],
    pub public_pem_key: String,
}

impl AsBytesToSigned for CreateAccountDto {
    #[inline(always)]
    fn bytes_to_sign(&self) -> Vec<u8> {
        self.public_pem_key.as_bytes().to_vec()
    }
}

/// AccountUpdateDto contains all information required to uopdate contributor.
///
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AccountUpdateDto {
    #[serde(with = "serde_arrays")]
    pub signature: [u8;512],
    pub old_hash: String,
    pub new_public_pem_key: String,
}

impl AsBytesToSigned for AccountUpdateDto {
    #[inline(always)]
    fn bytes_to_sign(&self) -> Vec<u8> {
        let old_hash_bytes = self.old_hash.as_bytes();
        let public_pem_key_bytes = self.new_public_pem_key.as_bytes();
        let mut bytes = Vec::with_capacity(
            old_hash_bytes.len() +
            public_pem_key_bytes.len()
        );
        bytes.extend(old_hash_bytes.iter());
        bytes.extend(public_pem_key_bytes.iter());

        bytes
    }
}

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

    #[inline(always)]
    pub fn create_account(&self, create_account: &CreateAccountDto) -> Result<(), RepositoryError> {
        let res = self.client.post(format!("{}/account/create", self.basic_url ))
            .json(create_account)
            .send()?;
        res.error_for_status()?;

        Ok(())
    }
}

#[cfg(test)]
pub mod tests;
