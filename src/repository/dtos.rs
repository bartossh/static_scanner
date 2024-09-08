use std::time::SystemTime;
use serde::{Deserialize, Serialize};
use super::errors::RepositoryError;

/// This functionality returns bytes that are used to create a signature.
pub trait AsBytesToSigned {
    fn bytes_to_sign(&self) -> Vec<u8>;
}

/// ContributorCreateDto contains all information required to create contributor.
///
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ContributorCreateDto {
    #[serde(with = "serde_arrays")]
    pub signature: [u8;512],
    pub public_pem_key: String,
}

impl AsBytesToSigned for ContributorCreateDto {
    #[inline(always)]
    fn bytes_to_sign(&self) -> Vec<u8> {
        self.public_pem_key.as_bytes().to_vec()
    }
}

/// Group represents group that regex config belogns to.
///
#[derive(Debug, PartialEq, Serialize, Deserialize, Eq, Clone)]
pub enum Group {
    Common,
    Http,
    Ssl,
    Jwt,
    Credentials,
    Database,
    Key,
    Cookie,
    Seed,
    Hash,
}

impl TryFrom<&str> for Group {
    type Error = RepositoryError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "common" => Ok(Self::Common),
            "http" => Ok(Self::Http),
            "ssl" => Ok(Self::Ssl),
            "jwt" => Ok(Self::Jwt),
            "credentials" => Ok(Self::Credentials),
            "database" => Ok(Self::Database),
            "key" => Ok(Self::Key),
            "cookie" => Ok(Self::Cookie),
            "seed" => Ok(Self::Seed),
            "hash" => Ok(Self::Hash),
            _ => Err(RepositoryError::WithMessage("unrecognized group variant".to_string())),
        }
    }
}

impl AsBytesToSigned for Group {
    #[inline(always)]
    fn bytes_to_sign(&self) -> Vec<u8> {
        let n: u32 = match self {
            Self::Common => 0,
            Self::Http => 1,
            Self::Ssl => 2,
            Self::Jwt => 3,
            Self::Credentials => 4,
            Self::Database => 5,
            Self::Key => 6,
            Self::Cookie => 7,
            Self::Seed => 8,
            Self::Hash => 9
        };
        n.to_ne_bytes().to_vec()
    }
}

/// KeysWithSecretsDto transfers inner config keys with secret information.
///
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct KeysWithSecretsDto {
    pub keys: Option<Vec<String>>,
    pub secrets: Option<Vec<String>>,
}

/// ConfigDTO transfers secret config inftormation.
///
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct ConfigDto {
    pub secret_regexes: Option<Vec<String>>,
    pub keys_with_secrets: Option<Vec<KeysWithSecretsDto>>,
    pub keys_required: Option<Vec<String>>,
}

/// RegexConfigurationDto transfers all information required to create regex config in repository.
///
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct RegexConfigurationCreateDto {
    pub name: String,
    pub description: String,
    pub config: ConfigDto,
    pub groups: Vec<Group>,
    #[serde(with = "serde_arrays")]
    pub contributor_pem_hash: [u8;64],
    #[serde(with = "serde_arrays")]
    pub signature: [u8;512],
}

impl AsBytesToSigned for RegexConfigurationCreateDto {
    #[inline(always)]
    fn bytes_to_sign(&self) -> Vec<u8> {
        let Ok(mut config_blob) = json_bytes(&self.config) else {
            return vec![];
        };
        config_blob.extend(self.name.as_bytes());
        config_blob.extend(self.description.as_bytes());
        for g in self.groups.iter() {
            config_blob.extend(g.bytes_to_sign());
        }
        config_blob.extend(&self.contributor_pem_hash);

        config_blob.to_vec()
    }
}

#[inline(always)]
fn json_bytes<T>(structure: T) -> Result<Vec<u8>, RepositoryError> where T: Serialize {
    let mut bytes: Vec<u8> = Vec::new();
    serde_json::to_writer(&mut bytes, &structure)?;
    Ok(bytes)
}

/// RegexConfigurationDeleteDto transfers information required to delete the regex config from repository.
///
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct RegexConfigurationDeleteDto {
    pub id: i32,
    #[serde(with = "serde_arrays")]
    pub contributor_pem_hash: [u8;64],
    #[serde(with = "serde_arrays")]
    pub signature: [u8;512],
}

impl AsBytesToSigned for RegexConfigurationDeleteDto {
    #[inline(always)]
    fn bytes_to_sign(&self) -> Vec<u8> {
        let mut bytes = self.contributor_pem_hash.to_vec();
        bytes.extend(self.id.to_ne_bytes());
        bytes
    }
}

/// RegexConfigurationDataDto trensfers regex config information stored in repository to the application client.
///
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct RegexConfigurationDataDto {
    pub id: i32,
    pub name: String,
    pub description: String,
    pub config: ConfigDto,
    pub groups: Vec<Group>,
    pub ts: SystemTime,
    pub verified: bool,
}


/// RegexConfigurationPAgginateQueryDto trensfers data with paggination and specification about the query.
///
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct RegexConfigurationPagginateQueryDto {
    pub from: SystemTime,
    pub to: SystemTime,
    pub groups: Option<Vec<Group>>,
    pub verified: Option<bool>,
}
