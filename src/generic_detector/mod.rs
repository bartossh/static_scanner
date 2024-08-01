use std::collections::{HashMap, HashSet};
use aho_corasick::AhoCorasick;
use regex::{RegexBuilder, Regex};
use serde::{Deserialize, Serialize};
use serde_yaml::from_str as yaml_from_str;
use std::fs::read_to_string;
use std::path::Path;
use std::io::{Result as IoResult, Error, ErrorKind};
use crate::result::{DecoderType, DetectorType, Secret};

/// KeyWithSecrets represpresents keys names that can heve cerain secret schema.
///
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct KeysWithSecrets {
    keys: Option<Vec<String>>,
    secrets: Option<Vec<String>>,
}

/// Schema represents a secret schema which is a set of known words that exist in the secret.
/// It can be created from yaml file with specific schema.
///
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Schema {
    name: String,
    secret_regexes: Option<Vec<String>>,
    keys_with_secerets: Option<Vec<KeysWithSecrets>>,
}

impl Schema {
    /// Reads Schema configurations from yaml file.
    ///
    #[inline(always)]
    pub fn read_from_yaml_file(path: &Path) -> IoResult<Vec<Schema>> {
        let yaml_cfg = read_to_string(path)?;
        let Ok(cfg) = yaml_from_str(&yaml_cfg) else {
            return Err(Error::new(ErrorKind::Other, format!("cannot deserialize")));
        };
        Ok(cfg)
    }
}

/// Scanner offers scanning capabilities.
/// Scanning returns result of all found secrets locations.
///
pub trait Scanner {
    fn scan(&self, s: &str) -> Result<Vec<Secret>, String>;
}

#[derive(Debug)]
struct VariableSchema {
    aho: AhoCorasick,
    reg: Vec<Regex>,
}

#[derive(Debug)]
pub struct Scan {
    name: String,
    secret_regex: Vec<Regex>,
    variables_schema: Vec<VariableSchema>,
}

impl Scanner for Scan {
    #[inline(always)]
    fn scan(&self, s: &str) -> Result<Vec<Secret>, String> {
        let mut detector = Detection::new(self);
        detector.detect(s)
    }
}

#[derive(Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SecretPosition{
    start: usize,
    end: usize,
}

impl SecretPosition {
    #[inline(always)]
    fn new(start: usize, end: usize) -> Self {
        Self{start, end}
    }
}

#[derive(Hash, Debug, PartialEq, Eq)]
struct SecretItem<'a> {
    key: &'a str,
    value: &'a str,
}

#[derive(Debug)]
struct Detection<'a> {
    unique: HashMap<SecretPosition, SecretItem<'a>>,
    scanner: &'a Scan,
}

impl<'a> Detection<'a> {
    #[inline(always)]
    fn new(s: &'a Scan) -> Self {
        Self {
            unique: HashMap::new(),
            scanner: s,
        }
    }

    #[inline(always)]
    fn detect(&'a mut self, s: &'a str) -> Result<Vec<Secret>, String> {
        for variable in self.scanner.variables_schema.iter() {
            for key in variable.aho.find_overlapping_iter(s) {
                'regs_loop: for r in variable.reg.iter() {
                    let Some(secrets) = r.captures(&s[key.end()..]) else {
                        continue 'regs_loop;
                    };
                    let Some(secret) = secrets.get(0) else {
                        continue 'regs_loop;
                    };
                    let position = SecretPosition::new(key.end()+secret.start(), key.end()+secret.end());
                    if self.unique.contains_key(&position) {
                        continue 'regs_loop;
                    }
                    self.unique.insert(position, SecretItem{key: &s[key.start()..key.end()], value: secret.as_str()});
                }
            }
        }

        'regex_loop: for r in self.scanner.secret_regex.iter() {
            let Some(secrets) = r.captures(&s) else {
                continue 'regex_loop;
            };
            'secrets_loop: for s in secrets.iter() {
                let Some(secret) = s else {
                  continue 'secrets_loop;
                };
                let position = SecretPosition::new(secret.start(), secret.end());
                if self.unique.contains_key(&position) {
                    continue 'secrets_loop;
                }
                self.unique.insert(position, SecretItem{key: "secret", value: secret.as_str()});
            }
        }


        Ok(self.collect())
    }

    fn collect(&self) -> Vec<Secret> {
        let mut secrets = Vec::new();
        let mut positions = Vec::new();

        for (k, _v) in self.unique.iter() {
           positions.push(k);
        }
        positions.sort();

        let mut keys: HashSet<&str> = HashSet::new();
        let mut raw: String = String::new();
        for position in positions.iter() {
            let Some(item) = self.unique.get(&position) else {
                continue;
            };

            if keys.insert(&item.key) {
                if raw.len() > 0 {
                    raw.push('\n');
                }
                raw.push_str(format!("{}: {}", item.key, item.value).as_str());
                continue;
            }
            let secret = Secret {
                detector_type: DetectorType::Unique(self.scanner.name.clone()),
                decoder_type: DecoderType::Plane,
                raw_result: raw.clone(),
                file: "".to_string(),
                line: 0,
                verified: false,
            };
            secrets.push(secret);

            keys.clear();
            keys.insert(&item.key);

            raw.clear();
            raw.push_str(format!("{}: {}", item.key, item.value).as_str());
        }

        if raw.len() > 0 {
            let secret = Secret {
                detector_type: DetectorType::Unique(self.scanner.name.clone()),
                decoder_type: DecoderType::Plane,
                raw_result: raw.clone(),
                file: "".to_string(),
                line: 0,
                verified: false,
            };
            secrets.push(secret);
        }

        secrets
    }
}

/// Builds the detector.
#[derive(Debug, Clone)]
pub struct Builder {
    name: Option<String>,
    secret_regexes: Vec<String>,
    variables: Vec<(Vec<String>, Vec<String>)>,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            name: None,
            secret_regexes: Vec::new(),
            variables: Vec::new(),
        }
    }

    /// Names the scanner.
    ///
    pub fn with_name(&mut self, name: &str) -> &mut Self {
        self.name = Some(name.to_string());
        self
    }

    /// Populates secret regexes with given regexes.
    /// Secret regexes are regexes to be precompiled to much a token as a secret.
    ///
    #[inline(always)]
    pub fn with_secret_regexes(&mut self, patterns: &[&str]) -> &mut Self {
        for pattern in patterns.iter() {
            self.secret_regexes.push(pattern.to_string());
        }
        self
    }

    /// Populates variables with given patterns.
    /// Variables will be precompiled to much a token as a variable.
    ///
    #[inline(always)]
    pub fn with_variables(&mut self, patterns: &[&str], regexes: &[&str]) -> &mut Self {
        let mut variables = (Vec::new(), Vec::new());
        for pattern in patterns.iter() {
            variables.0.push(pattern.to_string());
        }
        for reg in regexes.iter() {
            variables.1.push(reg.to_string());
        }
        self.variables.push(variables);
        self
    }

    /// Tries to build a scanner.
    ///
    #[inline(always)]
    pub fn try_build_scanner(&self) -> Result<Scan, String> {
        let mut variables_schema = Vec::new();
        for variables in self.variables.iter() {
            if variables.0.len() > 0 && variables.1.len() > 0 {
                let res = AhoCorasick::new(&variables.0);
                if let Err(err) = res {
                    return Err(err.to_string());
                }
                let Ok(aho) = res else {
                    return Err("Failed to create AhoCorasik".to_string());
                };
                let mut reg = Vec::new();
                'regex_loop: for rgx in variables.1.iter() {
                    let res = RegexBuilder::new(rgx).build();
                    if let Ok(r) = res {
                        reg.push(r);
                        continue 'regex_loop;
                    }
                    if let Err(e) = res {
                        return Err(e.to_string());
                    }
                }
                variables_schema.push(VariableSchema {
                    aho,
                    reg,
                });
            }
        }

        let mut secret_regex = Vec::new();

        for pattern in self.secret_regexes.iter() {
            let res = RegexBuilder::new(pattern).build();
            if let Ok(regex) = res {
                secret_regex.push(regex);
                continue;
            }
            if let Err(e) = res {
                return Err(e.to_string());
            }
        }

        Ok(Scan {
            name: match &self.name {
                Some(name) => name.clone(),
                None => "".to_string(),
            },
            secret_regex,
            variables_schema,
        })
   }
}

impl TryFrom<&Schema> for Scan {
    type Error = Error;

    #[inline(always)]
    fn try_from(s: &Schema) -> Result<Self, Self::Error> {
        let mut secrets: Vec<&str> = Vec::new();
        if let Some(secret_regexes) = &s.secret_regexes{
            for secret in secret_regexes.iter() {
                secrets.push(secret);
            }
        }
        let mut keys_w_secrets: Vec<(Vec<&str>, Vec<&str>)> = Vec::new();

        if let Some(keys_with_secrets) = &s.keys_with_secerets {
            for kws in keys_with_secrets.iter() {
                let mut pattern: (Vec<&str>, Vec<&str>) = (Vec::new(), Vec::new());
                let Some(keys) = &kws.keys else {
                    continue;
                };
                for k in keys.iter() {
                    pattern.0.push(k);
                }
                let Some(secrets) = &kws.secrets else {
                    continue;
                };
                for s in secrets.iter() {
                    pattern.1.push(s);
                }
                keys_w_secrets.push(pattern);
            }
        }

        let mut builder = Builder::new();
        builder.with_name(&s.name);
        builder.with_secret_regexes(&secrets);
        for kws in keys_w_secrets.iter() {
            builder.with_variables(&kws.0, &kws.1);
        }

        let Ok(scanner) = builder.try_build_scanner() else {
            return Err(Error::new(ErrorKind::InvalidData, "cannot build scanner from schema"));
        };

        Ok(scanner)
    }
}

#[derive(Debug)]
pub struct Inspector {
    scanners: Vec<Scan>,
}

impl Inspector {
    #[inline(always)]
    pub fn try_new(path_to_config_yaml: &str) -> IoResult<Self> {
        let path = Path::new(path_to_config_yaml);
        let mut scanners = Vec::new();
        for schema in Schema::read_from_yaml_file(path)?.iter() {
            scanners.push(schema.try_into()?);
        }
        Ok(Self {
            scanners,
        })
    }
}

impl Scanner for Inspector {
    #[inline(always)]
    fn scan(&self, s: &str) -> Result<Vec<Secret>, String> {
        let mut results: Vec<Secret> = Vec::new();
        for scanner in self.scanners.iter() {
            results.extend(scanner.scan(s)?);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIVEN_TEST_DATA: &str = r#"
        [
          {
            "User name": "test-user-0",
            "Password": "'Qp+*'!ruZ89pyD"
          },
          {
            "User name": "test-user-1",
            "Password": "o*P2PX)79&kHsF0"
          },
          {
            "User name": "test-user-2",
            "Password": "KGX!0cpQdCr{K#I"
          },
          {
            "User name": "test-user-3",
            "Password": "7jEN3G[8Ts]e[{8"
          },
          {
            "User name": "test-user-4",
            "Password": "CPJZj|j(cP951A6"
          },
          {
            "User name": "test-user-5",
            "Password": "*=AAFegePCfrl12"
          },
          {
            "User name": "test-user-6",
            "Password": "MhPZx&GFqG7]b8v"
          },
          {
            "User name": "test-user-7",
            "Password": "X]pks}tZpj41sfJ"
          },
          {
            "User name": "test-user-8",
            "Password": "4jh3ew2-{w%(%2c"
          },
          {
            "User name": "test-user-9",
            "Password": "!4c)qvesGQnLXs|"
          }

my id -> 234231rfffasdfadf
password => asdfq340fade9023&#$@#@$

"some_id = 1234dkanamd"
some passowrd -> alsdkfjaksdj3293u4189389u


[
{
"type": "service_account",
"project_id": "",
"private_key_id": "",
"private_key": "-----BEGIN PRIVATE KEY-----MIIBWwIBADCCATQGByqGSM44BAEwggEnAoGBAKUM1CBGwXTGv6j5PWTfcAkD5zp2fOQnT/bl9Be3y+c9yppoa9Z/WKv3Dc2rIg75hbjJcbgwFlLqpnJa7/a+g88UWzhZGHCRCtFMon3OFlw9xUzA3bh8VyzuMybG71eIt0TnJteFbc9bzHy742YQJkBUOmqkUkOcSUwd5AnXH8sxAh0Az+gTc64gel0LHg4k0a5Mi4xQomnMuC+Dy+pqBQKBgQCJc5Zsr2+CMUIF36EJI80+o7y76s+G4LUYu6+qnu5X/p5lK2mg2CqEHDQjkRMbBuAyVmIl/7uj14AUD4P4NJxptN4smzMLLu+dDyt1SzwZDPgDs6rTCKHkA18IDwazvpfr6RT1n8zZM8dbmWdXqDP5HNn4CQX6c/aFJe8dlwV3MAQeAhwPlZQFNUSYcSyX7jrv/WYvV1DyUMkYTmpVgmXA-----END PRIVATE KEY-----\n",
"client_email": "",
"client_id": "",
"auth_uri": "https://accounts.google.com/o/oauth2/auth",
"token_uri": "https://oauth2.googleapis.com/token",
"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
"client_x509_cert_url": ""
},
{
"type": "service_account",
"project_id": "",
"private_key_id": "",
"private_key": "-----BEGIN PRIVATE KEY-----MIIBWwIBADCCATQGByqGSM44BAEwggEnAoGBAKUM1CBGwXTGv6j5PWTfcAkD5zp2fOQnT/bl9Be3y+c9yppoa9Z/WKv3Dc2rIg75hbjJcbgwFlLqpnJa7/a+g88UWzhZGHCRCtFMon3OFlw9xUzA3bh8VyzuMybG71eIt0TnJteFbc9bzHy742YQJkBUOmqkUkOcSUwd5AnXH8sxAh0Az+gTc64gel0LHg4k0a5Mi4xQomnMuC+Dy+pqBQKBgQCJc5Zsr2+CMUIF36EJI80+o7y76s+G4LUYu6+qnu5X/p5lK2mg2CqEHDQjkRMbBuAyVmIl/7uj14AUD4P4NJxptN4smzMLLu+dDyt1SzwZDPgDs6rTCKHkA18IDwazvpfr6RT1n8zZM8dbmWdXqDP5HNn4CQX6c/aFJe8dlwV3MAQeAhwPlZQFNUSYcSyX7jrv/WYvV1DyUMkYTmpVgmXA-----END PRIVATE KEY-----\n",
"client_email": "",
"client_id": "",
"auth_uri": "https://accounts.google.com/o/oauth2/auth",
"token_uri": "https://oauth2.googleapis.com/token",
"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
"client_x509_cert_url": ""
}
]
]"#;

    #[test]
    fn it_should_create_scanner() {
        let Ok(scanner) = Builder::new()
            .with_name("GCP")
            .with_secret_regexes(&[r#"-----BEGIN PRIVATE KEY-----[\a-zA-Z0-9]*-----END PRIVATE KEY-----"#])
            .with_variables(&["auth_uri", "token_uri","auth_provider_x509_cert_url"], &[r#"https://[a-zA-Z-0-9./]*"#])
            .with_variables(&["private_key"], &[r#"-----BEGIN PRIVATE KEY-----[\a-zA-Z0-9]*-----END PRIVATE KEY-----"#])
            .try_build_scanner() else {
                    assert!(false);
                    return;
                };
        let Ok(results) = scanner.scan(GIVEN_TEST_DATA) else {
            assert!(false);
            return;
        };

        for result in results.iter() {
            assert!(result.raw_result.contains("-----BEGIN PRIVATE KEY----"));
            assert!(result.raw_result.contains("https://accounts.google.com/o/oauth2/auth"));
            assert!(result.raw_result.contains("https://oauth2.googleapis.com/token"));
            assert!(result.raw_result.contains("https://www.googleapis.com/oauth2/v1/certs"));
        }
    }
}
