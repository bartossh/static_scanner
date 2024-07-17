use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};
use serde_yaml::from_str;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs::read_to_string;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::path::Path;

const DEFINING: [char; 3] = [':', '=', ' '];
const ENDING: [char; 3] = [',', ';', ' '];
const MIN_SECRET_SIZE: usize = 8;
const LETTERS_TO_LOOK_IN_TO_THE_FUTURE: usize = 12;

/// Schema represents a secret schema which is a set of known words that exist in the secret.
/// It can be created from yaml file with specific schema.
///
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Schema {
    name: String,
    keys_required: Option<Vec<String>>,
    keys_optional: Option<Vec<String>>,
    min_opt_match: Option<usize>,
}

impl Display for Schema {
    #[inline(always)]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{:?}", self)
    }
}

impl Schema {
    /// Reads Schema configurations from yaml file.
    ///
    #[inline(always)]
    pub fn read_from_yaml_file(path: &Path) -> IoResult<Vec<Schema>> {
        let yaml_cfg = read_to_string(path)?;
        let Ok(cfg) = from_str(&yaml_cfg) else {
            return Err(Error::new(ErrorKind::Other, format!("cannot deserialize")));
        };
        Ok(cfg)
    }
}

/// Marks the secret to be unique.
///
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct Mark {
    pub key: String,
    pub start_index: usize,
    pub end_index: usize,
}

impl Display for Mark {
    #[inline(always)]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "{}: [ {} to {} ]",
            self.key, self.start_index, self.end_index
        )
    }
}

impl Mark {
    pub fn new(key: &str, si: usize, ei: usize) -> Self {
        Self {
            key: key.to_string(),
            start_index: si,
            end_index: ei,
        }
    }
}

/// Evidence holds data proving the secret leakage.
///
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    secret_name: String,
    values: HashMap<Mark, String>,
}

impl Display for Evidence {
    #[inline(always)]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let mut secrets = "".to_string();
        for (k, v) in self.values.iter() {
            secrets.push_str(&format!("  {}: {}\n", k, v));
        }
        write!(f, "{}\n{}", self.secret_name, secrets)
    }
}

impl Evidence {
    #[inline(always)]
    pub fn get_secret(&self, k: &Mark) -> Option<String> {
        let Some(v) = self.values.get(k) else {
            return None;
        };

        Some(v.to_owned())
    }
}

#[derive(Debug)]
struct Fingerprint {
    name: String,
    ac_required: Option<AhoCorasick>,
    ac_optional: Option<AhoCorasick>,
    required_len: usize,
    min_opt_match: Option<usize>,
}

impl TryFrom<&Schema> for Fingerprint {
    type Error = Error;

    #[inline(always)]
    fn try_from(s: &Schema) -> Result<Fingerprint, Self::Error> {
        let mut fingerprint = Fingerprint {
            name: s.name.clone(),
            ac_required: None,
            ac_optional: None,
            required_len: 0,
            min_opt_match: s.min_opt_match,
        };

        if let Some(patterns) = &s.keys_required {
            fingerprint.ac_required = Some(match AhoCorasick::new(patterns) {
                Ok(ac) => Ok(ac),
                Err(e) => Err(Error::new(ErrorKind::InvalidData, e.to_string())),
            }?);
            fingerprint.required_len = patterns.len();
        }

        if let Some(patterns) = &s.keys_optional {
            fingerprint.ac_optional = Some(match AhoCorasick::new(patterns) {
                Ok(ac) => Ok(ac),
                Err(e) => Err(Error::new(ErrorKind::InvalidData, e.to_string())),
            }?);
        }

        Ok(fingerprint)
    }
}

impl Fingerprint {
    #[inline(always)]
    fn cut_quotes(s: &str, start: usize) -> Option<String> {
        if start >= s.len() - 2 {
            return None;
        }
        let start = start + 1;

        let Some(relative_end) = s[start..].find("\n") else {
            return None;
        };

        let Some(relative_quote_start) = s[start..start + relative_end].find("\"") else {
            return None;
        };

        if relative_end < relative_quote_start {
            return None;
        }

        let Some(relative_quote_end) =
            s[start + relative_quote_start + 1..start + relative_end].find("\"")
        else {
            return None;
        };

        let result = s[start + relative_quote_start + 1
            ..start + relative_quote_start + 1 + relative_quote_end]
            .trim()
            .to_string();

        if result.len() < MIN_SECRET_SIZE {
            return None;
        }

        Some(result)
    }

    #[inline(always)]
    fn cut_from(s: &str, start: usize) -> Option<String> {
        if start >= s.len() - 1 {
            return None;
        }

        let mut secret_start = start;
        let search_end = if s.len() < secret_start + LETTERS_TO_LOOK_IN_TO_THE_FUTURE {
            s.len()
        } else {
            secret_start + LETTERS_TO_LOOK_IN_TO_THE_FUTURE
        };
        for ch in DEFINING.iter() {
            if let Some(idx) = s[secret_start..search_end].find(*ch) {
                secret_start += idx;
            }
        }

        if secret_start < s.len() - 1 {
            secret_start = secret_start + 1;
        }

        let mut secret_end = s.len();
        if let Some(idx) = s[secret_start..secret_end].find('\n') {
            secret_end = idx + secret_start;
        }
        for ch in ENDING.iter() {
            if let Some(idx) = s[secret_start..secret_end].find(*ch) {
                if idx + secret_start < secret_end && idx + secret_start < s.len() {
                    secret_end = idx + secret_start;
                }
            }
        }

        let result = s[secret_start..secret_end].trim().to_string();

        if result.len() < MIN_SECRET_SIZE {
            return None;
        }

        Some(result)
    }

    #[inline(always)]
    pub fn scan(&self, suspected_crime: &str) -> Option<Evidence> {
        let mut values = HashMap::with_capacity(
            (self.min_opt_match.unwrap_or_default() + self.required_len) * 5,
        );
        if let Some(ac_required) = &self.ac_required {
            'findings: for finding in ac_required.find_overlapping_iter(&suspected_crime) {
                let key = suspected_crime[finding.start()..finding.end()].to_string();
                let value = {
                    if let Some(v) = Fingerprint::cut_quotes(&suspected_crime, finding.end()) {
                        v
                    } else {
                        let Some(v) = Fingerprint::cut_from(&suspected_crime, finding.end()) else {
                            continue 'findings;
                        };
                        v
                    }
                };

                values.insert(
                    Mark::new(&key, finding.end(), finding.end() + key.len()),
                    value,
                );
            }
            if values.len() < ac_required.patterns_len() {
                return None;
            }
        }

        let required_count = values.len();

        if let Some(ac_optional) = &self.ac_optional {
            'findings: for finding in ac_optional.find_overlapping_iter(&suspected_crime) {
                let key = suspected_crime[finding.start()..finding.end()].to_string();
                let value = {
                    if let Some(v) = Fingerprint::cut_quotes(&suspected_crime, finding.end()) {
                        v
                    } else {
                        let Some(v) = Fingerprint::cut_from(&suspected_crime, finding.end()) else {
                            continue 'findings;
                        };
                        v
                    }
                };

                values.insert(
                    Mark::new(&key, finding.end(), finding.end() + key.len()),
                    value,
                );
            }
            if values.len() - required_count < self.min_opt_match.unwrap_or_default() {
                return None;
            }
        }

        Some(Evidence {
            secret_name: self.name.to_owned(),
            values: values,
        })
    }
}

/// Offers Fingerprints inspection.
/// Looks for all matching fingerprints to provide evidences of leaked secrets.
///
#[derive(Debug)]
pub struct Inspector {
    fingerprints: Vec<Fingerprint>,
}

impl Inspector {
    /// Ties to create a new Inspector from the path to a yaml file.
    ///
    pub fn try_new(path_to_config_yaml: &str) -> IoResult<Self> {
        let path = Path::new(path_to_config_yaml);
        let mut fingerprints = Vec::new();
        for schema in Schema::read_from_yaml_file(path)?.iter() {
            let fingerprint: Result<Fingerprint, _> = schema.try_into();
            let Ok(fingerprint) = fingerprint else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "cannot crate fingerprints",
                ));
            };
            fingerprints.push(fingerprint);
        }
        Ok(Self {
            fingerprints: fingerprints,
        })
    }

    /// Scans string of suspected crime comparing with internal prove of fingerprints.
    /// Returns vector of all found evidences of crimes of leaked secrets.
    ///  
    pub fn scan(&self, suspected_crime: &str) -> Vec<Evidence> {
        let mut evidences: Vec<Evidence> = Vec::with_capacity(self.fingerprints.len() * 10); // naive memory preallocation
        for fingerprint in self.fingerprints.iter() {
            if let Some(evidence) = fingerprint.scan(suspected_crime) {
                evidences.push(evidence);
            }
        }
        evidences
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_should_decode_yaml_config() {
        let path = Path::new("./assets/config.yaml");
        match Schema::read_from_yaml_file(path) {
            Ok(cfg) => {
                for c in cfg.iter() {
                    println!("{}", c);
                }
                assert!(true);
            }
            Err(e) => {
                println!("Err {:?}", e);
                assert!(false);
            }
        };
    }

    #[test]
    fn it_should_find_secrets_credentials_aws() {
        let suspected_crime = r#"        
[default]
aws_access_key_id=ASIAIOSFODNN7EXAMPLE
aws_secret_access_key =wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_session_token = IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZVERYLONGSTRINGEXAMPLE

[user1]
aws_access_key_id= ASIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
aws_session_token=fcZib3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZVERYLONGSTRINGEXAMPLE
"#;

        let path = Path::new("./assets/config.yaml");

        let Ok(schemas) = Schema::read_from_yaml_file(path) else {
            assert!(false);
            return;
        };

        let mut fingerprints: Vec<Fingerprint> = Vec::with_capacity(schemas.len());
        for s in schemas.iter() {
            let f: Result<Fingerprint, _> = s.try_into();
            let Ok(f) = f else {
                assert!(false);
                return;
            };
            fingerprints.push(f);
        }

        for fingerprint in fingerprints.iter() {
            match fingerprint.scan(&suspected_crime) {
                Some(evidence) => {
                    let Some(found) =
                        evidence.get_secret(&Mark::new(&"aws_session_token", 139, 156))
                    else {
                        assert!(false);
                        return;
                    };
                    assert_eq!(*found, *"IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZVERYLONGSTRINGEXAMPLE");
                }
                None => (),
            }
        }
    }

    #[test]
    fn it_should_find_secrets_credentials_gcp() {
        let suspected_crime = r#"        
[
  {
    "type": "service_account",
    "project_id": "",
    "private_key_id": "1234567890",
    "private_key": "-----BEGIN PRIVATE KEY-----MIIBWgIBADCCATMGByqGSM44BAEwggEmAoGBANnjjqR/ZTyjbyT5tRt/QJbX4imO0133m4dr6GHqufhL38S0m5duefYkSOB56njVVInEgdCnvupWcNH06FuxFNFopQkjn7z1PfsCOTL9Ar6DmHW0D94pt8HOaPEqTP1xgy2p93e8r5Wr1BPL2PdClTgtRUFcNGJitTAB7o1QjbznAh0AiZKwMNhX/fGhVWzdeocxdZeDGq+VWs0cIUKmkQKBgFHExnrSQvguEFJZZmPzRuGCjl12xHdAk2O8e7PEe5OSweE8bAIUguLQroVYu+wAEYM8iNW/SwfU2XwpolV0J74/UO/4952hUd6caWfLFZG5aI8/+4QdMpKeIgazgpMo3d0sI9DY1Y6dbbMrdWC1BGn66CGWt4m/V4LlSNFdlIc2BB4CHA0WiwYund93kHt8N0cwM4Jbg9fpDtwVfTMEiIU=-----END PRIVATE KEY-----\n",
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
    "private_key_id": "9876543210",
    "private_key": "-----BEGIN PRIVATE KEY-----MIIBWgIBADCCATMGByqGSM44BAEwggEmAoGBANnjjqR/ZTyjbyT5tRt/QJbX4imO0133m4dr6GHqufhL38S0m5duefYkSOB56njVVInEgdCnvupWcNH06FuxFNFopQkjn7z1PfsCOTL9Ar6DmHW0D94pt8HOaPEqTP1xgy2p93e8r5Wr1BPL2PdClTgtRUFcNGJitTAB7o1QjbznAh0AiZKwMNhX/fGhVWzdeocxdZeDGq+VWs0cIUKmkQKBgFHExnrSQvguEFJZZmPzRuGCjl12xHdAk2O8e7PEe5OSweE8bAIUguLQroVYu+wAEYM8iNW/SwfU2XwpolV0J74/UO/4952hUd6caWfLFZG5aI8/+4QdMpKeIgazgpMo3d0sI9DY1Y6dbbMrdWC1BGn66CGWt4m/V4LlSNFdlIc2BB4CHA0WiwYund93kHt8N0cwM4Jbg9fpDtwVfTMEiIU=-----END PRIVATE KEY-----\n",
    "client_email": "",
    "client_id": "",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": ""
  }
]
"#;

        let path = Path::new("./assets/config.yaml");

        let Ok(schemas) = Schema::read_from_yaml_file(path) else {
            assert!(false);
            return;
        };

        let mut fingerprints: Vec<Fingerprint> = Vec::with_capacity(schemas.len());
        for s in schemas.iter() {
            let f: Result<Fingerprint, _> = s.try_into();
            let Ok(f) = f else {
                assert!(false);
                return;
            };
            fingerprints.push(f);
        }

        for fingerprint in fingerprints.iter() {
            match fingerprint.scan(&suspected_crime) {
                Some(evidence) => {
                    if let Some(secret) = evidence.get_secret(&Mark::new("private_key_id", 87, 101))
                    {
                        assert_eq!(secret, "1234567890")
                    }
                }
                None => (),
            }
        }
    }

    #[test]
    fn it_should_find_secrets_credentials_twitter() {
        let suspected_crime = r#"
[
  {
    "Api Key":                "5PAgMqo1gXn7QyHzzGASDFN9Q",
    "Api Key Secret":         "PDrhKbxeYhxeWz6R1UddxdJFXCRsZadTtsDmwlUBxPGB4bU2aU",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAINuBw0mowW3KpPh0zxGB2vgGY7g%3DXePv83wPJ5VOvROMkfGwkPtptd5w9xAAGUHrgfkhppjXA2JWN5",
    "Access Token":           "955116647488028672-NvXaA5BEnf9gYAcK40hNZGTbPdlwmaU",
    "Access Token Secret":    "H1xeoEa7i6PnarMvpKIz2WiVgqJetEmnMRlRBVaZrOekd"
  },
  {
    "Api Key":                "IwSJrHZeuP1Hl9Edz9VQyqT7x",
    "Api Key Secret":         "hR7vHE72b5IIoKGh0icOBprExoZkamRrvjidXDadn5gudqff6z",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAwi3BY9v2NbI1%2BsINLKs0gNCF%2Fio%3DRwh43tAmNVdRVTzkvUx29gQ0exqGtFaQyTffzI1juiicxuT2W7",
    "Access Token":           "955116647488028672-dde5wWYS29lJUVaKoktDvyMlJS0zsKY",
    "Access Token Secret":    "BRyuRAFLPwQH1W0vIQlVxcJvbfOUV5j5xdUj4KbALU8RC"
  },
  {
    "Api Key":                "PyjocY7kHdiekmGsi6ndao2hR",
    "Api Key Secret":         "16hHCNCpykZliz6juLF5xkHuGniueh4PFRRjKLLnfhuuNjJPyE",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAASO6z6R5Iw8rIb8cCspGTp%2B6ERwo%3Dvt0hpY8WXq0HJisC9aikQn8ocDZLEIXSdoLTezIBcFlzLUkzJY",
    "Access Token":           "955116647488028672-RdYFDr6FkMrZN4bk3O4stZj3xqDc7AM",
    "Access Token Secret":    "69yZI4oq1IZXEtr2T6BQo05KqQLadzphmEqrI5rWRUHW7"
  },
  {
    "Api Key":                "oYBUjCeergTCyrbvhGhMQ6vG4",
    "Api Key Secret":         "sp1mizKQPorh0UCCL0G6WZVvtD15ourLcTOKutSiYywCl851QX",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAZv3%2BaU5t0Vtzwxa69CpXFLcG72E%3DqYWvGr4WKYaebn6qypSsRw3xzMvK1g4KciyYVqrPYwMVvPAgzL",
    "Access Token":           "955116647488028672-VPc28faQNZtHp0fikUhNFAcophLbcBH",
    "Access Token Secret":    "1zJUU8Nfeg0JyFNGGl3HqiW4eHvCD9PWRSINmdUBx4SXg"
  },
  {
    "Api Key":                "04NoreYdRRE7JyYSTagqUIhkm",
    "Api Key Secret":         "WfRLkulliRNtWaTEGmoTllgyB01di83cnRjPNMBGpkpGgd6SM0",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAEBVfpu94kepJoMULqERWxIL7g68%3DC3Jy2zaUnTrHNxZNRSrlOCIOjoBVyPDILDaffVoxxcQzwkPoGj",
    "Access Token":           "955116647488028672-iIPUHS2KA6t2A1MMuA71e9ujmrvLfo6",
    "Access Token Secret":    "QDmKy2R8Sy3owzAU5fn6Fm6nXQqvChybdp5Ha4zIy5jT9"
  },
  {
    "Api Key":                "53kDReVLIm9ekk7a7kWHxdQ6c",
    "Api Key Secret":         "f7a1xMAUjJMsd76SyfuqxIZiZvFDXTkaLE0OHaPZDpcG7YJ2Rb",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAM%2BcWWEICaBtt9kG6ho8WK9I%2FoTk%3DX3U2VpxkKYUEikurhLgV9HmuwMS61Pz94dp9IQkVJ1RAFNNFKi",
    "Access Token":           "955116647488028672-pTjShSi8sMSrBjMIvZH2cs8glCayepI",
    "Access Token Secret":    "hJGLZDjVIRBLu5v3YxMg7GzQ36GbJ1eW2zhCkwsHYSD0H"
  },
  {
    "Api Key":                "LPTtKbnTGgnzj4XrCBCYSqRcP",
    "Api Key Secret":         "nahpwSPzIsg14Z43O9o9anKbuCWYL6ZyjymrJDxngMxRLFxKfR",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAU7sfX1jG7feA1J3x%2FLOG4eioLy0%3DqW2ryZPU3PPo8yajka1CKgEDSFMjPRQijhydINoNBRqtZZKVUq",
    "Access Token":           "955116647488028672-QoKBPDd1td4Ngyp669xvZBFLjvEqrSh",
    "Access Token Secret":    "1PO1ztph22zLU39QZxqpcKlSoSugpsZSNClSROIu9JELs"
  },
  {
    "Api Key":                "NCYWHSACCsWdyVAYXZxb5cj30",
    "Api Key Secret":         "bsipEFMsDAJLS4Ac4xB1WWOGwtT2OfLgmPO4EtNXgnJGakgOQS",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAkVMyeUwCzFuIkozZ%2BWvu4li9wZg%3D2Q3dzqJZg41Hz7IYahNuY8VbA1lAzvi0ftOYt9UcC3BTAN1ssM",
    "Access Token":           "955116647488028672-v09GALnNJIyprRoly7y35ppWOT8cTuJ",
    "Access Token Secret":    "bAXEnYpxgIA9DetJPGbPRvIvOy6AugxnBQSnaYl1dvGqi"
  },
  {
    "Api Key":                "Wzd3WBYr9HhThzhFMBlYMLE9S",
    "Api Key Secret":         "K7Hw32JdwfCC3Iwgm6rgh3EUjiweyLD8L3tPC98VnDsQ715S5G",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAZVe4Znhi14HRCDDQHWZj4JhDT1I%3DUlwU7UWD90SmfWetqc2mLCl6NzaIWvTQeHusTGdvDdB0eAbtmj",
    "Access Token":           "955116647488028672-K4uKNEEep8jMHHcPLzFOWORzuK6yHX4",
    "Access Token Secret":    "5NS4g8AL56zI4rnnufTMujG0lXUk5KUAeKTjB22RFnFpl"
  },
  {
    "Api Key":                "QPLHSazDh18efjex1DCe9vqSV",
    "Api Key Secret":         "kskbOBkj7dk3h7Kee6VmVrKp8Lo4m5socnFE9Z3pOSZH7oXi0C",
    "Bearer Token":           "AAAAAAAAAAAAAAAAAAAAAOokiwEAAAAAQKu0SOsxZH4b9cz0NVWkIRxfxK4%3D0aR3NAlIjohUPj1lf39LirIeSO2y4RvsDGPFRgUiFuUD52YFqR",
    "Access Token":           "955116647488028672-JKMlfU95YvQqjmAjoNsJbQjQdBUtVlA",
    "Access Token Secret":    "vW36iduHNPQAq0EZobWTDDDCmXVPC3dmzYNjc7yORkQQR"
  },
]
"#;

        let path = Path::new("./assets/config_twitter.yaml");

        let Ok(schemas) = Schema::read_from_yaml_file(path) else {
            assert!(false);
            return;
        };

        let mut fingerprints: Vec<Fingerprint> = Vec::with_capacity(schemas.len());
        for s in schemas.iter() {
            let f: Result<Fingerprint, _> = s.try_into();
            let Ok(f) = f else {
                assert!(false);
                return;
            };
            fingerprints.push(f);
        }

        for fingerprint in fingerprints.iter() {
            match fingerprint.scan(&suspected_crime) {
                Some(evidence) => {
                    if let Some(secret) =
                        evidence.get_secret(&Mark::new("Access Token Secret", 868, 887))
                    {
                        assert_eq!(secret, "BRyuRAFLPwQH1W0vIQlVxcJvbfOUV5j5xdUj4KbALU8RC")
                    }
                }
                None => assert!(false),
            }
        }
    }
}
