use std::collections::HashMap;
use aho_corasick::AhoCorasick;
use tokenizers::pre_tokenizers::delimiter::CharDelimiterSplit;
use tokenizers::pre_tokenizers::{sequence::Sequence, split::Split};
use tokenizers::tokenizer::normalizer::SplitDelimiterBehavior;
use tokenizers::{OffsetReferential, OffsetType, PreTokenizedString, PreTokenizer};
use regex::{RegexBuilder, Regex};

/// Scanner offers scanning capabilities.
/// Scanning returns result of all found secrets locations.
///
pub trait Scanner {
    fn scan(&self, s: &str) -> Result<(), String>;
}

#[derive(Debug)]
struct VariableSchema {
    aho: AhoCorasick,
    reg: Vec<Regex>,
}

#[derive(Debug)]
struct Scan{
    secret_regex: Vec<Regex>,
    variables_schema: Option<VariableSchema>,
    pre_tokenizer: Sequence,
}

impl Scanner for Scan {
    fn scan(&self, s: &str) -> Result<(), String> {
        let mut detector = Detection::new(self);
        detector.detect(s)
    }
}

#[derive(Debug)]
struct Location {
    variable: usize,
    value: usize,
}

#[derive(Debug)]
struct Candidate {
    variable: usize,
    secret: usize,
}

#[derive(Debug)]
struct Detection<'a> {
    variable_assignemnts: HashMap<String, Location>,
    scanner: &'a Scan,
}

impl<'a> Detection<'a> {
    fn new(s: &'a Scan) -> Self {
        Self {
            variable_assignemnts: HashMap::new(),
            scanner: s,
        }
    }

    fn detect(&'a mut self, s: &str) -> Result<(), String> {
        let mut pre_tokenized = PreTokenizedString::from(s);
        if let Err(err)  = self.scanner.pre_tokenizer.pre_tokenize(&mut pre_tokenized) {
            return Err(err.to_string());
        }

        let tokens = pre_tokenized.get_splits(OffsetReferential::Original, OffsetType::Byte);
        let mut candidates = Vec::new(); // TODO: run per variable_schema
        let mut variable_idx: Option<usize> = None; // TODO: run per variable_schema shall be more then one in the future
        for (i, token) in tokens.iter().enumerate()
        {
            if let Some(candidate) = self.discover(i, token.0, &mut variable_idx) {
                candidates.push(candidate);
            }
        }

        for candidate in candidates.iter() {
            println!("----- FOUND -----");
            println!("[ {:?} {:?} ]", tokens.get(candidate.variable), tokens.get(candidate.secret));
            println!("-----  END  -----");
            println!("");
        }

        Ok(())
    }

    fn discover(&mut self, idx: usize, token: &str, variable_idx: &mut Option<usize>) -> Option<Candidate> {
        if let Some(var_idx) = variable_idx {
            if let Some(schema) = &self.scanner.variables_schema {
                for regex in schema.reg.iter() {
                    if regex.is_match(token) {
                        let var = var_idx.clone();
                        *variable_idx = None;
                        return Some(Candidate{
                            variable: var,
                            secret:idx,
                        });
                    }
                }
            }
        }


        if let Some(schema) = &self.scanner.variables_schema {
            if schema.aho.is_match(token) {
                *variable_idx = Some(idx);
            }
        }
        None
    }
}

/// Builds the detector.
#[derive(Debug)]
pub struct Builder {
    splits: Vec<String>,
    secret_regexes: Vec<String>,
    variables: (Vec<String>, Vec<String>),
}

impl Builder {
    pub fn new() -> Self {
        Self {
            splits: Vec::new(),
            secret_regexes: Vec::new(),
            variables: (Vec::new(), Vec::new()),
        }
    }

    /// Populates splits with given paterns.
    /// Splits are all patterns that acts as a space separating tokens.
    ///
    pub fn with_splits(&mut self, patterns: &[&str]) -> &mut Self {
        for pattern in patterns.iter() {
            self.splits.push(pattern.to_string())
        }
        self
    }

    /// Populates secret regexes with given regexes.
    /// Secret regexes are regexes to be precompiled to much a token as a secret.
    ///
    pub fn with_secret_regexes(&mut self, patterns: &[&str]) -> &mut Self {
        for pattern in patterns.iter() {
            self.secret_regexes.push(pattern.to_string());
        }
        self
    }

    /// Populates variables with given patterns.
    /// Variables will be precompiled to much a token as a variable.
    ///
    pub fn with_variables(&mut self, patterns: &[&str], regexes: &[&str]) -> &mut Self {
        for pattern in patterns.iter() {
            self.variables.0.push(pattern.to_string());
        }
        for reg in regexes.iter() {
            self.variables.1.push(reg.to_string());
        }
        self
    }

    /// Tries to build a scanner.
    ///
    pub fn try_build_scanner(&self) -> Result<impl Scanner, String>  {
        let mut pre_tokenizers_wrappers = Vec::new();

        for var in self.variables.0.iter() {
            let res = Split::new(var.as_str(), SplitDelimiterBehavior::Contiguous, false);
            if let Err(err) = res {
                return Err(err.to_string());
            }
            if let Ok(eq) = res {
                pre_tokenizers_wrappers.push(eq.into());
            }
        }

        for split in self.splits.iter() {
            let res = Split::new(split.as_str(), SplitDelimiterBehavior::Contiguous, false);
            if let Err(err) = res {
                return Err(err.to_string());
            }
            if let Ok(eq) = res {
                pre_tokenizers_wrappers.push(eq.into());
            }
        }

        pre_tokenizers_wrappers.push(CharDelimiterSplit::new(' ').into());
        pre_tokenizers_wrappers.push(CharDelimiterSplit::new('\n').into());
        pre_tokenizers_wrappers.push(CharDelimiterSplit::new(',').into());

        let pre_tokenizer = Sequence::new(pre_tokenizers_wrappers);

        let mut variables_schema = None;
        if self.variables.0.len() > 0 && self.variables.1.len() > 0 {
            let res = AhoCorasick::new(&self.variables.0);
            if let Err(err) = res {
                return Err(err.to_string());
            }
            if let Ok(aho) = res {
                let mut reg = Vec::new();
                'regex_loop: for rgx in self.variables.1.iter() {
                    let res = RegexBuilder::new(rgx).build();
                    if let Ok(r) = res {
                        reg.push(r);
                        continue 'regex_loop;
                    }
                    if let Err(e) = res {
                        return Err(e.to_string());
                    }
                }
                variables_schema = Some(VariableSchema {
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
            secret_regex,
            variables_schema,
            pre_tokenizer,
        })
   }
}

#[cfg(test)]
mod tests {
    use super::*;

    const given_test_data: &str = r#"
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
        let Ok(scanner) = Builder::new().
            with_splits(&[", ", " - ", " + ", " / ", " * "]).
            with_secret_regexes(&[r#"KEY-----[\a-zA-Z0-9]*-----END"#]).
            with_variables(&["auth_uri", "token_uri","auth_provider_x509_cert_url"], &[r#"https://[a-zA-Z-0-9./]*"#]).try_build_scanner() else {
                    assert!(false);
                    return;
                };
        let Ok(()) = scanner.scan(given_test_data) else {
            assert!(false);
            return;
        };

        println!("Greate success....");
    }
}
