use std::collections::HashMap;
use tokenizers::pre_tokenizers::delimiter::CharDelimiterSplit;
use tokenizers::pre_tokenizers::{sequence::Sequence, split::Split};
use tokenizers::tokenizer::normalizer::SplitDelimiterBehavior;
use tokenizers::{OffsetReferential, OffsetType, PreTokenizedString, PreTokenizer};


/// Scanner offers scanning capabilities.
/// Scanning returns result of all found secrets locations.
///
pub trait Scanner {
    fn scan(&self, s: &str) -> Result<(), String>;
}

#[derive(Debug)]
struct Scan{
    secret_regex: Vec<String>,
    variables: Vec<String>,
    assigments: Vec<String>,
    pre_tokenizer: Sequence,
}

impl Scanner for Scan {
    fn scan(&self, s: &str) -> Result<(), String> {
        let mut detector = Detection::new(self);
        detector.detect(s)
    }
}

#[derive(Debug)]
struct Detection<'a> {
    tokens_locations: HashMap<String, u32>,
    assignments_locations: HashMap<u32, u32>,
    scanner: &'a Scan,
}

impl<'a> Detection<'a> {
    fn new(s: &'a Scan) -> Self {
        Self {
            tokens_locations: HashMap::new(),
            assignments_locations: HashMap::new(),
            scanner: s,
        }
    }

    fn detect(&'a mut self, s: &str) -> Result<(), String> {
        let mut pre_tokenized = PreTokenizedString::from(s);
        if let Err(err)  = self.scanner.pre_tokenizer.pre_tokenize(&mut pre_tokenized) {
            return Err(err.to_string());
        }
        for token in pre_tokenized
            .get_splits(OffsetReferential::Original, OffsetType::Byte)
            .iter()
        {
            println!("TOKEN: [ {:?} ]", token);
        }

        Ok(())
    }
}

/// Builds the detector.
#[derive(Debug)]
pub struct Builder {
    assignemnts: Vec<String>,
    splits: Vec<String>,
    secret_regexes: Vec<String>,
    variables: Vec<String>,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            assignemnts: Vec::new(),
            splits: Vec::new(),
            secret_regexes: Vec::new(),
            variables: Vec::new(),
        }
    }

    /// Populates assigments with given paterns.
    /// Assignemnts means value after the pattern is asigned to value before the pattern.
    ///
    pub fn with_assignemts(&mut self, patterns: &[&str]) -> &mut Self {
        for pattern in patterns.iter() {
            self.assignemnts.push(pattern.to_string())
        }
        self
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
    pub fn with_variables(&mut self, patterns: &[&str]) -> &mut Self {
        for pattern in patterns.iter() {
            self.variables.push(pattern.to_string());
        }
        self
    }

    /// Tries to build a scanner.
    ///
    pub fn try_build_scanner(&self) -> Result<impl Scanner, String>  {
        let mut pre_tokenizers_wrappers = Vec::new();

        for reg in self.secret_regexes.iter() {
            let res = Split::new(reg.as_str(), SplitDelimiterBehavior::Contiguous, false);
            if let Err(err) = res {
                return Err(err.to_string());
            }
            if let Ok(eq) = res {
                pre_tokenizers_wrappers.push(eq.into());
            }
        }

        for assignment in self.assignemnts.iter() {
            let res = Split::new(assignment.as_str(), SplitDelimiterBehavior::Contiguous, false);
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
        pre_tokenizers_wrappers.push(CharDelimiterSplit::new(':').into());
        pre_tokenizers_wrappers.push(CharDelimiterSplit::new(',').into());

        let pre_tokenizer = Sequence::new(pre_tokenizers_wrappers);

        Ok(Scan {
            secret_regex: self.secret_regexes.to_owned(),
            variables: self.variables.to_owned(),
            assigments: self.assignemnts.to_owned(),
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
        let Ok(mut scanner) = Builder::new().
            with_assignemts(&[": ", " => ", " = ", " -> "]).
            with_splits(&[", ", " - ", " + ", " / ", " * "]).
            with_secret_regexes(&[r#"-----BEGIN PRIVATE KEY-----[\a-zA-Z0-9]*-----END PRIVATE KEY-----"#]).
            with_variables(&["project_id", "private_key_id", "private_key",
                    "client_email", "client_id", "auth_uri", "token_uri",
                    "auth_provider_x509_cert_url","client_x509_cert_url",
                ]).try_build_scanner() else {
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
