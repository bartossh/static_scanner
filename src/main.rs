use clap::{arg, command, error::ErrorKind, value_parser, Command, Error};
use crossbeam_channel::{unbounded, Receiver, Sender};
use rogue::detectors::regex::Schema;
use rogue::executor::{Config, Executor};
use rogue::reporter::{new as new_reporter, Format, Input, Output, Reporter};
use crossbeam_utils::sync::WaitGroup;
use rogue::repository::dtos::{
    AsBytesToSigned, ContributorCreateDto, Group, RegexConfigurationCreateDto, RegexConfigurationDataDto, RegexConfigurationPagginateQueryDto
};
use rogue::repository::Http2Agent;
use rogue::secure::Guard;
use rogue::source::{BranchLevel, DataSource};
use std::collections::HashMap;
use std::path::PathBuf;
use std::thread::{sleep, spawn};
use std::include_bytes;
use std::convert::Into;
use std::time::{Duration, SystemTime};
use inquire::Text;

const PACKAGE_OMIT: &str = ".npm/ .npmrc/ .git/ venv/ virtualenv/ .gem/ target/ bin/ .DS_Store/";
const REMOTE_REPO_URL: &str = "https://127.0.0.1:8080";

fn main() {
    let cert_bytes = include_bytes!("../certs/ca-cert.pem");
    let cmd = Command::new("rogue")
          .bin_name("rogue")
          .subcommand_required(true)
          .about("Detector scans for secrets according to configurations patterns.")
          .subcommand(
              command!("workshop")
              .about("Provides workshop functionalities, creating account. reading, saving and sharing configuration.")
              .arg(
                  arg!(--"private" <Path> "Path to RSA private key. It works with 4096 length key only.").value_parser(value_parser!(PathBuf)),
              ).arg(
                  arg!(--"public" <Path> "Path to RSA public key.").value_parser(value_parser!(PathBuf)),
              ).arg(
                  arg!(--"keys-create" "Create RSA keys."),
              ).arg(
                  arg!(--"account-create" "Create account in the remote repository."),
              ).arg(
                  arg!(--"config-create" <Path> "Creates config from given config path.").value_parser(value_parser!(PathBuf)),
              ).arg(
                  arg!(--"config-read" <Path> "Reads config from the workshop remote repository and saves it to gitven path.").value_parser(value_parser!(PathBuf)),
              ).arg(
                  arg!(--"verified" "Specifies if workshop shall return only verified connfigurations."),
              ).arg(
                  arg!(--"groups" <String> "Space separated names of a groups for query filter. Allowed groups are: common, http, ssl, jwt, credentials, database, key, cookie, seed, hash.").value_parser(value_parser!(String)),
              ).arg(
                  arg!(--"from" <String> "Beginning date in RFC-3339 format to search from, if not specified the unix time 0 is used.").value_parser(value_parser!(String)),
              ).arg(
                  arg!(--"to" <String> "Maximum date in RFC-3339 format to serch to, if not specified now time is used.").value_parser(value_parser!(String)),
          ))
          .subcommand(
              command!("filesystem")
              .about("Scan filesystem")
              .arg(
                  arg!(--"path" <Path> "Path to direcory to scan.").value_parser(value_parser!(PathBuf)),
              ).arg(
                  arg!(--"config" <Path> "Path to config YAML file used for scanner configuration.").value_parser(value_parser!(PathBuf)),
              ).arg(
                  arg!(--"omit" <String> "Space separated file patterns to ommit").value_parser(value_parser!(String)),
              ).arg(
                  arg!(--"dedup" <u64> "Level of de duplications. 0 or not specified - no dedup, 1 - file level dedup").value_parser(value_parser!(u8)),
              ).arg(
                  arg!(--"nodeps" "If specified omits default dependencies such as npm, venv, gems, ect."),
              ).arg(
                  arg!(--"scan-archives" "If specified performs archive scanning."),
              ).arg(
                  arg!(--"scan-binary" "If specified performs binary files scanning."),
              ).arg(
                  arg!(--"json" "Formats output to json, has precedance over yaml."),
              ).arg(
                  arg!(--"yaml" "Formats output to yaml."),
          ))
          .subcommand(
              command!("git")
              .about("Scan remote git repository")
              .arg(
                  arg!(--"url" <String> "URL to git repository to scan.").value_parser(value_parser!(String)),
              ).arg(
                    arg!(--"path" <Path> "Path to direcory to scan.").value_parser(value_parser!(PathBuf)),
              ).arg(
                  arg!(--"config" <Path> "Path to config YAML file used for scanner configuration.").value_parser(value_parser!(PathBuf)),
              ).arg(
                  arg!(--"omit" <String> "Space separated file patterns to ommit").value_parser(value_parser!(String)),
              ).arg(
                  arg!(--"dedup" <u64> "Level of de duplications. 0 or not specified - no dedup, 1 - branch level dedup, 2 - file level dedup.").value_parser(value_parser!(u8)),
              ).arg(
                  arg!(--"nodeps" "If specified omits default dependencies such as npm, venv, gems, ect."),
              ).arg(
                  arg!(--"scan-local" "If specified scans all local brancheses."),
              ).arg(
                  arg!(--"scan-remote" "If specified scans all remote brancheses."),
              ).arg(
                  arg!(--"branches" <String> "If specified scans branches from the given list, otherwise HEAD is scanned or all branches with flag --scan-local or -scan-remote."),
              ).arg(
                  arg!(--"scan-archives" "If specified performs archive scanning."),
              ).arg(
                  arg!(--"scan-binary" "If specified performs binary files scanning."),
              ).arg(
                  arg!(--"json" "Formats output to json, has precedance over yaml."),
              ).arg(
                  arg!(--"yaml" "Formats output to yaml."),
          ));
    let matches = cmd.get_matches();
    match matches.subcommand() {
        Some(("filesystem", matches)) => {
            match scan(
                DataSource::FileSystem,
                matches.get_one::<PathBuf>("path"),
                None,
                matches.get_one::<PathBuf>("config"),
                matches.get_one::<String>("omit"),
                matches.get_one("dedup"),
                matches.get_one("nodeps"),
                None,
                None,
                None,
                matches.get_one("scan-archives"),
                matches.get_one("scan-binary"),
                matches.get_one("json"),
                matches.get_one("yaml"),
            ) {
                Ok(s) => println!("[ 🛰️ Scanner ]\n{}", s),
                Err(e) => println!("[ 🤷 Error ]\n{}", e.to_string()),
            }
        }
        Some(("git", matches)) => {
            match scan(
                DataSource::Git,
                matches.get_one::<PathBuf>("path"),
                matches.get_one::<String>("url"),
                matches.get_one::<PathBuf>("config"),
                matches.get_one::<String>("omit"),
                matches.get_one("dedup"),
                matches.get_one("nodeps"),
                matches.get_one("scan-local"),
                matches.get_one("scan-remote"),
                matches.get_one("branches"),
                matches.get_one("scan-archives"),
                matches.get_one("scan-binary"),
                matches.get_one("json"),
                matches.get_one("yaml"),
            ) {
                Ok(s) => println!("[ 🛰️ Scanner ]\n{}", s),
                Err(e) => println!("[ 🤷 Error ]\n{}", e.to_string()),
            }
        }
        Some(("workshop", matches)) => {
            match repo(
                REMOTE_REPO_URL,
                cert_bytes,
                matches.get_one::<PathBuf>("private"),
                matches.get_one::<PathBuf>("public"),
                matches.get_one("keys-create"),
                matches.get_one("account-create"),
                matches.get_one::<PathBuf>("config-create"),
                matches.get_one::<PathBuf>("config-read"),
                matches.get_one::<bool>("verified"),
                matches.get_one::<String>("groups"),
                matches.get_one::<String>("from"),
                matches.get_one::<String>("to"),
            ) {
                Ok(s) => println!("[ 🏗  Workshop ]\n{}", s),
                Err(e) => println!("[ 🤷 Error ]\n{}", e.to_string()),
            }
        }
        _ => println!("Unknown command. Please check help."),
    };
}

#[inline(always)]
fn scan(
    data_source: DataSource,
    path: Option<&PathBuf>,
    url: Option<&String>,
    config: Option<&PathBuf>,
    omit: Option<&String>,
    dedup: Option<&u8>,
    nodeps: Option<&bool>,
    local: Option<&bool>,
    remote: Option<&bool>,
    branches: Option<&String>,
    decompress: Option<&bool>,
    read_binary: Option<&bool>,
    format_to_json: Option<&bool>,
    format_to_yaml: Option<&bool>,
) -> Result<String, Error> {
    let dedup = dedup.unwrap_or(&0);
    let nodeps = match nodeps {
        Some(b) => if *b { Some(PACKAGE_OMIT.to_string())} else { None },
        None => None,
    };

    let decompress = if let Some(d) = decompress { *d }else{ false };
    let read_binary = if let Some(d) = read_binary { *d }else{ false };
    let format_to_json = if let Some(d) = format_to_json { *d }else{ false };
    let format_to_yaml = if let Some(d) = format_to_yaml { *d }else{ false };

    let format = if format_to_json { Format::Json } else if format_to_yaml { Format::Yaml } else { Format::Text };

    let (sx_input, rx_input): (Sender<Option<Input>>, Receiver<Option<Input>>) = unbounded();

    let branch_level = branch_level(&local, &remote);

    let branches = &match branches {
        Some(b) => match b.as_str() {
            "" => None,
            _ => Some(b.split(" ").map(|s| s.to_owned()).collect::<Vec<String>>()),
        },
        None => None,
    };

    let mut executor = match Executor::new(&Config{data_source, path, url, config, omit, nodeps, branch_level, branches, sx_input, decompress, scan_binary: read_binary}){
        Ok(e) => Ok(e),
        Err(e) => Err(Error::raw(ErrorKind::InvalidValue, e)),
    }?;

    let wg_print = WaitGroup::new();
    let wg_print_clone = wg_print.clone();

    let dedup = dedup.clone();
    spawn(move || {
        let mut reporter = new_reporter(Output::StdOut, format, dedup);
        reporter.receive(rx_input);
        drop(wg_print_clone);
    });

    let result = executor.execute();

    wg_print.wait();

    match result {
        Ok(()) => Ok("Success".to_owned()),
        Err(e) => Err(Error::raw(ErrorKind::Format, e)),
    }
}

#[inline(always)]
fn repo(
    url: &str,
    cert: &[u8],
    priv_pem_path: Option<&PathBuf>,
    pub_pem_path: Option<&PathBuf>,
    keys_create: Option<&bool>,
    account_create: Option<&bool>,
    regex_config_read_path: Option<&PathBuf>,
    regex_config_save_path: Option<&PathBuf>,
    verified: Option<&bool>,
    groups: Option<&String>,
    from: Option<&String>,
    to: Option<&String>,
) -> Result<String, Error> {
    let keys_create = if let Some(keys_create) = keys_create { *keys_create } else { false };
    let account_create = if let Some(account_create) = account_create { *account_create } else { false };

    if let Some(msg) = resolve_conflicting_flags(keys_create, account_create, &regex_config_read_path, &regex_config_save_path) {
        return Err(Error::raw(ErrorKind::ArgumentConflict, msg));
    };

    let http_agent = Http2Agent::new(url.to_string(), cert);
    let Ok(agent) = http_agent else {
        return Err(Error::raw(ErrorKind::InvalidValue, format!("{:?}", http_agent.err())));
    };

    if let Some(regex_config_path) = regex_config_save_path {
        let from: SystemTime = if let Some(f) = from {
            match chrono::DateTime::parse_from_rfc3339(f) {
                Ok(d) => Ok(d.into()),
                Err(e) => Err(Error::raw(ErrorKind::Format, e.to_string())),
            }?
        } else { SystemTime::from(SystemTime::UNIX_EPOCH) };
        let to: SystemTime = if let Some(t) = to {
            match chrono::DateTime::parse_from_rfc3339(t) {
                Ok(d) => Ok(d.into()),
                Err(e) => Err(Error::raw(ErrorKind::Format, e.to_string())),
            }?
        } else { SystemTime::now() };

        let verified = if let Some(v) = verified { Some(*v) } else { None };
        let groups = if let Some(g) = groups { Some(g.split(" ").collect()) } else { None };

        return regex_read(&agent, regex_config_path, verified, groups, &from, &to);
    }

    let Some(priv_pem_path) = priv_pem_path else {
        return Err(Error::raw(ErrorKind::InvalidValue, "provide private key path".to_string()));
    };

    let Some(pub_pem_path) = pub_pem_path else {
        return Err(Error::raw(ErrorKind::InvalidValue, "provide public key path".to_string()));
    };

    if keys_create {
        return keys_create_and_save(priv_pem_path, pub_pem_path);
    }

    let guard = match Guard::read_from_files(priv_pem_path, pub_pem_path) {
        Ok(g) => Ok(g),
        Err(e) => Err(
            Error::raw(
                ErrorKind::Io,
                format!("cannot read keys from paths [ {} ] [ {} ], {}",
                    priv_pem_path.to_str().unwrap_or_default(),
                    pub_pem_path.to_str().unwrap_or_default(),
                    e.to_string(),
                ),
            ),
        ),
    }?;

    if account_create {
        return account_create_in_workshop(&guard, &agent);
    }

    if let Some(regex_config_path) = regex_config_read_path {
        return regex_create(&guard, &agent, regex_config_path);
    }

    Err(Error::raw(ErrorKind::InvalidSubcommand, "subcommad was not specified".to_string()))
}

#[inline(always)]
fn resolve_conflicting_flags(
    keys_create: bool,
    account_create: bool,
    config_create: &Option<&PathBuf>,
    config_read: &Option<&PathBuf>) -> Option<String> {
        let conf_create = if let Some(_) = config_create { true } else { false };
        let conf_read = if let Some(_) = config_read { true } else { false };
        for pair in [
            (keys_create, account_create, "keys-create, account-create"),
            (keys_create, conf_create, "keys-create, config-create"),
            (keys_create, conf_read, "keys-create, config-read"),
            (account_create, conf_create, "account-create, config-create"),
            (account_create, conf_read, "account-create, config-read"),
            (conf_create, conf_read, "config-create, config-read"),
            ].iter() {
                if pair.0 && pair.1 {
                    return Some(format!("Two conflicting flags specified in one command, cannot process {} at once", pair.2));
                }
        }
        None
}

#[inline(always)]
fn branch_level(local: &Option<&bool>, remote: &Option<&bool>) -> BranchLevel {
    let local = local.unwrap_or(&false);
    let remote = remote.unwrap_or(&false);
    if *local && *remote {
        return BranchLevel::All
    }
    if *local {
        return BranchLevel::Local;
    }
    if *remote {
        return  BranchLevel::Remote;
    }

    BranchLevel::Head
}

#[inline(always)]
fn keys_create_and_save(priv_path: &PathBuf, pub_path: &PathBuf) -> Result<String, Error> {
    let guard = match Guard::generate() {
        Ok(g) => Ok(g),
        Err(e) => Err(Error::raw(ErrorKind::Io, format!("cannot create openssl wrapper, {}", e.to_string()))),
    }?;

    match guard.save_keys_to_files(priv_path, pub_path) {
        Ok(()) => Ok(
            format!(
                "Saved private key to [ {} ]\nSaved public key to [ {} ]",
                priv_path.to_str().unwrap_or_default(),
                pub_path.to_str().unwrap_or_default()
            )
        ),
        Err(e) => Err(Error::raw(ErrorKind::Io, format!("cannot save keys on disk, {}", e.to_string()))),
    }
}

#[inline(always)]
fn account_create_in_workshop(guard: &Guard, agent: &Http2Agent) -> Result<String, Error> {
    let pub_pem = match guard.get_pub_key_pem() {
        Ok(p) => Ok(p),
        Err(e) => Err(Error::raw(ErrorKind::Io, format!("cannot read security guard public PEM key, {}", e.to_string()))),
    }?;

    let signature = match guard.sign(&pub_pem.as_bytes()) {
        Ok(s) => Ok(s),
        Err(e) => Err(Error::raw(ErrorKind::Io, format!("cannot sign PEM public key, {}", e.to_string()))),
    }?;

    let contributor_dto = ContributorCreateDto{
        public_pem_key: pub_pem.to_string(),
        signature: match signature.try_into() {
            Ok(s) => Ok(s),
            Err(_) => Err(Error::raw(ErrorKind::Io, "cannot convert signature vector to 64 bytes array".to_string())),
        }?,
    };

    match agent.create_account(&contributor_dto) {
        Ok(()) => Ok("Account has been created successfully".to_string()),
        Err(e) => Err(Error::raw(ErrorKind::Io, format!("cannot create account, {}", e.to_string()))),
    }
}

#[inline(always)]
fn regex_create(guard: &Guard, agent: &Http2Agent, regex_config_path: &PathBuf) -> Result<String, Error> {
    let schemas = match Schema::read_from_yaml_file(regex_config_path) {
        Ok(s) => Ok(s),
        Err(e) => Err(Error::raw(ErrorKind::Io, format!("cannot read regex config from file {:?}, {}", regex_config_path.to_str(),  e.to_string()))),
    }?;

    let mut counter = 0;
    for schema in schemas {
        let mut regex_config_create: RegexConfigurationCreateDto = schema.into();
        regex_config_create.contributor_pem_hash = match guard.pub_key_hash() {
            Ok(h) => Ok(h),
            Err(e) => Err(Error::raw(ErrorKind::Io, format!(
                "Created {} configs in remote repository. Cannot create public key hash, {}",
                counter,
                e.to_string()))),
        }?;
        let signature = match guard.sign(&regex_config_create.bytes_to_sign()) {
            Ok(b) => Ok(b),
            Err(e) => Err(Error::raw(ErrorKind::Io, format!(
                "Created {} configs in remote repository. Cannot sign regex config, {}",
                counter,
                e.to_string()))),
        }?;
        regex_config_create.signature = match signature.try_into() {
            Ok(s) => Ok(s),
            Err(_) => Err(Error::raw(ErrorKind::Io,
                format!("Created {} configs in remote repository. Cannot convert signature vector to 64 bytes array", counter))),
        }?;
        match agent.create_regex_config(&regex_config_create) {
            Ok(()) => Ok(()),
            Err(e) => Err(Error::raw(ErrorKind::Io,
                format!(
                    "Created {} configs in remote repository. Cannot create regex config [ {} ], {}",
                    counter,
                    regex_config_create.name,
                    e.to_string(),
                ),
            )),
        }?;
        println!(
            "created [ {} ] regex config from schema path {}\n",
            regex_config_create.name,
            regex_config_path.to_str().unwrap_or_default(),
        );
        counter+=1;
        sleep(Duration::from_millis(100));
    }

    Ok(format!("\nCreated in workshop repository total of {} cofigurations.\n", counter))
}

#[inline(always)]
fn regex_read(
    agent: &Http2Agent,
    regex_config_path: &PathBuf,
    verified: Option<bool>,
    groups: Option<Vec<&str>>,
    from: &SystemTime,
    to: &SystemTime,
) -> Result<String, Error> {
    let mut next: bool = true;
    let mut from = from.clone();
    let to = to.clone();

    let mut groups_dto = None;
    let mut cache: HashMap<String, RegexConfigurationDataDto> = HashMap::new();

    if let Some(groups) = groups {
        let mut groups_dto_v: Vec<Group> = Vec::with_capacity(groups.len());
        for g in groups {
            let g = match  g.try_into() {
                Ok(g) => Ok(g),
                Err(e) => Err(Error::raw(ErrorKind::InvalidValue, format!("{:?}", e))),
            }?;
            groups_dto_v.push(g);
        }
        groups_dto = Some(groups_dto_v);
    }
    println!("Found cofigurations:");
    while next {
       let config_pagginate = RegexConfigurationPagginateQueryDto{
           from,
           to,
           groups: groups_dto.clone(),
           verified,
       };

       let config_results = match agent.config_pagginate(&config_pagginate) {
           Ok(r) => Ok(r),
           Err(e) => Err(Error::raw(ErrorKind::Io, e.to_string())),
       }?;
       let mut new_found = false;
       if config_results.len() > 0 {
           for cfg in config_results.iter() {
               if let Some(_) =  cache.insert(cfg.name.clone(), cfg.clone()) {
                   continue;
               }
               if cfg.ts > from {
                   from = cfg.ts;
               }
               new_found = true;
               println!("\n - Name: {}\n - Description: {}", cfg.name, cfg.description);
           }
       } else {
           break;
       }
       if !new_found {
           break;
       }

        println!("");
        let yes = Text::new("Do you want to continue quering data? Write 'yes' or 'y' if so.").prompt();
        next = match yes {
            Ok(yes) => if yes.to_lowercase() == "yes" || yes.to_lowercase() == "y" { true } else { false },
            Err(_) => false,
        };
    }

    println!("");
    let yes = Text::new(&format!(
        "Do you want to save downloaded cofigurations to file {} ? Write 'yes' or 'y' if so.",
        regex_config_path.to_str().unwrap_or_default()),
    ).prompt();
    let agreed_to_save = match yes {
        Ok(yes) => if yes.to_lowercase() == "yes" || yes.to_lowercase() == "y" { true } else { false },
        Err(_) => false,
    };

    if !agreed_to_save {
        return Ok(format!("Data wasn't saved to file {}. Maybe next time...", regex_config_path.to_str().unwrap_or_default()));
    }

    let mut schemas: Vec<Schema> = Vec::with_capacity(cache.len());
    for (_, dto) in cache {
        let s = dto.into();
        schemas.push(s);
    }
    match Schema::write_to_yaml_file(regex_config_path, &schemas) {
        Ok(()) => Ok(format!("Saving {} configurations to file {}\n", schemas.len(), regex_config_path.to_str().unwrap_or_default())),
        Err(e) => Err(Error::raw(ErrorKind::Io, format!("{:?}", e))),
    }
}
