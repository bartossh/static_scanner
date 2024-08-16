use clap::{arg, command, error::ErrorKind, value_parser, Command, Error};
use crossbeam_channel::{unbounded, Receiver, Sender};
use static_detector::executor::{BranchLevel, Config, DataSource, Executor};
use static_detector::reporter::{Reporter, Input, Output, new as new_reporter};
use crossbeam_utils::sync::WaitGroup;
use std::path::PathBuf;
use std::thread::spawn;
use std::time::Instant;

const PACKAGE_OMIT: &str = ".npm/ .npmrc/ .git/ venv/ virtualenv/ .gem/ target/ bin/ .DS_Store/";

fn main() {
    let cmd = Command::new("detector")
          .bin_name("detector")
          .subcommand_required(true)
          .about("Detector scans for secrets according to configurations patterns.")
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
            ) {
                Ok(s) => println!("🎉 {s}"),
                Err(e) => println!("🤷 Failure {}", e.to_string()),
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
            ) {
                Ok(s) => println!("[ 🎉 Success ]\n{s}"),
                Err(e) => println!("[ 🤷 Failure ]:\n{}", e.to_string()),
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
) -> Result<String, Error> {
    let start = Instant::now();

    let dedup = dedup.unwrap_or(&0);
    let nodeps = match nodeps {
        Some(b) => if *b { Some(PACKAGE_OMIT.to_string())} else { None },
        None => None,
    };

    let (sx_input, rx_input): (Sender<Option<Input>>, Receiver<Option<Input>>) = unbounded();

    let branch_level = branch_level(&local, &remote);

    let branches = &match branches {
        Some(b) => match b.as_str() {
            "" => None,
            _ => Some(b.split(" ").map(|s| s.to_owned()).collect::<Vec<String>>()),
        },
        None => None,
    };

    let Ok(mut executor) = Executor::new(&Config{data_source, path, url, config, omit, nodeps, branch_level, branches}) else {
        return Err(Error::new(ErrorKind::InvalidValue));
    };

    let wg_print = WaitGroup::new();
    let wg_print_clone = wg_print.clone();

    let dedup = dedup.clone();
    spawn(move || {
        let mut reporter = new_reporter(Output::StdOut, dedup);
        reporter.receive(rx_input);
        drop(wg_print_clone);
    });

    executor.execute(sx_input);

    wg_print.wait();

    let duration = start.elapsed();
    return Ok(format!("Proccessing took {} milliseconds.\n", duration.as_millis()).to_owned());
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
