use clap::{arg, command, error::ErrorKind, value_parser, Command, Error};
use crossbeam_utils::sync::WaitGroup;
use paton::preprocessor::cleanup_large_spaces;
use paton::secret::Inspector;
use std::fmt::Write;
use std::fs::read_to_string;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use threadpool::Builder;
use walkdir::WalkDir;

const THREADS_NUM: usize = 8;
const DO_NOT_SCAN: [&str; 2] = [".git", ".DS_Store"];

fn main() {
    let cmd = Command::new("paton")
          .bin_name("paton")
          .subcommand_required(true)
          .about("Paton scans for secrets according to configurations patterns.")
          .subcommand(
              command!("filesystem")
              .about("Scan filesystem")
              .arg(
                  arg!(--"path" <Path> "Path to direcory to scan.")
                      .value_parser(value_parser!(PathBuf)),
              ).arg(
                  arg!(--"config" <Path> "Path to config YAML file used for scanner configuration.").value_parser(value_parser!(PathBuf)),
          )
          );
    let matches = cmd.get_matches();
    match matches.subcommand() {
        Some(("filesystem", matches)) => {
            match scan(
                matches.get_one::<PathBuf>("path"),
                matches.get_one::<PathBuf>("config"),
            ) {
                Ok(s) => println!("[ 📋 Scanner report ] :\n{s}"),
                Err(e) => println!("[ 🤷 Failure ]: {}", e.to_string()),
            }
        }
        _ => println!("Unknown command. Please check help."),
    };
}

fn scan(path: Option<&PathBuf>, config: Option<&PathBuf>) -> Result<String, Error> {
    let start = Instant::now();
    let Some(path) = path else {
        return Err(Error::new(ErrorKind::InvalidValue));
    };
    let Some(config_path) = config else {
        return Err(Error::new(ErrorKind::InvalidValue));
    };

    let inspector = Arc::new(Inspector::try_new(
        config_path.to_str().unwrap_or_default(),
    )?);

    let pool = Builder::new().num_threads(THREADS_NUM).build();
    let report = Arc::new(Mutex::new(String::new()));
    let wg = WaitGroup::new();

    'walker: for entry in WalkDir::new(path) {
        let Ok(entry) = entry else {
            continue 'walker;
        };
        if let Some(dir_name) = entry.path().to_str() {
            for pattern in DO_NOT_SCAN.iter() {
                if dir_name.contains(pattern) {
                    continue 'walker;
                }
            }
        }
        if entry.file_type().is_dir() {
            continue 'walker;
        }

        let entry = entry.into_path();
        let inspector = inspector.clone();
        let report = report.clone();
        let wg = wg.clone();

        pool.execute(move || {
            let Ok(file_data) = read_to_string(entry.as_path()) else {
                let Ok(mut report) = report.lock() else {
                    drop(wg);
                    return;
                };
                let _ = (*report).write_str(&format!(
                    "File {} not an UTF-8 format\n",
                    entry.as_path().to_str().unwrap_or_default(),
                ));
                drop(wg);
                return;
            };
            let file_data = cleanup_large_spaces(&file_data);
            let evidences = inspector.scan(&file_data);
            if evidences.len() == 0 {
                drop(wg);
                return;
            }
            let Ok(mut report) = report.lock() else {
                drop(wg);
                return;
            };
            let _ = (*report).write_str(&format!(
                "File {} result:\n",
                entry.as_path().to_str().unwrap_or_default(),
            ));
            for evidence in evidences {
                let _ = report.write_str(&format!("{evidence}\n"));
            }
            drop(wg);
        });
    }
    wg.wait();

    let Ok(mut report) = report.lock() else {
        return Err(Error::new(ErrorKind::Io));
    };
    let duration = start.elapsed();
    let _ = (*report).write_str(&format!(
        "Scanning took {} milliseconds.\n",
        duration.as_millis()
    ));

    return Ok(report.to_owned());
}
