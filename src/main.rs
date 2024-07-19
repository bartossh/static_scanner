use clap::{arg, command, error::ErrorKind, value_parser, Command, Error};
use paton::preprocessor::cleanup_large_spaces;
use paton::secret::Inspector;
use std::fmt::Write;
use std::fs::read_to_string;
use std::path::PathBuf;
use std::time::Instant;
use walkdir::WalkDir;

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

fn recursive_walker(root: &PathBuf, mut file_paths: &mut Vec<PathBuf>) {
    for entry in WalkDir::new(root) {
        let Ok(entry) = entry else {
            continue;
        };
        if entry.clone().into_path() == *root {
            continue;
        }
        if entry.file_type().is_dir() {
            recursive_walker(&entry.into_path(), &mut file_paths);
            continue;
        }
        file_paths.push(entry.into_path());
    }
}

fn scan(path: Option<&PathBuf>, config: Option<&PathBuf>) -> Result<String, Error> {
    let start = Instant::now();
    let Some(path) = path else {
        return Err(Error::new(ErrorKind::InvalidValue));
    };
    let Some(config_path) = config else {
        return Err(Error::new(ErrorKind::InvalidValue));
    };

    let inspector = Inspector::try_new(config_path.to_str().unwrap_or_default())?;

    let mut files: Vec<PathBuf> = Vec::new();
    recursive_walker(path, &mut files);

    let mut report: String = String::new();
    for entry in files {
        let Ok(file_data) = read_to_string(entry.as_path()) else {
            let _ = report.write_str(&format!(
                "File {} not an UTF-8 format\n",
                entry.as_path().to_str().unwrap_or_default(),
            ))?;
            continue;
        };
        let file_data = cleanup_large_spaces(&file_data);
        let evidences = inspector.scan(&file_data);
        if evidences.len() == 0 {
            continue;
        }
        report.write_str(&format!(
            "File {} result:\n",
            entry.as_path().to_str().unwrap_or_default(),
        ))?;
        for evidence in evidences {
            let _ = report.write_str(&format!("{evidence}\n"))?;
        }
    }
    let duration = start.elapsed();
    let _ = report.write_str(&format!(
        "Scanning took {} milliseconds.\n",
        duration.as_millis()
    ));

    return Ok(report);
}
