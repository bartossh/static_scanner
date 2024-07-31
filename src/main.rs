use clap::{arg, command, error::ErrorKind, value_parser, Command, Error};
use crossbeam_channel::{select, unbounded, Receiver, Sender};
use static_detector::generic_detector::{Inspector, Scanner};
use crossbeam_utils::sync::WaitGroup;
use std::fs::read_to_string;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::spawn;
use std::time::Instant;
use threadpool::Builder;
use walkdir::WalkDir;

const THREADS_NUM: usize = 8;

fn main() {
    let cmd = Command::new("detector")
          .bin_name("detector")
          .subcommand_required(true)
          .about("Detector scans for secrets according to configurations patterns.")
          .subcommand(
              command!("filesystem")
              .about("Scan filesystem")
              .arg(
                  arg!(--"path" <Path> "Path to direcory to scan.")
                      .value_parser(value_parser!(PathBuf)),
              ).arg(
                  arg!(--"config" <Path> "Path to config YAML file used for scanner configuration.").value_parser(value_parser!(PathBuf)),
              ).arg(
                  arg!(--"omit" <String> "Space separated file patterns to ommit").value_parser(value_parser!(String)),
          )
          );
    let matches = cmd.get_matches();
    match matches.subcommand() {
        Some(("filesystem", matches)) => {
            match scan(
                matches.get_one::<PathBuf>("path"),
                matches.get_one::<PathBuf>("config"),
                matches.get_one::<String>("omit"),
            ) {
                Ok(s) => println!("[ 📋 Finished ]\n{s}"),
                Err(e) => println!("[ 🤷 Failure ]:\n{}", e.to_string()),
            }
        }
        _ => println!("Unknown command. Please check help."),
    };
}

struct Message {
    evidences: Vec<String>,
    file_info: String,
}

fn stdout_print(ch: Receiver<Option<Message>>) {
    println!("[ SCANNING REPORT: ]");
    'printer: loop {
        select! {
            recv(ch) -> message => match message {
                Ok(m) => match m {
                    Some(m) => {
                        println!(
                            "{}",
                            m.file_info,
                        );
                        for evidence in m.evidences {
                            println!("{evidence}\n");
                        }
                    },
                    None => break 'printer,
                },
                Err(_) => break 'printer,
            },
        }
    }
}

fn scan(
    path: Option<&PathBuf>,
    config: Option<&PathBuf>,
    omit: Option<&String>,
) -> Result<String, Error> {
    let start = Instant::now();
    let Some(path) = path else {
        return Err(Error::new(ErrorKind::InvalidValue));
    };
    let Some(config_path) = config else {
        return Err(Error::new(ErrorKind::InvalidValue));
    };

    let mut omit_patterns: Vec<&str> = Vec::new();
    if let Some(patterns) = omit {
        for pattern in patterns.split(" ") {
            omit_patterns.push(pattern)
        }
    }

    let inspector = Arc::new(Inspector::try_new(
        config_path.to_str().unwrap_or_default(),
    )?);

    let pool = Builder::new().num_threads(THREADS_NUM - 1).build();
    let wg = WaitGroup::new();

    let (sx, rx): (Sender<Option<Message>>, Receiver<Option<Message>>) = unbounded();

    let wg_print = WaitGroup::new();

    let wg_print_clone = wg_print.clone();
    spawn(move || {
        stdout_print(rx);
        drop(wg_print_clone);
    });

    'walker: for entry in WalkDir::new(path) {
        let Ok(entry) = entry else {
            continue 'walker;
        };
        if let Some(dir_name) = entry.path().to_str() {
            for pattern in omit_patterns.iter() {
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
        let wg = wg.clone();
        let sx = sx.clone();

        pool.execute(move || {
            let Ok(file_data) = read_to_string(entry.as_path()) else {
                let _ = sx.send(Some(Message {
                    evidences: Vec::new(),
                    file_info: format!(
                        "[ File {} ] not an UTF-8 format",
                        entry.as_path().to_str().unwrap_or_default()
                    ),
                }));
                drop(wg);
                return;
            };
            let Ok(evidences) = inspector.scan(&file_data) else {
                drop(wg);
                return;
            };
            if evidences.len() == 0 {
                drop(wg);
                return;
            }
            let _ = sx.send(Some(Message {
                evidences,
                file_info: format!("[ File {} ]", entry.as_path().to_str().unwrap_or_default()),
            }));
            drop(wg);
        });
    }
    wg.wait();
    let _ = sx.send(None);
    wg_print.wait();

    let duration = start.elapsed();
    return Ok(format!("Scanning took {} milliseconds.\n", duration.as_millis()).to_owned());
}
