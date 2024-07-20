use clap::{arg, command, error::ErrorKind, value_parser, Command, Error};
use crossbeam_channel::{select, unbounded, Receiver, Sender};
use crossbeam_utils::sync::WaitGroup;
use paton::preprocessor::cleanup_large_spaces;
use paton::secret::{Evidence, Inspector};
use std::fs::read_to_string;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::spawn;
use std::time::Instant;
use threadpool::Builder;
use walkdir::WalkDir;

const THREADS_NUM: usize = 8;
const DO_NOT_SCAN: [&str; 7] = [
    ".git",
    ".DS_Store",
    "target",
    ".zip",
    ".rar",
    ".rpm",
    ".deb",
];

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
                Ok(s) => println!("[ 📋 Finished ]\n{s}"),
                Err(e) => println!("[ 🤷 Failure ]:\n{}", e.to_string()),
            }
        }
        _ => println!("Unknown command. Please check help."),
    };
}

struct Message {
    evidences: Vec<Evidence>,
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
            let file_data = cleanup_large_spaces(&file_data);
            let evidences = inspector.scan(&file_data);
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
