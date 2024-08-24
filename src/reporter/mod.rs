use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::iter::Iterator;
use std::rc::Rc;
use std::sync::Mutex;
use std::fmt::{Debug, Display};
use std::io::Write;
use crossbeam_channel::{select, Receiver, Sender};
use crate::result::{Secret, DecoderType, DetectorType};
use std::time::Instant;

const REPORT_HEADER: &str = "[ 📋 SCANNING REPORT 📋 ]";
const REPORT_FOOTER: &str = "[ 📋 --------------- 📋 ]";
const GUESS_ANALITICS_CAPACITY: usize = 4096;
const GUESS_CACHE_CAPACITY: usize = 1024 * 1000 * 8; // 1MB

/// ReportWrite compounds trait Write and Debug.
///
pub trait ReportWrite : Write + Debug {}

#[derive(Debug)]
/// Output determines the output of the Reporter.
pub enum Output {
    StdOut,
    Writer(Rc<Mutex<Box<dyn ReportWrite>>>),
    Receiver(Sender<Option<String>>)
}

#[derive(Debug)]
pub enum Input {
    Finding(Secret),
    Bytes(usize),
    Detectors(usize),
}

/// Reporter reports received secrets to specified Output.
/// Reporter isn't thread safe. Wrap it in Atomic Referance Counter to deal safely with the concurency.
pub trait Reporter :Debug {
    /// Sets output, shall be used before receive function is run.
    fn set_output(&mut self, output: Output);
    /// Receive reads the output from the channel and formats the output passing it to preset Output.
    fn receive(&mut self, rx_secret: Receiver<Option<Input>>);
}

#[derive(Debug)]
struct Scribe {
    output: Output,
    files_count: usize,
    bytes_count: usize,
    secret_count: usize,
    detectors_total_count: usize,
    detector_type_counts: HashMap<DetectorType, usize>,
    decoder_type_counts: HashMap<DecoderType, usize>,
    branch_type_counts: HashMap<String, usize>,
    hasher: Option<fn (secret: &Secret) -> String>,
    deduplicator: RefCell<Option<HashSet<String>>>,
    timer: Option<Instant>,
    cache: RefCell<String>,
}

impl Reporter for Scribe {
    #[inline(always)]
    fn receive(&mut self, rx_secret: Receiver<Option<Input>>) {
        self.to_output(&REPORT_HEADER);
        'printer: loop {
            select! {
                recv(rx_secret) -> message => match message {
                    Ok(m) => match m {
                        Some(s) => {
                            if let None = self.timer {
                                self.timer = Some(Instant::now());
                            }
                            match s {
                                Input::Finding(s) => {
                                    if self.is_duplicate(&s) {
                                        continue 'printer;
                                    }
                                    self.to_output(&s);
                                    self.update_analitics(&s);
                                    if self.cache.borrow().len() > GUESS_CACHE_CAPACITY - 1024 {
                                        self.flush();
                                    }
                                },
                                Input::Bytes(b) => self.update_files_scanned(b),
                                Input::Detectors(c) => self.detectors_total_count = c,
                            }
                        },
                        None => break 'printer,
                    },
                    Err(_) => break 'printer,
                },
            }
        }
        self.to_output(&REPORT_FOOTER);
        self.to_output(&"\n");
        self.formatted_analitics_to_output();
        if let Some(timer) = self.timer{
            let duration = timer.elapsed();
            self.to_output(&format!("Processing data took {} milliseconds.\n", duration.as_millis()).to_owned());
        }
        self.flush()
    }

    #[inline(always)]
    fn set_output(&mut self, output: Output) {
        self.output = output;
    }
}

impl Scribe {
    #[inline(always)]
    fn to_output(&self, s: &impl Display) {
        match &self.output {
            Output::StdOut => self.cache.borrow_mut().push_str(&format!("{s}\n")),
            Output::Writer(b) => {
                if let Ok(mut b) = b.lock() {
                    let _ = b.write(format!("{s}\n").as_bytes());
                }
            },
            Output::Receiver(rx) => {let _ = rx.send(Some(format!("{s}\n").to_string()));},
        };
    }

    #[inline(always)]
    fn flush(&mut self) {
        match &self.output {
            Output::StdOut => {
                println!("{}", self.cache.borrow());
                self.cache.borrow_mut().clear();
            },
            Output::Writer(_) => (),
            Output::Receiver(_) => (),
        };
    }

    #[inline(always)]
    fn update_analitics(&mut self, s: &Secret) {
        self.secret_count += 1;
        self.decoder_type_counts.entry(s.decoder_type.to_owned()).and_modify(|v| *v += 1).or_insert(1);
        self.detector_type_counts.entry(s.detector_type.to_owned()).and_modify(|v| *v += 1).or_insert(1);
        self.branch_type_counts.entry(s.branch.clone()).and_modify(|v| *v += 1).or_insert(1);
    }

    #[inline(always)]
    fn formatted_analitics_to_output(&self) {
        self.formatted_in_loop_to_output(self.decoder_type_counts.iter(), " FOUND SECRETS PER DECODER ", "Decoder Type");
        self.formatted_in_loop_to_output(self.detector_type_counts.iter(), " FOUND SECRETS PER DETECTOR ", "Detector Type");
        self.formatted_in_loop_to_output(self.branch_type_counts.iter(), " FOUND SECRETS PER BRANCH ", "Branch Name");
        self.formatted_header(&" SCAN STATISTICS ");
        self.formatted_single_param(self.detectors_total_count, &"Number of detectors used in scanning");
        self.formatted_single_param(self.secret_count, &"Total found secrets");
        self.formatted_single_param(self.files_count, &"Scanned files");
        self.formatted_single_param(
            &format!("{:.4}", if self.secret_count > 0 && self.files_count > 0 { self.secret_count as f64 / self.files_count as f64 } else { 0.0 }),
            &" Leaked secrets per file");
        let (bytes, unit) = Self::bytes_human_readable(self.bytes_count);
        self.formatted_single_param(format!("{:.3}",bytes), &unit);
    }

    #[inline(always)]
    fn formatted_header(&self, header: &str) {
        self.to_output(&format!("|{0:=^59}|", &format!("{header}")));
    }

    #[inline(always)]
    fn formatted_in_loop_to_output<T, E>(&self, iter: impl Iterator<Item = (T, E)>, header: &str, title: &str)
    where
        T: Display,
        E: Display,
    {
        self.formatted_header(header);
        self.to_output(&format!("|{0:-^59}|", ""));
        self.to_output(&format!("| {0: ^46} | {1: ^8} |", title, "Found"));
        self.to_output(&format!("|{0:-^59}|", ""));
        for (k, v) in iter {
            self.to_output(&format!("| {0: ^46} | {1: ^8} |", format!("{k}"), format!("{v}")));
        }
        self.to_output(&format!("|{0:=^59}|", "="));
        self.to_output(&"");
    }

    #[inline(always)]
    fn formatted_single_param<T>(&self, param: T, title: &str)
    where T: Display
    {
        self.to_output(&format!("|{0:-^59}|", ""));
        self.to_output(&format!("| {0: ^46} | {1: ^8} |", title, param));
        self.to_output(&format!("|{0:=^59}|", ""));
    }

    #[inline(always)]
    fn is_duplicate(&self, s: &Secret) -> bool {
        let mut deduplicator = self.deduplicator.borrow_mut();
        if let Some(dupl) = deduplicator.as_mut() {
            let Some(f) = self.hasher else {
                return false;
            };
            return !dupl.insert(f(s));
        }

        false
    }

    #[inline(always)]
    fn update_files_scanned(&mut self, bytes: usize) {
        self.files_count += 1;
        self.bytes_count += bytes * 8;
    }

    #[inline(always)]
    fn bytes_human_readable(bytes: usize) -> (f64, String) {
        if bytes > 1000000000 {
            return (bytes as f64 / 1000000000.0, "Scanned GB".to_string())
        }
        if bytes > 1000000 {
            return (bytes as f64 / 1000000.0, "Scanned MB".to_string())
        }
        if bytes > 1000 {
            return (bytes as f64 / 1000.0, "Scanned KB".to_string())
        }
        (bytes as f64, "Scanned B".to_string())
    }
}

/// Creates new Reporter.
#[inline(always)]
pub fn new(output: Output, dedup: u8) -> impl Reporter {
    return Scribe{
        output,
        files_count: 0,
        bytes_count: 0,
        secret_count: 0,
        detectors_total_count: 0,
        detector_type_counts: HashMap::with_capacity(GUESS_ANALITICS_CAPACITY),
        decoder_type_counts: HashMap::with_capacity(GUESS_ANALITICS_CAPACITY),
        branch_type_counts: HashMap::with_capacity(GUESS_ANALITICS_CAPACITY),
        hasher: match dedup {
            0 => None,
            1 => Some(hasher_level_branch),
            2.. => Some(hasher_level_file),
        },
        deduplicator: if dedup > 0 {
            RefCell::new(Some(HashSet::with_capacity(GUESS_ANALITICS_CAPACITY)))
        } else {
            RefCell::new(None)
        },
        timer: None,
        cache: RefCell::new(String::with_capacity(GUESS_CACHE_CAPACITY)),
    }
}

#[inline(always)]
fn hasher_level_file(s: &Secret) -> String {
    format!("{}:{}", s.file, s.line).to_string()
}

#[inline(always)]
fn hasher_level_branch(s: &Secret) -> String {
    format!("{}:{}:{}", s.file, s.line, s.branch).to_string()
}
