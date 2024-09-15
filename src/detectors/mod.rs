pub mod errors;
pub mod regex;
pub mod fingerprint;

use std::fmt::Debug;
use crate::lines::LinesEndsProvider;
use crossbeam_channel::Sender;
use crate::reporter::Input;

/// Scanner offers scanning capabilities.
/// Scanning returns result of all found secrets locations.
///
pub trait Scanner: Debug {
    fn scan(&self, lines_ends: &impl LinesEndsProvider, s: &str, file: &str, branch: &str, sx: Sender<Option<Input>>);
}
