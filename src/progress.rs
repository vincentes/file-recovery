//! Progress reporting via indicatif: bytes scanned / total, percentage,
//! files found so far, and ETA. Hidden entirely in --quiet mode.

use indicatif::{ProgressBar, ProgressStyle};

pub struct Reporter {
    bar: ProgressBar,
}

impl Reporter {
    pub fn new(total: u64, quiet: bool, label: &str) -> Self {
        let bar = if quiet {
            ProgressBar::hidden()
        } else {
            let b = ProgressBar::new(total);
            let template = format!(
                "{label} [{{bar:40}}] {{bytes}}/{{total_bytes}} ({{percent}}%) ETA {{eta}} {{msg}}"
            );
            if let Ok(style) = ProgressStyle::with_template(&template) {
                b.set_style(style);
            }
            b
        };
        Self { bar }
    }

    pub fn set(&self, pos: u64) {
        self.bar.set_position(pos);
    }

    pub fn inc(&self, n: u64) {
        self.bar.inc(n);
    }

    pub fn message(&self, msg: String) {
        self.bar.set_message(msg);
    }

    /// Print a line above the bar (used for verbose per-file output).
    pub fn note(&self, msg: &str) {
        self.bar.println(msg);
    }

    pub fn finish(self, msg: &str) {
        self.bar.finish_with_message(msg.to_string());
    }
}
