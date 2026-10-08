//! Launch-time measurement (spec target: launch to first interactive frame
//! < 400 ms).
//!
//! Every launch logs one INFO line with the phase breakdown, in milliseconds
//! since the OS created the process (so image and DLL loading before `main`
//! is included). No paths, no user data.
//!
//! `PURGEKIT_LAUNCH_TIMING=1` also prints the line to stderr.
//! `PURGEKIT_LAUNCH_TIMING=exit` prints it and quits after the first frame,
//! so a script can launch the app repeatedly and collect samples.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

pub const ENV: &str = "PURGEKIT_LAUNCH_TIMING";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Log,
    Print,
    PrintAndExit,
}

impl Mode {
    pub fn from_env() -> Self {
        Self::parse(std::env::var(ENV).ok().as_deref())
    }

    fn parse(v: Option<&str>) -> Self {
        match v {
            Some("exit") => Mode::PrintAndExit,
            Some(v) if !v.is_empty() && v != "0" => Mode::Print,
            _ => Mode::Log,
        }
    }
}

pub struct LaunchTimer {
    /// Process age when `main` started; `None` if the OS query failed.
    pre_main: Option<Duration>,
    start: Instant,
    marks: Vec<(&'static str, Duration)>,
    pub mode: Mode,
}

impl LaunchTimer {
    /// Call first thing in `main`.
    pub fn start(pre_main: Option<Duration>) -> Self {
        LaunchTimer {
            pre_main,
            start: Instant::now(),
            marks: Vec::new(),
            mode: Mode::from_env(),
        }
    }

    /// Records the end of a phase.
    pub fn mark(&mut self, phase: &'static str) {
        self.marks.push((phase, self.start.elapsed()));
    }

    /// One line: `total=..ms pre_main=..ms phase=+..ms ...` where each phase is
    /// the time since the previous mark.
    pub fn summary(&self) -> String {
        let base = self.pre_main.unwrap_or_default();
        let total = base + self.marks.last().map(|m| m.1).unwrap_or_default();
        let ms = |d: Duration| d.as_secs_f64() * 1000.0;
        let mut s = format!("total={:.1}ms", ms(total));
        match self.pre_main {
            Some(p) => {
                let _ = write!(s, " pre_main={:.1}ms", ms(p));
            }
            None => s.push_str(" pre_main=unknown"),
        }
        let mut prev = Duration::ZERO;
        for (name, at) in &self.marks {
            let _ = write!(s, " {name}=+{:.1}ms", ms(at.saturating_sub(prev)));
            prev = *at;
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parsing() {
        assert_eq!(Mode::parse(None), Mode::Log);
        assert_eq!(Mode::parse(Some("")), Mode::Log);
        assert_eq!(Mode::parse(Some("0")), Mode::Log);
        assert_eq!(Mode::parse(Some("1")), Mode::Print);
        assert_eq!(Mode::parse(Some("exit")), Mode::PrintAndExit);
    }

    #[test]
    fn summary_lists_phases_in_order() {
        let mut t = LaunchTimer::start(Some(Duration::from_millis(50)));
        t.marks = vec![
            ("a", Duration::from_millis(10)),
            ("b", Duration::from_millis(30)),
        ];
        assert_eq!(
            t.summary(),
            "total=80.0ms pre_main=50.0ms a=+10.0ms b=+20.0ms"
        );
    }
}
