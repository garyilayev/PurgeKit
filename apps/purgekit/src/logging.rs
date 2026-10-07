//! `tracing` to rotating log files: 5 files of 5 MB in `logs\`.
//! Callers log known-folder tokens and rule IDs, never usernames, paths with
//! usernames, URLs, file contents or credential databases.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const MAX_BYTES: u64 = 5 * 1024 * 1024;
const KEEP: usize = 5;

pub struct Rotating {
    dir: PathBuf,
    file: Option<File>,
    written: u64,
}

impl Rotating {
    fn path(&self, n: usize) -> PathBuf {
        if n == 0 {
            self.dir.join("purgekit.log")
        } else {
            self.dir.join(format!("purgekit.{n}.log"))
        }
    }

    fn open(&mut self) {
        let p = self.path(0);
        self.written = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        self.file = OpenOptions::new().create(true).append(true).open(p).ok();
    }

    fn rotate(&mut self) {
        self.file = None;
        let _ = std::fs::remove_file(self.path(KEEP - 1));
        for n in (0..KEEP - 1).rev() {
            let _ = std::fs::rename(self.path(n), self.path(n + 1));
        }
        self.open();
    }
}

impl Write for Rotating {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written + buf.len() as u64 > MAX_BYTES {
            self.rotate();
        }
        match &mut self.file {
            Some(f) => {
                let n = f.write(buf)?;
                self.written += n as u64;
                Ok(n)
            }
            None => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().map_or(Ok(()), |f| f.flush())
    }
}

#[derive(Clone)]
struct Shared(Arc<Mutex<Rotating>>);

impl Write for Shared {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

pub fn init(dir: PathBuf) {
    let _ = std::fs::create_dir_all(&dir);
    let mut r = Rotating {
        dir,
        file: None,
        written: 0,
    };
    r.open();
    let shared = Shared(Arc::new(Mutex::new(r)));
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || shared.clone())
        .try_init();
}
