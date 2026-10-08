//! `tracing` to rotating log files: 5 files of 5 MB in `logs\`.
//! Callers log known-folder tokens and rule IDs, never usernames, paths with
//! usernames, URLs, file contents or credential databases.
//!
//! Formatted lines go over a channel to one writer thread, so a `tracing`
//! call on the UI thread does no file I/O. `flush` waits for the queue; it
//! runs at exit and from the panic hook.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, mpsc};

const WRITER_THREAD: &str = "log-writer";

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

enum Msg {
    Line(Vec<u8>),
    Flush(mpsc::Sender<()>),
}

static QUEUE: OnceLock<mpsc::Sender<Msg>> = OnceLock::new();

#[derive(Clone)]
struct Queue(mpsc::Sender<Msg>);

impl Write for Queue {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // `tracing_subscriber::fmt` writes one whole event per call.
        let _ = self.0.send(Msg::Line(buf.to_vec()));
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Blocks until every queued line is written. No-op before `init` or on the
/// writer thread itself.
pub fn flush() {
    let Some(tx) = QUEUE.get() else { return };
    if std::thread::current().name() == Some(WRITER_THREAD) {
        return;
    }
    let (ack, done) = mpsc::channel();
    if tx.send(Msg::Flush(ack)).is_ok() {
        let _ = done.recv();
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
    let (tx, rx) = mpsc::channel::<Msg>();
    let shared = Arc::new(Mutex::new(r));
    let for_thread = shared.clone();
    let spawned = std::thread::Builder::new()
        .name(WRITER_THREAD.into())
        .spawn(move || {
            for msg in rx {
                let mut r = for_thread.lock().unwrap();
                match msg {
                    Msg::Line(b) => {
                        let _ = r.write_all(&b);
                    }
                    Msg::Flush(ack) => {
                        let _ = r.flush();
                        let _ = ack.send(());
                    }
                }
            }
        });
    let builder = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO);
    let installed = if spawned.is_ok() {
        let q = Queue(tx.clone());
        builder.with_writer(move || q.clone()).try_init().is_ok()
    } else {
        // No writer thread: fall back to writing inline.
        let s = Shared(shared);
        builder.with_writer(move || s.clone()).try_init().is_ok()
    };
    if installed && spawned.is_ok() {
        let _ = QUEUE.set(tx);
        // Keep the last lines before a crash. The panic message is not logged:
        // it can hold paths with the username.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            flush();
            prev(info);
        }));
    }
}
