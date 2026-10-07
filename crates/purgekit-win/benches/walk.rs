//! Walker benchmark: the custom handle-relative walker (returns 128-bit file
//! IDs without opening files) against a `jwalk` baseline over `std::fs`.
//!
//! Tree size: `PURGEKIT_BENCH_FILES` (default 20,000; CI uses 200,000). The
//! fixture is generated once under %TEMP%\purgekit-bench-<n> and reused, so
//! runs after the first measure a warm cache. For a cold run, reboot first.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{Criterion, criterion_group, criterion_main};
use purgekit_core::RelPath;
use purgekit_engine::backend::{FsBackend, WalkEntry, WalkSkip, WalkVisitor};
use purgekit_win::WinFs;

fn fixture() -> (PathBuf, u64) {
    let n: u64 = std::env::var("PURGEKIT_BENCH_FILES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let root = std::env::temp_dir().join(format!("purgekit-bench-{n}"));
    let done = root.join(".complete");
    if !done.exists() {
        let _ = std::fs::remove_dir_all(&root);
        for i in 0..n {
            let dir = root
                .join(format!("d{}", i % 100))
                .join(format!("e{}", i % 37));
            if i < 100 * 37 {
                std::fs::create_dir_all(&dir).unwrap();
            }
            std::fs::write(dir.join(format!("f{i}.bin")), [0u8; 64]).unwrap();
        }
        std::fs::write(&done, b"").unwrap();
    }
    (root, n)
}

struct Count(AtomicU64);

impl WalkVisitor for Count {
    fn cancelled(&self) -> bool {
        false
    }
    fn enter_dir(&self, _: &RelPath) -> bool {
        true
    }
    fn files(&self, batch: Vec<WalkEntry>) {
        self.0.fetch_add(batch.len() as u64, Ordering::Relaxed);
    }
    fn skipped(&self, _: WalkSkip) {}
}

fn bench(c: &mut Criterion) {
    let (root, n) = fixture();
    let mut g = c.benchmark_group(format!("walk_{n}"));
    g.sample_size(10);
    g.bench_function("purgekit_walker", |b| {
        b.iter(|| {
            let v = Count(AtomicU64::new(0));
            WinFs.walk(&root, &v).unwrap();
            v.0.into_inner()
        })
    });
    g.bench_function("jwalk_baseline", |b| {
        b.iter(|| {
            jwalk::WalkDir::new(&root)
                .skip_hidden(false)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_file())
                .count()
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
