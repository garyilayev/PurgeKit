//! Checkbox toggle to updated total: target < 16 ms (one frame) on a
//! 100k-node tree. Toggles are O(depth), so this should be microseconds.

use criterion::{Criterion, criterion_group, criterion_main};
use purgekit_core::{FileId128, FileTime, RelPath};
use purgekit_engine::tree::{CleanerInput, FoundFile, NodeKind, ResultTree};
use purgekit_rules::builtin;

fn tree(n: usize) -> ResultTree {
    let (rule, _) = builtin().find("windows.user_temp").unwrap();
    let files = (0..n)
        .map(|i| FoundFile {
            rule,
            volume: 1,
            file_id: FileId128::from_u64(i as u64 + 1),
            rel: RelPath::parse(&format!("d{}/e{}/f{}/file{i}", i % 50, i % 7, i % 13)).unwrap(),
            logical: 4096,
            alloc: 4096,
            modified: FileTime(1),
        })
        .collect();
    ResultTree::build(
        builtin(),
        vec![CleanerInput {
            rule,
            files,
            virtual_size: None,
            selected: true,
        }],
    )
}

fn bench(c: &mut Criterion) {
    let mut t = tree(100_000);
    let leaf = (0..t.len() as u32)
        .rev()
        .find(|&i| t.node(i).kind == NodeKind::File)
        .unwrap();
    let cleaner = t.cleaners().next().unwrap();
    c.bench_function("toggle_leaf_100k", |b| {
        b.iter(|| {
            t.toggle(leaf);
            t.selected_total()
        })
    });
    c.bench_function("toggle_cleaner_100k", |b| {
        b.iter(|| {
            t.toggle(cleaner);
            t.selected_total()
        })
    });
    c.bench_function("build_plan_100k", |b| {
        b.iter(|| t.build_plan(builtin()).file_count())
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
