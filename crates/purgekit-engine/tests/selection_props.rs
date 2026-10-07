//! Property test: lazy O(depth) selection always agrees with a naive model
//! that stores the state of every file, and the plan contains exactly the
//! files the tree reports as selected.

use std::collections::HashMap;

use proptest::prelude::*;
use purgekit_core::{FileId128, FileTime, RelPath, Selection};
use purgekit_engine::tree::{CleanerInput, FoundFile, NodeKind, ResultTree};
use purgekit_rules::builtin;

fn build(paths: &[(String, u64)]) -> ResultTree {
    let (rule, _) = builtin().find("windows.user_temp").unwrap();
    let files = paths
        .iter()
        .enumerate()
        .map(|(i, (p, size))| FoundFile {
            rule,
            volume: 1,
            file_id: FileId128::from_u64(i as u64 + 1),
            rel: RelPath::parse(p).unwrap(),
            logical: *size,
            alloc: *size,
            modified: FileTime(0),
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

fn paths() -> impl Strategy<Value = Vec<(String, u64)>> {
    prop::collection::btree_map(
        prop::collection::vec(prop::sample::select(vec!["a", "b", "c", "d"]), 1..5)
            .prop_map(|v| v.join("/")),
        1u64..10_000,
        1..40,
    )
    .prop_map(|m| {
        // Drop paths that are a prefix of another (a name cannot be both file and dir).
        let keys: Vec<String> = m.keys().cloned().collect();
        m.into_iter()
            .filter(|(k, _)| {
                !keys
                    .iter()
                    .any(|o| o.len() > k.len() && o.starts_with(&format!("{k}/")))
            })
            .map(|(k, v)| (format!("{k}.f"), v))
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn lazy_selection_matches_naive_model(paths in paths(), ops in prop::collection::vec((0usize..200, any::<bool>()), 0..40)) {
        let mut tree = build(&paths);
        // Naive model: file node index -> selected.
        let mut model: HashMap<u32, bool> = HashMap::new();
        let files: Vec<u32> = (0..tree.len() as u32).filter(|&i| tree.node(i).kind == NodeKind::File).collect();
        for &f in &files { model.insert(f, true); }

        for (pick, state) in ops {
            let i = (pick % tree.len()) as u32;
            tree.set_selected(i, state);
            // Every file under i takes `state`.
            for &f in &files {
                let mut cur = f;
                loop {
                    if cur == i { model.insert(f, state); break; }
                    let p = tree.node(cur).parent;
                    if p == u32::MAX { break; }
                    cur = p;
                }
            }
            // Check every node's aggregate against the model.
            for n in 0..tree.len() as u32 {
                let mut exp_bytes = 0u64;
                let mut exp_count = 0u32;
                let mut total = 0u32;
                for &f in &files {
                    let mut cur = f;
                    let under = loop {
                        if cur == n { break true; }
                        let p = tree.node(cur).parent;
                        if p == u32::MAX { break false; }
                        cur = p;
                    };
                    if under {
                        total += 1;
                        if model[&f] { exp_bytes += tree.node(f).total_alloc; exp_count += 1; }
                    }
                }
                prop_assert_eq!(tree.selected(n), (exp_bytes, exp_count), "node {}", n);
                let exp_sel = if exp_count == 0 || total == 0 { Selection::Unchecked } else if exp_count == total { Selection::Checked } else { Selection::Partial };
                prop_assert_eq!(tree.selection(n), exp_sel);
            }
        }
        let plan = tree.build_plan(builtin());
        let expected: u32 = model.values().filter(|v| **v).count() as u32;
        prop_assert_eq!(plan.file_count() as u32, expected);
        prop_assert_eq!(plan.total_alloc(), tree.selected_total().0);
    }
}
