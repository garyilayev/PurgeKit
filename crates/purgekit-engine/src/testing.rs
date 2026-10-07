//! In-memory `FsBackend` for tests. It models directories, files, reparse
//! points (links), cloud placeholders, read-only files, hard-link counts and
//! locked files, and follows the same no-follow rules as the real backend.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use purgekit_core::{FileId128, FileTime, KnownFolder, RelPath, SkipReason};
use purgekit_rules::EntryTimes;

use crate::backend::{
    FsBackend, FsError, OpenedFile, RootInfo, Skip, VolumeInfo, WalkEntry, WalkSkip, WalkVisitor,
};

#[derive(Debug, Clone)]
pub enum MemKind {
    Dir,
    File,
    /// Symlink or junction: never entered or deleted.
    Link,
}

#[derive(Debug, Clone)]
pub struct MemNode {
    pub name: String,
    pub kind: MemKind,
    pub file_id: FileId128,
    pub size: u64,
    pub alloc: u64,
    pub times: EntryTimes,
    pub readonly: bool,
    pub cloud: bool,
    pub links: u32,
    pub locked: bool,
}

#[derive(Default)]
struct State {
    /// Key: folded absolute path with `/` separators.
    nodes: BTreeMap<String, MemNode>,
    next_id: u64,
}

pub struct MemFs {
    state: Mutex<State>,
    folders: HashMap<KnownFolder, PathBuf>,
    pub running: Mutex<HashSet<String>>,
    pub recycle_bin: Mutex<(u64, u64)>,
    pub free: Mutex<u64>,
    pub volume_serial: u64,
}

fn key(p: &Path) -> String {
    p.to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_lowercase()
}

fn join_key(base: &str, name: &str) -> String {
    format!("{base}/{}", name.to_lowercase())
}

impl Default for MemFs {
    fn default() -> Self {
        Self::new()
    }
}

impl MemFs {
    /// Known folders live under `C:/Users/test`; `{Windows}` is `C:/Windows`.
    pub fn new() -> Self {
        let home = PathBuf::from("C:/Users/test");
        let mut folders = HashMap::new();
        folders.insert(KnownFolder::LocalAppData, home.join("AppData/Local"));
        folders.insert(KnownFolder::RoamingAppData, home.join("AppData/Roaming"));
        folders.insert(KnownFolder::LocalAppDataLow, home.join("AppData/LocalLow"));
        folders.insert(KnownFolder::Temp, home.join("AppData/Local/Temp"));
        folders.insert(KnownFolder::ProgramData, PathBuf::from("C:/ProgramData"));
        folders.insert(KnownFolder::Windows, PathBuf::from("C:/Windows"));
        MemFs {
            state: Mutex::new(State {
                nodes: BTreeMap::new(),
                next_id: 1,
            }),
            folders,
            running: Mutex::new(HashSet::new()),
            recycle_bin: Mutex::new((0, 0)),
            free: Mutex::new(10 << 30),
            volume_serial: 0xC0FFEE,
        }
    }

    pub fn folder(&self, f: KnownFolder) -> PathBuf {
        self.folders[&f].clone()
    }

    fn ensure_dirs(st: &mut State, path: &Path) {
        let mut cur = PathBuf::new();
        for c in path.components() {
            cur.push(c);
            let k = key(&cur);
            if k.ends_with(':') || k.is_empty() {
                continue;
            }
            if !st.nodes.contains_key(&k) {
                let id = st.next_id;
                st.next_id += 1;
                st.nodes.insert(
                    k,
                    MemNode {
                        name: c.as_os_str().to_string_lossy().into_owned(),
                        kind: MemKind::Dir,
                        file_id: FileId128::from_u64(id),
                        size: 0,
                        alloc: 0,
                        times: EntryTimes::default(),
                        readonly: false,
                        cloud: false,
                        links: 1,
                        locked: false,
                    },
                );
            }
        }
    }

    /// Adds a file `age_secs` old (all timestamps). Returns its file ID.
    pub fn add_file(&self, path: impl AsRef<Path>, size: u64, age_secs: u64) -> FileId128 {
        let path = path.as_ref();
        let mut st = self.state.lock().unwrap();
        if let Some(parent) = path.parent() {
            Self::ensure_dirs(&mut st, parent);
        }
        let id = st.next_id;
        st.next_id += 1;
        let t = FileTime(FileTime::now().0.saturating_sub(age_secs * 10_000_000));
        let alloc = size.div_ceil(4096) * 4096;
        let fid = FileId128::from_u64(id);
        st.nodes.insert(
            key(path),
            MemNode {
                name: path.file_name().unwrap().to_string_lossy().into_owned(),
                kind: MemKind::File,
                file_id: fid,
                size,
                alloc,
                times: EntryTimes {
                    created: t,
                    modified: t,
                    changed: t,
                },
                readonly: false,
                cloud: false,
                links: 1,
                locked: false,
            },
        );
        fid
    }

    pub fn add_dir(&self, path: impl AsRef<Path>) {
        Self::ensure_dirs(&mut self.state.lock().unwrap(), path.as_ref());
    }

    /// Adds a link (junction/symlink). It is a leaf here: its target is never
    /// reachable through it, which is exactly what no-follow guarantees.
    pub fn add_link(&self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        let mut st = self.state.lock().unwrap();
        if let Some(parent) = path.parent() {
            Self::ensure_dirs(&mut st, parent);
        }
        let id = st.next_id;
        st.next_id += 1;
        st.nodes.insert(
            key(path),
            MemNode {
                name: path.file_name().unwrap().to_string_lossy().into_owned(),
                kind: MemKind::Link,
                file_id: FileId128::from_u64(id),
                size: 0,
                alloc: 0,
                times: EntryTimes::default(),
                readonly: false,
                cloud: false,
                links: 1,
                locked: false,
            },
        );
    }

    pub fn modify(&self, path: impl AsRef<Path>, f: impl FnOnce(&mut MemNode)) {
        let mut st = self.state.lock().unwrap();
        f(st.nodes.get_mut(&key(path.as_ref())).expect("node exists"));
    }

    /// Replaces a file with a new one at the same path (new file ID).
    pub fn replace_file(&self, path: impl AsRef<Path>, size: u64, age_secs: u64) -> FileId128 {
        self.remove(path.as_ref());
        self.add_file(path, size, age_secs)
    }

    pub fn remove(&self, path: impl AsRef<Path>) {
        self.state.lock().unwrap().nodes.remove(&key(path.as_ref()));
    }

    pub fn exists(&self, path: impl AsRef<Path>) -> bool {
        self.state
            .lock()
            .unwrap()
            .nodes
            .contains_key(&key(path.as_ref()))
    }

    /// Snapshot of every path (folded keys), for "nothing else changed" checks.
    pub fn snapshot(&self) -> Vec<String> {
        self.state.lock().unwrap().nodes.keys().cloned().collect()
    }

    fn children(st: &State, dir_key: &str) -> Vec<(String, MemNode)> {
        let prefix = format!("{dir_key}/");
        st.nodes
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .filter(|(k, _)| !k[prefix.len()..].contains('/'))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn walk_dir(&self, dir_key: &str, rel: &RelPath, visitor: &dyn WalkVisitor) {
        if visitor.cancelled() {
            return;
        }
        let children = Self::children(&self.state.lock().unwrap(), dir_key);
        let mut batch = Vec::new();
        let mut subdirs = Vec::new();
        for (k, n) in children {
            let child_rel = match rel.join(&n.name) {
                Ok(r) => r,
                Err(_) => {
                    visitor.skipped(WalkSkip::BadName);
                    continue;
                }
            };
            match n.kind {
                MemKind::Link => visitor.skipped(WalkSkip::ReparsePoint),
                _ if n.cloud => visitor.skipped(WalkSkip::Cloud),
                MemKind::Dir => subdirs.push((k, child_rel)),
                MemKind::File => batch.push(WalkEntry {
                    rel: child_rel,
                    file_id: n.file_id,
                    logical_size: n.size,
                    alloc_size: n.alloc,
                    times: n.times,
                    readonly: n.readonly,
                }),
            }
        }
        if !batch.is_empty() {
            visitor.files(batch);
        }
        for (k, r) in subdirs {
            if visitor.enter_dir(&r) {
                self.walk_dir(&k, &r, visitor);
            }
        }
    }
}

impl FsBackend for MemFs {
    fn resolve(&self, folder: KnownFolder) -> Option<PathBuf> {
        self.folders.get(&folder).cloned()
    }

    fn walk(&self, root: &Path, visitor: &dyn WalkVisitor) -> Result<RootInfo, FsError> {
        let k = key(root);
        let kind = self
            .state
            .lock()
            .unwrap()
            .nodes
            .get(&k)
            .map(|n| n.kind.clone());
        match kind {
            None => Err(FsError::NotFound),
            Some(MemKind::Link) => Err(FsError::RootIsLink),
            Some(MemKind::File) => Err(FsError::Other("root is a file".into())),
            Some(MemKind::Dir) => {
                self.walk_dir(&k, &RelPath::root(), visitor);
                Ok(RootInfo {
                    volume_serial: self.volume_serial,
                })
            }
        }
    }

    fn delete_file(
        &self,
        root: &Path,
        rel: &RelPath,
        check: &dyn Fn(&OpenedFile) -> Result<(), Skip>,
    ) -> Result<(), Skip> {
        let mut st = self.state.lock().unwrap();
        let mut k = key(root);
        match st.nodes.get(&k).map(|n| &n.kind) {
            Some(MemKind::Dir) => {}
            Some(MemKind::Link) => return Err(SkipReason::LinkOrCloud.into()),
            _ => return Err(Skip::with(SkipReason::Changed, "root missing")),
        }
        let comps: Vec<&str> = rel.components().collect();
        for (i, c) in comps.iter().enumerate() {
            k = join_key(&k, c);
            let Some(n) = st.nodes.get(&k) else {
                return Err(Skip::with(SkipReason::Changed, "not found"));
            };
            let last = i + 1 == comps.len();
            match n.kind {
                MemKind::Link => return Err(SkipReason::LinkOrCloud.into()),
                MemKind::Dir if last => {}
                MemKind::Dir => continue,
                MemKind::File if !last => {
                    return Err(Skip::with(SkipReason::Changed, "not a directory"));
                }
                MemKind::File => {}
            }
        }
        let n = st.nodes.get(&k).unwrap();
        if n.cloud {
            return Err(SkipReason::LinkOrCloud.into());
        }
        if n.locked {
            return Err(Skip::with(SkipReason::InUse, "SHARING_VIOLATION"));
        }
        let opened = OpenedFile {
            volume_serial: self.volume_serial,
            file_id: n.file_id,
            is_dir: matches!(n.kind, MemKind::Dir),
            readonly: n.readonly,
            reparse: false,
            cloud: n.cloud,
            link_count: n.links,
            alloc_size: n.alloc,
            times: n.times,
        };
        check(&opened)?;
        let alloc = n.alloc;
        st.nodes.remove(&k);
        drop(st);
        *self.free.lock().unwrap() += alloc;
        Ok(())
    }

    fn remove_dir_if_empty(&self, root: &Path, rel: &RelPath) -> bool {
        if rel.is_root() {
            return false;
        }
        let mut st = self.state.lock().unwrap();
        let mut k = key(root);
        for c in rel.components() {
            k = join_key(&k, c);
            match st.nodes.get(&k).map(|n| &n.kind) {
                Some(MemKind::Dir) => {}
                _ => return false,
            }
        }
        if !Self::children(&st, &k).is_empty() {
            return false;
        }
        st.nodes.remove(&k).is_some()
    }

    fn running_processes(&self) -> HashSet<String> {
        self.running.lock().unwrap().clone()
    }

    fn free_space(&self, _path: &Path) -> Option<u64> {
        Some(*self.free.lock().unwrap())
    }

    fn recycle_bin_query(&self) -> Option<(u64, u64)> {
        Some(*self.recycle_bin.lock().unwrap())
    }

    fn recycle_bin_empty(&self) -> Result<(), Skip> {
        let mut rb = self.recycle_bin.lock().unwrap();
        *self.free.lock().unwrap() += rb.0;
        *rb = (0, 0);
        Ok(())
    }

    fn registry_key_exists(&self, _key: &str) -> bool {
        false
    }

    fn volumes(&self) -> Vec<VolumeInfo> {
        vec![VolumeInfo {
            name: "C:".into(),
            label: "Local Disk".into(),
            root: PathBuf::from("C:/"),
            total: 100 << 30,
            free: *self.free.lock().unwrap(),
        }]
    }
}
