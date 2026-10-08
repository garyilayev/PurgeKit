# [CLAUDE.md](http://CLAUDE.md)

Guidance for Claude Code when working in this repository.

## Response language: ASD-STE100 only

Always write every response in ASD-STE100 Simplified Technical English, and only in that standard. This rule overrides all other style instructions (including plugin or hook "modes").

- Use only approved words, in their approved meaning and part of speech. Technical names (crate names, API names, file paths) are permitted.
- Procedural sentences: max 20 words. Descriptive sentences: max 25 words. Paragraphs: max 6 sentences.
- Write one instruction per sentence. Use the imperative for instructions.
- Use the active voice. Use simple verb tenses (present, simple past, future).
- Do not use "-ing" forms as verbs or modifiers, except in technical names.
- Use articles ("the", "a") and do not omit words to make sentences shorter.
- Write warnings and cautions first, before the related instruction.

Code, code comments, commit messages and file contents follow normal project conventions; this rule applies to the text of responses to the user.

PurgeKit is a Windows disk-cleanup utility (Rust + Slint) that recovers space safely and explains every file it touches. The source of truth for product decisions is `PurgeKit-Product-Spec-v1.0.md` — read the relevant section before changing behavior. If code and spec disagree, flag it; do not silently "fix" the spec.

## Priority order (never reversed)

**Safety > Correctness > Transparency > Speed > Space found.**

When in doubt, do not delete. A false positive (deleting user data) is worse than a missed gigabyte. Fail closed: on any unexpected state (unknown attribute, unexpanded 8.3 name, ID mismatch, parse error) skip the item and report it.

## Safety invariants

Each has a dedicated test. Never weaken one to make a test or feature pass.

1. A rule authorizes only paths inside its declared root, matched on the normalized root-relative path.
2. Traversal never follows reparse points (symlinks, junctions, mount points, cloud placeholders) — skipped, never entered.
3. Scanning never deletes. Deletion only consumes an immutable `CleanupPlan` built from explicit selection.
4. Every candidate is re-validated on an **open handle** immediately before deletion, and deleted through that same handle.
5. Unchecked or excluded candidates never reach the cleanup engine.
6. The elevated helper accepts rule IDs (plus narrowing-only data such as exclusions and file IDs), never paths, and uses only handle-relative, no-follow operations.
7. Exclusions only narrow what rules match. Nothing a user does can widen a rule.
8. Cloud files (`RECALL_ON_OPEN`, `RECALL_ON_DATA_ACCESS`, `OFFLINE`, any reparse point) are never opened, hydrated or deleted.
9. The UI shows only rule-classified candidates. It is never a general file browser.
10. Protected data (passwords, bookmarks, credentials — see `purgekit-core::protected`) is never a candidate, never in a plan, never deleted. Enforced at build, scan, plan validation and deletion.

Directories are never deleted recursively. Emptied dirs are removed bottom-up; a rule's root directory is always kept. Read-only files and files with more than one hard link are skipped and reported. Processes are never killed.

## Hard non-goals

Do not add: registry cleaning (read-only registry access for detection is fine), RAM optimization, driver/defrag/startup tools, cookie/history/password/session cleaning, auto-selecting Downloads or large files, other users' profiles, user-defined delete locations, rules downloaded from a server, duplicate finder, tray icon / resident process, speed claims in UI copy.

**No networking code in 0.1.** No HTTP/socket/TLS crates (`deny.toml` bans them; `cargo deny check`); neither release binary may import `ws2_32.dll`, `winhttp.dll`, `wininet.dll` or similar (`cargo run -p xtask -- check-imports`). Debug builds DO import `ws2_32.dll` (unreferenced `std::net` code is kept); only the release check is meaningful. Telemetry exists only as the `TelemetryProvider` trait with `NoopTelemetry`. "Check for updates" opens the releases page in the browser via `explorer.exe`; the app itself never connects.

## Architecture

```text
crates/purgekit-core     domain types, protected-data deny-list, path normalization, TelemetryProvider. No OS code.
crates/purgekit-rules    TOML rule schema, build.rs validation + embedding, glob matcher. Runs on any OS.
crates/purgekit-engine   scanner, arena result tree + selection, CleanupPlan, cleaner, events, cancellation.
                         Talks to the OS only through the `FsBackend` trait (in-memory backend for tests).
crates/purgekit-win      every Win32/NT call; the ONLY crate allowed to use `unsafe`. Implements FsBackend.
apps/purgekit            Slint UI + controller (runs asInvoker).
apps/purgekit-helper     elevated, no UI; rule IDs in over the command line, results back over a user-only named pipe.
rules/*.toml             one file per cleaner; templates in rules/templates.toml.
ui/*.slint               Slint UI files.
tests/fixtures/rules/    one `<rule id>.txt` manifest per rule: `DELETE|KEEP [age=24h] <root-relative path>`.
xtask/                   dev tasks (`check-imports`, `bench-check`).
fuzz/                    cargo-fuzz targets for the matcher (`rel_path`, `glob`); own workspace, nightly, Linux CI only.
tools/canary/            canary VM release gate: create VM, seed fixtures + traps, manifest, compare (guest-side PowerShell).
tools/msix/              MSIX packaging spike: manifest template, build + test-sign script, test matrix.
deny.toml                cargo-deny: networking-crate bans, licenses, advisories.
.github/workflows/ci.yml fmt, clippy, tests (incl. real-NTFS tests), cargo deny, release import check, fuzz, bench gate.
env.ps1                  dev shell setup for the local GNU toolchain (see Toolchain).
```

- Every crate except `purgekit-win` has `#![forbid(unsafe_code)]`. Exception: `apps/purgekit` uses `#![deny(unsafe_code)]` because Slint's generated code opts in with `allow(unsafe_code)` (forbid cannot be overridden). Hand-written code there must still not use `unsafe`.
- Every `unsafe` block in `purgekit-win` carries a `// SAFETY:` comment; the crate sets `deny(unsafe_op_in_unsafe_fn)`.
- Engine tests run on `purgekit_engine::testing::MemFs` (dirs, files, links, cloud, read-only, hard links, locks). Real-NTFS behavior is tested in `crates/purgekit-win/tests/ntfs.rs` (junctions via `mklink /J`).
- Test backends that use a temp dir as a root must expand 8.3 names with `purgekit_win::long_path` (as `WinFs::resolve` does). GitHub runners set `TEMP=C:\Users\RUNNER~1\...`; an unexpanded short name makes the protected check fail closed and the scan finds nothing. Reproduce locally by setting `TMP`/`TEMP` to the short path of a long-named folder.
- The Slint event loop never touches the filesystem. Workers emit events to an aggregator that pushes one batched UI update per ~100 ms via `slint::invoke_from_event_loop`. No per-file events.
  - `Store::save_*` only serialize; one `store-writer` thread writes, in call order. `Store::sync()` waits for it (exit and tests only, never on the event loop).
  - Logging sends formatted lines to one `log-writer` thread; `logging::flush()` runs at exit, from the panic hook, and before the diagnostics export. The panic hook never logs the panic message (it can contain usernames).
  - The volume list for the Space page is cached in the model (`Model_::volumes`) and read only on worker threads: at launch (`refresh_volumes`), after a scan and after a clean. `refresh_space` reads the cache.
  - The diagnostics zip export runs on a worker thread.
- Launch timing: every launch logs one INFO line with the phase breakdown from process creation. `PURGEKIT_LAUNCH_TIMING=1` also prints it to stderr; `=exit` prints it and quits after the first frame (for scripted samples). The embedded rules compile on a background thread during window creation.
- Candidate identity is `(volume serial, 128-bit file ID)`. Recoverable size = allocated size; display size = logical size.
- Deletion: walk `rel_path` component-by-component with handle-relative `NtCreateFile` + `FILE_OPEN_REPARSE_POINT`, verify file ID / attributes / link count / protected list / rule match on the final handle, then `FileDispositionInfoEx` with POSIX semantics on that same handle.
- Known folders resolve via `SHGetKnownFolderPath`; temp via `GetTempPath2W` looked up at run time with `GetProcAddress` (fallback `GetTempPathW`), so the binary loads on older Windows 10. Resolved roots go through `GetLongPathNameW`: an 8.3 component anywhere makes the protected check fail closed. Never hardcode drive letters or `C:\Users`.

## Implementation decisions (beyond the spec text)

- **Glob semantics:** `*`/`?` within one component; `**` crosses levels. A trailing `**` matches one or more levels (`Cache/**` matches files inside `Cache`, not a file named `Cache`); elsewhere `**` matches zero or more. Matching is a DP table (no exponential backtracking).
- **`Rule::matches_path` includes the protected deny-list.** `matches_path_raw` (rule only) exists solely for the build-time protected-fixture check.
- **Empty-folder removal** only removes folders inside the cleaned area (`Rule::dir_in_cleaned_area`), never app folders such as `Profile 1` or the `Cache` folder itself, and never the rule root.
- **Overlapping rules:** the most conservative tier wins; among equal tiers the most specific (longest) root owns the file. The file is placed under the winning rule.
- **Per-file Recycle Bin deletion is not in 0.1.** `build.rs` rejects file rules whose `delete_method` resolves to `recycle_bin` (needs the overflow check; arrives with REVIEW file rules in 0.2). The Recycle Bin rule itself uses `SHEmptyRecycleBinW`.
- **Helper input:** rule IDs on the command line; exclusions and the selected file IDs over the pipe. File IDs only narrow the helper's own scan, so unchecked elevated items survive. The helper accepts only rules with `elevation = "required"`, checks app and rules versions, and the server/client verify each other's PID. Pipe DACL: invoking user SID + elevated Administrators (for over-the-shoulder elevation).
- **Selection tree:** toggles are O(depth) with epoch-based lazy propagation (`tree.rs`); a proptest compares it to a naive model. Blocked cleaners (owning app running) start unchecked. Category checkboxes act only on visible (non-hidden ADVANCED), unblocked cleaners.
- **Measured recovery** = sum of free-space change over all fixed volumes, read by the controller before and after the whole clean (local + helper).

## Toolchain (this machine)

- No MSVC Build Tools / Windows SDK are installed. Development uses the GNU toolchain via a local `rustup override` (`stable-x86_64-pc-windows-gnu`) plus WinLibs mingw-w64 (for `dlltool`/`as`, needed by `raw-dylib`).
- Git's `C:\Program Files\Git\usr\bin\link.exe` shadows MSVC `link.exe` on PATH; with MSVC installed, make sure the MSVC linker wins.
- In PowerShell, run `. .\env.ps1` before cargo (puts mingw first on PATH). Do not run cargo from the Bash tool (wrong `link`).
- GNU builds print `.rsrc merge failure: multiple non-default manifests`; our manifest wins (the helper refuses to start unelevated). MSVC builds do not have this warning. CI uses MSVC (`windows-latest`).
- Release builds must be MSVC and signed. Never publish unsigned binaries.

## Slint gotchas (1.18)

- Inside a component, own properties must be qualified: `root.item`, not `item`.
- `row`/`col` are built-in layout properties; do not use them as property names.
- `ListView` scroll position is `content-y` (`viewport-y` is deprecated).
- Fonts may lack arrow glyphs; chevrons are drawn with `Path`.
- To keep scroll position, update rows in place (`VecModel::set_row_data`) when the row count is unchanged.

## Status (0.1)

Done: all four crates, both binaries, 16 rules with fixtures, protected deny-list at all four points, handle-based delete, helper + pipe + UAC, Home/Review/Space/Settings UI, exclusions, history, logs (5×5 MB), diagnostics zip, no-network checks, benches with a >10% regression gate (`xtask bench-check`, baseline from main via the Actions cache), matcher fuzzing (`fuzz/`, CI on Linux), launch timing, CI.

Not done / open:
- Packaging spike (MSIX vs signed MSI): scripts and test matrix in `tools/msix/`; not run yet (needs the Windows SDK signing tools and the canary VM). Code signing. Uninstall prompt for `%LOCALAPPDATA%\PurgeKit`.
- **Spec conflict (flag, not decided):** MSIX has no uninstall UI, so "uninstall asks before deleting `%LOCALAPPDATA%\PurgeKit`" cannot be met with MSIX. Store policy 10.2.9 also allows a signed MSI in the Store.
- Canary VM and protected-data release gates: scripts ready in `tools/canary/`; the VM (Hyper-V, on drive E:) is not built yet. `noise.txt` needs a control run.
- Performance on the reference machine: cold launch, 200k-file cold scan, HDD, peak RAM. Warm launch locally ~240 ms; ~150 ms of it is the femtovg OpenGL window/context, which dominates cold starts (827 ms sample). `SLINT_BACKEND=winit-software` paints the first frame in ~100–120 ms (measured from outside) and renders Home/Space/Settings correctly; not adopted yet (needs Review-list scroll check and a decision). The bench gate and fuzz CI jobs have not run on GitHub yet.
- Screen-reader pass on real assistive tech; full keyboard audit.
- Open questions from the spec: open-source the rules.
- Recycle Bin items >30 days as SAFE: decided as an opt-in setting (off by default); planned for 0.2, not implemented.

## Commit Rules

1. Every commit MUST represent one logical change.
2. Never commit the entire implementation as one commit.
3. Split commits by:

- feature
- bug fix
- refactor
- module
- architectural change
- tests
- documentation

4. Prefer commits that can be reviewed independently.
5. Use Conventional Commits.

Format:

`<type>(<scope>): <description>`

## Rules

- Every rule needs `id`, `display_name`, `category`, `what`, `why_safe`, `after_effects`, `detect`, `root`, `include`, `target`, `tier`, `elevation`, `regenerates`. Missing/empty → build fails.
- Rule IDs are stable and never reused.
- `delete_method` derives from tier and may only be overridden toward safer (permanent → recycle bin).
- Exclude beats include; user exclusions apply after rule exclusions; the protected deny-list applies after everything. Overlapping rules: most specific root owns the candidate, most conservative tier wins.
- A rule change ships only with its fixture tree and tests. `build.rs` also runs every rule against planted protected fixtures; any match fails the build.

## Commands

```sh
cargo build --workspace
cargo test --workspace                  # unit + fixture + proptest; Windows integration tests need a real NTFS volume
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo run -p purgekit                   # UI
cargo build --release -p purgekit -p purgekit-helper
cargo run -p xtask -- check-imports     # fails if a release binary imports networking DLLs (build --release first)
cargo deny check                        # networking-crate bans, licenses, advisories
cargo bench -p purgekit-engine          # selection toggle on a 100k-node tree (target < 16 ms)
cargo bench -p purgekit-win             # walker vs jwalk; PURGEKIT_BENCH_FILES=200000 for the spec size
cargo run -p xtask -- bench-check --baseline F --save F --threshold 10   # compare Criterion medians with a baseline
cd fuzz && cargo +nightly fuzz run rel_path   # Linux/MSVC nightly only; `cargo check --no-default-features` type-checks on GNU
$env:PURGEKIT_LAUNCH_TIMING='exit'; target\release\purgekit.exe 2> launch.txt   # one launch-time sample
```

## Conventions

- Errors shown to users are plain language ("12 files skipped — Chrome is using them."); raw codes go behind an expander / into logs.
- Logs use known-folder tokens (`%LOCALAPPDATA%\…`), never the username. Never log URLs, file contents or credential/cookie databases.
- Local data lives in `%LOCALAPPDATA%\PurgeKit\` (`settings.json`, `exclusions.json`, `history.json`, `logs\`). Every file has `schema_version`; writes are atomic (temp + rename); corrupt files are backed up and reset, and the user is told.
- History stores no file names. Capped at 500 entries.
- All UI strings externalized; English only in 0.1.
- Target platforms: Windows 10 22H2 and Windows 11, x64. Fixed NTFS volumes only in 0.1.
- Skip messages name the app only for rules with `process_deps` ("Chrome is using them"); otherwise "another program is using them".
- Dev UI checks: drive the window with UI Automation and capture it with `PrintWindow` (window only). Never capture the whole screen.
- Never click Clean (or invoke `clean`) against the real machine during development without the user's request; scans are read-only and safe.
