# PurgeKit

**See what's wasting space. Remove it safely.**

PurgeKit is a Windows disk-cleanup utility that recovers space safely and
explains every file it touches. It is free, local only, and has no account,
no ads and no networking code.

- Every result says what it is, why it is safe to remove and what happens after.
- Only files matched by built-in, reviewed rules are shown (`rules/*.toml`).
  Passwords, bookmarks and other protected data are never candidates.
- Nothing is deleted until you review the selection and click Clean.
  Deletion re-checks each file on an open handle and never follows links
  or junctions.
- One small elevated helper is started only when you select Windows temp
  files; it accepts rule IDs, never paths.

## Install

Download `PurgeKit-Setup-<version>.exe` from the
[releases page](https://github.com/garyilayev/PurgeKit/releases).
Requires Windows 10 22H2 or Windows 11 (x64).

Releases are code-signed. Free code signing provided by
[SignPath.io](https://about.signpath.io), certificate by
[SignPath Foundation](https://signpath.org).

## Build from source

```sh
cargo build --release -p purgekit -p purgekit-helper
cargo test --workspace
```

See `CLAUDE.md` for the architecture, safety invariants and toolchain notes.

## License

[MIT](LICENSE)
