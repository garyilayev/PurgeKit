//! "Export diagnostics": a redacted zip for bug reports. It holds logs (which
//! never contain usernames or file names), settings, exclusions, history and a
//! summary. Written with a minimal stored (uncompressed) zip writer.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

struct Entry {
    name: String,
    crc: u32,
    size: u32,
    offset: u32,
}

pub struct ZipWriter<W: Write> {
    out: W,
    pos: u32,
    entries: Vec<Entry>,
}

impl<W: Write> ZipWriter<W> {
    pub fn new(out: W) -> Self {
        ZipWriter {
            out,
            pos: 0,
            entries: Vec::new(),
        }
    }

    fn put(&mut self, b: &[u8]) -> io::Result<()> {
        self.out.write_all(b)?;
        self.pos += b.len() as u32;
        Ok(())
    }

    pub fn add(&mut self, name: &str, data: &[u8]) -> io::Result<()> {
        let crc = crc32fast::hash(data);
        let size = u32::try_from(data.len()).map_err(|_| io::Error::other("file too large"))?;
        let offset = self.pos;
        let mut h = Vec::with_capacity(30 + name.len());
        h.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        h.extend_from_slice(&20u16.to_le_bytes()); // version needed
        h.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 names
        h.extend_from_slice(&0u16.to_le_bytes()); // stored
        h.extend_from_slice(&0u32.to_le_bytes()); // time/date
        h.extend_from_slice(&crc.to_le_bytes());
        h.extend_from_slice(&size.to_le_bytes());
        h.extend_from_slice(&size.to_le_bytes());
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        self.put(&h)?;
        self.put(data)?;
        self.entries.push(Entry {
            name: name.into(),
            crc,
            size,
            offset,
        });
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        let cd_start = self.pos;
        let entries = std::mem::take(&mut self.entries);
        for e in &entries {
            let mut h = Vec::with_capacity(46 + e.name.len());
            h.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            h.extend_from_slice(&20u16.to_le_bytes());
            h.extend_from_slice(&20u16.to_le_bytes());
            h.extend_from_slice(&0x0800u16.to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes());
            h.extend_from_slice(&0u32.to_le_bytes());
            h.extend_from_slice(&e.crc.to_le_bytes());
            h.extend_from_slice(&e.size.to_le_bytes());
            h.extend_from_slice(&e.size.to_le_bytes());
            h.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            h.extend_from_slice(&[0u8; 12]); // extra, comment, disk, int attr
            h.extend_from_slice(&0u32.to_le_bytes()); // ext attr
            h.extend_from_slice(&e.offset.to_le_bytes());
            h.extend_from_slice(e.name.as_bytes());
            self.put(&h)?;
        }
        let cd_size = self.pos - cd_start;
        let mut end = Vec::with_capacity(22);
        end.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        end.extend_from_slice(&[0u8; 4]);
        end.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        end.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        end.extend_from_slice(&cd_size.to_le_bytes());
        end.extend_from_slice(&cd_start.to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes());
        self.put(&end)?;
        Ok(self.out)
    }
}

/// Builds `diagnostics-<ts>.zip` in `data_dir` and returns its path.
pub fn export(data_dir: &Path, summary: &str) -> io::Result<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = data_dir.join(format!("diagnostics-{ts}.zip"));
    let file = std::fs::File::create(&path)?;
    let mut zip = ZipWriter::new(io::BufWriter::new(file));
    zip.add("summary.txt", summary.as_bytes())?;
    for name in ["settings.json", "exclusions.json", "history.json"] {
        if let Ok(data) = std::fs::read(data_dir.join(name)) {
            zip.add(name, &data)?;
        }
    }
    if let Ok(dir) = std::fs::read_dir(data_dir.join("logs")) {
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.ends_with(".log")
                && let Ok(data) = std::fs::read(e.path())
            {
                zip.add(&format!("logs/{name}"), &data)?;
            }
        }
    }
    zip.finish()?.flush()?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_layout() {
        let mut z = ZipWriter::new(Vec::new());
        z.add("a.txt", b"hello").unwrap();
        z.add("logs/b.log", b"").unwrap();
        let bytes = z.finish().unwrap();
        assert_eq!(&bytes[..4], &[0x50, 0x4b, 0x03, 0x04]);
        let end = &bytes[bytes.len() - 22..];
        assert_eq!(&end[..4], &[0x50, 0x4b, 0x05, 0x06]);
        assert_eq!(u16::from_le_bytes([end[10], end[11]]), 2);
    }
}
