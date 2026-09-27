//! Runtime observability with bounded JSON-lines persistence. [PARTIAL]
//!
//! The packet path updates atomics only. A once-per-second checkpoint writes a
//! small, secret-free JSON record to a rotating file, so operators can answer
//! "did capture run, did mutation happen, and did fail-closed injection fire?"
//! without relying on an unbounded GUI buffer or parsing human log text.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_BACKUPS: usize = 5;
static PROCESSED_PACKETS: AtomicU64 = AtomicU64::new(0);
static MUTATED_PACKETS: AtomicU64 = AtomicU64::new(0);
static HELD_PACKETS: AtomicU64 = AtomicU64::new(0);
static FAIL_OPEN_EVENTS: AtomicU64 = AtomicU64::new(0);
static INJECTION_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static INJECTION_SUCCESSES: AtomicU64 = AtomicU64::new(0);
static INJECTION_FAILURES: AtomicU64 = AtomicU64::new(0);
static RELAY_FAIL_CLOSED: AtomicU64 = AtomicU64::new(0);
static CAPTURE_ERRORS: AtomicU64 = AtomicU64::new(0);
static LAST_CHECKPOINT: AtomicU64 = AtomicU64::new(0);
static LOGGER: OnceLock<Mutex<Option<RotatingJsonl>>> = OnceLock::new();

/// Snapshot is intentionally numeric and Copy: it is safe to put in the
/// dashboard and in a log record without carrying packet bytes, IPs, SNIs, or
/// bearer tokens across an observability boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub processed_packets: u64,
    pub mutated_packets: u64,
    pub held_packets: u64,
    pub fail_open_events: u64,
    pub injection_attempts: u64,
    pub injection_successes: u64,
    pub injection_failures: u64,
    pub relay_fail_closed: u64,
    pub capture_errors: u64,
}

pub fn snapshot() -> MetricsSnapshot {
    MetricsSnapshot {
        processed_packets: PROCESSED_PACKETS.load(Ordering::Relaxed),
        mutated_packets: MUTATED_PACKETS.load(Ordering::Relaxed),
        held_packets: HELD_PACKETS.load(Ordering::Relaxed),
        fail_open_events: FAIL_OPEN_EVENTS.load(Ordering::Relaxed),
        injection_attempts: INJECTION_ATTEMPTS.load(Ordering::Relaxed),
        injection_successes: INJECTION_SUCCESSES.load(Ordering::Relaxed),
        injection_failures: INJECTION_FAILURES.load(Ordering::Relaxed),
        relay_fail_closed: RELAY_FAIL_CLOSED.load(Ordering::Relaxed),
        capture_errors: CAPTURE_ERRORS.load(Ordering::Relaxed),
    }
}

pub fn packet_processed() {
    PROCESSED_PACKETS.fetch_add(1, Ordering::Relaxed);
}

pub fn packet_mutated() {
    MUTATED_PACKETS.fetch_add(1, Ordering::Relaxed);
}

pub fn packet_held() {
    HELD_PACKETS.fetch_add(1, Ordering::Relaxed);
}

pub fn fail_open_event() {
    FAIL_OPEN_EVENTS.fetch_add(1, Ordering::Relaxed);
}

pub fn injection_attempt() {
    INJECTION_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
}

pub fn injection_success() {
    INJECTION_SUCCESSES.fetch_add(1, Ordering::Relaxed);
}

pub fn injection_failure() {
    INJECTION_FAILURES.fetch_add(1, Ordering::Relaxed);
}

pub fn relay_fail_closed() {
    RELAY_FAIL_CLOSED.fetch_add(1, Ordering::Relaxed);
}

pub fn capture_error() {
    CAPTURE_ERRORS.fetch_add(1, Ordering::Relaxed);
}

/// Initialize the bounded event log. Errors are deliberately returned to the
/// caller rather than panicking: packet capture must not crash because an
/// optional diagnostics directory is read-only. `init_logging` reports the
/// failure through the normal human log.
pub fn init() -> io::Result<()> {
    let slot = LOGGER.get_or_init(|| Mutex::new(None));
    let mut guard = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_some() {
        return Ok(());
    }
    let dir = std::env::var_os("DPI_GUARD_LOG_DIR")
        .map(PathBuf::from)
        .or_else(default_log_dir)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "cannot determine log directory"))?;
    fs::create_dir_all(&dir)?;
    let path = dir.join("dpi_guard-events.jsonl");
    *guard = Some(RotatingJsonl::open(
        path,
        DEFAULT_MAX_BYTES,
        DEFAULT_BACKUPS,
    )?);
    Ok(())
}

fn default_log_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .map(|dir| dir.join("logs"))
}

/// Write at most one record per second. The atomic checkpoint gate means a
/// busy packet stream cannot turn metrics into a disk-write amplification
/// attack.
pub fn checkpoint() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let previous = LAST_CHECKPOINT.load(Ordering::Relaxed);
    if now == previous
        || LAST_CHECKPOINT
            .compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    let metrics = snapshot();
    let line = format_record(now, metrics);
    if let Some(slot) = LOGGER.get() {
        let mut guard = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(logger) = guard.as_mut() {
            let _ = logger.write_line(&line);
        }
    }
}

fn format_record(epoch_secs: u64, m: MetricsSnapshot) -> String {
    format!(
        "{{\"ts_unix_secs\":{epoch_secs},\"event\":\"metrics\",\"processed_packets\":{},\"mutated_packets\":{},\"held_packets\":{},\"fail_open_events\":{},\"injection_attempts\":{},\"injection_successes\":{},\"injection_failures\":{},\"relay_fail_closed\":{},\"capture_errors\":{}}}",
        m.processed_packets,
        m.mutated_packets,
        m.held_packets,
        m.fail_open_events,
        m.injection_attempts,
        m.injection_successes,
        m.injection_failures,
        m.relay_fail_closed,
        m.capture_errors,
    )
}

struct RotatingJsonl {
    path: PathBuf,
    max_bytes: u64,
    backups: usize,
    file: Option<File>,
    bytes: u64,
}

impl RotatingJsonl {
    fn open(path: PathBuf, max_bytes: u64, backups: usize) -> io::Result<Self> {
        if max_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "JSON-lines max_bytes must be non-zero",
            ));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        let bytes = file.seek(SeekFrom::End(0))?;
        if bytes >= max_bytes {
            drop(file);
            let mut logger = Self {
                path,
                max_bytes,
                backups,
                file: None,
                bytes,
            };
            logger.rotate()?;
            return Ok(logger);
        }
        Ok(Self {
            path,
            max_bytes,
            backups,
            file: Some(file),
            bytes,
        })
    }

    fn write_line(&mut self, line: &str) -> io::Result<()> {
        let mut encoded = line.as_bytes().to_vec();
        encoded.push(b'\n');
        // `>=` (not `>`): the file must never cross the cap, so a write that
        // would land exactly on the boundary rotates first. `RotatingJsonl::open`
        // already refuses to adopt a file at or above the cap with the same
        // semantics, and the rotation test locks this boundary in.
        if self.bytes > 0 && self.bytes.saturating_add(encoded.len() as u64) >= self.max_bytes {
            self.rotate()?;
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("rotating logger is closed"))?;
        file.write_all(&encoded)?;
        file.flush()?;
        self.bytes = self.bytes.saturating_add(encoded.len() as u64);
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.take() {
            file.sync_all()?;
            drop(file);
        }
        if self.backups == 0 {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.path)?;
            self.file = Some(file);
            self.bytes = 0;
            return Ok(());
        }
        for index in (1..=self.backups).rev() {
            let source = if index == 1 {
                self.path.clone()
            } else {
                backup_path(&self.path, index - 1)
            };
            let destination = backup_path(&self.path, index);
            if source.exists() {
                let _ = fs::remove_file(&destination);
                fs::rename(source, destination)?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)?;
        self.file = Some(file);
        self.bytes = 0;
        Ok(())
    }
}

fn backup_path(path: &Path, index: usize) -> PathBuf {
    PathBuf::from(format!("{}.{}", path.display(), index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_numeric_and_json_record_has_no_secrets() {
        let line = format_record(
            7,
            MetricsSnapshot {
                processed_packets: 1,
                mutated_packets: 2,
                ..MetricsSnapshot::default()
            },
        );
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["event"], "metrics");
        assert_eq!(value["processed_packets"], 1);
        assert!(!line.contains("token"));
        assert!(!line.contains("sni"));
    }

    #[test]
    fn rotates_before_crossing_cap_and_keeps_bounded_backups() {
        let path = std::env::temp_dir().join(format!(
            "dpi_guard_events_{}_{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut logger = RotatingJsonl::open(path.clone(), 32, 2).unwrap();
        logger.write_line("{\"event\":\"one\"}").unwrap();
        logger.write_line("{\"event\":\"two\"}").unwrap();
        assert!(path.exists());
        assert!(backup_path(&path, 1).exists());
        assert!(
            std::fs::read_dir(path.parent().unwrap())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&*path.file_name().unwrap().to_string_lossy()))
                .count()
                <= 3
        );
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup_path(&path, 1));
        let _ = fs::remove_file(backup_path(&path, 2));
    }
}
