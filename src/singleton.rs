//! singleton — one-instance lock next to the executable. [UNTESTED]
//!
//! patterniha's Python relay and `dpi_guard` must not run at the same time
//! (both would open WinDivert and both would try to bind 127.0.0.1:40443),
//! and two copies of `dpi_guard` must not race over the same capture handle.
//! `acquire()` creates an exclusive file lock on `dpi_guard.instance.lock`
//! **in the directory of the running executable** (never cwd) and keeps it
//! until the process exits or the guard drops.
//!
//! * Unix: `flock(LOCK_EX | LOCK_NB)` on an open fd.
//! * Windows: `CreateFileW` with `dwShareMode = 0` — a second opener gets
//!   `ERROR_SHARING_VIOLATION`.
//!
//! The crate is `#![deny(unsafe_code)]`; this module opts back in because
//! both platform locks are FFI calls. The unsafe blocks are tiny, each
//! documented with its exact safety invariant.

#![allow(unsafe_code)]

use crate::error::DpiGuardError;
use std::path::PathBuf;

/// Name of the lock file, placed next to the current executable.
pub const LOCK_FILE_NAME: &str = "dpi_guard.instance.lock";

/// Determine the directory the executable lives in. Falls back to the cwd
/// only if the OS cannot report the exe path (extremely unusual); the lock
/// is best-effort in that case.
pub fn lock_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join(LOCK_FILE_NAME);
        }
    }
    PathBuf::from(LOCK_FILE_NAME)
}

/// Acquired singleton. The lock is released on drop. Keep the guard alive
/// for the lifetime of the process (store in `main`).
pub struct SingletonGuard {
    #[cfg(unix)]
    _file: std::fs::File,
    #[cfg(windows)]
    _handle: SingletonHandle,
    path: PathBuf,
}

impl Drop for SingletonGuard {
    /// Release the lock.
    ///
    /// **The lock file is deliberately left on disk.** Deleting it here is
    /// a correctness bug, not a tidiness win:
    ///
    /// 1. instance A releases its lock (unlock / close) but has not yet
    ///    reached the unlink;
    /// 2. instance B acquires the lock on that same file and starts;
    /// 3. A now unlinks the path — it is B's lock file, and B's `flock`
    ///    (or Windows handle) is on an inode with no directory entry;
    /// 4. instance C creates a *fresh* file at the path, locks it
    ///    unopposed, and runs **concurrently with B**.
    ///
    /// Two live instances means two WinDivert capture handles and a race
    /// for the relay port — exactly what this module exists to prevent.
    /// The previous code's own comment ("if another instance raced us
    /// leave its file") described the right behaviour but the `remove_file`
    /// call did not implement it: there is no portable way to say "unlink
    /// only if this is still the entry I locked" without reopening and
    /// re-checking under the lock, and the file is a zero-cost artifact
    /// anyway. An empty `dpi_guard.instance.lock` next to the exe is
    /// harmless and is reused (`OPEN_ALWAYS` / `create(true)`) next run.
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            // Explicit unlock is nice-to-have; closing the fd also releases.
            use std::os::unix::io::AsRawFd;
            unsafe { libc_flock(self._file.as_raw_fd(), libc::LOCK_UN) };
        }
        #[cfg(windows)]
        {
            unsafe { windows_close_handle(self._handle.0) };
        }
        // Intentionally NOT removing `self.path` — see the doc comment.
        let _ = &self.path;
    }
}

/// Try to acquire the one-instance lock. Returns a guard on success or a
/// descriptive error if another instance (or patterniha) holds it.
pub fn acquire() -> Result<SingletonGuard, DpiGuardError> {
    let path = lock_path();

    // Unix uses the File descriptor for flock. Windows must NOT open the
    // file here: the subsequent CreateFileW call is the exclusive open, and
    // keeping this preliminary handle alive can make that call fail with a
    // self-inflicted sharing violation.
    #[cfg(any(unix, not(any(unix, windows))))]
    let file = std::fs::OpenOptions::new()
        .create(true)
        // Lock file: append-only pid note, never rewrite existing content.
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: `fd` is a live, open file descriptor owned by `file`.
        // LOCK_NB makes this non-blocking; a held lock returns EWOULDBLOCK.
        let rc = unsafe { libc_flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(DpiGuardError::Config(format!(
                "another instance (or patterniha) is already running — lock {path:?} held ({err})"
            )));
        }
        // Write our pid for diagnostics (best effort, not used for control).
        use std::io::Write;
        let _ = writeln!(&file, "{}", std::process::id());
        Ok(SingletonGuard { _file: file, path })
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is a valid NUL-terminated UTF-16 path for the
        // duration of the call. dwShareMode=0 makes the open exclusive.
        let handle = unsafe {
            windows_create_file_w(
                wide.as_mut_ptr(),
                windows::GENERIC_READ | windows::GENERIC_WRITE,
                0, // share mode 0 → exclusive
                std::ptr::null_mut(),
                windows::OPEN_ALWAYS,
                windows::FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == windows::INVALID_HANDLE_VALUE {
            let err = std::io::Error::last_os_error();
            return Err(DpiGuardError::Config(format!(
                "another instance (or patterniha) is already running — lock {path:?} held ({err})"
            )));
        }
        Ok(SingletonGuard {
            _handle: SingletonHandle(handle),
            path,
        })
    }

    #[cfg(not(any(unix, windows)))]
    {
        // Unknown platform: compile but be honest that locking is absent.
        let _ = file;
        log::warn!("singleton locking is not implemented on this platform");
        Ok(SingletonGuard { path })
    }
}

// ---- Unix FFI (minimal, no libc dependency) -----------------------------

#[cfg(unix)]
mod libc {
    pub const LOCK_EX: i32 = 2;
    pub const LOCK_NB: i32 = 4;
    pub const LOCK_UN: i32 = 8;
}

#[cfg(unix)]
unsafe fn libc_flock(fd: std::os::unix::io::RawFd, operation: i32) -> i32 {
    extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    // SAFETY: caller passes a valid open fd and a valid LOCK_* constant.
    unsafe { flock(fd, operation) }
}

// ---- Windows FFI (minimal, no windows crate dependency) -----------------

#[cfg(windows)]
mod windows {
    pub const GENERIC_READ: u32 = 0x8000_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const OPEN_ALWAYS: u32 = 4;
    pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    pub const INVALID_HANDLE_VALUE: *mut core::ffi::c_void = -1isize as *mut core::ffi::c_void;
}

#[cfg(windows)]
struct SingletonHandle(*mut core::ffi::c_void);
#[cfg(windows)]
unsafe impl Send for SingletonHandle {}

#[cfg(windows)]
unsafe fn windows_create_file_w(
    lp_file_name: *mut u16,
    dw_desired_access: u32,
    dw_share_mode: u32,
    lp_security_attributes: *mut core::ffi::c_void,
    dw_creation_disposition: u32,
    dw_flags_and_attributes: u32,
    h_template_file: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    extern "system" {
        fn CreateFileW(
            lpfilename: *const u16,
            dwdesiredaccess: u32,
            dwsharemode: u32,
            lpsecurityattributes: *mut core::ffi::c_void,
            dwcreationdisposition: u32,
            dwflagsandattributes: u32,
            htemplatefile: *mut core::ffi::c_void,
        ) -> *mut core::ffi::c_void;
    }
    // SAFETY: caller guarantees `lp_file_name` is a NUL-terminated UTF-16
    // buffer and the remaining arguments are valid CreateFileW constants.
    unsafe {
        CreateFileW(
            lp_file_name,
            dw_desired_access,
            dw_share_mode,
            lp_security_attributes,
            dw_creation_disposition,
            dw_flags_and_attributes,
            h_template_file,
        )
    }
}

#[cfg(windows)]
unsafe fn windows_close_handle(handle: *mut core::ffi::c_void) {
    extern "system" {
        fn CloseHandle(hobject: *mut core::ffi::c_void) -> i32;
    }
    // SAFETY: `handle` was returned by CreateFileW and not previously closed.
    unsafe {
        CloseHandle(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_path_points_next_to_exe() {
        let p = lock_path();
        assert!(p.ends_with(LOCK_FILE_NAME));
    }

    #[test]
    #[cfg(unix)]
    fn second_acquire_with_same_path_fails() {
        // Use a unique temp path so parallel test runs don't collide.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "dpi_guard_singleton_test_{}.lock",
            std::process::id()
        ));
        let f1 = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        use std::os::unix::io::AsRawFd;
        let rc = unsafe { libc_flock(f1.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "first lock should succeed");

        let f2 = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let rc2 = unsafe { libc_flock(f2.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_ne!(rc2, 0, "second non-blocking lock must fail");
        let _ = std::fs::remove_file(&path);
    }

    /// Regression for the unlink race: dropping a guard must release the
    /// lock but must NOT delete the lock file.
    ///
    /// If the file were deleted, an instance that acquired the lock in the
    /// window between release and unlink would have its own lock file
    /// unlinked out from under it, letting a third instance create a fresh
    /// file and run concurrently. Keeping the file makes the next
    /// `acquire()` contend on the same inode, which is the whole point.
    #[test]
    #[cfg(unix)]
    fn drop_releases_the_lock_but_keeps_the_file() {
        use std::os::unix::io::AsRawFd;

        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "dpi_guard_singleton_keep_{}_{:?}.lock",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);

        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let rc = unsafe { libc_flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "first lock should succeed");

        let guard = SingletonGuard {
            _file: file,
            path: path.clone(),
        };
        drop(guard);

        // The file must still exist ...
        assert!(
            path.exists(),
            "drop must not unlink the lock file (that is the race)"
        );

        // ... and the lock must actually have been released, so a fresh
        // open of the same path can take it.
        let again = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let rc2 = unsafe { libc_flock(again.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc2, 0, "lock must be free after the guard is dropped");

        let _ = unsafe { libc_flock(again.as_raw_fd(), libc::LOCK_UN) };
        let _ = std::fs::remove_file(&path);
    }
}
