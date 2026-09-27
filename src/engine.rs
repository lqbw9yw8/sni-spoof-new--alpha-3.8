//! engine — Windows-only packet I/O on WinDivert 0.5. [PARTIAL]
//!
//! Written against the published 0.5.5 API (`network`, `recv(Some(&mut buf))`,
//! `send`, `shutdown`, `close`). Still needs a Windows host with the
//! driver to field-test. Pure logic (checksums, fail-open, TLS parse) is
//! delegated to cfg-free modules that have unit tests; the current checkout
//! has not executed the Rust test suite.
#![allow(unsafe_code)]

use crate::error::DpiGuardError;
use crate::fail_open::{handle_exception_fail_open, WireAction};
use crate::sequence::race_condition_fix_delay;
use std::borrow::Cow;
use std::ffi::{c_void, OsString};
use std::net::IpAddr;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Set to true once the WinDivert capture handle is open and the recv loop
/// is about to block. `main` waits on this (bounded) before starting the
/// relay, so the relay never sends packets before capture is live.
static CAPTURE_READY: AtomicBool = AtomicBool::new(false);

/// True once the Windows capture loop has opened its handle and is ready
/// to divert packets. On non-Windows this always returns false (stub).
pub fn capture_is_ready() -> bool {
    CAPTURE_READY.load(Ordering::SeqCst)
}

/// Block up to `timeout` until [`capture_is_ready`] becomes true. Returns
/// true if capture came up, false on timeout. A bounded wait means a
/// capture that fails to start cannot hang the relay forever.
pub fn wait_until_capture_ready(timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if CAPTURE_READY.load(Ordering::SeqCst) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    CAPTURE_READY.load(Ordering::SeqCst)
}

/// Exponential backoff for a persistently failing `recv`: the failure
/// counter is incremented before the first sleep, so the schedule starts
/// at 40 ms, then 80 ms, 160 ms ... capped at 500 ms.
///
/// A **flapping** interface — the adapter being reset, the machine waking
/// from sleep, or a link that keeps dropping and coming back — makes
/// `recv` fail immediately and repeatedly. Without a delay the capture
/// loop spins on a dead handle: one core pinned at 100 % and a log line
/// per iteration (which, written to a file, grows without bound). Pure so
/// it can be unit tested.
pub fn recv_backoff(consecutive_errors: u32) -> Duration {
    let exp = consecutive_errors.min(5);
    let ms = 20u64.saturating_mul(1u64 << exp);
    Duration::from_millis(ms.min(500))
}
use windivert::layer::NetworkLayer;
use windivert::prelude::{WinDivert, WinDivertFlags, WinDivertPacket, WinDivertShutdownMode};

pub use crate::DEFAULT_FILTER;

type Divert = WinDivert<NetworkLayer>;

/// Raw pointer so `WinDivertShutdown` can run concurrent with a blocking
/// `recv` (the C API documents this; the Rust wrapper takes `&mut self`).
static DIVERT: AtomicPtr<Divert> = AtomicPtr::new(std::ptr::null_mut());

const MAX_HELD: usize = 256;

type DivertPacket = WinDivertPacket<'static, NetworkLayer>;

struct Held {
    key: Option<(IpAddr, IpAddr, u16, u16)>,
    packet: DivertPacket,
}

fn held_lock() -> std::sync::MutexGuard<'static, Vec<Held>> {
    static HELD: Mutex<Vec<Held>> = Mutex::new(Vec::new());
    match HELD.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

fn flow_key_of(raw: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16)> {
    let p = crate::packet::parse_l3l4(raw)?;
    Some((p.src, p.dst, p.src_port, p.dst_port))
}

fn remember_hold(packet: DivertPacket) -> bool {
    let mut g = held_lock();
    if g.len() >= MAX_HELD {
        return false;
    }
    let key = flow_key_of(packet.data.as_ref());
    g.push(Held { key, packet });
    true
}

fn forget_held_for_flow(raw: &[u8]) {
    let mut g = held_lock();
    if g.is_empty() {
        // Hot-path fast exit: with no held packets (the overwhelmingly
        // common case) the old code still re-parsed the packet's flow key
        // and swept up to MAX_HELD entries with full-packet memcmp on
        // every sent packet. One lock + length check replaces all of it.
        return;
    }
    let key = flow_key_of(raw);
    g.retain(|h| {
        if h.packet.data.as_ref() == raw {
            return false;
        }
        match (h.key, key) {
            (Some(a), Some(b)) => a != b,
            _ => true,
        }
    });
}

fn send_packet(ptr: *mut Divert, packet: &DivertPacket) {
    if ptr.is_null() {
        return;
    }
    if let Err(e) = unsafe { (*ptr).send(packet) } {
        log::error!("WinDivert send error: {e}");
    }
}

/// Re-inject packets previously returned as `WireAction::Hold`, using the
/// WinDivert address captured with the original divert (not a zeroed
/// send-only address). Called by the 200ms watchdog after
/// `Pipeline::take_expired_held`.
pub fn reinject_held_packets(packets: &[Vec<u8>]) -> Result<(), DpiGuardError> {
    let ptr = DIVERT.load(Ordering::SeqCst);
    for want in packets {
        let found = {
            let mut g = held_lock();
            let idx = g
                .iter()
                .position(|h| h.packet.data.as_ref() == want.as_slice())
                .or_else(|| {
                    let k = flow_key_of(want);
                    g.iter().position(|h| h.key.is_some() && h.key == k)
                });
            idx.map(|i| g.remove(i))
        };
        match found {
            Some(h) => send_packet(ptr, &h.packet),
            None => {
                // The pipeline may already have released this flow while the
                // watchdog was taking its snapshot. There is no safe
                // WinDivert address to attach to `want` in that case: the
                // 0.5.5 API explicitly requires the captured address before
                // `send`, so never fall back to an unsafe zero-address
                // packet. The capture loop has already sent the current
                // packet for this flow, or the packet was removed during
                // shutdown; log and continue without duplicating it.
                log::debug!("held packet no longer present; no captured address to reinject");
            }
        }
    }
    Ok(())
}

fn flush_all_holds(ptr: *mut Divert) {
    let leftover: Vec<Held> = {
        let mut g = held_lock();
        std::mem::take(&mut *g)
    };
    for h in leftover {
        send_packet(ptr, &h.packet);
    }
}

pub fn open_handle(filter: &str) -> Result<Divert, DpiGuardError> {
    WinDivert::network(filter, 0, WinDivertFlags::new())
        .map_err(|e| DpiGuardError::Driver(format!("WinDivert::network open failed: {e}")))
}

/// Handles retired by filter reload / capture shutdown, parked (shut down
/// but not closed) until [`crate::handle_retire`]'s grace period expires,
/// so a thread still inside `send`/`shutdown` on the old pointer is never
/// racing a freed allocation. The list is hard-bounded to
/// [`handle_retire::RETIRED_CAP`] entries; see that module for the safety
/// argument and the pure, OS-independent policy tests.
fn retired_handles() -> std::sync::MutexGuard<'static, Vec<(Box<Divert>, std::time::Instant)>> {
    static RETIRED: Mutex<Vec<(Box<Divert>, std::time::Instant)>> = Mutex::new(Vec::new());
    match RETIRED.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Number of parked (shut-down, not yet closed) driver handles. Exposed for
/// the dashboard's driver-handle-count metric.
pub fn retired_handle_count() -> usize {
    retired_handles().len()
}

/// Whether the live capture handle is currently open (1 driver handle) —
/// together with [`retired_handle_count`] this gives the dashboard's total.
pub fn live_handle_open() -> bool {
    !DIVERT.load(Ordering::SeqCst).is_null()
}

/// Shut the handle down so a blocking `recv` unblocks, then **park** the
/// `Box` until the grace period in [`crate::handle_retire`] has passed.
/// Dropping immediately is a use-after-free if the watchdog already did
/// `DIVERT.load()` and has not finished `send`.
///
/// After parking, sweep the list with the pure policy in
/// [`handle_retire::close_count`]: close (drop) everything past the grace
/// period, oldest first, and force the list back under the hard cap if a
/// pathological filter-reload storm exceeds it. Drops are wrapped in
/// `catch_unwind` — a panic while releasing a handle must never unwind into
/// the capture loop and black-hole the packet path.
fn retire(ptr: *mut Divert) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: `ptr` came from `Box::into_raw` in `store_handle` and is
    // unique after the `AtomicPtr` swap. Shutdown is documented as safe
    // concurrent with an in-flight Recv. The Box is then parked, so no
    // other `from_raw` will run on the same allocation.
    let now = std::time::Instant::now();
    let mut to_close: Vec<Box<Divert>> = Vec::new();
    {
        let mut retired = retired_handles();
        unsafe {
            let mut wd = Box::from_raw(ptr);
            let _ = wd.shutdown(WinDivertShutdownMode::Both);
            retired.push((wd, now));
        }
        let ages_ms: Vec<u64> = retired
            .iter()
            .map(|(_, at)| now.saturating_duration_since(*at).as_millis() as u64)
            .collect();
        let close_n = crate::handle_retire::close_count(
            &ages_ms,
            crate::handle_retire::RETIRED_CAP,
            crate::handle_retire::RETIRED_GRACE.as_millis() as u64,
        );
        if close_n > 0 {
            log::debug!("closing {close_n} retired WinDivert handle(s) past the grace window");
        }
        let forced = close_n.saturating_sub(
            ages_ms
                .iter()
                .take_while(|&&a| a >= crate::handle_retire::RETIRED_GRACE.as_millis() as u64)
                .count(),
        );
        if forced > 0 {
            log::error!(
                "filter-reload storm: force-closing {forced} retired WinDivert handle(s) still inside the {}s grace window to hold the {}-handle cap",
                crate::handle_retire::RETIRED_GRACE.as_secs(),
                crate::handle_retire::RETIRED_CAP
            );
        }
        to_close.extend(retired.drain(..close_n).map(|(wd, _)| wd));
    }
    for wd in to_close {
        // Closing = dropping the Box (Drop closes the driver handle). A
        // panic here must not take down the capture loop: catch it, log,
        // and move on — the handle is already shut down either way.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(wd)));
    }
}

fn store_handle(wd: Divert) -> *mut Divert {
    let ptr = Box::into_raw(Box::new(wd));
    let old = DIVERT.swap(ptr, Ordering::SeqCst);
    retire(old);
    ptr
}

fn drop_stored_handle() {
    let ptr = DIVERT.swap(std::ptr::null_mut(), Ordering::SeqCst);
    retire(ptr);
}

/// Abort a blocking `recv` so Ctrl+C does not wait for the next packet.
pub fn request_shutdown() {
    let ptr = DIVERT.load(Ordering::SeqCst);
    if !ptr.is_null() {
        // SAFETY: WinDivertShutdown is defined to fail in-flight Recv calls.
        unsafe {
            let _ = (*ptr).shutdown(WinDivertShutdownMode::Both);
        }
    }
}

/// Pending filter change, requested by the config hot-reload watcher when
/// `intercept_ports` / `intercept_all_*` change. The capture loop consumes
/// it and reopens the handle before the next packet.
fn pending_filter_lock() -> std::sync::MutexGuard<'static, Option<String>> {
    static PENDING_FILTER: Mutex<Option<String>> = Mutex::new(None);
    match PENDING_FILTER.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Store a new filter and abort the in-flight `recv` so the capture loop
/// can reopen with it. No-op until the capture loop is running.
pub fn request_filter_reload(new_filter: &str) {
    *pending_filter_lock() = Some(new_filter.to_string());
    request_shutdown();
}

/// Reopen the capture handle with a pending filter, if one was requested.
/// Returns true when a pending filter was consumed. The old handle has
/// already been shut down by `request_filter_reload`, so on open failure we
/// fall back to the previous filter to keep the packet path alive.
fn apply_pending_filter(ptr: &mut *mut Divert, current: &mut String) -> bool {
    let pending = match pending_filter_lock().take() {
        Some(f) => f,
        None => return false,
    };
    match open_handle(&pending) {
        Ok(h) => {
            *ptr = store_handle(h);
            log::info!("WinDivert filter reloaded: {pending}");
            *current = pending;
        }
        Err(e) => {
            log::error!("WinDivert filter reload failed ({e}); falling back to previous filter");
            match open_handle(current.as_str()) {
                Ok(h) => *ptr = store_handle(h),
                Err(e2) => log::error!("previous-filter reopen also failed: {e2}"),
            }
        }
    }
    true
}

/// Blocking capture loop. Run it on a dedicated thread / `spawn_blocking`
/// — `recv` is a blocking driver call.
pub fn capture_loop<F>(
    filter: &str,
    running: Arc<AtomicBool>,
    injection_delay: Option<(u64, u64)>,
    mut on_packet: F,
) -> Result<(), DpiGuardError>
where
    F: FnMut(&[u8]) -> Result<WireAction, DpiGuardError> + Send + 'static,
{
    let handle = open_handle(filter)?;
    let mut ptr = store_handle(handle);
    let mut current_filter = filter.to_string();
    let mut buf = vec![0u8; 65535];

    // The handle is open and recv is about to block: the relay may now
    // connect. main waits on this before spawnng the relay.
    CAPTURE_READY.store(true, Ordering::SeqCst);

    // Consecutive `recv` failures, used for exponential backoff so a
    // flapping interface cannot turn this loop into a busy spin.
    let mut consecutive_errors: u32 = 0;
    while running.load(Ordering::SeqCst) {
        // Apply a hot-reloaded filter before blocking on the next packet.
        apply_pending_filter(&mut ptr, &mut current_filter);
        let recv = unsafe { (*ptr).recv(Some(&mut buf)) };
        let recv = match recv {
            Ok(pkt) => {
                consecutive_errors = 0;
                pkt
            }
            Err(e) => {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                crate::observability::capture_error();
                consecutive_errors = consecutive_errors.saturating_add(1);
                // Log the first failure and then every 100th. A link that
                // drops and returns once a second would otherwise write a
                // warning per iteration.
                if consecutive_errors == 1 || consecutive_errors % 100 == 0 {
                    log::warn!(
                        "WinDivert recv error ({consecutive_errors} in a row), backing off {:?}: {e}",
                        recv_backoff(consecutive_errors)
                    );
                } else {
                    log::debug!("WinDivert recv error: {e}");
                }
                std::thread::sleep(recv_backoff(consecutive_errors));
                continue;
            }
        };

        // `into_owned` moves the receive buffer when the driver already
        // handed us an owned packet, and copies only when it borrowed the
        // reusable `buf` — never worse than the previous unconditional
        // `to_vec()`.
        let original: Vec<u8> = recv.data.into_owned();
        let address = recv.address.clone();
        let action = handle_exception_fail_open(&original, &mut on_packet);
        match action {
            WireAction::Hold => {
                crate::observability::packet_held();
                let held = WinDivertPacket::<'static, NetworkLayer> {
                    address: address.clone(),
                    data: Cow::Owned(original.clone()),
                };
                if !remember_hold(held) {
                    // Cap full: fail-open the original immediately with
                    // the real divert address so the connection cannot
                    // black-hole.
                    let pkt = WinDivertPacket::<'static, NetworkLayer> {
                        address,
                        data: Cow::Owned(original),
                    };
                    send_packet(ptr, &pkt);
                }
            }
            WireAction::Passthrough => {
                // The packet was not modified: reinject the buffer we
                // already own. This used to rebuild an identical `Vec`
                // inside the pipeline (`Send(vec![raw.to_vec()])`) just to
                // rediscover these bytes — one avoidable alloc + full
                // memcpy per pass-through packet, on ~99% of traffic.
                forget_held_for_flow(&original);
                let pkt = WinDivertPacket::<'static, NetworkLayer> {
                    address,
                    data: Cow::Owned(original),
                };
                send_packet(ptr, &pkt);
            }
            WireAction::Send(packets) => {
                forget_held_for_flow(&original);
                for (i, bytes) in packets.into_iter().enumerate() {
                    if i > 0 {
                        // Jitter between the injected fake/decoy packets.
                        // `injection_delay_min_ms`/`_max_ms` (config, part of
                        // the anti-fingerprint bundle) widen the fixed 50 us
                        // gap into a randomised one so the fake's timing is
                        // not a constant the DPI can key on.
                        std::thread::sleep(match injection_delay {
                            Some((min, max)) => {
                                crate::anti_fingerprint::random_injection_delay(min, max)
                            }
                            None => race_condition_fix_delay(),
                        });
                    }
                    let pkt = WinDivertPacket::<'static, NetworkLayer> {
                        address: address.clone(),
                        data: Cow::Owned(bytes),
                    };
                    send_packet(ptr, &pkt);
                }
            }
        }
    }
    flush_all_holds(ptr);
    drop_stored_handle();
    CAPTURE_READY.store(false, Ordering::SeqCst);
    Ok(())
}

pub fn parse_tls_client_hello(tcp_payload: &[u8]) -> Option<Vec<u8>> {
    crate::fragmentation::sni_bytes(tcp_payload)
}

pub fn recalculate_checksums(pkt: &mut Vec<u8>) {
    crate::packet::recalculate_all_checksums(pkt);
}

/// Reject address-less injection instead of constructing a zeroed
/// `WinDivertPacket`. In windivert 0.5.5, `WinDivertPacket::new` is unsafe
/// specifically because its address is zeroed and **must be filled with the
/// correct captured interface/direction before `send`**. The live capture
/// path always sends a packet carrying the address returned by `recv`; this
/// compatibility entry point has no address and therefore cannot be safe.
pub fn inject_packet(_packet: &[u8]) -> Result<(), DpiGuardError> {
    Err(DpiGuardError::Driver(
        "address-less injection refused: use the captured WinDivert address".into(),
    ))
}

pub fn thread_safe_logging_init() {
    crate::init_logging();
}

pub fn graceful_shutdown(running: Arc<AtomicBool>) -> Result<(), DpiGuardError> {
    running.store(false, Ordering::SeqCst);
    request_shutdown();
    Ok(())
}

/// Files held by the backend for its entire lifetime. Hashing a path and
/// then loading it later leaves a replacement window; these read handles are
/// opened with delete/write sharing disabled before the hash is computed.
/// The DLL module reference is also retained so the verified module cannot be
/// unloaded and replaced while WinDivert is using it.
pub struct DriverPin {
    _dll_file: std::fs::File,
    _sys_file: std::fs::File,
    module: *mut c_void,
}

impl Drop for DriverPin {
    fn drop(&mut self) {
        // SAFETY: `module` is a live reference returned by LoadLibraryExW and
        // is released exactly once, after the capture handle has shut down.
        unsafe {
            FreeLibrary(self.module);
        }
    }
}

const FILE_SHARE_READ: u32 = 0x0000_0001;
const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;

extern "system" {
    fn FreeLibrary(module: *mut c_void) -> i32;
    fn GetModuleFileNameW(module: *mut c_void, filename: *mut u16, size: u32) -> u32;
    fn LoadLibraryExW(filename: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
}

fn nul_terminated_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn comparable_path(path: &Path) -> String {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let text = canonical.to_string_lossy().replace('/', "\\");
    text.strip_prefix("\\\\?\\")
        .unwrap_or(&text)
        .to_ascii_lowercase()
}

/// Return the path of the module Windows actually loaded. Checking only the
/// file next to the executable is insufficient when the loader resolved a
/// same-named DLL from another directory.
fn loaded_module_path(module: *mut c_void) -> Result<PathBuf, DpiGuardError> {
    let mut buf = vec![0u16; 32_768];
    let len = unsafe { GetModuleFileNameW(module, buf.as_mut_ptr(), buf.len() as u32) };
    if len == 0 || len as usize >= buf.len() {
        return Err(DpiGuardError::Driver(format!(
            "cannot determine the loaded WinDivert.dll path: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(PathBuf::from(OsString::from_wide(&buf[..len as usize])))
}

fn load_verified_dll(path: &Path) -> Result<*mut c_void, DpiGuardError> {
    let wide = nul_terminated_wide(path);
    // The absolute path plus DLL-load-directory flags prevents the normal
    // current-directory/PATH search from selecting a planted DLL. Holding
    // the returned module reference keeps this exact loaded image alive.
    let module = unsafe {
        LoadLibraryExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        )
    };
    if module.is_null() {
        return Err(DpiGuardError::Driver(format!(
            "LoadLibraryExW could not load the verified WinDivert.dll at {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    let loaded = match loaded_module_path(module) {
        Ok(path) => path,
        Err(e) => {
            unsafe {
                FreeLibrary(module);
            }
            return Err(e);
        }
    };
    if comparable_path(&loaded) != comparable_path(path) {
        unsafe {
            FreeLibrary(module);
        }
        return Err(DpiGuardError::Driver(format!(
            "WinDivert.dll loader path mismatch: expected {}, loaded {}",
            path.display(),
            loaded.display()
        )));
    }
    Ok(module)
}

fn open_pinned_file(path: &Path) -> Result<std::fs::File, DpiGuardError> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        // Do not grant delete/write sharing. A replacement cannot occur
        // between hashing this handle and the driver loader using the path.
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(DpiGuardError::Io)
}

/// Confirm the WinDivert binaries sit next to the **executable** (never cwd),
/// hash the exact open handles, load the DLL from that absolute path, and
/// verify the module path Windows resolved. The returned [`DriverPin`] must
/// stay alive until capture shutdown; it closes the hash/replace race that a
/// one-shot `Result<()>` check could not close.
pub fn version_check(expected_hashes: &[String]) -> Result<DriverPin, DpiGuardError> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .ok_or_else(|| {
            DpiGuardError::Driver("cannot determine executable directory for driver search".into())
        })?;

    // These are the names used by the WinDivert import and by the official
    // architecture-specific driver package. Do not accept alternate names.
    let dll = exe_dir.join("WinDivert.dll");
    let sys_name = if cfg!(target_arch = "x86") {
        "WinDivert32.sys"
    } else {
        "WinDivert64.sys"
    };
    let sys = exe_dir.join(sys_name);

    if !dll.is_file() || !sys.is_file() {
        return Err(DpiGuardError::Driver(format!(
            "WinDivert.dll and {sys_name} not found next to the executable — download the official release, do not commit the driver to git, do not load from cwd"
        )));
    }

    let pins: Vec<String> = expected_hashes
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    if pins.len() != 2 {
        return Err(DpiGuardError::Driver(format!(
            "win_divert_sha256 must contain exactly two SHA-256 pins in order: WinDivert.dll, {sys_name}"
        )));
    }
    if pins
        .iter()
        .any(|p| p.len() != 64 || !p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(DpiGuardError::Driver(
            "win_divert_sha256 entries must be exactly 64 hexadecimal characters".into(),
        ));
    }

    // The two handles are opened before either digest is calculated. This
    // makes the path, bytes, and retained file identity one atomic check from
    // the perspective of a local attacker.
    let mut dll_file = open_pinned_file(&dll)?;
    let mut sys_file = open_pinned_file(&sys)?;
    let dll_hash = crate::integrity::sha256_hex_file_handle(
        &mut dll_file,
        &dll,
        crate::integrity::MAX_DRIVER_BYTES,
    )?;
    let sys_hash = crate::integrity::sha256_hex_file_handle(
        &mut sys_file,
        &sys,
        crate::integrity::MAX_DRIVER_BYTES,
    )?;
    let dll_ok = crate::integrity::constant_time_eq(dll_hash.as_bytes(), pins[0].as_bytes());
    let sys_ok = crate::integrity::constant_time_eq(sys_hash.as_bytes(), pins[1].as_bytes());
    if !dll_ok || !sys_ok {
        let bad = if !dll_ok { &dll } else { &sys };
        let hash = if !dll_ok { &dll_hash } else { &sys_hash };
        return Err(DpiGuardError::Driver(format!(
            "refusing to load {}: SHA-256 {hash} does not match its ordered trusted pin (possible tampered or swapped driver)",
            bad.display()
        )));
    }
    log::info!("verified {} SHA-256", dll.display());
    log::info!("verified {} SHA-256", sys.display());

    let module = load_verified_dll(&dll)?;
    log::info!(
        "WinDivert.dll and {sys_name} are pinned, path-verified, and held for the backend lifetime"
    );
    Ok(DriverPin {
        _dll_file: dll_file,
        _sys_file: sys_file,
        module,
    })
}

#[cfg(test)]
mod tests {
    // Fail-open tests live in `fail_open.rs` so they run on Linux CI.
}
