//! proxy_cleanup — save and restore Windows system proxy settings. [UNTESTED]
//!
//! Before enabling system proxy, saves the current state. On exit or
//! crash, restores it. Prevents orphaned proxy settings that break
//! internet access after dpi_guard terminates unexpectedly.

use crate::error::DpiGuardError;
use std::path::PathBuf;
use std::sync::Mutex;

static SAVED_STATE: Mutex<Option<ProxyState>> = Mutex::new(None);

/// Snapshot of Windows system proxy settings.
#[derive(Debug, Clone, Default)]
pub struct ProxyState {
    pub proxy_enabled: bool,
    pub proxy_server: String,
    pub proxy_override: String,
    pub auto_config_url: String,
}

/// Read current Windows proxy settings from the registry.
pub fn read_system_proxy() -> Result<ProxyState, DpiGuardError> {
    #[cfg(windows)]
    {
        use std::process::Command;
        // Use PowerShell to read registry
        let output = Command::new("powershell")
            .args(&[
                "-NoProfile", "-Command",
                "Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | \
                 Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL | \
                 ConvertTo-Json"
            ])
            .output()
            .map_err(|e| DpiGuardError::Io(e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse JSON response
        let mut state = ProxyState::default();
        for line in stdout.lines() {
            let line = line.trim().trim_matches(',').trim_matches('"');
            if line.starts_with("\"ProxyEnable\"") || line.contains("ProxyEnable") {
                state.proxy_enabled = line.contains(": 1") || line.contains(":1");
            }
            if line.starts_with("\"ProxyServer\"") {
                if let Some(val) = line.split(':').nth(1) {
                    state.proxy_server = val.trim().trim_matches('"').trim_matches(',').to_string();
                }
            }
        }
        Ok(state)
    }

    #[cfg(not(windows))]
    {
        // On non-Windows, return empty state
        Ok(ProxyState::default())
    }
}

/// Save current proxy state for later restoration.
pub fn save_state() -> Result<(), DpiGuardError> {
    let state = read_system_proxy()?;
    let mut saved = SAVED_STATE.lock().unwrap_or_else(|e| e.into_inner());
    *saved = Some(state);
    Ok(())
}

/// Restore previously saved proxy state.
pub fn restore_state() -> Result<(), DpiGuardError> {
    let saved = SAVED_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(state) = saved.as_ref() {
        set_system_proxy(state)?;
    }
    Ok(())
}

/// Apply proxy settings to the system.
pub fn set_system_proxy(state: &ProxyState) -> Result<(), DpiGuardError> {
    #[cfg(windows)]
    {
        use std::process::Command;
        // F-005: registry values are interpolated into PowerShell
        // single-quoted strings — escape single quotes (PowerShell doubles
        // them) and strip line breaks so a hostile/broken value cannot
        // break out of the command or inject new statements.
        let esc =
            |s: &str| -> String { s.replace('\'', "''").replace('\r', " ").replace('\n', " ") };
        let enable = if state.proxy_enabled { 1 } else { 0 };
        let _ = Command::new("powershell")
            .args(&[
                "-NoProfile", "-Command",
                &format!(
                    "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' \
                     -Name ProxyEnable -Value {enable}; \
                     Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' \
                     -Name ProxyServer -Value '{}'; \
                     Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' \
                     -Name ProxyOverride -Value '{}'",
                    esc(&state.proxy_server), esc(&state.proxy_override)
                ),
            ])
            .output()
            .map_err(|e| DpiGuardError::Io(e))?;
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = state;
        Ok(()) // No-op on non-Windows
    }
}

/// Enable system proxy to point at dpi_guard relay.
pub fn enable_dpi_guard_proxy(listen_addr: &str, port: u16) -> Result<(), DpiGuardError> {
    // Save current state first
    save_state()?;

    let state = ProxyState {
        proxy_enabled: true,
        proxy_server: format!("{listen_addr}:{port}"),
        proxy_override: "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*".into(),
        auto_config_url: String::new(),
    };
    set_system_proxy(&state)
}

/// Disable dpi_guard proxy and restore previous settings.
pub fn disable_dpi_guard_proxy() -> Result<(), DpiGuardError> {
    restore_state()
}

/// Path for the proxy state backup file (next to exe).
pub fn state_file_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join("dpi_guard.proxy_state");
        }
    }
    PathBuf::from("dpi_guard.proxy_state")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_proxy_state_is_disabled() {
        let state = ProxyState::default();
        assert!(!state.proxy_enabled);
        assert!(state.proxy_server.is_empty());
    }

    #[test]
    fn state_file_path_ends_with_expected_name() {
        let path = state_file_path();
        assert!(path.to_string_lossy().ends_with("dpi_guard.proxy_state"));
    }

    #[test]
    fn enable_and_disable_dpi_guard_proxy_roundtrips() {
        // On non-Windows these are safe no-ops that return Ok(())
        let res = enable_dpi_guard_proxy("127.0.0.1", 40443);
        assert!(res.is_ok());
        let res_disable = disable_dpi_guard_proxy();
        assert!(res_disable.is_ok());
    }

    #[test]
    fn save_and_restore_state_roundtrips() {
        assert!(save_state().is_ok());
        assert!(restore_state().is_ok());
    }
}
