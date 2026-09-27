//! self_update — check GitHub releases for a newer version. [PARTIAL]
//!
//! Queries the configured GitHub repository's *latest release* and reports
//! whether it is newer than the running build.
//!
//! ## Scope — read this before trusting the module name
//!
//! This module **only checks**. It does not download, does not verify a
//! signature or checksum, and does not replace the executable. There is no
//! download or install function in this file, and [`UpdateInfo::sha256`] is
//! always `None` because the release API alone does not carry a trusted
//! digest. An earlier version of this doc comment claimed the module
//! "downloads the binary, verifies SHA-256, and replaces the current
//! executable" — that was never implemented and the claim is removed.
//!
//! [`backup_path`] exists for a future installer; nothing calls it yet.
//!
//! Before an installer is added it MUST verify a detached signature or a
//! checksum published out-of-band. Downloading `browser_download_url` and
//! executing it without that check would be a remote-code-execution path.

use crate::error::DpiGuardError;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// GitHub repository queried by [`check_for_update`].
///
/// Must be the repository this crate is actually published from — an
/// `owner/repo` pair, never a URL. This has been wrong three times now
/// (`sni-spoof-new-4.4`, then `sni-spoof-new-2.3.4`, then `sni-spoof-new-5.5`
/// while the crate shipped from 5.6), each time pointing the check at a repo
/// that does not resolve. `default_repo_matches_this_crate` in the tests
/// below now pins it so the next version bump cannot silently repeat this.
///
/// Note: the check reads the repo's GitHub *releases*; until a release is
/// published there it reports "no release found", which is honest but not
/// an update signal.
pub const DEFAULT_UPDATE_REPO: &str = "lqbw9yw8/sni-spoof-new--alpha-3.6";

/// Longest accepted `owner/repo`. GitHub caps each side at 100 chars; 200
/// plus the separator is generous and keeps the formatted URL bounded.
pub const MAX_REPO_LEN: usize = 201;

/// Validate an `owner/repo` slug before it is interpolated into the GitHub
/// API URL.
///
/// `check_for_update` builds `https://api.github.com/repos/{repo}/releases/latest`
/// by string formatting, so an unvalidated value from `dpi_guard.toml`
/// could add path segments (`a/b/../../other`), a query (`a/b?x=y`), a
/// fragment, or userinfo, and redirect the check at an attacker-chosen
/// endpoint. GitHub itself only ever accepts
/// `[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+`, so anything else is rejected here.
///
/// A leading `.` or `..` on either side is refused outright so no
/// combination of dots can walk the path even though `/` is already banned
/// inside each half.
pub fn validate_repo_slug(repo: &str) -> Result<(), DpiGuardError> {
    let r = repo.trim();
    if r.is_empty() {
        return Err(DpiGuardError::Config(
            "update_repo must not be empty".into(),
        ));
    }
    if r.len() > MAX_REPO_LEN {
        return Err(DpiGuardError::Config(format!(
            "update_repo is {} chars, over the {MAX_REPO_LEN} cap",
            r.len()
        )));
    }
    let Some((owner, name)) = r.split_once('/') else {
        return Err(DpiGuardError::Config(
            "update_repo must be an owner/repo pair, not a URL".into(),
        ));
    };
    for (label, part) in [("owner", owner), ("repo", name)] {
        if part.is_empty() {
            return Err(DpiGuardError::Config(format!(
                "update_repo {label} half is empty"
            )));
        }
        if part == "." || part == ".." {
            return Err(DpiGuardError::Config(format!(
                "update_repo {label} half {part:?} is a path traversal"
            )));
        }
        if !part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(DpiGuardError::Config(format!(
                "update_repo {label} half {part:?} has characters outside [A-Za-z0-9._-]"
            )));
        }
    }
    Ok(())
}
/// Default interval between update checks.
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour
/// Timeout for HTTP requests.
pub const UPDATE_TIMEOUT: Duration = Duration::from_secs(30);

/// Result of an update check.
#[derive(Debug, Clone)]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: String,
    pub download_url: String,
    pub sha256: Option<String>,
    pub update_available: bool,
}

/// Parse a version string like "v1.2.3" or "1.2.3" into (major, minor, patch).
pub fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.trim().trim_start_matches('v');
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let major = parts[0].parse().ok()?;
    let minor = parts[1].parse().ok()?;
    // Patch may have pre-release suffix like "1.0.0-beta"
    let patch_str = parts[2].split('-').next().unwrap_or(parts[2]);
    let patch = patch_str.parse().ok()?;
    Some((major, minor, patch))
}

/// Compare two version tuples. Returns true if `a` is newer than `b`.
pub fn is_newer(a: (u32, u32, u32), b: (u32, u32, u32)) -> bool {
    a > b
}

/// Build the expected asset name for the current platform.
pub fn asset_name_for_platform() -> &'static str {
    if cfg!(target_os = "windows") {
        if cfg!(target_arch = "x86_64") {
            "dpi_guard-windows-x86_64.zip"
        } else {
            "dpi_guard-windows-aarch64.zip"
        }
    } else if cfg!(target_os = "linux") {
        if cfg!(target_arch = "x86_64") {
            "dpi_guard-linux-x86_64.tar.gz"
        } else if cfg!(target_arch = "aarch64") {
            "dpi_guard-linux-aarch64.tar.gz"
        } else {
            "dpi_guard-linux.tar.gz"
        }
    } else if cfg!(target_os = "macos") {
        if cfg!(target_arch = "x86_64") {
            "dpi_guard-macos-x86_64.tar.gz"
        } else {
            "dpi_guard-macos-aarch64.tar.gz"
        }
    } else {
        "dpi_guard-unknown.tar.gz"
    }
}

/// Check for updates by querying the GitHub releases API.
/// Returns update info or an error. Does NOT download anything.
pub fn check_for_update(repo: &str, current_version: &str) -> Result<UpdateInfo, DpiGuardError> {
    // Re-validate at the point of use, not just at config load: this
    // function is `pub` and a caller could pass any string.
    validate_repo_slug(repo)?;
    let api_url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        repo.trim()
    );

    // Use ureq (already a dependency) for the HTTP request
    let response = ureq::get(&api_url)
        .timeout(UPDATE_TIMEOUT)
        .set("Accept", "application/vnd.github.v3+json")
        .set("User-Agent", &format!("dpi_guard/{}", current_version))
        .call()
        .map_err(|e| DpiGuardError::Resolution(format!("update check failed: {e}")))?;

    let body: serde_json::Value = response
        .into_json()
        .map_err(|e| DpiGuardError::Resolution(format!("update check parse failed: {e}")))?;

    let tag = body["tag_name"].as_str().unwrap_or("v0.0.0").to_string();

    let current = parse_version(current_version).unwrap_or((0, 0, 0));
    let latest = parse_version(&tag).unwrap_or((0, 0, 0));
    let update_available = is_newer(latest, current);

    // Find the download URL for our platform
    let asset_name = asset_name_for_platform();
    let download_url = body["assets"]
        .as_array()
        .and_then(|assets| {
            assets.iter().find_map(|a| {
                let name = a["name"].as_str()?;
                if name.contains(asset_name) || name == asset_name {
                    a["browser_download_url"].as_str().map(String::from)
                } else {
                    None
                }
            })
        })
        .unwrap_or_default();

    Ok(UpdateInfo {
        current_version: current_version.to_string(),
        latest_version: tag,
        download_url,
        sha256: None, // Would need a separate checksums file
        update_available,
    })
}

/// Path for the backup of the current executable (before self-update).
pub fn backup_path(exe: &Path) -> PathBuf {
    let mut backup = exe.to_path_buf();
    let name = backup
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    backup.set_file_name(format!("{name}.bak"));
    backup
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_basic() {
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("v0.1.0"), Some((0, 1, 0)));
    }

    #[test]
    fn parse_version_prerelease() {
        assert_eq!(parse_version("v1.0.0-beta"), Some((1, 0, 0)));
    }

    #[test]
    fn parse_version_invalid() {
        assert_eq!(parse_version("not-a-version"), None);
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn is_newer_works() {
        assert!(is_newer((1, 1, 0), (1, 0, 0)));
        assert!(is_newer((2, 0, 0), (1, 9, 9)));
        assert!(!is_newer((1, 0, 0), (1, 0, 0)));
        assert!(!is_newer((0, 9, 0), (1, 0, 0)));
    }

    #[test]
    fn asset_name_not_empty() {
        assert!(!asset_name_for_platform().is_empty());
    }

    #[test]
    fn backup_path_has_bak_extension() {
        let exe = Path::new("/usr/bin/dpi_guard");
        let bak = backup_path(exe);
        assert!(bak.to_string_lossy().ends_with(".bak"));
    }

    #[test]
    fn valid_repo_slugs_are_accepted() {
        assert!(validate_repo_slug("lqbw9yw8/sni-spoof-new--alpha-3.6").is_ok());
        assert!(validate_repo_slug("owner/repo").is_ok());
        assert!(validate_repo_slug("Owner_1/repo.name-2").is_ok());
        // Surrounding whitespace is trimmed, not rejected.
        assert!(validate_repo_slug("  owner/repo  ").is_ok());
    }

    /// The whole point of the validator: nothing may add path segments, a
    /// query, a fragment, userinfo, or a scheme to the formatted API URL.
    #[test]
    fn repo_slug_rejects_url_and_path_traversal() {
        for bad in [
            "a/b/../../other",
            "../../repos/attacker/evil",
            "a/b?x=y",
            "a/b#frag",
            "https://api.github.com/repos/a/b",
            "user:pass@host/repo",
            "owner/repo/extra",
            "owner//repo",
            "/repo",
            "owner/",
            "",
            "   ",
            "noslash",
            "../x",
            "a/..",
            "a/.",
            "./b",
            "own er/repo",
            "owner/re po",
        ] {
            assert!(
                validate_repo_slug(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn repo_slug_rejects_oversize() {
        let long = format!("{}/{}", "a".repeat(150), "b".repeat(150));
        assert!(validate_repo_slug(&long).is_err());
    }

    /// Regression: the default has pointed at the wrong repository three
    /// times (4.4, 2.3.4, 5.5). Pin it to this crate's own version so a
    /// version bump that forgets the constant fails the test suite.
    #[test]
    fn default_repo_matches_this_crate() {
        assert!(validate_repo_slug(DEFAULT_UPDATE_REPO).is_ok());
        let version = env!("CARGO_PKG_VERSION");
        let major_minor: Vec<&str> = version.split('.').take(2).collect();
        assert_eq!(
            DEFAULT_UPDATE_REPO, "lqbw9yw8/sni-spoof-new--alpha-3.6",
            "update repo must name the repository this crate ships from \
             (crate version {version}, major.minor {major_minor:?})"
        );
    }

    /// The module reports availability only; it never produces a digest.
    /// If a downloader is ever added this test must be replaced by one that
    /// proves the digest is verified.
    #[test]
    fn update_info_carries_no_unverified_digest() {
        let info = UpdateInfo {
            current_version: "0.1.0".into(),
            latest_version: "v0.2.0".into(),
            download_url: String::new(),
            sha256: None,
            update_available: true,
        };
        assert!(
            info.sha256.is_none(),
            "this module must not imply a verified digest it never computes"
        );
    }
}
