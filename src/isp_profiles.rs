//! isp_profiles — ISP-specific DPI bypass profiles. [UNTESTED]
//!
//! Different ISPs use different DPI systems (TSPU, Sandvine, Fortinet,
//! custom). Each profile bundles recommended settings for that ISP.

use crate::config::Settings;
use std::str::FromStr;

/// Known ISP profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IspProfile {
    /// Iran — MCI (Hamrah-e Aval) — TSPU-based
    Mci,
    /// Iran — ایرانسل (Irancell) — different TSPU config
    Irancell,
    /// Iran — automatic detection (probe-based)
    Auto,
    /// Russia — TSPU
    Russia,
    /// China — GFW
    China,
    /// Generic / unknown ISP — default Stealth
    Generic,
}

impl IspProfile {
    pub const ALL: [IspProfile; 6] = [
        IspProfile::Mci,
        IspProfile::Irancell,
        IspProfile::Auto,
        IspProfile::Russia,
        IspProfile::China,
        IspProfile::Generic,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            IspProfile::Mci => "mci",
            IspProfile::Irancell => "irancell",
            IspProfile::Auto => "auto",
            IspProfile::Russia => "russia",
            IspProfile::China => "china",
            IspProfile::Generic => "generic",
        }
    }

    /// Apply ISP-specific overrides to a base settings struct.
    /// Only changes fields that differ from the defaults; other fields
    /// retain whatever the operator configured.
    pub fn apply_overrides(&self, s: &mut Settings) {
        match self {
            IspProfile::Mci => {
                s.mutation_profile = "Stealth".into();
                s.fragment_chunk_size = 32;
                s.decoy_ttl = 6;
                s.enable_combined_fragmentation = true;
                s.enable_tls_record_fragmentation = true;
                s.relay_fake_sni = "www.microsoft.com".into();
                s.enable_decoys = true;
                s.intercept_all_tcp = true;
                s.intercept_all_udp = false;
            }
            IspProfile::Irancell => {
                s.mutation_profile = "Stealth".into();
                s.fragment_chunk_size = 48;
                s.decoy_ttl = 8;
                s.enable_combined_fragmentation = true;
                s.enable_tls_record_fragmentation = true;
                s.relay_fake_sni = "www.apple.com".into();
                s.enable_decoys = true;
                s.intercept_all_tcp = true;
                s.intercept_all_udp = false;
            }
            IspProfile::Russia => {
                s.mutation_profile = "RussiaDpi".into();
                // F-008: 8 is the smallest chunk Settings::validate accepts
                // (0 or 8..=16384); 2 would make the profile invalid.
                s.fragment_chunk_size = 8;
                s.decoy_ttl = 4;
                s.enable_tls_record_fragmentation = true;
                s.enable_reverse_frag = true;
                s.enable_wrong_seq = true;
                s.enable_wrong_checksum = true;
                s.relay_fake_sni = "www.google.com".into();
                s.intercept_all_tcp = true;
                s.intercept_all_udp = true;
            }
            IspProfile::China => {
                s.mutation_profile = "ChinaGfw".into();
                s.fragment_chunk_size = 64;
                s.decoy_ttl = 8;
                s.enable_quic_port_bypass = true;
                s.enable_combined_fragmentation = true;
                s.relay_fake_sni = "www.microsoft.com".into();
                s.intercept_all_tcp = true;
                s.intercept_all_udp = true;
            }
            IspProfile::Auto | IspProfile::Generic => {
                // No overrides — use defaults or operator-configured values
            }
        }
    }

    /// Return a list of recommended fake SNIs for this ISP.
    pub fn recommended_fake_snis(&self) -> Vec<&'static str> {
        match self {
            IspProfile::Mci => vec![
                "www.microsoft.com",
                "speedtest.net",
                "www.cloudflare.com",
                "learn.microsoft.com",
            ],
            IspProfile::Irancell => vec![
                "www.apple.com",
                "www.microsoft.com",
                "cdn.discordapp.com",
                "www.vercel.com",
            ],
            IspProfile::Russia => vec!["www.google.com", "www.microsoft.com", "www.apple.com"],
            IspProfile::China => vec!["www.microsoft.com", "www.apple.com", "www.cloudflare.com"],
            IspProfile::Auto | IspProfile::Generic => vec![
                "www.microsoft.com",
                "www.apple.com",
                "www.cloudflare.com",
                "speedtest.net",
            ],
        }
    }
}

impl FromStr for IspProfile {
    type Err = crate::error::DpiGuardError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mci" => Ok(IspProfile::Mci),
            "irancell" => Ok(IspProfile::Irancell),
            "auto" => Ok(IspProfile::Auto),
            "russia" => Ok(IspProfile::Russia),
            "china" => Ok(IspProfile::China),
            "generic" => Ok(IspProfile::Generic),
            other => Err(crate::error::DpiGuardError::Config(
                format!("unknown isp_profile {other:?}; expected mci, irancell, auto, russia, china, generic")
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_profiles() {
        assert_eq!(IspProfile::from_str("mci").unwrap(), IspProfile::Mci);
        assert_eq!(
            IspProfile::from_str("irancell").unwrap(),
            IspProfile::Irancell
        );
        assert_eq!(IspProfile::from_str("AUTO").unwrap(), IspProfile::Auto);
        assert_eq!(IspProfile::from_str("Russia").unwrap(), IspProfile::Russia);
        assert_eq!(IspProfile::from_str("china").unwrap(), IspProfile::China);
        assert_eq!(
            IspProfile::from_str("generic").unwrap(),
            IspProfile::Generic
        );
        assert!(IspProfile::from_str("unknown").is_err());
    }

    #[test]
    fn apply_overrides_changes_settings() {
        let mut s = Settings::default();
        IspProfile::Mci.apply_overrides(&mut s);
        assert_eq!(s.mutation_profile, "Stealth");
        assert_eq!(s.fragment_chunk_size, 32);
        assert_eq!(s.decoy_ttl, 6);
        assert_eq!(s.relay_fake_sni, "www.microsoft.com");
    }

    #[test]
    fn apply_overrides_russia_enables_reverse_frag() {
        let mut s = Settings::default();
        IspProfile::Russia.apply_overrides(&mut s);
        assert!(s.enable_reverse_frag);
        assert!(s.enable_wrong_seq);
        assert_eq!(s.mutation_profile, "RussiaDpi");
    }

    #[test]
    fn auto_and_generic_do_not_change_settings() {
        let mut s1 = Settings::default();
        let original = s1.clone();
        IspProfile::Auto.apply_overrides(&mut s1);
        assert_eq!(s1.mutation_profile, original.mutation_profile);

        let mut s2 = Settings::default();
        IspProfile::Generic.apply_overrides(&mut s2);
        assert_eq!(s2.mutation_profile, original.mutation_profile);
    }

    #[test]
    fn recommended_snis_not_empty() {
        for profile in IspProfile::ALL {
            assert!(!profile.recommended_fake_snis().is_empty());
        }
    }
}
