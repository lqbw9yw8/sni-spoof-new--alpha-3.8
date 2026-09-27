//! netguard — destination / hostname allow-deny guards (SSRF surface). [UNTESTED]
//!
//! The relay connects to a single operator-configured destination and the
//! DoH client fetches from an operator-configured URL. Both are user input
//! that ultimately drives an outbound socket, so they are validated here
//! before any I/O. The rules are deliberately conservative:
//!
//! * loopback, unspecified, broadcast, multicast, link-local, and the cloud
//!   metadata endpoint `169.254.169.254` are refused as relay/DoH targets.
//! * IPv4-mapped IPv6 addresses are unwrapped and re-checked, so
//!   `::ffff:127.0.0.1` cannot smuggle a loopback target past an IPv6-only
//!   check.
//! * RFC1918 private space (10/8, 172.16/12, 192.168/16) is **allowed** —
//!   the relay is commonly pointed at an internal host. Only the categories
//!   above are refused.
//! * hostnames `localhost`, `metadata.google.internal`, `*.local`, and
//!   `*.internal` are refused (mDNS / cloud-metadata / loopback names).
//! * the DoH URL must be `https`, carry no userinfo, and parse cleanly.
//!
//! This module is pure logic (no network) and has branch-level unit tests;
//! the current checkout's Rust tests are not executed in this environment.

use crate::error::DpiGuardError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Cloud metadata services listen here. It sits inside the 169.254/16
/// link-local block but is called out by name because it is the canonical
/// SSRF target on every major cloud.
pub const METADATA_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// Unwrap an IPv4-mapped/compatible IPv6 address to its IPv4 form so a
/// single IPv4 rule set covers both representations. Returns the address
/// unchanged when it is a "real" IPv6 address.
pub fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// True when `ip` must never be used as a relay/DoH/connect target:
/// loopback, unspecified, broadcast, multicast, link-local, or the cloud
/// metadata address. IPv4-mapped IPv6 is unwrapped first.
///
/// RFC1918 private space is **not** forbidden here.
pub fn is_forbidden_dest(ip: IpAddr) -> bool {
    let ip = unmapped(ip);
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4 == METADATA_IP
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || is_ipv6_link_local(&v6)
            // Unique-local addresses (fc00::/7) are the IPv6 analogue of
            // RFC1918 and are intentionally allowed.
        }
    }
}

fn is_ipv6_link_local(v6: &Ipv6Addr) -> bool {
    let segs = v6.segments();
    // fe80::/10
    (segs[0] & 0xffc0) == 0xfe80
}

/// Parse the legacy IPv4 spellings accepted by several URL/socket stacks.
///
/// Rust's `IpAddr::from_str` intentionally accepts only dotted-decimal IPv4,
/// while Windows `getaddrinfo` and URL parsers have historically accepted
/// forms such as `2130706433`, `0x7f000001`, `0177.0.0.1` — and the *short*
/// dotted forms `a`, `a.b`, `a.b.c` (e.g. `127.1` == `127.0.0.1`), where the
/// final component covers all remaining octets big-endian, exactly as the
/// canonical `inet_aton` semantics describe. If we validate only with
/// `IpAddr`, those spellings can resolve to 127.0.0.1 or another forbidden
/// address after the hostname check. Treat them as literals here.
fn parse_legacy_ipv4(host: &str) -> Option<Ipv4Addr> {
    let parse_part = |part: &str| {
        let (digits, radix) = if let Some(rest) = part.strip_prefix("0x") {
            (rest, 16)
        } else if part.len() > 1 && part.starts_with('0') {
            (part, 8)
        } else {
            (part, 10)
        };
        if digits.is_empty() {
            return None;
        }
        u32::from_str_radix(digits, radix).ok()
    };

    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        // inet_aton short forms: 2..=4 components. Every component before
        // the last is a single octet; the last one fills the remaining
        // width (`a.b` -> a.0.0.(b), `a.b.c` -> a.b.(c as 16-bit)). A
        // component that does not fit its slot means this was never an
        // IPv4 spelling — return None and let the caller treat it as a
        // hostname (real public hostnames cannot be all-numeric dotted
        // labels, so nothing slips past this way).
        if parts.len() < 2 || parts.len() > 4 {
            return None;
        }
        let mut values: Vec<u32> = Vec::with_capacity(parts.len());
        for part in &parts {
            values.push(parse_part(part)?);
        }
        for v in &values[..values.len() - 1] {
            if *v > u32::from(u8::MAX) {
                return None;
            }
        }
        let last = *values.last().unwrap();
        let missing = 4 - values.len(); // 0, 1 or 2 octets left to fill
        if last >= 1u32 << (8 * (missing + 1)) {
            return None;
        }
        let mut octets: Vec<u8> = values[..values.len() - 1]
            .iter()
            .map(|&v| v as u8)
            .collect();
        // Append the last value's bytes, most significant first, until the
        // address is four octets wide.
        let mut shift = 8 * missing;
        loop {
            octets.push(((last >> shift) & 0xff) as u8);
            if shift == 0 {
                break;
            }
            shift -= 8;
        }
        return Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
    }

    // A single numeric/hex component is the historical 32-bit form. Do not
    // reinterpret ordinary hostnames such as `123.example`.
    if host.chars().all(|c| c.is_ascii_digit()) || host.starts_with("0x") {
        return parse_part(host).map(Ipv4Addr::from);
    }
    None
}

/// True when `host` is a name the relay must not resolve/connect to.
/// Comparison is ASCII-case-insensitive and tolerates a trailing dot.
///
/// Refused: `localhost` (and any `*.localhost`), the GCP metadata name
/// `metadata.google.internal`, `*.local` (mDNS), and `*.internal`.
/// A bare IP literal is not evaluated here — callers parse it through
/// [`is_forbidden_dest`] instead.
pub fn is_forbidden_hostname(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return false; // empty is handled elsewhere as "missing"
    }
    // If it parses as an IP literal, apply the IP rule instead of the name
    // rule (so 127.0.0.1 is caught even though it is not a DNS name).
    if let Ok(ip) = h.parse::<IpAddr>() {
        return is_forbidden_dest(ip);
    }
    // Also catch legacy decimal/hex/octal IPv4 spellings before a resolver
    // gets a chance to reinterpret them as a hostname (SSRF hardening).
    if let Some(ip) = parse_legacy_ipv4(&h) {
        return is_forbidden_dest(IpAddr::V4(ip));
    }
    if h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    if h == "metadata.google.internal"
        || h == "metadata.goog"
        || h == "metadata.azure.com"
        || h == "169.254.169.254.nip.io"
    {
        return true;
    }
    if h == "local" || h.ends_with(".local") {
        return true;
    }
    if h == "internal" || h.ends_with(".internal") {
        return true;
    }
    false
}

/// Validate a DoH endpoint URL. Must be `https`, have no username/password
/// userinfo, a non-empty host, and a scheme/host that parse. Returns the
/// normalized (trimmed) URL on success.
///
/// A host that is a forbidden IP literal is refused; a hostname that is on
/// the forbidden-name list is refused.
pub fn validate_doh_url(url: &str) -> Result<String, DpiGuardError> {
    let url = url.trim();
    if !url.starts_with("https://") {
        return Err(DpiGuardError::Config(
            "doh_server must be an https:// URL".into(),
        ));
    }
    // Strip scheme for manual parsing (no url crate dependency).
    let rest = &url["https://".len()..];
    // userinfo is "user:pass@host" — refuse any '@' before the first '/'
    // (and before any '?'), since a DoH endpoint never needs credentials.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty()
        || authority.contains('@')
        || authority
            .chars()
            .any(|c| c.is_ascii_control() || c.is_ascii_whitespace())
    {
        return Err(DpiGuardError::Config(
            "doh_server has empty/userinfo/whitespace authority".into(),
        ));
    }
    let validate_port = |port: &str| {
        port.parse::<u16>()
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| DpiGuardError::Config("doh_server has an invalid port".into()))
    };
    // Split host from port. Accept [v6]:port as well as host:port. Reject
    // malformed suffixes instead of treating `host:garbage` as a hostname.
    let host = if let Some(open) = authority.strip_prefix('[') {
        let close = open
            .find(']')
            .ok_or_else(|| DpiGuardError::Config("doh_server has malformed [IPv6] host".into()))?;
        let suffix = &open[close + 1..];
        if !suffix.is_empty() {
            let port = suffix.strip_prefix(':').ok_or_else(|| {
                DpiGuardError::Config("doh_server has malformed [IPv6]:port".into())
            })?;
            validate_port(port)?;
        }
        &open[..close]
    } else {
        // A raw IPv6 without brackets would contain multiple colons; reject
        // that as ambiguous rather than handing it to a second parser.
        match authority.matches(':').count() {
            0 => authority,
            1 => {
                let Some((h, port)) = authority.split_once(':') else {
                    return Err(DpiGuardError::Config(
                        "doh_server has malformed authority".into(),
                    ));
                };
                if h.is_empty() {
                    return Err(DpiGuardError::Config("doh_server has an empty host".into()));
                }
                validate_port(port)?;
                h
            }
            _ => {
                return Err(DpiGuardError::Config(
                    "doh_server IPv6 literals must use brackets".into(),
                ));
            }
        }
    };
    if host.is_empty() {
        return Err(DpiGuardError::Config("doh_server has an empty host".into()));
    }
    if is_forbidden_hostname(host) {
        return Err(DpiGuardError::Config(format!(
            "doh_server host {host:?} resolves to a forbidden/loopback/metadata target"
        )));
    }
    Ok(url.to_string())
}

/// Validate an IP literal intended as the relay connect target. Loopback,
/// link-local, multicast, broadcast, unspecified, and metadata addresses
/// are refused. RFC1918 is allowed.
pub fn validate_relay_ip(ip: IpAddr) -> Result<(), DpiGuardError> {
    if is_forbidden_dest(ip) {
        return Err(DpiGuardError::Config(format!(
            "relay_connect_host IP {ip} is forbidden (loopback/link-local/multicast/metadata)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_forbidden() {
        assert!(is_forbidden_dest(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_forbidden_dest("127.0.0.1".parse().unwrap()));
        assert!(is_forbidden_dest("127.255.255.255".parse().unwrap()));
        assert!(is_forbidden_dest("::1".parse().unwrap()));
    }

    #[test]
    fn unspecified_and_broadcast_forbidden() {
        assert!(is_forbidden_dest(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(is_forbidden_dest(IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(is_forbidden_dest("::".parse().unwrap()));
    }

    #[test]
    fn multicast_forbidden() {
        assert!(is_forbidden_dest("224.0.0.1".parse().unwrap()));
        assert!(is_forbidden_dest("239.255.255.250".parse().unwrap()));
        assert!(is_forbidden_dest("ff02::1".parse().unwrap()));
    }

    #[test]
    fn link_local_and_metadata_forbidden() {
        assert!(is_forbidden_dest("169.254.1.1".parse().unwrap()));
        assert!(is_forbidden_dest(METADATA_IP.into()));
        assert!(is_forbidden_dest("fe80::1".parse().unwrap()));
    }

    #[test]
    fn rfc1918_is_allowed() {
        // Private space is allowed per spec (relay may target an internal host).
        assert!(!is_forbidden_dest("10.0.0.1".parse().unwrap()));
        assert!(!is_forbidden_dest("172.16.5.5".parse().unwrap()));
        assert!(!is_forbidden_dest("192.168.1.1".parse().unwrap()));
        // Public addresses allowed.
        assert!(!is_forbidden_dest("1.1.1.1".parse().unwrap()));
        assert!(!is_forbidden_dest("8.8.8.8".parse().unwrap()));
        // IPv6 unique-local allowed.
        assert!(!is_forbidden_dest("fd00::1".parse().unwrap()));
    }

    #[test]
    fn mapped_ipv6_loopback_is_forbidden() {
        // ::ffff:127.0.0.1 must be caught.
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_forbidden_dest(mapped));
        assert_eq!(unmapped(mapped), IpAddr::V4(Ipv4Addr::LOCALHOST));
        // ::ffff:1.1.1.1 is allowed.
        let ok: IpAddr = "::ffff:1.1.1.1".parse().unwrap();
        assert!(!is_forbidden_dest(ok));
    }

    #[test]
    fn legacy_ipv4_spellings_cannot_smuggle_loopback() {
        assert_eq!(parse_legacy_ipv4("2130706433"), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(parse_legacy_ipv4("0x7f000001"), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(parse_legacy_ipv4("0177.0.0.1"), Some(Ipv4Addr::LOCALHOST));
        assert!(is_forbidden_hostname("2130706433"));
        assert!(is_forbidden_hostname("0x7f000001"));
        assert!(is_forbidden_hostname("0177.0.0.1"));
        assert!(validate_doh_url("https://2130706433/dns-query").is_err());
        assert!(validate_doh_url("https://0x7f000001/dns-query").is_err());
    }

    #[test]
    fn short_form_ipv4_cannot_smuggle_loopback() {
        // `inet_aton` short forms — Windows getaddrinfo resolves these the
        // same way, so they must be classified before any resolver runs.
        assert_eq!(parse_legacy_ipv4("127.1"), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(parse_legacy_ipv4("127.0.1"), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(parse_legacy_ipv4("0x7f.1"), Some(Ipv4Addr::LOCALHOST));
        assert!(is_forbidden_hostname("127.1"));
        assert!(is_forbidden_hostname("127.1.")); // trailing dot tolerated
        assert!(is_forbidden_hostname("0x7f.1"));
        assert!(validate_doh_url("https://127.1/dns-query").is_err());
        // Short forms that land in allowed space stay allowed.
        assert_eq!(parse_legacy_ipv4("1.2"), Some(Ipv4Addr::new(1, 0, 0, 2)));
        assert_eq!(
            parse_legacy_ipv4("10.257"),
            Some(Ipv4Addr::new(10, 0, 1, 1))
        );
        assert!(!is_forbidden_hostname("10.1"));
        // Not IP spellings at all: too many parts / out-of-slot components.
        assert_eq!(parse_legacy_ipv4("1.2.3.4.5"), None);
        assert_eq!(parse_legacy_ipv4("300.1"), None);
        assert_eq!(parse_legacy_ipv4("1.20000000"), None); // last slot overflow
        assert_eq!(parse_legacy_ipv4("123.example"), None);
        assert!(!is_forbidden_hostname("1.2.3.4.5"));
    }

    #[test]
    fn legacy_public_ipv4_is_not_mistaken_for_forbidden() {
        assert_eq!(
            parse_legacy_ipv4("16843009"),
            Some(Ipv4Addr::new(1, 1, 1, 1))
        );
        assert!(!is_forbidden_hostname("16843009"));
    }

    #[test]
    fn forbidden_hostnames() {
        assert!(is_forbidden_hostname("localhost"));
        assert!(is_forbidden_hostname("LocalHost."));
        assert!(is_forbidden_hostname("foo.localhost"));
        assert!(is_forbidden_hostname("metadata.google.internal"));
        assert!(is_forbidden_hostname("printer.local"));
        assert!(is_forbidden_hostname("corp.internal"));
        assert!(is_forbidden_hostname("127.0.0.1"));
    }

    #[test]
    fn ordinary_hostnames_allowed() {
        assert!(!is_forbidden_hostname("example.com"));
        assert!(!is_forbidden_hostname("speedtest.example.com"));
        assert!(!is_forbidden_hostname("cloudflare-dns.com"));
        assert!(!is_forbidden_hostname("1.1.1.1.nip.io"));
    }

    #[test]
    fn doh_url_must_be_https() {
        assert!(validate_doh_url("http://1.1.1.1/dns-query").is_err());
        assert!(validate_doh_url("ftp://1.1.1.1/").is_err());
        assert!(validate_doh_url("1.1.1.1/dns-query").is_err());
        assert!(validate_doh_url("").is_err());
    }

    #[test]
    fn doh_url_rejects_userinfo_and_forbidden_host() {
        assert!(validate_doh_url("https://user:pass@1.1.1.1/dns-query").is_err());
        assert!(validate_doh_url("https://127.0.0.1/dns-query").is_err());
        assert!(validate_doh_url("https://localhost/dns-query").is_err());
        assert!(validate_doh_url("https://metadata.google.internal/dns-query").is_err());
    }

    #[test]
    fn doh_url_accepts_valid() {
        assert_eq!(
            validate_doh_url("https://1.1.1.1/dns-query").unwrap(),
            "https://1.1.1.1/dns-query"
        );
        assert_eq!(
            validate_doh_url("  https://cloudflare-dns.com/dns-query  ").unwrap(),
            "https://cloudflare-dns.com/dns-query"
        );
        assert!(validate_doh_url("https://[2606:4700:4700::1111]/dns-query").is_ok());
    }

    #[test]
    fn doh_url_rejects_malformed_or_out_of_range_ports() {
        assert!(validate_doh_url("https://example.com:0/dns-query").is_err());
        assert!(validate_doh_url("https://example.com:65536/dns-query").is_err());
        assert!(validate_doh_url("https://example.com:abc/dns-query").is_err());
        assert!(validate_doh_url("https://[2606:4700:4700::1111]:443/dns-query").is_ok());
        assert!(validate_doh_url("https://[2606:4700:4700::1111]garbage/dns-query").is_err());
        assert!(validate_doh_url("https://2606:4700:4700::1111/dns-query").is_err());
    }

    #[test]
    fn relay_ip_rejects_loopback_allows_public() {
        assert!(validate_relay_ip("127.0.0.1".parse().unwrap()).is_err());
        assert!(validate_relay_ip("169.254.169.254".parse().unwrap()).is_err());
        assert!(validate_relay_ip("::1".parse().unwrap()).is_err());
        assert!(validate_relay_ip("10.0.0.5".parse().unwrap()).is_ok());
        assert!(validate_relay_ip("1.1.1.1".parse().unwrap()).is_ok());
    }
}
