//! http_host — HTTP `Host` splitting trick + SNI filter lists. [UNTESTED]
//!
//! Two small, independently-testable helpers used by the relay/pipeline:
//!
//! 1. **Host trick.** Some stateful DPI boxes parse an HTTP request line by
//!    line; splitting the `Host:` header into its own TCP segment (or
//!    splitting its value across a boundary) can defeat a naive
//!    line-at-a-time blocker the same way TCP fragmentation defeats an
//!    SNI-at-offset blocker. This module only computes the byte cuts —
//!    `packet::tcp_segment_payload` performs the actual segmentation.
//!
//! 2. **SNI allow/deny.** `sni_only` / `sni_except` let the operator limit
//!    which domains the relay's fake-SNI injection applies to. Matching is
//!    ASCII-case-insensitive and supports a leading `*.` wildcard.
//!
//! No network I/O; pure functions so every branch is unit-tested on all OS.

use crate::error::DpiGuardError;

/// Return the byte offsets `(host_line_start, host_line_end)` of the
/// `Host:` header line in an HTTP/1.x request buffer (including the
/// terminating `\r\n`), or `None` if no Host header is present. Search is
/// case-insensitive on the header name and stops at the end-of-headers
/// marker (`\r\n\r\n`) so a body containing the word "Host:" cannot fool it.
pub fn find_host_line(req: &[u8]) -> Option<(usize, usize)> {
    let end = memchr_double_crlf(req).unwrap_or(req.len());
    let head = &req[..end];
    // Find "host:" (ASCII-case-insensitive) that starts a header line, i.e.
    // is at offset 0 or immediately after a `\n`.
    let needle = b"host:";
    let mut i = 0usize;
    while i + needle.len() <= head.len() {
        if head[i..i + needle.len()].eq_ignore_ascii_case(needle)
            && (i == 0 || head[i - 1] == b'\n')
        {
            // Extend to the end of this line (inclusive of \r\n).
            let line_end = find_crlf(head, i).unwrap_or(head.len());
            return Some((i, line_end));
        }
        i += 1;
    }
    None
}

/// Locate the first `\r\n` at or after `from`, returning the offset just
/// past it (so `&req[start..ret]` is the full line including CRLF).
fn find_crlf(buf: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i + 2);
        }
        i += 1;
    }
    None
}

/// Locate the end-of-headers marker `\r\n\r\n`.
fn memchr_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Split an HTTP request buffer so the `Host:` header line occupies its own
/// middle segment. Returns `(before, host_line, after)` when a Host header
/// is found. The caller wraps each piece in its own TCP segment. If no Host
/// header is present, returns `None` (caller should send the request as-is).
pub fn split_host_line(req: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (s, e) = find_host_line(req)?;
    let before = req[..s].to_vec();
    let host = req[s..e].to_vec();
    let after = req[e..].to_vec();
    Some((before, host, after))
}

/// True when the HTTP request begins with a method token and HTTP version —
/// a cheap "this is plain HTTP" gate so the Host trick is never applied to a
/// TLS record (which starts with 0x16).
pub fn looks_like_http_request(req: &[u8]) -> bool {
    if req.is_empty() {
        return false;
    }
    // request-line = METHOD SP request-target SP HTTP-version CRLF
    let Some(sp) = req.iter().position(|&b| b == b' ') else {
        return false;
    };
    let method = &req[..sp];
    if method.is_empty() || !method.iter().all(u8::is_ascii_uppercase) {
        return false;
    }
    req[sp..].windows(5).any(|w| w == b"HTTP/")
}

/// Match a hostname against a single pattern. Patterns:
/// * exact:    `example.com`
/// * wildcard: `*.example.com` matches `a.example.com` and `b.c.example.com`,
///   but NOT the bare `example.com`
///
/// Comparison is ASCII-case-insensitive; a trailing dot is tolerated on
/// either side. An empty pattern never matches.
pub fn hostname_matches(pattern: &str, host: &str) -> bool {
    let pat = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if pat.is_empty() || host.is_empty() {
        return false;
    }
    if let Some(suffix) = pat.strip_prefix("*.") {
        // *.example.com — host must have at least one additional label and
        // end with ".example.com".
        host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}"))
    } else {
        pat == host
    }
}

/// Decide whether SNI-based evasion should apply to `sni` given the
/// operator's `sni_only` / `sni_except` lists.
///
/// * if `sni_only` is non-empty, the SNI must match at least one entry.
/// * if the SNI matches any `sni_except` entry, it is refused.
/// * deny wins over allow (if somehow both list the same name).
pub fn sni_allowed(sni: &str, sni_only: &[String], sni_except: &[String]) -> bool {
    if sni_except.iter().any(|p| hostname_matches(p, sni)) {
        return false;
    }
    if !sni_only.is_empty() && !sni_only.iter().any(|p| hostname_matches(p, sni)) {
        return false;
    }
    true
}

/// Apply the Host-line split to a payload only when it looks like HTTP and
/// a Host header is present; otherwise return the payload unchanged as a
/// single segment. Convenience wrapper so the pipeline has one call site.
pub fn maybe_split_http_host(payload: &[u8], enable: bool) -> Vec<Vec<u8>> {
    if !enable || payload.is_empty() || payload[0] == 0x16 {
        return vec![payload.to_vec()];
    }
    if !looks_like_http_request(payload) {
        return vec![payload.to_vec()];
    }
    match split_host_line(payload) {
        Some((b, h, a)) => {
            let mut out = Vec::with_capacity(3);
            if !b.is_empty() {
                out.push(b);
            }
            out.push(h);
            if !a.is_empty() {
                out.push(a);
            }
            out
        }
        None => vec![payload.to_vec()],
    }
}

/// Segmentation cuts for TLS-record-level splitting before the SNI,
/// re-exported here for callers that want both tricks from one module.
pub fn tls_cuts_before_sni(rec: &[u8]) -> Result<Vec<Vec<u8>>, DpiGuardError> {
    crate::fragmentation::tls_record_split_before_sni(rec)
}

/// #13 — Host-dot: append a dot after the hostname in the HTTP Host header.
/// This creates an additional confusion layer for DPI that parses the Host
/// header. For example, "Host: example.com\r\n" becomes "Host: example.com.\r\n".
/// Returns the modified request bytes, or the original if no Host header found.
pub fn apply_hostdot(req: &[u8]) -> Vec<u8> {
    let Some((start, end)) = find_host_line(req) else {
        return req.to_vec();
    };
    let host_line = &req[start..end];
    // Find the colon after "Host"
    let Some(colon_pos) = host_line.iter().position(|&b| b == b':') else {
        return req.to_vec();
    };
    // Find the hostname value (after "Host:" and optional whitespace)
    let value_start = colon_pos + 1;
    let value = &host_line[value_start..];
    // Strip trailing \r\n
    let value_trimmed = value
        .strip_suffix(b"\r\n")
        .or_else(|| value.strip_suffix(b"\n"))
        .unwrap_or(value);
    // Check if already has trailing dot
    if value_trimmed.last() == Some(&b'.') {
        return req.to_vec();
    }
    // Insert a dot before the line ending
    let dot_pos = start + value_start + value_trimmed.len();
    let mut out = Vec::with_capacity(req.len() + 1);
    out.extend_from_slice(&req[..dot_pos]);
    out.push(b'.');
    out.extend_from_slice(&req[dot_pos..]);
    out
}

/// #12 — OOB (Out-of-Band) data injection.
/// Injects a single byte of "garbage" data before the real payload.
/// The DPI may parse the OOB byte as part of the request, getting confused.
/// The server will ignore the extra byte (TCP reassembly handles it).
pub fn inject_oob_byte(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 1);
    out.push(0x00); // OOB marker
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ: &[u8] = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n";

    #[test]
    fn finds_host_line() {
        let (s, e) = find_host_line(REQ).unwrap();
        assert_eq!(&REQ[s..e], b"Host: example.com\r\n");
    }

    #[test]
    fn tls_cuts_before_sni_delegates_to_fragmentation() {
        let record = crate::fragmentation::encode_client_hello("example.com");
        let parts = tls_cuts_before_sni(&record).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0][0], 0x16);
    }

    #[test]
    fn host_match_case_insensitive() {
        let (s, e) = find_host_line(b"GET / HTTP/1.1\r\nHOST: EXAMPLE.COM\r\n\r\n").unwrap();
        assert_eq!(
            &b"GET / HTTP/1.1\r\nHOST: EXAMPLE.COM\r\n\r\n"[s..e],
            b"HOST: EXAMPLE.COM\r\n"
        );
    }

    #[test]
    fn ignores_host_in_body() {
        // A Host: that appears AFTER the end-of-headers marker is in the
        // body and must not be treated as the header line.
        let body = b"GET / HTTP/1.1\r\nContent-Length: 10\r\n\r\nHost: fake\r\n";
        assert!(find_host_line(body).is_none());
    }

    #[test]
    fn split_host_three_pieces_roundtrip() {
        let (b, h, a) = split_host_line(REQ).unwrap();
        let mut joined = Vec::new();
        joined.extend_from_slice(&b);
        joined.extend_from_slice(&h);
        joined.extend_from_slice(&a);
        assert_eq!(joined, REQ);
        assert_eq!(h, b"Host: example.com\r\n");
    }

    #[test]
    fn http_detection() {
        assert!(looks_like_http_request(REQ));
        assert!(looks_like_http_request(b"POST /x HTTP/1.0\r\n"));
        assert!(!looks_like_http_request(b"\x16\x03\x01"));
        assert!(!looks_like_http_request(b""));
        assert!(!looks_like_http_request(b"get / http/1.1\r\n"));
    }

    #[test]
    fn maybe_split_skips_tls() {
        let mut tls = vec![0x16, 0x03, 0x01];
        tls.extend_from_slice(REQ);
        let segs = maybe_split_http_host(&tls, true);
        assert_eq!(segs.len(), 1);
    }

    #[test]
    fn hostname_exact_and_wildcard() {
        assert!(hostname_matches("example.com", "example.com"));
        assert!(hostname_matches("EXAMPLE.COM.", "Example.com"));
        assert!(!hostname_matches("example.com", "www.example.com"));
        assert!(hostname_matches("*.example.com", "www.example.com"));
        assert!(hostname_matches("*.example.com", "a.b.example.com"));
        assert!(!hostname_matches("*.example.com", "example.com"));
        assert!(!hostname_matches("", "example.com"));
    }

    #[test]
    fn sni_filter_allow_deny() {
        let only = vec!["*.allowed.com".to_string(), "keep.org".to_string()];
        let except = vec!["blocked.allowed.com".to_string()];

        assert!(sni_allowed("keep.org", &only, &except));
        assert!(sni_allowed("www.allowed.com", &only, &except));
        // deny wins
        assert!(!sni_allowed("blocked.allowed.com", &only, &except));
        // not in allow list
        assert!(!sni_allowed("other.net", &only, &except));

        // empty allow = allow all (subject to deny)
        assert!(sni_allowed("anything.net", &[], &[]));
        assert!(!sni_allowed(
            "blocked.com",
            &[],
            &["blocked.com".to_string()]
        ));
    }
}
