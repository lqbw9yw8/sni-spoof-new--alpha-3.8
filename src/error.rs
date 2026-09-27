use thiserror::Error;

/// One error type for the whole crate. Every fallible function returns
/// this, so the engine's fail-open handler can match on a single type.
#[derive(Debug, Error)]
pub enum DpiGuardError {
    #[error("packet too short: need {need} bytes, have {have}")]
    PacketTooShort { need: usize, have: usize },

    #[error("SNI not found in ClientHello")]
    SniNotFound,

    #[error("TLS record is not a ClientHello")]
    NotClientHello,

    #[error("value out of range: {0}")]
    OutOfRange(String),

    #[error("this feature needs Windows + WinDivert, running on {os}")]
    PlatformNotSupported { os: &'static str },

    #[error("WinDivert driver error: {0}")]
    Driver(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("DNS resolution error: {0}")]
    Resolution(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_formatting() {
        let e1 = DpiGuardError::PacketTooShort { need: 10, have: 5 };
        assert_eq!(e1.to_string(), "packet too short: need 10 bytes, have 5");

        let e2 = DpiGuardError::SniNotFound;
        assert_eq!(e2.to_string(), "SNI not found in ClientHello");

        let e3 = DpiGuardError::NotClientHello;
        assert_eq!(e3.to_string(), "TLS record is not a ClientHello");

        let e4 = DpiGuardError::OutOfRange("test range".into());
        assert_eq!(e4.to_string(), "value out of range: test range");

        let e5 = DpiGuardError::PlatformNotSupported { os: "linux" };
        assert_eq!(
            e5.to_string(),
            "this feature needs Windows + WinDivert, running on linux"
        );

        let e6 = DpiGuardError::Driver("driver error".into());
        assert_eq!(e6.to_string(), "WinDivert driver error: driver error");

        let e7 = DpiGuardError::Config("bad config".into());
        assert_eq!(e7.to_string(), "config error: bad config");

        let e8 = DpiGuardError::Resolution("dns failed".into());
        assert_eq!(e8.to_string(), "DNS resolution error: dns failed");

        let e9 = DpiGuardError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        assert!(e9.to_string().contains("not found"));
    }
}
