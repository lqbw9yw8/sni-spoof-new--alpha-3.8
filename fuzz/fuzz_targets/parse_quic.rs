#![no_main]

use dpi_guard::quic::is_quic_initial;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Long-header Initial detection is intentionally pure and bounded. The
    // target exercises every truncated varint/connection-id boundary without
    // requiring a network or a WinDivert handle.
    let _ = is_quic_initial(data);
});
