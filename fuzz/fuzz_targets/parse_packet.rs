#![no_main]

use dpi_guard::packet::{l3_slice, parse_l3l4, recalculate_all_checksums};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser must return None on truncated/malformed IPv4/IPv6/TCP/UDP;
    // it must never panic. Checksum recalculation is included because the
    // live pipeline calls it after every rewrite.
    let _ = l3_slice(data);
    let _ = parse_l3l4(data);
    let mut copy = data.to_vec();
    recalculate_all_checksums(&mut copy);
});
