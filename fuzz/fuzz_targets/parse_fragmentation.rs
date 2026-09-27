#![no_main]

use dpi_guard::fragmentation::{list_extensions, parse_client_hello, sni_bytes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TLS record/extension walkers are fed directly with arbitrary truncated
    // bytes. Every failure is a Result/Option, never an unwind.
    let _ = parse_client_hello(data);
    let _ = list_extensions(data);
    let _ = sni_bytes(data);
});
