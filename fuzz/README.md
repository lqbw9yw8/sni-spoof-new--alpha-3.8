# Parser fuzzing

These targets exercise the same pure parsing entry points used by the live
pipeline. They do not open WinDivert and can run on Linux:

```bash
cargo install cargo-fuzz
cargo fuzz run parse_packet -- -max_total_time=900
cargo fuzz run parse_quic -- -max_total_time=900
cargo fuzz run parse_fragmentation -- -max_total_time=900
```

Expected result: no crash artifacts. A crash is a release blocker because the
capture boundary must turn malformed input into an untouched pass-through, not
an unwind. `target/` and `fuzz/artifacts/` are intentionally ignored.

This is a fuzz harness definition, not evidence that a fuzz campaign has
already run in the current environment.
