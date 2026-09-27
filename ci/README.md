# ci/

## CI is enabled (since the 2026-09 fix round)

`.github/workflows/` now exists and holds the four workflows the docs
promise; the YAML files in `ci/` are **byte-identical copies** kept for
reference only. Do not cite `ci/*.yml` as evidence that CI ran — cite the
run list on GitHub (`gh run list`), which is now non-empty after the first
push following this change.

What runs:

- `.github/workflows/ci.yml` — `cargo fmt --check` gate (the tree is
  formatted now), `cargo build --all-targets` + `cargo test --all-targets`
  on ubuntu-latest **and** windows-latest, clippy (non-blocking), the jsdom
  dashboard suite, and docs checks (`gen_status.py --check`, `lint_docs.py`).
  The Windows leg fetches the hash-pinned WinDivert SDK with
  `scripts/fetch-windivert.ps1` before linking (the binaries are not in git).
- `.github/workflows/build-windows.yml` — release `dpi_guard.exe` as the
  artifact `dpi_guard-windows` with its SHA-256 story in the run output.
- `.github/workflows/e2e.yml` — manual/weekly field smoke: real driver load
  + real exe + `/api/status` probe + stop-file shutdown on windows-latest.
- `.github/workflows/release.yml` — tag-driven release publishing the
  Windows zip plus `SHA256SUMS.txt`.

`ci/github-actions.yml` is the legacy template (superseded by `ci.yml`).

The Windows artifact never bundles WinDivert.dll or WinDivert64.sys. Fetch the
official pinned driver with `scripts/fetch-windivert.ps1` and verify the hashes
before running the executable.
