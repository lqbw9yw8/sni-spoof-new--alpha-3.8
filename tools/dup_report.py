#!/usr/bin/env python3
"""Duplicate / redundancy report for the dpi_guard repository.

Answers one question: **what in this repo is written more than once?**
Everything it prints is measured — line numbers come from a real scan of
the working tree, never from memory or from a previous report.

Four independent detectors, because "duplicate" means different things in
different layers of this project:

1. ``code``   — duplicated source blocks (>= ``--min-lines`` consecutive
   non-blank, whitespace-normalised lines) inside ``src/**/*.rs``.
2. ``fn``     — the same top-level function name defined in two modules.
3. ``schema`` — the settings surface declared three times: the Rust
   ``Settings`` struct, the web dashboard's ``FIELDS`` schema, and the
   native eGUI panel's ``*_row(...)`` calls.
4. ``docs``   — markdown paragraphs (>= 12 words) that appear verbatim in
   more than one document.

Usage::

    python3 tools/dup_report.py            # full human-readable report
    python3 tools/dup_report.py --json     # machine-readable
    python3 tools/dup_report.py --only docs

Exit status is always 0: this is a report, not a lint gate. A CI gate that
fails on duplicates would have to be tuned per detector first.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_MIN_LINES = 8
DEFAULT_MIN_WORDS = 12

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _rust_files() -> list[Path]:
    return sorted((REPO / "src").rglob("*.rs"))


def _markdown_files() -> list[Path]:
    out: list[Path] = []
    for p in sorted(REPO.rglob("*.md")):
        parts = set(p.parts)
        skip = {"node_modules", "target", "agent", ".agents", ".git"}
        if parts & skip:
            continue
        out.append(p)
    return out


def _code_lines(path: Path) -> list[tuple[int, str]]:
    """(1-based line number, normalised text) for every meaningful line."""
    rows: list[tuple[int, str]] = []
    for i, raw in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        stripped = raw.strip()
        if not stripped or stripped.startswith("//"):
            continue
        rows.append((i, re.sub(r"\s+", " ", stripped)))
    return rows


# ---------------------------------------------------------------------------
# 1. duplicate code blocks
# ---------------------------------------------------------------------------


def scan_code_blocks(min_lines: int) -> dict:
    windows: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
    for path in _rust_files():
        rel = path.relative_to(REPO).as_posix()
        rows = _code_lines(path)
        for i in range(len(rows) - min_lines + 1):
            chunk = rows[i : i + min_lines]
            key = "\n".join(text for _, text in chunk)
            windows[key].append((rel, chunk[0][0], chunk[0][1][:80]))

    pairs: dict[tuple[str, str], dict] = {}
    same_file: list[dict] = []
    for key, hits in windows.items():
        if len(hits) < 2:
            continue
        files = {h[0] for h in hits}
        if len(files) == 1:
            # Repeated inside one file: only interesting when the copies are
            # far apart (a copy-pasted block, not an adjacent match arm).
            lines = sorted(h[1] for h in hits)
            if lines[-1] - lines[0] < min_lines * 2:
                continue
            same_file.append(
                {
                    "file": hits[0][0],
                    "occurrences": [
                        {"line": ln, "preview": prev} for _, ln, prev in hits
                    ],
                    "lines": min_lines,
                }
            )
            continue
        ordered = sorted(files)
        pair = (ordered[0], ordered[1])
        entry = pairs.setdefault(
            pair, {"files": list(ordered), "occurrences": [], "duplicated_lines": 0}
        )
        entry["duplicated_lines"] += min_lines
        for f, ln, prev in hits:
            entry["occurrences"].append({"file": f, "line": ln, "preview": prev})

    for entry in pairs.values():
        entry["occurrences"].sort(key=lambda o: (o["file"], o["line"]))
    for entry in same_file:
        entry["occurrences"].sort(key=lambda o: o["line"])

    ranked = sorted(pairs.values(), key=lambda e: -e["duplicated_lines"])
    same_file.sort(key=lambda e: -len(e["occurrences"]))
    return {"cross_file": ranked, "within_file": same_file}


# ---------------------------------------------------------------------------
# 2. duplicate function names
# ---------------------------------------------------------------------------

FN_RE = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")


def scan_duplicate_fn_names() -> list[dict]:
    defs: dict[str, list[dict]] = defaultdict(list)
    for path in _rust_files():
        rel = path.relative_to(REPO).as_posix()
        in_test = False
        for i, raw in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            if raw.startswith("mod tests") or raw.startswith("#[cfg(test)]"):
                in_test = True
            if raw.startswith("}") and in_test and not raw.startswith("    "):
                in_test = False
            m = FN_RE.match(raw)
            if m and not in_test:
                defs[m.group(1)].append({"file": rel, "line": i})
    out = []
    for name, hits in defs.items():
        if len({h["file"] for h in hits}) > 1:
            out.append({"name": name, "definitions": hits})
    out.sort(key=lambda e: (-len(e["definitions"]), e["name"]))
    return out


# ---------------------------------------------------------------------------
# 3. the settings surface, declared three times
# ---------------------------------------------------------------------------


def _settings_keys() -> list[str]:
    """Field names of `pub struct Settings` in src/config.rs."""
    path = REPO / "src" / "config.rs"
    text = path.read_text(encoding="utf-8", errors="replace")
    start = text.index("pub struct Settings")
    depth = 0
    i = text.index("{", start)
    j = i
    while True:
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    body = text[i + 1 : j]
    keys = []
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("//") or line.startswith("#["):
            continue
        m = re.match(r"pub ([a-z_][a-z0-9_]*)\s*:", line)
        if m:
            keys.append(m.group(1))
    return keys


def _webui_keys() -> list[str]:
    """`k: "..."` entries of the FIELDS schema in src/webui/index.html."""
    text = (REPO / "src" / "webui" / "index.html").read_text(
        encoding="utf-8", errors="replace"
    )
    return re.findall(r'k:\s*"([a-z_][a-z0-9_]*)"', text)


def _native_gui_keys() -> list[str]:
    """Setting names the eGUI panel binds to (row/string/combo helpers)."""
    text = (REPO / "src" / "native_gui.rs").read_text(encoding="utf-8", errors="replace")
    found = set()
    for m in re.finditer(
        r'(?:check_row|text_row|drag_row|combo_row|list_row)\(\s*ui,\s*"[^"]*",\s*[^,]+,\s*',
        text,
    ):
        tail = text[m.end() : m.end() + 200]
        km = re.search(r"(?:&mut\s*)?self\.settings\.([a-z_][a-z0-9_]*)", tail)
        if km:
            found.add(km.group(1))
    # direct `self.settings.x` reads/writes count too
    for m in re.finditer(r"self\.settings\.([a-z_][a-z0-9_]*)(?![\w(])", text):
        found.add(m.group(1))
    return sorted(found)


def scan_schema() -> dict:
    settings = _settings_keys()
    web = _webui_keys()
    native = _native_gui_keys()
    s, w, n = set(settings), set(web), set(native)
    return {
        "settings_fields": len(settings),
        "webui_fields": len(web),
        "native_gui_fields_touched": len(native),
        "webui_missing_from_settings": sorted(w - s),
        "settings_missing_from_webui": sorted(s - w),
        "settings_missing_from_native_gui": sorted(s - n),
        "declared_in_all_three": len(s & w & n),
        "declared_only_in_native_gui": sorted(n - s),
    }


# ---------------------------------------------------------------------------
# 4. duplicate documentation
# ---------------------------------------------------------------------------


def _paragraphs(text: str) -> list[tuple[int, str]]:
    out = []
    line_no = 1
    buf: list[str] = []
    buf_start = 1
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped:
            if buf:
                para = " ".join(buf)
                if len(para.split()) >= DEFAULT_MIN_WORDS:
                    out.append((buf_start, para))
                buf = []
            line_no += 1
            buf_start = line_no
            continue
        if stripped.startswith(("#", "|", "```", "---", "===")):
            if buf:
                para = " ".join(buf)
                if len(para.split()) >= DEFAULT_MIN_WORDS:
                    out.append((buf_start, para))
                buf = []
            buf_start = line_no + 1
            line_no += 1
            continue
        if not buf:
            buf_start = line_no
        buf.append(re.sub(r"\s+", " ", stripped))
        line_no += 1
    if buf:
        para = " ".join(buf)
        if len(para.split()) >= DEFAULT_MIN_WORDS:
            out.append((buf_start, para))
    return out


def scan_docs(min_words: int = DEFAULT_MIN_WORDS) -> list[dict]:
    seen: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for path in _markdown_files():
        rel = path.relative_to(REPO).as_posix()
        for line_no, para in _paragraphs(path.read_text(encoding="utf-8", errors="replace")):
            key = re.sub(r"\s+", " ", para).strip().lower().rstrip(".")
            if len(key.split()) < min_words:
                continue
            seen[key].append((rel, line_no))
    groups = []
    for key, hits in seen.items():
        files = {h[0] for h in hits}
        if len(files) < 2:
            continue
        groups.append(
            {
                "words": len(key.split()),
                "files": sorted(files),
                "occurrences": [
                    {"file": f, "line": ln} for f, ln in sorted(hits)
                ],
                "preview": key[:160],
            }
        )
    groups.sort(key=lambda g: -g["words"] * len(g["files"]))
    return groups


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def render(report: dict) -> str:
    out: list[str] = []
    add = out.append

    add("=" * 78)
    add("DUPLICATE / REDUNDANCY REPORT — dpi_guard")
    add("=" * 78)

    code = report["code"]
    add("\n## 1. Duplicated source blocks (src/**/*.rs)\n")
    if not code["cross_file"]:
        add("    none found")
    for entry in code["cross_file"][:12]:
        add(
            f"    {entry['duplicated_lines']:>5} duplicated lines  "
            f"{entry['files'][0]}  <->  {entry['files'][1]}"
        )
        for occ in entry["occurrences"][:4]:
            add(f"        {occ['file']}:{occ['line']}  {occ['preview']}")
        add("")
    if code["within_file"]:
        add("    repeated inside a single file:")
        for entry in code["within_file"][:8]:
            lines = ", ".join(str(o["line"]) for o in entry["occurrences"])
            add(f"        {entry['file']}: lines {lines}  ({entry['lines']} lines each)")

    add("\n## 2. Same function name defined in two modules\n")
    if not report["fn_names"]:
        add("    none found")
    for entry in report["fn_names"]:
        where = ", ".join(f"{d['file']}:{d['line']}" for d in entry["definitions"])
        add(f"    fn {entry['name']:<32} {where}")

    s = report["schema"]
    add("\n## 3. The settings surface, declared three times\n")
    add(f"    config::Settings fields ............ {s['settings_fields']}")
    add(f"    webui/index.html FIELDS ............ {s['webui_fields']}")
    add(
        f"    native_gui.rs settings touched ..... {s['native_gui_fields_touched']}"
        f"  ({s['declared_in_all_three']} of them also in Settings + webui)"
    )
    if s["settings_missing_from_native_gui"]:
        add(
            f"    Settings fields the desktop panel never shows "
            f"({len(s['settings_missing_from_native_gui'])}): "
            + ", ".join(s["settings_missing_from_native_gui"][:12])
        )
    if s["settings_missing_from_webui"]:
        add("    Settings fields missing from webui: " + ", ".join(s["settings_missing_from_webui"]))
    if s["webui_missing_from_settings"]:
        add("    webui keys that are not Settings: " + ", ".join(s["webui_missing_from_settings"]))
    if s["declared_only_in_native_gui"]:
        add("    native_gui references unknown keys: " + ", ".join(s["declared_only_in_native_gui"]))

    docs = report["docs"]
    add("\n## 4. Duplicated documentation paragraphs\n")
    if not docs:
        add("    none found")
    total = sum(g["words"] * (len(g["files"]) - 1) for g in docs)
    add(f"    {len(docs)} paragraphs appear in more than one file "
        f"(~{total} redundant words)")
    for g in docs[:10]:
        add(f"    [{g['words']} words] " + " + ".join(g["files"]))
        add(f"        {g['preview']}")

    add("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--min-lines", type=int, default=DEFAULT_MIN_LINES)
    ap.add_argument(
        "--only",
        choices=["code", "fn", "schema", "docs"],
        help="run a single detector",
    )
    args = ap.parse_args()

    report: dict = {}
    if args.only in (None, "code"):
        report["code"] = scan_code_blocks(args.min_lines)
    if args.only in (None, "fn"):
        report["fn_names"] = scan_duplicate_fn_names()
    if args.only in (None, "schema"):
        report["schema"] = scan_schema()
    if args.only in (None, "docs"):
        report["docs"] = scan_docs()

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    if args.only == "code":
        print(json.dumps(report["code"], indent=2))
        return 0
    if args.only == "fn":
        for e in report["fn_names"]:
            print(f"fn {e['name']}: " + ", ".join(f"{d['file']}:{d['line']}" for d in e["definitions"]))
        return 0
    if args.only == "schema":
        print(json.dumps(report["schema"], indent=2))
        return 0
    if args.only == "docs":
        for g in report["docs"]:
            print(f"[{g['words']}w] " + " + ".join(g["files"]) + f" :: {g['preview'][:90]}")
        return 0

    print(render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
