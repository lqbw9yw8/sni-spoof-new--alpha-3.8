#!/usr/bin/env python3
"""Regenerate TEST_MATRIX.md from the actual source tree.

The point of this script is that the status table cannot drift from the
code: it is derived, never hand-written. Run it after any change that adds
or removes a module, a test, or a public function:

    python3 tools/gen_status.py           # regenerate TEST_MATRIX.md
    python3 tools/gen_status.py --check   # CI: fail (exit 1) on drift

`--check` never writes; it regenerates in memory, diffs against the
committed file and prints the drift. The `<!-- commit: ... -->` marker line
is ignored by the comparison so a fresh checkout cannot fail spuriously.

What it can prove (static facts):
  * how many lines each module has
  * how many #[test] / #[tokio::test] functions it declares
  * the [DONE]/[PARTIAL]/[STUB]/[UNTESTED]/[BLOCKED] tag in the module doc comment
  * whether each `pub fn` is called from production code, only from tests,
    or never
  * whether each Settings field is read by any engine module

What it CANNOT prove — and therefore never claims:
  * that the tests pass (nothing here runs cargo)
  * that a feature behaves correctly on Windows with WinDivert loaded
  * that a `pub fn` which IS called actually has the intended effect

Those require `cargo test` and real Windows field testing. See AI_RULES.md.
"""

import json
import os
import re
import subprocess
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")

# Modules that make up the runtime engine. A Settings field is considered
# "wired" if any of these reads it outside a test module.
ENGINE_MODULES = {
    "pipeline", "relay", "main", "engine", "engine_stub", "lib", "stealth",
    "fragmentation", "sequence", "fooling", "quic", "ech", "utls", "geedge",
    "sni_mutations", "doh", "autottl", "scanner", "anti_fingerprint",
    "http_host", "strategy", "isp_profiles", "dns_cache", "connection",
    "warmup", "client_detect", "proxy_cleanup", "mobile_gateway",
    "self_update", "netguard", "dns_guard", "webui", "native_gui",
    "singleton", "integrity", "handle_retire", "fail_open", "packet",
    "dns_guard",
}


def read_sources():
    out = {}
    for f in sorted(os.listdir(SRC)):
        if f.endswith(".rs"):
            with open(os.path.join(SRC, f), encoding="utf-8") as fh:
                out[f[:-3]] = fh.read()
    return out


def test_spans(s):
    """Byte ranges covered by `#[cfg(test)] mod ... { }`.

    Matches only a real attribute at the start of a line, so the literal
    string `#[cfg(test)]` appearing inside a `//!` doc comment does not
    truncate the file. (An earlier version of this logic had that bug and
    reported live security functions as dead.)
    """
    spans = []
    for m in re.finditer(r"^#\[cfg\(test\)\]\s*\nmod \w+ \{", s, re.M):
        i = s.find("{", m.start())
        depth = 0
        j = i
        while j < len(s):
            if s[j] == "{":
                depth += 1
            elif s[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        spans.append((m.start(), j))
    return spans


def in_spans(pos, spans):
    return any(a <= pos <= b for a, b in spans)


def doc_tag(s):
    head = "\n".join(l for l in s.split("\n")[:40] if l.lstrip().startswith("//"))
    m = re.search(r"\[(DONE|PARTIAL|STUB|UNTESTED|BLOCKED)\]", head)
    return m.group(1) if m else None


def analyse():
    src = read_sources()
    spans = {m: test_spans(s) for m, s in src.items()}

    mods = {}
    for m, s in src.items():
        mods[m] = {
            "lines": s.count("\n") + 1,
            "tests": len(re.findall(r"#\[(?:tokio::)?test\]", s)),
            "tag": doc_tag(s),
            "win": s.count("cfg(windows)"),
            "unsafe": ("allow(unsafe_code)" in s) or ("unsafe {" in s),
        }

    # public function reachability
    live, testonly, dead = [], [], []
    for m, s in src.items():
        for fm in re.finditer(r"^pub fn (\w+)", s, re.M):
            fn, defpos = fm.group(1), fm.start()
            prod = tst = 0
            for g, t in src.items():
                for h in re.finditer(r"\b" + re.escape(fn) + r"\b", t):
                    if g == m and abs(h.start() - defpos) < 12:
                        continue  # the definition itself
                    if in_spans(h.start(), spans[g]):
                        tst += 1
                    else:
                        prod += 1
            (live if prod else (testonly if tst else dead)).append((m, fn))

    # Settings wiring
    cfg = src["config"]
    sm = re.search(r"pub struct Settings \{(.*?)\n\}", cfg, re.S)
    fields = re.findall(r"\n    pub (\w+):", sm.group(1)) if sm else []
    unwired = []
    for f in fields:
        found = False
        for g, t in src.items():
            if g == "config" or g not in ENGINE_MODULES:
                continue
            for h in re.finditer(r"\b" + re.escape(f) + r"\b", t):
                if not in_spans(h.start(), spans[g]):
                    found = True
                    break
            if found:
                break
        if not found:
            unwired.append(f)

    # module dependency graph
    dep = defaultdict(set)
    for m, s in src.items():
        for u in re.findall(r"use crate::(\w+)", s):
            if u in src and u != m:
                dep[m].add(u)
        for u in re.findall(r"\bcrate::(\w+)::", s):
            if u in src and u != m:
                dep[m].add(u)
    rev = defaultdict(set)
    for a, bs in dep.items():
        for b in bs:
            rev[b].add(a)

    return dict(mods=mods, live=live, testonly=testonly, dead=dead,
                fields=fields, unwired=unwired,
                dep={k: sorted(v) for k, v in dep.items()},
                rev={k: sorted(v) for k, v in rev.items()})


def ui_controls():
    p = os.path.join(SRC, "webui", "index.html")
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as fh:
        return set(re.findall(r'k:\s*"(\w+)"', fh.read()))


def git_head():
    """Short HEAD of THIS repository, or "unknown".

    Audit F-01: `git -C ROOT rev-parse HEAD` happily walks *up* the
    filesystem and returns the enclosing repository's HEAD when ROOT itself
    is not a git checkout (that is exactly what happens in a sandbox that
    unpacks the tarball). The marker in TEST_MATRIX.md then names a commit
    that has nothing to do with this tree, which is worse than no marker.
    Confirm the discovered toplevel really is ROOT before trusting HEAD.
    """
    try:
        top = subprocess.check_output(
            ["git", "-C", ROOT, "rev-parse", "--show-toplevel"],
            text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "unknown"
    try:
        if os.path.realpath(top) != os.path.realpath(ROOT):
            return "unknown"
        return subprocess.check_output(
            ["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
            text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "unknown"


def verification_level(mod, info, dead_by_mod, testonly_by_mod):
    """Static verification level. Deliberately conservative."""
    if info["tests"] == 0:
        return "UNTESTED", "no #[test] in this module"
    if info["tag"] == "STUB":
        return "STUB", "module doc declares STUB"
    if info["tag"] == "PARTIAL":
        return "PARTIAL", "module doc declares documented limits"
    if info["tag"] == "UNTESTED":
        return "UNTESTED", "module doc declares that current tests were not executed"
    if info["tag"] == "BLOCKED":
        return "BLOCKED", "module doc declares an unavailable dependency/platform"
    if mod in testonly_by_mod and len(testonly_by_mod[mod]) >= 3:
        n = len(testonly_by_mod[mod])
        return "PARTIAL", f"{n} pub fn are only reached from tests"
    if info["win"] > 0:
        return "UNVERIFIED-WIN", "has cfg(windows) paths not exercised on Linux"
    return "TESTED-STATIC", "tests exist in source (not executed here)"


def main():
    a = analyse()
    ui = ui_controls()
    head = git_head()

    dead_by = defaultdict(list)
    for m, f in a["dead"]:
        dead_by[m].append(f)
    to_by = defaultdict(list)
    for m, f in a["testonly"]:
        to_by[m].append(f)

    L = []
    w = L.append
    w("# TEST MATRIX — تولید خودکار، دست نزنید")
    w("")
    w("<!-- GENERATED BY tools/gen_status.py — DO NOT EDIT BY HAND -->")
    w(f"<!-- commit: {head} -->")
    w("")
    w("این جدول از روی خود سورس تولید می‌شود، نه از روی حافظه یا ادعا.")
    w("برای به‌روزرسانی: `python3 tools/gen_status.py`")
    w("")
    w("## ⚠️ معنی دقیق ستون‌ها")
    w("")
    w("| ستون | یعنی چه | یعنی چه **نیست** |")
    w("|---|---|---|")
    w("| `tests` | تعداد `#[test]` که در فایل **نوشته** شده | اینکه تست‌ها **پاس** شده‌اند |")
    w("| `tag` | برچسبی که خود ماژول در doc-comment ادعا کرده | حقیقت تأییدشده |")
    w("| `dead` | `pub fn` که هیچ‌جا صدا زده نمی‌شود | لزوماً کد بی‌فایده |")
    w("| `test-only` | `pub fn` که فقط تست‌ها صدایش می‌زنند | متصل بودن به موتور |")
    w("")
    w("**هیچ ستونی در این فایل ثابت نمی‌کند برنامه روی ویندوز درست کار می‌کند.**")
    w("")
    w("---")
    w("")
    w("## جدول ماژول‌ها")
    w("")
    w("| ماژول | خط | tests | tag | dead | test-only | cfg(win) | سطح تأیید |")
    w("|---|---:|---:|:---:|---:|---:|---:|---|")

    counts = defaultdict(int)
    for m in sorted(a["mods"], key=lambda x: -a["mods"][x]["lines"]):
        i = a["mods"][m]
        lvl, _why = verification_level(m, i, dead_by, to_by)
        counts[lvl] += 1
        w("| `{}` | {} | {} | {} | {} | {} | {} | {} |".format(
            m, i["lines"], i["tests"], i["tag"] or "—",
            len(dead_by.get(m, [])) or "—", len(to_by.get(m, [])) or "—",
            i["win"] or "—", lvl))

    tot_lines = sum(i["lines"] for i in a["mods"].values())
    tot_tests = sum(i["tests"] for i in a["mods"].values())
    w("| **مجموع** | **{}** | **{}** | | **{}** | **{}** | | |".format(
        tot_lines, tot_tests, len(a["dead"]), len(a["testonly"])))
    w("")
    w("### توزیع سطح تأیید")
    w("")
    for k in sorted(counts, key=lambda x: -counts[x]):
        w(f"* `{k}` — {counts[k]} ماژول")
    w("")
    w("---")
    w("")
    w("## دسترسی توابع عمومی")
    w("")
    n_all = len(a["live"]) + len(a["testonly"]) + len(a["dead"])
    w(f"مجموع `pub fn`: **{n_all}**")
    w("")
    w(f"* ✅ از کد تولیدی صدا زده می‌شوند: **{len(a['live'])}**")
    w(f"* 🟡 فقط از تست‌ها صدا زده می‌شوند: **{len(a['testonly'])}**")
    w(f"* 🔴 هیچ‌جا صدا زده نمی‌شوند: **{len(a['dead'])}**")
    w("")
    if a["dead"]:
        w("### 🔴 بدون هیچ فراخوان")
        w("")
        w("نه کد تولیدی و نه تست صدایشان نمی‌زند.")
        w("")
        for m in sorted(dead_by, key=lambda x: -len(dead_by[x])):
            w(f"* `{m}` — " + ", ".join(f"`{f}`" for f in sorted(dead_by[m])))
        w("")
    if a["testonly"]:
        w("### 🟡 فقط از تست‌ها")
        w("")
        w("پیاده‌سازی و تست دارند اما **به مسیر اجرای واقعی وصل نیستند**.")
        w("برای اینها `DONE` ننویسید.")
        w("")
        for m in sorted(to_by, key=lambda x: -len(to_by[x])):
            w(f"* `{m}` — " + ", ".join(f"`{f}`" for f in sorted(to_by[m])))
        w("")
    w("---")
    w("")
    w("## اتصال تنظیمات")
    w("")
    w(f"* فیلدهای `Settings`: **{len(a['fields'])}**")
    if ui is not None:
        w(f"* کنترل‌های UI در `index.html`: **{len(ui)}**")
        miss_ui = sorted(set(a["fields"]) - ui)
        extra_ui = sorted(ui - set(a["fields"]))
        w(f"* در Settings ولی نه در UI: **{len(miss_ui)}**"
          + (" — " + ", ".join(f"`{x}`" for x in miss_ui) if miss_ui else ""))
        w(f"* در UI ولی نه در Settings: **{len(extra_ui)}**"
          + (" — " + ", ".join(f"`{x}`" for x in extra_ui) if extra_ui else ""))
    w(f"* بدون خواننده در ماژول‌های موتور: **{len(a['unwired'])}**"
      + (" — " + ", ".join(f"`{x}`" for x in a["unwired"]) if a["unwired"] else ""))
    w("")
    w("> «خوانده می‌شود» یعنی نام فیلد در کد غیرتستیِ یک ماژول موتور ظاهر شده.")
    w("> این **اثبات نمی‌کند** که تنظیم اثر واقعی دارد.")
    w("")
    w("---")
    w("")
    w("## ماژول‌های بدون هیچ تست")
    w("")
    zero = [m for m, i in a["mods"].items() if i["tests"] == 0]
    for m in sorted(zero, key=lambda x: -a["mods"][x]["lines"]):
        w(f"* `{m}` — {a['mods'][m]['lines']} خط")
    w("")

    body = "\n".join(L) + "\n"
    summary = (f"({len(a['mods'])} modules, "
               f"{tot_tests} tests declared, {len(a['dead'])} dead fns)")

    # --check: verify the committed TEST_MATRIX.md still matches the source
    # tree instead of rewriting it. This is what CI runs; exit 1 on drift so
    # a hand-edited table cannot merge. The `<!-- commit: ... -->` marker is
    # excluded from the comparison: it records which commit generated the
    # table, so it differs on every fresh checkout by construction.
    if "--check" in sys.argv:
        path = os.path.join(ROOT, "TEST_MATRIX.md")
        try:
            with open(path, encoding="utf-8") as fh:
                current = fh.read()
        except OSError as e:
            print(f"TEST_MATRIX.md unreadable: {e}")
            return 1

        def norm(text):
            return [ln for ln in text.splitlines()
                    if not ln.startswith("<!-- commit:")]

        if norm(current) == norm(body):
            print(f"TEST_MATRIX.md up to date {summary}")
            return 0
        import difflib
        diff = difflib.unified_diff(
            norm(current), norm(body),
            fromfile="TEST_MATRIX.md (committed)",
            tofile="TEST_MATRIX.md (regenerated)", lineterm="")
        print("TEST_MATRIX.md is out of date with the source tree.\n"
              "Run `python3 tools/gen_status.py` and commit the result.\n")
        for line in diff:
            print(line)
        return 1

    with open(os.path.join(ROOT, "TEST_MATRIX.md"), "w", encoding="utf-8") as fh:
        fh.write(body)

    with open(os.path.join(ROOT, "tools", "status.json"), "w", encoding="utf-8") as fh:
        json.dump({"commit": head, "modules": a["mods"],
                   "dead": dead_by, "test_only": to_by,
                   "settings_fields": len(a["fields"]),
                   "unwired": a["unwired"],
                   "dependencies": a["dep"]}, fh, indent=2, ensure_ascii=False)

    print(f"TEST_MATRIX.md written  {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
