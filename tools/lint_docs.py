#!/usr/bin/env python3
"""Documentation lint — keeps the prose from drifting away from the source.

This script exists because the docs in this repo drifted repeatedly: README
claimed "344 tests" while TEST_MATRIX.md said 431, README said "77 settings"
while `Settings` has 82, the install steps linked to a *different* GitHub
repo (`sni-spoof-new-5.6`), and a CI workflow copied a file that does not
exist. None of those are caught by `cargo test` or by the jsdom suite, so
they are checked here instead.

    python3 tools/lint_docs.py            # exit 1 on any violation
    python3 tools/lint_docs.py --quiet    # only print the violation list

Checks
------
1. every file under docs/archive/ carries the ARCHIVED-DO-NOT-TRUST banner
2. README/STATUS point at the canonical repo, not another one
3. every "N settings / N تنظیم" figure matches `Settings` in src/config.rs
4. every quoted test / module count matches tools/status.json
5. FA/EN parity: bilingual step headings keep both halves
6. local file links resolve (no `START_HERE.md`-style dead references)

Nothing here can prove the *code* works — only that the prose agrees with
the tree. See AI_RULES.md section 8.
"""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUIET = "--quiet" in sys.argv

violations = []


def v(check, path, line_no, msg):
    violations.append(f"[{check}] {path}:{line_no}: {msg}")


def rel(p):
    return os.path.relpath(p, ROOT).replace(os.sep, "/")


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def lines(text):
    return text.splitlines()


def prose_lines(text):
    """Yield (lineno, line) for prose only — ``` code fences are skipped.

    A shell comment inside a bash block (`# ... 56 settings ...`) is a test
    suite name, not a claim about how many Settings fields exist, and
    linting it produced a false positive on README:492.
    """
    fence = False
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        if not fence:
            yield n, line


# A line that is explicitly labelled as describing a past state is allowed to
# quote the numbers of that time ("در همان زمان: ۴۲۴ تست" / "historical").
# Anything else quoting a total must match the source tree.
HISTORICAL = ("در همان زمان", "تاریخی", "قبلاً", "پیش‌تر",
              "historical", "at the time", "previously", "used to")


def is_historical(line):
    low = line.lower()
    return any(h.lower() in low for h in HISTORICAL)


# ---------------------------------------------------------------- canonical id

def canonical_repo():
    """Owner/name of this repository, from the git remote when available."""
    try:
        url = subprocess.check_output(
            ["git", "-C", ROOT, "config", "--get", "remote.origin.url"],
            text=True, stderr=subprocess.DEVNULL).strip()
        m = re.search(r"[:/]([^/:]+/[^/]+?)(?:\.git)?$", url)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


# ------------------------------------------------------------------- settings

def settings_fields():
    """Public field names of `struct Settings` in src/config.rs."""
    src = read("src", "config.rs")
    start = src.find("pub struct Settings {")
    if start < 0:
        return []
    depth, i, body = 0, src.index("{", start), ""
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                break
        if depth >= 1:
            body += src[i]
        i += 1
    return re.findall(r"^\s*pub\s+([a-z][a-z0-9_]*)\s*:", body, re.M)


# --------------------------------------------------------------------- checks

def check_archive_banners():
    d = os.path.join(ROOT, "docs", "archive")
    if not os.path.isdir(d):
        return
    for name in sorted(os.listdir(d)):
        if not name.endswith(".md"):
            continue
        p = os.path.join(d, name)
        head = read("docs", "archive", name)[:400]
        if "ARCHIVED" not in head or "DO NOT TRUST" not in head:
            v("archive-banner", rel(p), 1,
              "archived doc must start with the ARCHIVED — DO NOT TRUST banner")


def check_repo_identity(canonical):
    """README must not send the reader to a different repository."""
    if not canonical:
        print("  (repo identity check skipped: no git remote configured)")
        return
    owner = canonical.split("/")[0]
    for doc in ("README.md",):
        text = read(doc)
        for n, line in prose_lines(text):
            for m in re.finditer(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", line):
                slug = m.group(1)
                if slug.split("/")[0] != owner:
                    continue
                # The regex character class excludes "/", so `slug` is already
                # just `owner/name` — a trailing /path, /tree/main or #anchor is
                # never captured. The only suffix that can appear is a literal
                # `.git` from a clone URL.
                #
                # Do NOT normalise with `.split(".")[0]`: that truncates at the
                # first dot, so a repository whose *name* contains a dot (e.g.
                # `sni-spoof-new--alpha-3.12`) was compared as
                # `sni-spoof-new--alpha-3` and flagged as linking to a foreign
                # repo even when the link was exactly this one. Strip only a
                # trailing `.git`.
                base = slug[: -len(".git")] if slug.endswith(".git") else slug
                if base != canonical:
                    v("repo-identity", doc, n,
                      f"links to `{slug}` but this repository is `{canonical}`")


def check_settings_counts():
    real = len(settings_fields())
    if not real:
        v("settings-count", "src/config.rs", 0, "could not parse struct Settings")
        return
    pat = re.compile(r"(\d+)\s*(?:settings|تنظیم)", re.I)
    for doc in ("README.md", "STATUS.md"):
        if not os.path.exists(os.path.join(ROOT, doc)):
            continue
        for n, line in prose_lines(read(doc)):
            if is_historical(line):
                continue
            for m in pat.finditer(line):
                claimed = int(m.group(1))
                # "5 new flags" style prose is not a total; only totals in the
                # 20..400 range are treated as a claim about Settings.
                if claimed == real or not (20 <= claimed <= 400):
                    continue
                v("settings-count", doc, n,
                  f"claims {claimed} settings; src/config.rs has {real}")


def check_status_numbers():
    sj = os.path.join(ROOT, "tools", "status.json")
    if not os.path.exists(sj):
        return
    with open(sj, encoding="utf-8") as fh:
        st = json.load(fh)
    mods = len(st.get("modules", {}))
    tests = sum(m.get("tests", 0) for m in st.get("modules", {}).values())
    fields = st.get("settings_fields")

    # A "N تست" / "N tests" figure in STATUS.md must match the declared
    # #[test] count. Anything else is a stale hand-edited number.
    doc = "STATUS.md"
    if os.path.exists(os.path.join(ROOT, doc)):
        for n, line in prose_lines(read(doc)):
            if is_historical(line):
                continue
            for m in re.finditer(r"(\d{2,4})\s*(?:تست|tests?)\b", line):
                claimed = int(m.group(1))
                if claimed in (tests, mods) or not (20 <= claimed <= 999):
                    continue
                v("status-numbers", doc, n,
                  f"quotes {claimed} tests; source declares {tests} "
                  f"(tools/status.json). Update the prose or re-run gen_status.py")
            for m in re.finditer(r"(\d{2,3})\s*(?:ماژول|modules?)\b", line):
                claimed = int(m.group(1))
                if claimed == mods or not (2 <= claimed <= 200):
                    continue
                v("status-numbers", doc, n,
                  f"quotes {claimed} modules; source has {mods}")

    if fields and os.path.exists(os.path.join(ROOT, "README.md")):
        for n, line in prose_lines(read("README.md")):
            if is_historical(line):
                continue
            for m in re.finditer(r"all\s+(\d+)\s+`?Settings`?", line):
                if int(m.group(1)) != fields:
                    v("status-numbers", "README.md", n,
                      f"claims all {m.group(1)} Settings fields; there are {fields}")


def check_bilingual_headings():
    """README step headings are bilingual: `### N) فارسی / English`."""
    doc = "README.md"
    if not os.path.exists(os.path.join(ROOT, doc)):
        return
    for n, line in prose_lines(read(doc)):
        m = re.match(r"^###\s+[۰-۹0-9]+[\).\.]", line)
        if not m:
            continue
        body = line.split("###", 1)[1]
        has_fa = bool(re.search(r"[\u0600-\u06FF]", body))
        has_en = bool(re.search(r"[A-Za-z]{3,}", body))
        if has_fa and not has_en:
            v("fa-en-parity", doc, n,
              "step heading is Persian-only; add the English half after ' / '")
        if has_en and not has_fa:
            v("fa-en-parity", doc, n,
              "step heading is English-only; add the Persian half")


def check_local_links():
    """Every repo-relative markdown link must resolve to a real file."""
    for doc in ("README.md", "STATUS.md", "ARCHITECTURE.md", "KNOWN_ISSUES.md"):
        if not os.path.exists(os.path.join(ROOT, doc)):
            continue
        base = os.path.dirname(os.path.join(ROOT, doc))
        for n, line in prose_lines(read(doc)):
            for m in re.finditer(r"\]\((?!https?://|#|mailto:)([^)\s]+)\)", line):
                target = m.group(1).split("#")[0]
                if not target or target.startswith("/"):
                    continue
                if not os.path.exists(os.path.normpath(os.path.join(base, target))):
                    v("dead-link", doc, n, f"link target `{target}` does not exist")


def is_gitignored(path):
    """True if .gitignore deliberately excludes `path` from the repository.

    `check_workflow_paths` exists to catch a workflow that copies a file which
    was never committed (the START_HERE.md bug). That premise does not hold for
    paths the repository *intentionally* does not track: e2e.yml copies
    WinDivert.dll/WinDivert64.sys into place after scripts/fetch-windivert.ps1
    downloads and SHA-256-verifies them at run time, and .gitignore keeps them
    out of git on purpose (see ci/README.md and build-windows.bat).

    Those are runtime artifacts, not missing sources, so they are exempt. A
    genuinely absent tracked file — the original bug — is not gitignored and is
    still reported.
    """
    try:
        return subprocess.call(
            ["git", "-C", ROOT, "check-ignore", "--quiet", "--", path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception:
        return False


def check_workflow_paths():
    """Files referenced by CI workflows must exist (START_HERE.md bug)."""
    wf = os.path.join(ROOT, ".github", "workflows")
    if not os.path.isdir(wf):
        return
    for name in sorted(os.listdir(wf)):
        if not name.endswith((".yml", ".yaml")):
            continue
        p = os.path.join(wf, name)
        for n, line in enumerate(open(p, encoding="utf-8"), 1):
            for m in re.finditer(r'Copy-Item\s+"([^"$]+)"', line):
                src = m.group(1).strip().rstrip("\\")
                src = src.replace("\\", "/")
                if src.startswith("target/"):
                    continue  # build output
                if not os.path.exists(os.path.join(ROOT, src)):
                    if is_gitignored(src):
                        continue  # fetched/generated at run time by design
                    v("workflow-path", f".github/workflows/{name}", n,
                      f"copies `{src}` which is not in the repository")


def main():
    checks = [
        ("archive banners", lambda: check_archive_banners()),
        ("repo identity", lambda: check_repo_identity(canonical_repo())),
        ("settings counts", check_settings_counts),
        ("status numbers", check_status_numbers),
        ("FA/EN parity", check_bilingual_headings),
        ("local links", check_local_links),
        ("workflow paths", check_workflow_paths),
    ]
    for label, fn in checks:
        fn()

    if violations:
        print(f"tools/lint_docs.py: {len(violations)} parity violation(s)\n")
        for x in violations:
            print("  " + x)
        return 1
    if not QUIET:
        print("tools/lint_docs.py: 0 parity violations "
              f"({len(checks)} checks, {len(settings_fields())} Settings fields)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
