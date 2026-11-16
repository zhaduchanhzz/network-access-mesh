#!/usr/bin/env python3
"""docs-check for the MeshGuard plan (task P0-T04, `make docs-check`).

Runs, from the repository root:
  1. tools/plan_lint.py      — IDs, cross-references, placeholders, stale terms, mermaid brackets, task counts
  2. tools/split_plan.py     — regenerates docs/ from the master (CI then runs `git diff --exit-code docs/`)
  3. tools/roadmap_check.py  — ROADMAP.md agrees with the master
  4. checks implemented here:
     a. every edge of the §21.2 diagram exists in the dependency column of §20
     b. every line of §3–§18 labelled REQUIRES VALIDATION carries a V-nn or AC-nn code on the same line
     c. every V-nn referenced anywhere in the master has a row in §22.4
     d. every relative Markdown link in docs/ and in the root *.md files resolves to an existing file

Exit code 0 only when every step passes. Standard library only.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MASTER = ROOT / "docs" / "planning" / "implementation-master-plan.md"
TOOLS = ROOT / "tools"

TASK_RE = re.compile(r"P(\d)-T(\d+)([a-z]?)")
GATE_RE = re.compile(r"\bG(\d)([ab]?)\b")


def run(cmd: list[str]) -> bool:
    print(f"\n$ {' '.join(cmd)}")
    res = subprocess.run(cmd, cwd=ROOT)
    return res.returncode == 0


# ---------------------------------------------------------------- master parsing
def sections(lines: list[str]) -> dict[str, tuple[int, int]]:
    """Map '## N.' / '### N.M' / '## Appendix X' headings to [start, end) line ranges."""
    heads = [(i, ln) for i, ln in enumerate(lines) if ln.startswith("## ") or ln.startswith("### ")]
    out: dict[str, tuple[int, int]] = {}
    for k, (i, ln) in enumerate(heads):
        level = ln.split(" ", 1)[0]
        end = len(lines)
        for j, ln2 in heads[k + 1:]:
            if len(ln2.split(" ", 1)[0]) <= len(level):
                end = j
                break
        m = re.match(r"#+ (\d+(?:\.\d+)?)[. ]", ln)
        key = m.group(1) if m else ln.split(" ", 1)[1].strip()
        out.setdefault(key, (i, end))
    return out


def split_row(ln: str) -> list[str]:
    cells = re.split(r"(?<!\\)\|", ln.strip())
    return [c.strip() for c in cells[1:-1]]


def all_tasks(lines: list[str]) -> list[str]:
    ids = []
    for ln in lines:
        if ln.startswith("| P") and TASK_RE.match(ln[2:]):
            ids.append(split_row(ln)[0])
    return ids


def expand_deps(cell: str, tasks: list[str]) -> set[str]:
    """Task and gate IDs named in a dependency cell, with ranges and 'Tất cả Pn' expanded."""
    found: set[str] = set()
    for m in re.finditer(r"Tất cả P(\d)", cell):
        found |= {t for t in tasks if t.startswith(f"P{m.group(1)}-")}
    # ranges: P1-T10…T13 or P1-T10…P1-T13 (suffixed tasks inside the numeric range are included)
    for m in re.finditer(r"P(\d)-T(\d+)[a-z]?\s*(?:…|\.\.\.)\s*(?:P\d-)?T(\d+)", cell):
        ph, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
        for t in tasks:
            tm = TASK_RE.fullmatch(t)
            if tm and tm.group(1) == ph and lo <= int(tm.group(2)) <= hi:
                found.add(t)
    # explicit IDs, plus short continuations like "P3-T03, T04"
    phase = None
    for m in re.finditer(r"P(\d)-T\d+[a-z]?|(?<![\w-])T\d+[a-z]?", cell):
        tok = m.group(0)
        if tok.startswith("P"):
            phase = tok[1]
            found.add(tok)
        elif phase:
            found.add(f"P{phase}-{tok}")
    found |= {f"G{m.group(1)}{m.group(2)}" for m in GATE_RE.finditer(cell)}
    return found


def check_diagram_edges(lines: list[str], secs: dict[str, tuple[int, int]]) -> list[str]:
    tasks = all_tasks(lines)
    deps: dict[str, set[str]] = {}
    s, e = secs["20"]
    for ln in lines[s:e]:
        if ln.startswith("| P") and TASK_RE.match(ln[2:]):
            row = split_row(ln)
            if len(row) >= 3:
                deps[row[0]] = expand_deps(row[2], tasks)
    s, e = secs["21.2"]
    block, inside = [], False
    for ln in lines[s:e]:
        if ln.strip().startswith("```mermaid"):
            inside = True
            continue
        if inside and ln.strip().startswith("```"):
            break
        if inside:
            block.append(ln)
    nodes: dict[str, set[str]] = {}
    edges: list[tuple[str, str]] = []
    node_re = re.compile(r"^\s*([A-Za-z][\w]*)\s*(\[[^\]]*\]|\{\{[^}]*\}\}|\([^)]*\))?\s*$")
    for ln in block:
        if "-->" not in ln:
            continue
        parts = [p.strip() for p in ln.split("-->")]
        ids = []
        for p in parts:
            m = node_re.match(p)
            if not m:
                continue
            nid, label = m.group(1), m.group(2) or ""
            if label:
                ents = {t.group(0) for t in TASK_RE.finditer(label)}
                ents |= {f"G{g.group(1)}{g.group(2)}" for g in GATE_RE.finditer(label)} if label.startswith("{{") else set()
                nodes[nid] = ents
            ids.append(nid)
        edges += list(zip(ids, ids[1:]))
    problems = []
    checked = 0
    for a, b in edges:
        for target in nodes.get(b, set()):
            if not TASK_RE.fullmatch(target):
                continue  # edges into a gate have no table row
            if target not in deps:
                problems.append(f"§21.2 node {b}: task {target} has no row in §20")
                continue
            for src in nodes.get(a, set()):
                checked += 1
                if src not in deps[target]:
                    problems.append(f"§21.2 edge {src} --> {target}: §20 dependency of {target} does not name {src}")
    if checked < 50:  # the diagram has ~90 task edges; a low count means the parser broke
        problems.append(f"only {checked} task edges parsed from §21.2 — parser out of date?")
    print(f"§21.2: {len(edges)} edges, {checked} task dependencies checked against §20")
    return problems


def check_requires_validation(lines: list[str], secs: dict[str, tuple[int, int]]) -> list[str]:
    problems = []
    s, _ = secs["3"]
    _, e = secs["18"]
    for i in range(s, e):
        ln = lines[i]
        if "REQUIRES VALIDATION" in ln and not re.search(r"\b(V|AC)-\d{2}\b", ln):
            problems.append(f"line {i + 1}: REQUIRES VALIDATION without a V-nn or AC-nn code: {ln.strip()[:100]}")
    return problems


def check_v_rows(lines: list[str], secs: dict[str, tuple[int, int]]) -> list[str]:
    s, e = secs["22.4"]
    defined = {m.group(1) for ln in lines[s:e] for m in [re.match(r"\| (V-\d{2}) \|", ln)] if m}
    used = {m.group(0) for ln in lines for m in re.finditer(r"\bV-\d{2}\b", ln)}
    return [f"{v} is referenced but has no row in §22.4" for v in sorted(used - defined)]


def check_links() -> list[str]:
    problems = []
    files = sorted((ROOT / "docs").rglob("*.md")) + sorted(ROOT.glob("*.md"))
    link_re = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
    for f in files:
        in_code = False
        for n, ln in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if ln.strip().startswith("```"):
                in_code = not in_code
                continue
            if in_code:
                continue
            for m in link_re.finditer(re.sub(r"\\[\[\]]", "", ln)):  # \[ \] are literal text, not links
                target = m.group(1)
                if re.match(r"^(https?:|mailto:|#)", target):
                    continue
                path = target.split("#", 1)[0]
                if path and not (f.parent / path).resolve().exists():
                    problems.append(f"{f.relative_to(ROOT).as_posix()}:{n}: broken link -> {target}")
    return problems


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to a legacy code page
    ok = True
    py = sys.executable
    ok &= run([py, str(TOOLS / "plan_lint.py"), str(MASTER.relative_to(ROOT))])
    ok &= run([py, str(TOOLS / "split_plan.py")])
    ok &= run([py, str(TOOLS / "roadmap_check.py"), "ROADMAP.md", str(MASTER.relative_to(ROOT)), "."])

    lines = MASTER.read_text(encoding="utf-8").splitlines()
    secs = sections(lines)
    checks = {
        "§21.2 edges exist in §20": check_diagram_edges(lines, secs),
        "REQUIRES VALIDATION has a V/AC code (§3–§18)": check_requires_validation(lines, secs),
        "every V code has a §22.4 row": check_v_rows(lines, secs),
        "relative links resolve": check_links(),
    }
    print()
    for name, problems in checks.items():
        status = "OK" if not problems else f"{len(problems)} problem(s)"
        print(f"[{status}] {name}")
        for p in problems:
            print(f"    - {p}")
        ok &= not problems
    print("\nDOCS CHECK OK" if ok else "\nDOCS CHECK FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
