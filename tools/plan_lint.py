"""Cross-reference lint for the master plan (read-only).

usage: python plan_lint.py <master.md>
Checks: task IDs referenced vs defined, ID families referenced vs defined, table column counts,
section references, placeholders left over, stale terms, mermaid bracket balance, task counts.
"""
import io
import re
import sys
from collections import Counter, defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
path = sys.argv[1]
text = open(path, encoding="utf-8").read().replace("\r\n", "\n")
lines = text.split("\n")
problems = defaultdict(list)


def cells(row):
    """Split a markdown table row on unescaped pipes."""
    parts = re.split(r"(?<!\\)\|", row)
    return [p.strip() for p in parts[1:-1]]


# ---------- headings / sections ----------
sections, fence = set(), False
heading_lines = {}
for i, ln in enumerate(lines, 1):
    if ln.lstrip().startswith("```"):
        fence = not fence
        continue
    if fence:
        continue
    m = re.match(r"^## (\d+)\. ", ln)
    if m:
        sections.add(m.group(1))
    m = re.match(r"^### (\d+\.\d+) ", ln)
    if m:
        sections.add(m.group(1))
    m = re.match(r"^## Appendix ([A-Z])\b", ln)
    if m:
        sections.add(m.group(1))
    m = re.match(r"^### ([A-Z]\.\d+) ", ln)
    if m:
        sections.add(m.group(1))
    if re.match(r"^#{1,6} ", ln):
        heading_lines[i] = ln

# ---------- tables: column counts + first-cell definitions ----------
defined = defaultdict(list)  # id -> [line numbers]
i = 0
fence = False
while i < len(lines):
    ln = lines[i]
    if ln.lstrip().startswith("```"):
        fence = not fence
        i += 1
        continue
    if not fence and ln.startswith("|"):
        start = i
        while i < len(lines) and lines[i].startswith("|"):
            i += 1
        block = lines[start:i]
        ncol = len(cells(block[0]))
        for off, row in enumerate(block):
            c = cells(row)
            if len(c) != ncol:
                problems["table column count"].append(f"line {start + off + 1}: {len(c)} cells, header has {ncol}: {row[:90]}")
            if off >= 2 and c:
                first = c[0].strip("*").strip("`").strip()
                for m in re.finditer(r"^(P\d-T\d+[a-z]?|V-\d+|T-\d+|R-\d+|TD-\d+|ADR-\d+|AC-\d+|D-\d+|L\d+|IT-\d+[a-c]?|(?:HS|PL|ID|DP|RT|CL|EG|ST|GW)-\d+[a-z]?|X-\d+)\b", first):
                    defined[m.group(1)].append(start + off + 1)
        continue
    i += 1

# IT ids are defined inside the 4th cell of the §5.2 table and in prose
for m in re.finditer(r"\bIT-(\d{2})([a-c])?(?=[ :(,;.]|\b)", text):
    pass
it_defined = set(re.findall(r"\b(IT-\d{2}[a-c]?)(?::| \(| —)", text))
for x in it_defined:
    defined.setdefault(x, []).append(0)
# AC-05a / AC-05b are defined inside the AC-05 row
for x in ("AC-05a", "AC-05b"):
    if x in text:
        defined.setdefault(x, []).append(0)

# ---------- references ----------
families = {
    "task": r"(?<![A-Za-z0-9])P\d-T\d+[a-z]?(?![0-9A-Za-z])",
    "V": r"(?<![A-Za-z0-9-])V-\d{2}(?!\d)",
    "T": r"(?<![A-Za-z0-9-])T-\d{2}(?!\d)",
    "R": r"(?<![A-Za-z0-9-])R-\d{2}(?!\d)",
    "TD": r"(?<![A-Za-z0-9-])TD-\d{2}(?!\d)",
    "ADR": r"(?<![A-Za-z0-9-])ADR-\d{2}(?!\d)",
    "AC": r"(?<![A-Za-z0-9-])AC-\d{2}[ab]?(?!\d)",
    "D": r"(?<![A-Za-z0-9-])D-\d{1,2}(?![\d.])",
    "IT": r"(?<![A-Za-z0-9-])IT-\d{2}[a-c]?(?!\d)",
    "fact": r"(?<![A-Za-z0-9-])(?:HS|PL|DP|RT|CL|EG|ST|GW)-\d{2}[a-z]?(?!\d)",
    "X": r"(?<![A-Za-z0-9-])X-\d{1,2}(?!\d)",
}
for fam, pat in families.items():
    refs = Counter(re.findall(pat, text))
    for ref in sorted(refs):
        base = ref
        if ref not in defined:
            # IT-12 (umbrella), IT-01 family etc.
            if fam == "IT" and (ref + "a" in defined or ref.rstrip("abc") in defined):
                continue
            if fam == "AC" and ref.rstrip("ab") in defined:
                continue
            if fam == "fact" and ref.rstrip("abcdefgh") in defined and ref[-1].isalpha() and ref not in ("RT-02a",):
                pass
            problems[f"undefined {fam} reference"].append(f"{ref} (x{refs[ref]})")

# range references like P1-T10…T13: make sure both ends exist
for m in re.finditer(r"(P\d)-T(\d+)([a-z]?)…T(\d+)([a-z]?)", text):
    a = f"{m.group(1)}-T{m.group(2)}{m.group(3)}"
    b = f"{m.group(1)}-T{m.group(4)}{m.group(5)}"
    for x in (a, b):
        if x not in defined:
            problems["undefined task in range"].append(f"{m.group(0)} -> {x}")

# duplicate definitions (families that must be unique)
for k, v in defined.items():
    real = [n for n in v if n]
    if k.startswith(("P", "V-", "R-", "TD-", "ADR-", "AC-", "D-", "X-")) and len(real) > 1:
        problems["duplicate definition"].append(f"{k} at lines {real}")
    if k.startswith("T-") and len(real) not in (2, 3):
        problems["threat rows (need 2 or 3)"].append(f"{k} at lines {real}")

# ---------- section references ----------
for m in re.finditer(r"§(\d+(?:\.\d+)?)", text):
    s = m.group(1)
    if s not in sections:
        ln = text.count("\n", 0, m.start()) + 1
        problems["section reference not found"].append(f"§{s} (line {ln})")
for m in re.finditer(r"Appendix ([A-Z])(?:\.(\d+))?", text):
    key = m.group(1) + ("." + m.group(2) if m.group(2) else "")
    if key not in sections:
        ln = text.count("\n", 0, m.start()) + 1
        problems["appendix reference not found"].append(f"Appendix {key} (line {ln})")

# ---------- placeholders and stale terms ----------
for m in re.finditer(r"\b(?:[A-Z]{1,3}-N\d[a-z]|P\d-TN\d[a-z])\b", text):
    ln = text.count("\n", 0, m.start()) + 1
    problems["placeholder id left"].append(f"{m.group(0)} (line {ln})")
stale = {
    "short_id": r"short_id",
    "colon action endpoint": r"\}:(?!action`)[a-z]|/[a-z-]+:(?:suspend|resume|approve|reject|revoke|apply|rollback|validate|submit|sync|claim|expire|retry|cancel|restart|upgrade|backup|restore|reconfigure)\b",
    "old IT range": r"IT-01…IT-13",
    "old task count": r"\b(?:98|137) task",
    "reject pending auth": r"reject pending auth",
    "current_policy_version_id": r"current_policy_version_id",
    "TODO/TBD": r"\bTODO\b|\bTBD\b|\?\?\?",
}
body_text = text.split(chr(10) + "## Appendix D")[0]  # the review log quotes old terms on purpose
for name, pat in stale.items():
    for m in re.finditer(pat, body_text):
        ln = text.count("\n", 0, m.start()) + 1
        ctx = text[max(0, m.start() - 40):m.end() + 40].replace("\n", " ")
        problems[f"stale: {name}"].append(f"line {ln}: …{ctx}…")

# ---------- mermaid sanity ----------
fence, kind, start = False, "", 0
for i, ln in enumerate(lines, 1):
    s = ln.strip()
    if s.startswith("```"):
        if not fence:
            fence, kind, start = True, s[3:].strip(), i
        else:
            fence = False
        continue
    if fence and kind == "mermaid" and "--o{" not in ln and "}o--" not in ln and "||--" not in ln:
        for o, c in (("[", "]"), ("(", ")"), ("{", "}")):
            if ln.count(o) != ln.count(c):
                problems["mermaid bracket imbalance"].append(f"line {i}: {ln.strip()[:100]}")
                break
if fence:
    problems["unclosed code fence"].append(f"opened at line {start}")

# ---------- task statistics ----------
tasks = sorted(k for k in defined if re.match(r"P\d-T", k))
per_phase = Counter(t[:2] for t in tasks)
m = re.search(r"(\d+) task có phụ thuộc", text)
claimed = int(m.group(1)) if m else None
if claimed != len(tasks):
    problems["task count claim"].append(f"summary says {claimed}, table has {len(tasks)}")

# dependency cells must reference defined tasks only (already covered) and no self-dependency
for t in tasks:
    ln = defined[t][0]
    c = cells(lines[ln - 1])
    if len(c) >= 3 and re.search(rf"(?<![A-Za-z0-9]){re.escape(t)}(?![0-9A-Za-z])", c[2]):
        problems["task depends on itself"].append(t)

print(f"lines: {len(lines)}  sections: {len(sections)}  tasks: {len(tasks)} {dict(sorted(per_phase.items()))}")
for fam in ("V-", "T-", "R-", "TD-", "ADR-", "AC-", "D-", "IT-"):
    ids = sorted(k for k in defined if k.startswith(fam) and not k.startswith("TD-") or (fam == "TD-" and k.startswith("TD-")))
    ids = [k for k in ids if k.startswith(fam)]
    print(f"  {fam}: {len(ids)} defined; last = {ids[-1] if ids else '-'}")
if not problems:
    print("LINT OK: no problems found")
else:
    total = sum(len(v) for v in problems.values())
    print(f"LINT: {total} problem(s) in {len(problems)} group(s)")
    for name in sorted(problems):
        items = problems[name]
        print(f"\n[{name}] ({len(items)})")
        for it in items[:60]:
            print("  -", it)
        if len(items) > 60:
            print(f"  … {len(items) - 60} more")
