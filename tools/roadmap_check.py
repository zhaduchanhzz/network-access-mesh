"""Check ROADMAP.md against the master plan: IDs exist, task counts per phase and total, decision range, links.

usage: python roadmap_check.py <ROADMAP.md> <master.md> <project_root>
"""
import io
import os
import re
import sys
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
road_p, master_p, root = sys.argv[1:4]
road = open(road_p, encoding="utf-8").read()
master = open(master_p, encoding="utf-8").read()
problems = []

# task counts
tasks = re.findall(r"(?m)^\| (P\d-T\d+[a-z]?) \|", master)
per = Counter(t[1] for t in tasks)
rows = re.findall(r"(?m)^\| (\d) — [^|]+\|[^|]+\|[^|]+\| (\d+) \|", road)
for ph, n in rows:
    if per.get(ph, 0) != int(n):
        problems.append(f"phase {ph}: roadmap says {n} tasks, master has {per.get(ph, 0)}")
if len(rows) != 8:
    problems.append(f"expected 8 phase rows with task counts, found {len(rows)}")
m = re.search(r"Tổng cộng (\d+) task", road)
if not m or int(m.group(1)) != len(tasks):
    problems.append(f"total tasks: roadmap says {m.group(1) if m else None}, master has {len(tasks)}")

# ids referenced in the roadmap must exist in the master
fams = {
    "task": r"(?<![A-Za-z0-9])P\d-T\d+[a-z]?(?![0-9A-Za-z])",
    "AC": r"(?<![A-Za-z0-9-])AC-\d{2}(?!\d)",
    "R": r"(?<![A-Za-z0-9-])R-\d{2}(?!\d)",
    "D": r"(?<![A-Za-z0-9-])D-\d{1,2}(?![\d.])",
    "ADR": r"(?<![A-Za-z0-9-])ADR-\d{2}(?!\d)",
    "V": r"(?<![A-Za-z0-9-])V-\d{2}(?!\d)",
    "IT": r"(?<![A-Za-z0-9-])IT-\d{2}(?!\d)",
    "TD": r"(?<![A-Za-z0-9-])TD-\d{2}(?!\d)",
}
for fam, pat in fams.items():
    for ref in sorted(set(re.findall(pat, road))):
        if not re.search(rf"(?m)^\| \**`?{re.escape(ref)}`?\** \|", master):
            problems.append(f"{fam} id {ref} is not defined in the master")
for g in sorted(set(re.findall(r"\bG\d[ab]?\b", road))):
    base = g[:2]
    if not re.search(rf"Go/No-Go {base}\b", master):
        problems.append(f"gate {g} not found in the master")

# decision range
dmax = max(int(x) for x in re.findall(r"(?m)^\| D-(\d+) \|", master))
m = re.search(r"D-1…D-(\d+)", road)
if m and int(m.group(1)) != dmax:
    problems.append(f"decision range says D-1…D-{m.group(1)}, master goes to D-{dmax}")

# AC rows: 20
acs = re.findall(r"(?m)^\| (AC-\d{2}) \|", road)
if len(acs) != 20 or len(set(acs)) != 20:
    problems.append(f"AC table has {len(acs)} rows")

# links
for target in sorted(set(re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", road))):
    if target.startswith("http"):
        continue
    if not os.path.exists(os.path.join(root, target)):
        problems.append(f"link target missing: {target}")

# mermaid bracket balance
in_m = False
for ln in road.split("\n"):
    if ln.strip().startswith("```"):
        in_m = ln.strip() == "```mermaid" if not in_m else False
        continue
    if in_m:
        for o, c in (("[", "]"), ("(", ")"), ("{", "}")):
            if ln.count(o) != ln.count(c):
                problems.append(f"mermaid bracket imbalance: {ln.strip()[:80]}")
                break

print(f"master: {len(tasks)} tasks {dict(sorted(per.items()))}; decisions up to D-{dmax}")
if problems:
    print(f"ROADMAP CHECK: {len(problems)} problem(s)")
    for p in problems:
        print("  -", p)
else:
    print("ROADMAP CHECK OK")
