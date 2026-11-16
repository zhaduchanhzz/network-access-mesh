#!/usr/bin/env python3
"""Split docs/planning/implementation-master-plan.md into topical documents.

The master plan is the single source of truth. Every other file under docs/ is
generated from it by this script, so never edit the generated files by hand:
edit the master, then run:

    python tools/split_plan.py

Standard library only. Exits non-zero if the mapping references a section that
does not exist, or if a numbered section of the master is not covered by any
topical file.
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
MASTER = DOCS / "planning" / "implementation-master-plan.md"
MASTER_REL = "planning/implementation-master-plan.md"

# (output path relative to docs/, document title, list of section specs)
# Spec forms:
#   "6"        whole section 6 (heading, preamble and every subsection)
#   "5.2"      one subsection
#   "5:pre"    heading and preamble of section 5 only
#   "-14.3"    exclusion, valid after a whole-section spec
#   "@rollback" special: rollback rows collected from the roadmap (section 19)
MAPPING: list[tuple[str, str, list[str]]] = [
    ("architecture/repository-assessment.md", "Repository Assessment", ["2", "-2.7"]),
    ("architecture/compatibility-matrix.md", "Compatibility Matrix", ["2.7"]),
    ("architecture/system-design.md", "System Design", ["3:pre", "3.1", "3.5", "4"]),
    ("architecture/c4-diagrams.md", "C4 Diagrams", ["3.2", "3.3", "3.4"]),
    ("architecture/multi-tenant-design.md", "Multi-Tenant Design", ["5:pre", "5.1", "5.4", "5.5"]),
    ("architecture/database-design.md", "Database Design", ["6"]),
    ("architecture/network-topology.md", "Network Topology", ["14.3", "14.6", "15.3"]),
    ("architecture/control-data-flows.md", "Control & Data Flows", ["9"]),
    ("architecture/relay-architecture.md", "Relay Architecture (DERP/STUN)", ["10"]),
    ("architecture/tenant-orchestrator.md", "Tenant Orchestrator", ["11"]),
    ("architecture/portal-design.md", "Portal Design (Super Admin / Tenant Admin)", ["12"]),
    ("security/zero-trust-design.md", "Zero Trust Design", ["7"]),
    ("security/threat-model.md", "Threat Model", ["18"]),
    ("security/permission-matrix.md", "Authentication, Authorization & Permission Matrix", ["8"]),
    ("security/tenant-isolation.md", "Tenant Isolation", ["5.2", "5.3"]),
    ("api/api-contracts.md", "API Contracts", ["13"]),
    ("deployment/ubuntu-server-inventory.md", "Server Inventory (Ubuntu host + VPS)", ["A"]),
    ("deployment/deployment-plan.md", "Deployment Plan", ["14", "-14.3", "-14.6"]),
    ("deployment/network-port-matrix.md", "Network Port Matrix & Connectivity Requirements", ["15:pre", "15.1", "15.2", "15.5"]),
    ("deployment/domain-and-tls-plan.md", "Domain & TLS Plan", ["15.4"]),
    ("deployment/rollback-plan.md", "Rollback Plan", ["11.4", "17.6", "@rollback"]),
    ("operations/monitoring-and-operations.md", "Monitoring & Operations", ["16"]),
    ("operations/backup-recovery-ha.md", "Backup, Recovery & High Availability", ["17"]),
    ("planning/milestones.md", "Roadmap & Milestones", ["19", "22.3"]),
    ("planning/task-breakdown.md", "Task Breakdown", ["20"]),
    ("planning/dependency-graph.md", "Dependency Graph", ["21"]),
    ("planning/test-strategy.md", "Test Strategy", ["22:pre", "22.1", "22.4"]),
    ("planning/acceptance-criteria.md", "MVP Acceptance Criteria", ["22.2"]),
    ("planning/risks-and-technical-debt.md", "Risks & Technical Debt", ["23"]),
    ("planning/build-mode-instructions.md", "Build Mode Execution Instructions", ["25"]),
    ("planning/review-log.md", "Review Log & Dispositions", ["D"]),
    ("adr/architecture-decision-records.md", "Architecture Decision Records", ["24"]),
]

# Sections that intentionally live only in the master / README.
MASTER_ONLY = {"context", "conventions", "1", "B", "C"}

H2 = re.compile(r"^## (.+?)\s*$")
H3 = re.compile(r"^### (.+?)\s*$")


class Section:
    def __init__(self, key: str, heading: str) -> None:
        self.key = key
        self.heading = heading
        self.preamble: list[str] = []
        self.subs: list[tuple[str, str, list[str]]] = []  # (key, heading, lines)

    def render(self, exclude: set[str] | None = None) -> list[str]:
        out = [self.heading, *self.preamble]
        for key, heading, lines in self.subs:
            if exclude and key in exclude:
                continue
            out += [heading, *lines]
        return out

    def render_pre(self) -> list[str]:
        return [self.heading, *self.preamble]

    def sub(self, key: str) -> list[str] | None:
        for k, heading, lines in self.subs:
            if k == key:
                return [heading, *lines]
        return None


def section_key(title: str) -> str:
    m = re.match(r"(\d+)\.\s", title)
    if m:
        return m.group(1)
    m = re.match(r"Appendix ([A-Z])\b", title)
    if m:
        return m.group(1)
    if title.startswith("Context"):
        return "context"
    if title.startswith("Quy ước"):
        return "conventions"
    return "x:" + title


def sub_key(sec_key: str, title: str, index: int) -> str:
    m = re.match(r"(\d+\.\d+)\b", title)
    if m:
        return m.group(1)
    m = re.match(r"([A-Z]\.\d+)\b", title)
    if m:
        return m.group(1)
    m = re.match(r"Phase (\d+)\b", title)
    if m:
        return f"{sec_key}.P{m.group(1)}"
    return f"{sec_key}.x{index}"


def parse(text: str) -> tuple[list[str], dict[str, Section], list[str]]:
    """Return (front matter lines, sections by key, section order)."""
    front: list[str] = []
    sections: dict[str, Section] = {}
    order: list[str] = []
    current: Section | None = None
    current_sub: list[str] | None = None
    in_fence = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
        m2 = None if in_fence else H2.match(line)
        m3 = None if in_fence else H3.match(line)
        if m2:
            key = section_key(m2.group(1))
            current = Section(key, line)
            sections[key] = current
            order.append(key)
            current_sub = None
        elif m3 and current is not None:
            key = sub_key(current.key, m3.group(1), len(current.subs))
            current_sub = []
            current.subs.append((key, line, current_sub))
        elif current is None:
            front.append(line)
        elif current_sub is not None:
            current_sub.append(line)
        else:
            current.preamble.append(line)
    return front, sections, order


def strip_trailing_rule(lines: list[str]) -> list[str]:
    out = list(lines)
    while out and out[-1].strip() in ("", "---"):
        out.pop()
    return out


def rollback_table(sections: dict[str, Section]) -> list[str]:
    sec = sections.get("19")
    rows = ["### Rollback strategy theo từng phase (trích từ §19)", "", "| Phase | Rollback strategy |", "|---|---|"]
    if sec:
        for _key, heading, lines in sec.subs:
            title = heading.lstrip("# ").strip()
            for line in lines:
                if line.startswith("| Rollback strategy |"):
                    cell = line.split("|")[2].strip()
                    rows.append(f"| {title} | {cell} |")
    return rows


def compose(specs: list[str], sections: dict[str, Section], errors: list[str], used: set[str]) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(specs):
        spec = specs[i]
        if spec == "@rollback":
            block = rollback_table(sections)
        elif spec.endswith(":pre"):
            key = spec[:-4]
            sec = sections.get(key)
            if not sec:
                errors.append(f"missing section {key}")
                i += 1
                continue
            block = sec.render_pre()
            used.add(key + ":pre")
        elif re.fullmatch(r"\d+|[A-Z]", spec):
            sec = sections.get(spec)
            if not sec:
                errors.append(f"missing section {spec}")
                i += 1
                continue
            exclude: set[str] = set()
            while i + 1 < len(specs) and specs[i + 1].startswith("-"):
                exclude.add(specs[i + 1][1:])
                i += 1
            for ex in exclude:
                if sec.sub(ex) is None:
                    errors.append(f"missing subsection {ex} (exclusion)")
            block = sec.render(exclude)
            used.add(spec + ":pre")
            used.update(k for k, _h, _l in sec.subs if k not in exclude)
        else:
            sec_key = spec.split(".")[0]
            sec = sections.get(sec_key)
            block_opt = sec.sub(spec) if sec else None
            if block_opt is None:
                errors.append(f"missing subsection {spec}")
                i += 1
                continue
            block = block_opt
            used.add(spec)
        out += strip_trailing_rule(block) + [""]
        i += 1
    return strip_trailing_rule(out)


def header(title: str, rel_path: str, specs: list[str]) -> list[str]:
    depth = rel_path.count("/")
    to_docs = "../" * depth
    src = ", ".join(
        ("hàng Rollback của §19" if s == "@rollback" else ("§" + s.replace(":pre", " (phần mở đầu)")))
        for s in specs
        if not s.startswith("-")
    )
    excl = ", ".join("§" + s[1:] for s in specs if s.startswith("-"))
    if excl:
        src += f" (trừ {excl})"
    return [
        f"# {title}",
        "",
        f"> **Trích sinh tự động** từ [implementation-master-plan.md]({to_docs}{MASTER_REL}) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.",
        f"> Nguồn: {src}. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README]({to_docs}README.md).",
        "",
    ]


def readme(front: list[str], sections: dict[str, Section]) -> list[str]:
    status = [l for l in front if l.startswith(">")]
    out = [
        "# MeshGuard ZTNA — Tài liệu thiết kế",
        "",
        "Bộ tài liệu kiến trúc và kế hoạch triển khai của MeshGuard ZTNA (multi-tenant Zero Trust Mesh VPN trên Headscale + official Tailscale Client).",
        "",
        *status,
        "",
        "## Cách dùng",
        "",
        f"- **Bản master**: [{MASTER_REL}]({MASTER_REL}) — nguồn sự thật duy nhất, gồm đủ 25 mục và phụ lục.",
        "- Các file còn lại được **trích sinh tự động** từ master. Quy trình sửa: sửa master → `python tools/split_plan.py` → commit cả master lẫn file sinh.",
        "- Không ghi mật khẩu, private key hay token vào bất kỳ file nào trong thư mục này.",
        "",
        "## Mục lục",
        "",
        "| Tài liệu | Nội dung (mục của master) |",
        "|---|---|",
        f"| [{MASTER_REL}]({MASTER_REL}) | Toàn bộ Implementation Master Plan |",
    ]
    for rel, title, specs in MAPPING:
        src = ", ".join(
            ("Rollback của §19" if s == "@rollback" else "§" + s.replace(":pre", ""))
            for s in specs
            if not s.startswith("-")
        )
        out.append(f"| [{rel}]({rel}) | {title} — {src} |")
    out.append(
        "| [planning/review-findings.md](planning/review-findings.md) | Bản ghi nguyên văn các phát hiện của vòng phản biện "
        "(không sinh từ master; tổng hợp và cách xử lý ở Appendix D) |"
    )
    conv = sections.get("conventions")
    if conv:
        out += ["", *strip_trailing_rule(conv.render())]
    return out


def main() -> int:
    if not MASTER.exists():
        print(f"master plan not found: {MASTER}", file=sys.stderr)
        return 2
    text = MASTER.read_text(encoding="utf-8")
    front, sections, order = parse(text)
    errors: list[str] = []
    used: set[str] = set()
    written: list[tuple[str, int]] = []
    for rel, title, specs in MAPPING:
        body = compose(specs, sections, errors, used)
        lines = header(title, rel, specs) + body
        path = DOCS / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        written.append((rel, len(lines)))
    readme_lines = readme(front, sections)
    (DOCS / "README.md").write_text("\n".join(readme_lines) + "\n", encoding="utf-8", newline="\n")
    written.append(("README.md", len(readme_lines)))

    # Coverage: every subsection (and every preamble with real content) of a numbered
    # section must appear in at least one topical file.
    for key in order:
        if key in MASTER_ONLY or key.startswith("x:"):
            if key.startswith("x:"):
                errors.append(f"unrecognised section heading: {sections[key].heading}")
            continue
        sec = sections[key]
        has_pre = any(l.strip() and l.strip() != "---" for l in sec.preamble)
        if has_pre and key + ":pre" not in used:
            errors.append(f"preamble of section {key} is not covered by any file")
        for sub_k, heading, _lines in sec.subs:
            if sub_k not in used:
                errors.append(f"subsection {sub_k} ({heading.strip()}) is not covered by any file")

    for rel, n in written:
        print(f"wrote docs/{rel} ({n} lines)")
    if errors:
        print("\nERRORS:", file=sys.stderr)
        for e in errors:
            print("  - " + e, file=sys.stderr)
        return 1
    print(f"\nOK: {len(written)} files generated from {MASTER.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
