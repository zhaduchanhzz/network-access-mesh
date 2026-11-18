"""Pure part of the G3 tool (P3-T14): parse the steps of a job (GET /platform/jobs/{id}), per-step durations, p50/p95/max
over the rounds, the Markdown tables of the evidence file, the orphan-finding difference against a baseline, the slug of
a round. No I/O, no Docker — unit-tested by tests/g3/test_g3.py (CI: ci.yml). Standard library only.

Percentiles are the nearest-rank kind (no interpolation): pXX of n sorted values is the value at rank ceil(XX/100 * n)
— always one of the measured values; with n = 20, p50 = the 10th value and p95 = the 19th.
"""
from __future__ import annotations

import datetime as dt
import math
import re

SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")      # TenantSlug of api/openapi.yaml (no "--")
FINISHED = ("succeeded", "failed", "failed_resumable", "rolled_back", "cancelled")


def parse_ts(value: str | None) -> dt.datetime | None:
    """RFC 3339 of the API (…Z or ±hh:mm, optional fraction of any length) → aware datetime; None/'' → None."""
    if not value:
        return None
    v = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?([+-]\d{2}:\d{2})", v)
    if not m:
        raise ValueError(f"not an RFC 3339 timestamp: {value!r}")
    frac = (m.group(2) or ".0")[1:7].ljust(6, "0")             # Python takes at most microseconds
    return dt.datetime.fromisoformat(f"{m.group(1).replace(' ', 'T')}.{frac}{m.group(3)}")


def seconds(a: dt.datetime | None, b: dt.datetime | None) -> float | None:
    return None if a is None or b is None else round((b - a).total_seconds(), 3)


def job_steps(job: dict) -> list[dict]:
    """The steps of a job view as rows {name, status, attempt, duration_s}; duration = finished_at - started_at (None
    while running or for a step that never started — skipped steps 1–2 of a retry)."""
    rows = []
    for s in job.get("steps") or []:
        rows.append({"name": str(s.get("name", "")), "status": str(s.get("status", "")), "attempt": int(s.get("attempt") or 0),
                     "duration_s": seconds(parse_ts(s.get("started_at")), parse_ts(s.get("finished_at")))})
    return rows


def job_timing(job: dict) -> dict:
    """Wall times of a job: total = last finished_at - created_at; queue = first started_at of a step run by the
    worker (attempt > 0, not steps 1–2 done by the api in the request) - created_at."""
    created = parse_ts(job.get("created_at"))
    starts = [parse_ts(s.get("started_at")) for s in job.get("steps") or [] if s.get("started_at")]
    ends = [parse_ts(s.get("finished_at")) for s in job.get("steps") or [] if s.get("finished_at")]
    worker_starts = [parse_ts(s.get("started_at")) for s in job.get("steps") or []
                     if s.get("started_at") and s.get("name") not in ("validate", "registry.create")]
    return {"total_s": seconds(created, max(ends)) if ends else None,
            "queue_s": seconds(created, min(worker_starts)) if worker_starts else None,
            "steps_s": seconds(min(starts), max(ends)) if starts and ends else None}


def nearest_rank(values: list[float], pct: float) -> float | None:
    """Nearest-rank percentile (0 < pct ≤ 100) of the values; None when there are none."""
    if not values:
        return None
    if not 0 < pct <= 100:
        raise ValueError("pct must be in (0, 100]")
    ordered = sorted(values)
    return ordered[max(1, math.ceil(pct / 100 * len(ordered))) - 1]


def summarize(values: list[float]) -> dict:
    vals = [float(v) for v in values if v is not None]
    return {"n": len(vals), "p50": nearest_rank(vals, 50), "p95": nearest_rank(vals, 95), "max": max(vals) if vals else None}


def step_stats(jobs: list[dict]) -> dict:
    """{"steps": [(name, summary)] in the order of the first job, then names seen later; "total": summary of the job
    totals; "queue": summary of the queue waits} over the views of finished jobs."""
    order: list[str] = []
    per: dict[str, list[float]] = {}
    totals, queues = [], []
    for job in jobs:
        for row in job_steps(job):
            if row["name"] not in per:
                order.append(row["name"])
                per[row["name"]] = []
            if row["duration_s"] is not None:
                per[row["name"]].append(row["duration_s"])
        t = job_timing(job)
        totals.append(t["total_s"])
        queues.append(t["queue_s"])
    return {"steps": [(n, summarize(per[n])) for n in order], "total": summarize(totals), "queue": summarize(queues)}


def fmt_s(v: float | None) -> str:
    return "—" if v is None else f"{v:.2f}"


def stats_table(title: str, stats: dict) -> str:
    """Markdown table: one row per step + the job total and the queue wait (seconds, nearest-rank)."""
    lines = [f"**{title}** (giây; p50/p95 nearest-rank)", "", "| Bước | n | p50 | p95 | max |", "|---|---|---|---|---|"]
    for i, (name, s) in enumerate(stats["steps"], 1):
        lines.append(f"| {i} `{name}` | {s['n']} | {fmt_s(s['p50'])} | {fmt_s(s['p95'])} | {fmt_s(s['max'])} |")
    for label, key in (("**Cả job** (created_at → bước cuối xong)", "total"), ("Chờ hàng đợi (created_at → bước đầu ở worker)", "queue")):
        s = stats[key]
        lines.append(f"| {label} | {s['n']} | {fmt_s(s['p50'])} | {fmt_s(s['p95'])} | {fmt_s(s['max'])} |")
    return "\n".join(lines) + "\n"


def finding_key(f: dict) -> str:
    return f"{f.get('kind', '')} {f.get('subject', '')}"


def new_findings(baseline: list[dict], now: list[dict]) -> list[dict]:
    """Findings of `now` that were not in the baseline (kind + subject). The orphan detector judges every entry of the
    tenants directory, and a host shared with tenants built before the run (A/B) may carry findings that are not the
    run's: the run is judged by what it ADDS, the baseline is reported on its own."""
    seen = {finding_key(f) for f in baseline}
    return [f for f in now if finding_key(f) not in seen]


def round_slug(prefix: str, tag: str, n: int) -> str:
    """Slug of round n: <prefix><tag>-<nn> (e.g. g3-k7q2-01). Raises when it is not a valid TenantSlug."""
    slug = f"{prefix}{tag}-{n:02d}"
    if not SLUG_RE.match(slug) or "--" in slug:
        raise ValueError(f"slug {slug!r} không hợp lệ (TenantSlug: ^[a-z][a-z0-9-]{{1,30}}[a-z0-9]$, không '--')")
    return slug


def rounds_table(rounds: list[dict]) -> str:
    """One row per round: slug, provisioning (status, total), healthy, edge check, new orphans after the provisioning,
    deprovision (status, total), new orphans at the end, result."""
    lines = ["| Vòng | Slug | Provision | Tổng (s) | Instance | Edge (bước 18) | Mồ côi mới sau provision | Deprovision | "
             "Tổng (s) | Mồ côi mới cuối vòng | Kết quả |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rounds:
        p, d = r.get("provision") or {}, r.get("deprovision") or {}
        lines.append("| {n} | `{slug}` | {ps} | {pt} | {h} | {e} | {o1} | {ds} | {dt_} | {o2} | {res} |".format(
            n=r.get("n"), slug=r.get("slug"), ps=p.get("status", "—"), pt=fmt_s((p.get("timing") or {}).get("total_s")),
            h=r.get("instance_health", "—"), e=r.get("edge", {}).get("summary", "—") if r.get("edge") else "—",
            o1=_count(r.get("orphans_after_provision")), ds=d.get("status", "—"),
            dt_=fmt_s((d.get("timing") or {}).get("total_s")), o2=_count(r.get("orphans_after_deprovision")),
            res="**PASS**" if r.get("ok") else f"**FAIL** {r.get('error', '')}".strip()))
    return "\n".join(lines) + "\n"


def _count(o: dict | None) -> str:
    if not o:
        return "—"
    if o.get("error"):
        return "lỗi: " + str(o["error"])[:60]
    return str(len(o.get("new") or []))
