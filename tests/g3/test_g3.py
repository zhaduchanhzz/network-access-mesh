#!/usr/bin/env python3
"""Self-test of the G3 tool without Docker or network (P3-T14): timestamps and step durations of a job view,
nearest-rank percentiles, per-step statistics, the Markdown tables, the orphan baseline difference, round slugs, the
credential file (location, mode, TOTP forms) and the target (environment file, placeholders, unknown keys). Run in CI
(ci.yml). Standard library only.

    python3 tests/g3/test_g3.py
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import g3stats as s  # noqa: E402
import g3scenarios  # noqa: E402
from g3target import ROOT, G3Error, Target, load_creds  # noqa: E402

failures = 0
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8")


def check(ok: bool, name: str, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'} {name}{'' if ok or not detail else ' — ' + str(detail)}")
    failures += 0 if ok else 1


def raises(fn, name: str, exc=(G3Error, ValueError)) -> None:
    try:
        fn()
    except exc:
        check(True, name)
    else:
        check(False, name, "no error")


def job(created: str, steps: list[tuple[str, str, str | None, str | None]], status: str = "succeeded") -> dict:
    return {"id": "j", "status": status, "created_at": created,
            "steps": [{"name": n, "status": st, "attempt": 1 if a else 0, "started_at": a, "finished_at": b}
                      for n, st, a, b in steps]}


# ---- timestamps
check(s.parse_ts("2026-11-18T10:00:00Z").timestamp() == s.parse_ts("2026-11-18T17:00:00+07:00").timestamp(),
      "parse_ts: Z and offset")
check(s.seconds(s.parse_ts("2026-11-18T10:00:00.1Z"), s.parse_ts("2026-11-18T10:00:01.123456789Z")) == 1.023,
      "parse_ts: fractions of any length (nanoseconds cut to microseconds)")
check(s.parse_ts(None) is None and s.parse_ts("") is None, "parse_ts: null")
raises(lambda: s.parse_ts("18/11/2026 10:00"), "parse_ts: not RFC 3339 ⇒ error")

# ---- job view → step rows and timings
J1 = job("2026-11-18T10:00:00Z", [("validate", "succeeded", "2026-11-18T10:00:00Z", "2026-11-18T10:00:00.010Z"),
                                  ("registry.create", "succeeded", "2026-11-18T10:00:00.010Z", "2026-11-18T10:00:00.020Z"),
                                  ("placement.allocate", "succeeded", "2026-11-18T10:00:02Z", "2026-11-18T10:00:02.5Z"),
                                  ("instance.start", "succeeded", "2026-11-18T10:00:02.5Z", "2026-11-18T10:00:07Z")])
rows = s.job_steps(J1)
check([r["name"] for r in rows] == ["validate", "registry.create", "placement.allocate", "instance.start"]
      and rows[2]["duration_s"] == 0.5 and rows[3]["duration_s"] == 4.5, "job_steps: order and durations", rows)
tm = s.job_timing(J1)
check(tm == {"total_s": 7.0, "queue_s": 2.0, "steps_s": 7.0}, "job_timing: total, queue (first step of the worker)", tm)
J_skip = job("2026-11-18T10:00:00Z", [("validate", "skipped", None, None), ("placement.allocate", "running",
                                                                            "2026-11-18T10:00:01Z", None)], "running")
check(s.job_steps(J_skip)[0]["duration_s"] is None and s.job_steps(J_skip)[1]["duration_s"] is None,
      "job_steps: skipped / running steps have no duration")

# ---- percentiles (nearest rank)
v20 = list(range(1, 21))
check(s.nearest_rank(v20, 50) == 10 and s.nearest_rank(v20, 95) == 19 and s.nearest_rank(v20, 100) == 20,
      "nearest_rank: n=20 ⇒ p50 = 10th, p95 = 19th, p100 = max")
check(s.nearest_rank([3.0], 95) == 3.0 and s.nearest_rank([], 50) is None, "nearest_rank: one value / none")
check(s.nearest_rank([5, 1, 4, 2, 3], 50) == 3, "nearest_rank: unsorted input")
raises(lambda: s.nearest_rank([1], 0), "nearest_rank: pct 0 ⇒ error")
check(s.summarize([2.0, None, 1.0]) == {"n": 2, "p50": 1.0, "p95": 2.0, "max": 2.0}, "summarize: None ignored")

# ---- step statistics over rounds
J2 = job("2026-11-18T11:00:00Z", [("validate", "succeeded", "2026-11-18T11:00:00Z", "2026-11-18T11:00:00.010Z"),
                                  ("registry.create", "succeeded", "2026-11-18T11:00:00.010Z", "2026-11-18T11:00:00.020Z"),
                                  ("placement.allocate", "succeeded", "2026-11-18T11:00:01Z", "2026-11-18T11:00:02Z"),
                                  ("instance.start", "succeeded", "2026-11-18T11:00:02Z", "2026-11-18T11:00:12Z"),
                                  ("activate", "succeeded", "2026-11-18T11:00:12Z", "2026-11-18T11:00:12.5Z")])
st = s.step_stats([J1, J2])
names = [n for n, _ in st["steps"]]
start = dict(st["steps"])["instance.start"]
check(names == ["validate", "registry.create", "placement.allocate", "instance.start", "activate"],
      "step_stats: steps in order of first appearance", names)
check(start == {"n": 2, "p50": 4.5, "p95": 10.0, "max": 10.0} and st["total"]["max"] == 12.5 and st["total"]["n"] == 2,
      "step_stats: per-step and total summaries", (start, st["total"]))
md = s.stats_table("tenant.provision", st)
check("| 4 `instance.start` | 2 | 4.50 | 10.00 | 10.00 |" in md and "**Cả job**" in md and md.count("\n|") >= 7,
      "stats_table: Markdown rows", md)

# ---- orphan baseline difference
base = [{"kind": "directory_foreign", "subject": "tenant-a"}]
now = base + [{"kind": "secret_orphan", "subject": "x#2", "detail": "d"}]
check(s.new_findings(base, now) == [{"kind": "secret_orphan", "subject": "x#2", "detail": "d"}] and s.new_findings(now, base) == [],
      "new_findings: only what the run added")

# ---- slugs
check(s.round_slug("g3-", "ab12", 7) == "g3-ab12-07" and s.round_slug("g3drv-", "0f0f", 20) == "g3drv-0f0f-20",
      "round_slug: <prefix><tag>-<nn>")
raises(lambda: s.round_slug("G3-", "ab", 1), "round_slug: upper case ⇒ error")
raises(lambda: s.round_slug("g3-", "a" * 40, 1), "round_slug: longer than 32 ⇒ error")
raises(lambda: s.round_slug("g3--", "ab", 1), "round_slug: '--' ⇒ error")

# ---- report rendering (no I/O)
doc = {"meta": {"env": "ci.env", "domain": "meshguard-ci.test", "started": "t0", "finished": "t1", "slug_prefix": "g3-",
                "tag": "ab12", "rounds_planned": 2, "baseline": {"findings": base, "summary": "x"}, "stopped": ""},
       "rounds": [{"n": 1, "slug": "g3-ab12-01", "ok": True, "provision": {"status": "succeeded", "timing": {"total_s": 7.0}},
                   "instance_health": "healthy", "edge": {"summary": "/key 200, 22/22", "ok": True},
                   "orphans_after_provision": {"new": []}, "deprovision": {"status": "succeeded", "timing": {"total_s": 3.0}},
                   "orphans_after_deprovision": {"new": []}},
                  {"n": 2, "slug": "g3-ab12-02", "ok": False, "error": "provision: job rolled_back",
                   "provision": {"status": "rolled_back", "timing": {"total_s": 9.0}}}],
       "stats": {"provision": st, "deprovision": s.step_stats([])}, "result": {"passed": 1, "planned": 2}}
lm = g3scenarios.loop_markdown(doc)
check("1/2 vòng PASS" in lm and "| 1 | `g3-ab12-01` | succeeded | 7.00 | healthy |" in lm and "**FAIL** provision: job rolled_back" in lm,
      "loop_markdown: rounds and statistics", lm[:400])
tc = g3scenarios.tenant_c_markdown({"meta": {"slug": "g3-c-ab12", "env": "ci.env", "domain": "d", "started": "t",
                                             "same_host": True}, "steps": [("1 tạo", True, "a|b"), ("2", False, "x")],
                                    "result": {"passed": 1, "total": 2, "duration_s": 3.0}})
check("1/2 bước PASS" in tc and "functional" in tc and "a/b" in tc and "**FAIL**" in tc, "tenant_c_markdown", tc)

# ---- credential file
with tempfile.TemporaryDirectory() as d:
    f = pathlib.Path(d) / "creds.json"
    b32 = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    f.write_text(json.dumps({"super_admins": [{"username": "sa1", "password": "p1", "totp_base32": b32.lower()},
                                              {"username": "sa2", "password": "p2", "totp_raw": "rawsecret"}]}), encoding="utf-8")
    os.chmod(f, 0o600)
    t = Target(ROOT / "infrastructure" / "environments" / "ci" / "ci.env", {"connect": "192.0.2.1"})
    c = load_creds(f, t)
    check(c[0]["totp_key"] == b"12345678901234567890" and c[1]["totp_key"] == b"rawsecret",
          "load_creds: totp_base32 (lower case, no padding) and totp_raw")
    check({"p1", "p2", "rawsecret"} <= t.secret_values and "p1" not in t.redact("x p1 y"), "load_creds: values redacted")
    if os.name == "posix":
        os.chmod(f, 0o644)
        raises(lambda: load_creds(f), "load_creds: group/other readable ⇒ error")
        os.chmod(f, 0o600)
    f.write_text(json.dumps({"super_admins": [{"username": "sa1", "password": "p", "totp_raw": "x"}]}), encoding="utf-8")
    raises(lambda: load_creds(f), "load_creds: one Super Admin ⇒ error (dual control needs two)")
    f.write_text(json.dumps({"super_admins": [{"username": "sa", "password": "p", "totp_raw": "x"},
                                              {"username": "sa", "password": "q", "totp_raw": "y"}]}), encoding="utf-8")
    raises(lambda: load_creds(f), "load_creds: the same person twice ⇒ error")
    f.write_text(json.dumps({"super_admins": [{"username": "a", "password": "p", "totp_base32": "!!"},
                                              {"username": "b", "password": "q", "totp_raw": "y"}]}), encoding="utf-8")
    raises(lambda: load_creds(f), "load_creds: TOTP not Base32 ⇒ error")
raises(lambda: load_creds(ROOT / "config" / "secrets" / "staging" / "g3.json"), "load_creds: inside config/secrets/ ⇒ refused",
       (G3Error,))

# ---- target
env_ci = ROOT / "infrastructure" / "environments" / "ci" / "ci.env"
t = Target(env_ci, {"connect": "192.0.2.1", "host_docker": "ssh h@${MG_TENANT_NAMESERVERS} sudo -n docker"})
check(t.domain == "meshguard-ci.test" and t.host_docker[-3:] == ["sudo", "-n", "docker"] and t.host_docker[1] == "h@192.0.2.53"
      and t.client_docker == t.host_docker and t.edge_ip == "192.0.2.1", "Target: environment file, placeholders, client = host by default")
check(t.cfg["tenants_dir"] == "/opt/meshguard/tenants" and t.cfg["edge_container"] == "mg-edge" and t.name("bin") == "g3-bin",
      "Target: host layout defaults (layout.sh, compose projects)")
cmd = t.host_cmd("run", "--rm", "alpine", "sh", "-ec", "cat > /out/x; chmod 0755 /out/x")
check(cmd[:4] == ["ssh", "h@192.0.2.53", "sudo", "-n"] and cmd[-1] == "'cat > /out/x; chmod 0755 /out/x'" and cmd[-2] == "-ec",
      "Target: through ssh each docker argument is quoted (the remote shell must not apply the redirection)")
local = Target(env_ci, {"connect": "192.0.2.1", "host_docker": "sudo -n docker"})
check(local.host_cmd("sh", "-ec", "a > b")[-1] == "a > b", "Target: local docker arguments are passed unquoted")
raises(lambda: Target(env_ci, {"nope": 1}), "Target: unknown key ⇒ error")
raises(lambda: Target(env_ci, {"connect": "${MG_NOT_THERE}"}), "Target: unknown placeholder ⇒ error")
raises(lambda: Target(env_ci, {}), "Target: no connect address (ci.env has no MG_LAN_IPV4) ⇒ error")
staging = ROOT / "infrastructure" / "environments" / "staging" / "staging.env"
ts = Target(staging)
check(ts.edge_ip and ts.edge_ip == ts.env["MG_LAN_IPV4"] and ts.domain == ts.env["MG_BASE_DOMAIN"],
      "Target: staging connects LAN-direct to MG_LAN_IPV4 of staging.env (no literal address in the tool)")
src = "\n".join(p.read_text(encoding="utf-8") for p in sorted(HERE.glob("*.py")) if p.name != "test_g3.py")
check(ts.env["MG_LAN_IPV4"] not in src and ts.env["MG_BASE_DOMAIN"] not in src and ts.env["MG_PUBLIC_IPV4"] not in src,
      "tool source: no IP or domain of staging written in code")
sys.exit(1 if failures else 0)
