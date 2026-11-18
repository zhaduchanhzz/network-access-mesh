"""The two G3 scenarios of P3-T14 (§19 Phase 3, §20 row P3-T14, §22.3 M3):

loop       N rounds (default 20) of: POST /platform/tenants (slug <prefix><tag>-<nn>) ⇒ job tenant.provision succeeded
           (19 steps, times per step from the job's steps) ⇒ tenant active, mg-hs-<slug> healthy, edge check of step 18
           again (prober RPC), orphan detector (P3-T07) — no NEW finding against the baseline taken before round 1 ⇒
           DELETE /platform/tenants/{id} (2P: A requests, A's self-approval refused, B approves) ⇒ job
           tenant.deprovision succeeded ⇒ tenant deleted ⇒ orphan detector again: no new finding. The first failing
           round stops the loop; its tenant is left as it is and the evidence kept (job views, findings, worker/agent
           logs since the round started). Statistics p50/p95/max per step over the rounds.
tenant-c   tenant C: create ⇒ two clients enrolled by the helper (P3-T14a, worker's registry) ⇒ allow fixture through
           the policy core ⇒ TCP c1→c2:8000 connects ⇒ suspend ⇒ blocked (no peer; listener answers locally) ⇒ resume ⇒
           connects again ⇒ deprovision (2P) ⇒ the clients lose the tenant, no new orphan.

Outputs (in --out): loop.json / tenant-c.json (everything measured), loop.md / tenant-c.md (tables ready for
docs/planning/evidence/P3-T14.md), rounds/ (job views, findings and redacted logs of a failed round).
"""
from __future__ import annotations

import json
import pathlib
import secrets
import time

import g3host
import g3stats
from g3clients import Client
from g3platform import Platform
from g3target import ROOT, G3Error, Target

ALLOW = ROOT / "infrastructure" / "headscale" / "templates" / "test-allow-intra.hujson"


def log(msg: str) -> None:
    print(f"[g3 {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def write(path: pathlib.Path, doc) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def _steps_brief(job: dict) -> str:
    return ", ".join(f"{s['name']}={s['status']}" for s in g3stats.job_steps(job) if s["status"] != "succeeded") or "mọi bước succeeded"


# ---------------------------------------------------------------------------------------------------- shared pieces
def provision(t: Target, pf: Platform, slug: str, owner_domain: str, timeout: float) -> dict:
    r, job = pf.create_tenant(slug, f"owner@{slug}.{owner_domain}")
    out = {"http": r.status, "job_id": job.get("id", ""), "tenant_id": job.get("tenant_id", "")}
    if r.status != 202 or not out["job_id"]:
        out.update(status=f"HTTP {r.status}", error=f"POST /platform/tenants ⇒ {r.status} {job.get('code', '')} "
                   f"{job.get('detail', '')}".strip())
        return out
    done = pf.wait_job(out["job_id"], timeout)
    out.update(status=done.get("status"), job=done, steps=g3stats.job_steps(done), timing=g3stats.job_timing(done),
               error_code=(done.get("error") or {}).get("code"))
    if done.get("status") != "succeeded":
        out["error"] = f"job {done.get('status')} ({out['error_code']}; {_steps_brief(done)})"
    return out


def deprovision(t: Target, pf: Platform, tenant_id: str, slug: str, timeout: float) -> dict:
    d = pf.deprovision(tenant_id, slug, f"G3 (P3-T14): kiểm thử vòng đời — {slug}")
    if not d.get("available"):
        return {"status": "unavailable", **d}
    if d.get("error"):
        return {"status": "refused", **d}
    done = pf.wait_job(d["job_id"], timeout)
    d.update(status=done.get("status"), job=done, steps=g3stats.job_steps(done), timing=g3stats.job_timing(done),
             error_code=(done.get("error") or {}).get("code"))
    if done.get("status") != "succeeded":
        d["error"] = f"job {done.get('status')} ({d['error_code']}; {_steps_brief(done)})"
    elif d.get("self_approval_status") != 403:
        d["error"] = f"người yêu cầu tự duyệt ⇒ HTTP {d.get('self_approval_status')} (cần 403)"
    return d


def orphan_delta(t: Target, scope: str, baseline: list[dict], settled: bool = True) -> dict:
    o = g3host.orphans(t, scope, settled)
    if o.get("error"):
        return o
    o["new"] = g3stats.new_findings(baseline, o["findings"])
    return o


def evidence(t: Target, out: pathlib.Path, label: str, since: float, doc: dict) -> None:
    d = out / "rounds" / label
    write(d / "round.json", doc)
    try:
        g3host.logs_since(t, t.worker_container(), since, d / "worker.log")
        g3host.logs_since(t, t.cfg["agent_container"], since, d / "agent.log")
    except G3Error as e:
        (d / "logs-error.txt").write_text(t.redact(str(e)), encoding="utf-8")


# ---------------------------------------------------------------------------------------------------- loop
def run_loop(t: Target, pf: Platform, out: pathlib.Path, n: int, prefix: str, owner_domain: str, timeout: float,
             require_deprovision: bool = True) -> int:
    tag = secrets.token_hex(2)
    meta = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "env": t.env_file.name, "domain": t.domain,
            "rounds_planned": n, "slug_prefix": prefix, "tag": tag, "target": {k: v for k, v in t.cfg.items()
                                                                                  if "docker" not in k}}
    log(f"G3 loop: {n} vòng, slug {g3stats.round_slug(prefix, tag, 1)} … ({t.env_file.name}, {t.domain})")
    pf.a.fresh()
    pf.b.fresh()
    base = g3host.orphans(t, prefix)
    if base.get("error"):
        raise G3Error("bộ phát hiện mồ côi (baseline) lỗi: " + base["error"])
    meta["baseline"] = base
    log(f"baseline mồ côi (phạm vi {prefix}*): {len(base['findings'])} finding — {base.get('summary', '')}")
    rounds: list[dict] = []
    doc = {"meta": meta, "rounds": rounds}
    stop = ""
    for i in range(1, n + 1):
        slug = g3stats.round_slug(prefix, tag, i)
        t0 = time.time()
        r: dict = {"n": i, "slug": slug, "started": t0, "ok": False}
        rounds.append(r)
        log(f"── vòng {i}/{n}: {slug}")
        p = provision(t, pf, slug, owner_domain, timeout)
        r["provision"] = p
        r["tenant_id"] = p.get("tenant_id", "")
        if p.get("error"):
            r["error"] = "provision: " + p["error"]
        else:
            tenant = pf.tenant(r["tenant_id"])
            r["tenant_status"] = tenant.get("status")
            r["instance_health"] = g3host.instance_health(t, slug)
            r["edge"] = g3host.edge_check(t, slug)
            r["orphans_after_provision"] = orphan_delta(t, prefix, base["findings"])
            o1 = r["orphans_after_provision"]
            log(f"  provision {p['status']} {g3stats.fmt_s(p['timing']['total_s'])} s; tenant {r['tenant_status']}; "
                f"{slug} {r['instance_health']}; edge {r['edge']['summary']}; mồ côi mới "
                f"{len(o1.get('new') or []) if not o1.get('error') else 'lỗi'}")
            if r["tenant_status"] != "active" or r["instance_health"] != "healthy" or not r["edge"]["ok"]:
                r["error"] = f"sau provision: tenant {r['tenant_status']}, instance {r['instance_health']}, edge {r['edge']['summary']}"
            elif o1.get("error") or o1.get("new"):
                r["error"] = "mồ côi sau provision: " + (o1.get("error") or "; ".join(g3stats.finding_key(f) for f in o1["new"]))
        if not r.get("error"):
            d = deprovision(t, pf, r["tenant_id"], slug, timeout)
            r["deprovision"] = d
            if d["status"] == "unavailable":
                r["error"] = d["error"]
                if require_deprovision:
                    stop = "deprovision chưa có (P3-T09) — dừng: không gỡ thì trần quota.max_tenants chặn các vòng sau"
            elif d.get("error"):
                r["error"] = "deprovision: " + d["error"]
            else:
                tenant = pf.tenant(r["tenant_id"])
                r["tenant_status_after"] = tenant.get("status")
                r["orphans_after_deprovision"] = orphan_delta(t, prefix, base["findings"])
                o2 = r["orphans_after_deprovision"]
                log(f"  deprovision {d['status']} {g3stats.fmt_s(d['timing']['total_s'])} s (2P: tự duyệt ⇒ "
                    f"{d.get('self_approval_status')}, B duyệt ⇒ {d.get('approve_status')}); tenant {r['tenant_status_after']}; "
                    f"mồ côi mới {len(o2.get('new') or []) if not o2.get('error') else 'lỗi'}")
                if r["tenant_status_after"] != "deleted":
                    r["error"] = f"sau deprovision: tenant {r['tenant_status_after']}"
                elif o2.get("error") or o2.get("new"):
                    r["error"] = "mồ côi sau deprovision: " + (o2.get("error") or "; ".join(g3stats.finding_key(f) for f in o2["new"]))
        r["duration_s"] = round(time.time() - t0, 1)
        r["ok"] = not r.get("error")
        write(out / "loop.json", doc)
        if not r["ok"]:
            log(f"  FAIL vòng {i}: {r['error']} — dừng, giữ chứng cứ trong {out / 'rounds' / slug}")
            evidence(t, out, slug, t0 - 5, r)
            stop = stop or f"vòng {i} lỗi"
            break
        log(f"  PASS vòng {i} ({r['duration_s']} s)")
    meta["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    meta["stopped"] = stop
    passed = sum(1 for r in rounds if r["ok"])
    doc["stats"] = {"provision": g3stats.step_stats([r["provision"]["job"] for r in rounds if r["ok"]]),
                    "deprovision": g3stats.step_stats([r["deprovision"]["job"] for r in rounds if r["ok"]])}
    doc["result"] = {"passed": passed, "planned": n, "ok": passed == n and not stop}
    write(out / "loop.json", doc)
    (out / "loop.md").write_text(loop_markdown(doc), encoding="utf-8")
    log(f"G3 loop: {passed}/{n} vòng PASS{' — ' + stop if stop else ''}; bảng: {out / 'loop.md'}")
    return 0 if doc["result"]["ok"] else 1


def loop_markdown(doc: dict) -> str:
    m, res = doc["meta"], doc.get("result", {})
    lines = [f"### Vòng lặp provision — {res.get('passed', 0)}/{res.get('planned', m['rounds_planned'])} vòng PASS",
             "", f"- Môi trường: `{m['env']}` (`{m['domain']}`), {m['started']} → {m.get('finished', '?')} (UTC); slug "
             f"`{m['slug_prefix']}{m['tag']}-NN`", f"- Baseline bộ phát hiện mồ côi (phạm vi `{m['slug_prefix']}*`, trước "
             f"vòng 1): {len(m['baseline']['findings'])} finding — {m['baseline'].get('summary', '')}"]
    if m.get("stopped"):
        lines.append(f"- **Dừng:** {m['stopped']}")
    lines += ["", g3stats.rounds_table(doc["rounds"]), g3stats.stats_table("tenant.provision", doc["stats"]["provision"]),
              g3stats.stats_table("tenant.deprovision", doc["stats"]["deprovision"])]
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------------- tenant C
def run_tenant_c(t: Target, pf: Platform, out: pathlib.Path, slug: str, owner_domain: str, timeout: float,
                 keep: bool = False) -> int:
    rows: list[tuple[str, bool, str]] = []
    doc: dict = {"meta": {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "env": t.env_file.name,
                          "domain": t.domain, "slug": slug, "client_docker": " ".join(t.client_docker[:1]),
                          "same_host": t.client_docker == t.host_docker}, "steps": rows}
    t0 = time.time()

    def step(name: str, ok: bool, detail: str) -> bool:
        rows.append((name, ok, detail))
        log(f"{'PASS' if ok else 'FAIL'} {name} — {detail}")
        write(out / "tenant-c.json", doc)
        return ok

    clients = [Client(t, "c1", slug), Client(t, "c2", slug)]
    vol = t.name("enroll")
    enrolled = False
    tenant_id = ""
    try:
        pf.a.fresh()
        pf.b.fresh()
        base = g3host.orphans(t, slug)
        doc["baseline"] = base
        p = provision(t, pf, slug, owner_domain, timeout)
        doc["provision"] = p
        tenant_id = p.get("tenant_id", "")
        if not step("1 tạo tenant C (POST /platform/tenants → tenant.provision)", not p.get("error"),
                    f"job {p.get('status')} {g3stats.fmt_s((p.get('timing') or {}).get('total_s'))} s; "
                    f"{p.get('error', '')}"):
            raise G3Error(p.get("error", ""))
        health, edge = g3host.instance_health(t, slug), g3host.edge_check(t, slug)
        step("1b instance healthy + edge (bước 18)", health == "healthy" and edge["ok"], f"mg-hs-{slug} {health}; {edge['summary']}")

        # 2 — enrollment helper (P3-T14a) over the worker's registry: two one-time keys, two clients
        g3host.ensure_image(t, t.images["tailscale"], client=True)
        g3host.ensure_image(t, t.images["alpine"])
        t.hd("volume", "rm", "-f", vol, check=False)
        t.hd("volume", "create", "--label", "meshguard.role=g3", vol)
        t.hd("run", "--rm", "--network", "none", "-v", f"{vol}:/g3", t.images["alpine"], "sh", "-ec",
             "mkdir -p /g3/state; chown 65532:65532 /g3 /g3/state; chmod 0700 /g3 /g3/state")
        env = {"MG_G3_TENANT": tenant_id, "MG_G3_ENROLL_USER": "g3-tenant-c", "MG_G3_STATE_DIR": "/g3/state",
               "MG_G3_KEY_DIR": "/g3/keys", "MG_G3_ENROLL_COUNT": "2", "MG_G3_HOSTS": "c1,c2"}
        rc, issued, outp = g3host.hostside(t, "enroll-issue", env, mounts=[f"{vol}:/g3"])
        enrolled = rc == 0
        keys = issued.get("issued") or []
        if not step("2a helper: user + 2 pre-auth key một lần (≤ 15 phút) qua adapter + registry của worker",
                    rc == 0 and len(keys) == 2,
                    "; ".join(f"key #{k['key_id']} {k['key_prefix']}… hết hạn {k['expiration']}" for k in keys)
                    or outp[-300:]):
            raise G3Error("enroll-issue")
        for c, k in zip(clients, keys):
            c.remove()
            c.start()
            c.push_key(vol, f"keys/{k['file']}")
        ups = [c.up() for c in clients]
        rc, ver, outp = g3host.hostside(t, "enroll-verify", env, mounts=[f"{vol}:/g3"])
        nodes = ver.get("nodes") or []
        if not step("2b hai client join (tailscale up --auth-key=file:…), node đăng ký bằng đúng key, key đã dùng; file key xóa",
                    all(u[0] == 0 for u in ups) and rc == 0 and len(nodes) == 2,
                    "; ".join(f"{n['host']} node #{n['node_id']} key #{n['key_id']} {n['register_method']} used={n['key_used']}"
                              for n in nodes) + (f" — up {[u[0] for u in ups]} {ver.get('errors') or outp[-200:]}" if rc else "")):
            raise G3Error("enroll-verify")

        # 3 — allow fixture through the policy core, TCP c1 → c2:8000
        code, res, err = g3host.policy_apply(t, slug, ALLOW.read_text(encoding="utf-8"))
        step("3a áp fixture allow (test-allow-intra) qua lõi policy", code == 0 and res.get("state") == "applied",
             f"exit {code} {res.get('state')} version {res.get('version')} {err if code else ''}")
        c1, c2 = clients
        c2.listen()
        peers = c1.wait_peers(1)
        ip2 = c2.ip4()
        ans = c1.tcp(ip2)
        if not step("3b TCP c1→c2:8000 thông", peers == 1 and ans.endswith(f"c2 tcp/{8000}"),
                    f"c1 peers {peers}; c2 {ip2}; trả lời {ans or 'không kết nối'}"):
            raise G3Error("tcp")

        # 4 — suspend ⇒ blocked
        r, job = pf.lifecycle(tenant_id, "suspend")
        done = pf.wait_job(job.get("id", ""), timeout) if r.status == 202 else {"status": f"HTTP {r.status}"}
        doc["suspend"] = done
        step("4a suspend (POST /platform/tenants/{id}/suspend)", done.get("status") == "succeeded",
             f"HTTP {r.status}, job {done.get('status')} {g3stats.fmt_s(g3stats.job_timing(done)['total_s']) if done.get('steps') else ''} s")
        peers = c1.wait_peers(0)
        ans, local = c1.tcp(ip2), c2.local()
        step("4b suspend ⇒ TCP bị chặn (listener vẫn trả lời cục bộ)", peers == 0 and ans == "" and local.endswith("tcp/8000"),
             f"c1 peers {peers}; tcp {ans or 'không kết nối'}; cục bộ trên c2: {local or 'không'}")
        st = pf.tenant(tenant_id).get("status")

        # 5 — resume ⇒ connects again
        r, job = pf.lifecycle(tenant_id, "resume")
        done = pf.wait_job(job.get("id", ""), timeout) if r.status == 202 else {"status": f"HTTP {r.status}"}
        doc["resume"] = done
        step("5a resume", done.get("status") == "succeeded" and st == "suspended",
             f"tenant lúc suspend: {st}; HTTP {r.status}, job {done.get('status')}")
        peers = c1.wait_peers(1)
        ans = c1.tcp(c2.ip4())
        step("5b resume ⇒ TCP thông lại", peers == 1 and ans.endswith("tcp/8000"), f"c1 peers {peers}; trả lời {ans or 'không kết nối'}")

        # 6 — deprovision (2P)
        d = deprovision(t, pf, tenant_id, slug, timeout)
        doc["deprovision"] = d
        step("6a deprovision qua 2P (A yêu cầu, A tự duyệt ⇒ 403, B duyệt ⇒ job)", d.get("status") == "succeeded"
             and not d.get("error"), f"DELETE {d.get('request_status')}, tự duyệt {d.get('self_approval_status')}, "
             f"B duyệt {d.get('approve_status')}, job {d.get('status')} {d.get('error', '')}")
        if d.get("status") == "succeeded":
            enrolled = False                       # the instance and its users/keys are gone with the tenant
            st = pf.tenant(tenant_id).get("status")
            ans = c1.tcp(ip2, wait_s=5)
            o = orphan_delta(t, slug, base.get("findings") or [])
            doc["orphans_after_deprovision"] = o
            step("6b tenant deleted, client mất tenant (TCP không còn), không còn mồ côi mới (container, network, thư mục, secret, API key)",
                 st == "deleted" and not ans.endswith("tcp/8000") and not o.get("error") and not o.get("new"),
                 f"tenant {st}; tcp sau deprovision {ans or 'không kết nối'}; mồ côi mới "
                 f"{o.get('error') or [g3stats.finding_key(f) for f in o.get('new') or []] or 0}")
    except G3Error as e:
        step("dừng", False, t.redact(str(e))[-400:])
        evidence(t, out, f"tenant-c-{slug}", t0 - 5, doc)
    finally:
        for c in clients:
            if not keep:
                c.remove()
        if enrolled:
            g3host.hostside(t, "enroll-cleanup", {"MG_G3_TENANT": tenant_id, "MG_G3_ENROLL_USER": "g3-tenant-c",
                                                  "MG_G3_STATE_DIR": "/g3/state"}, mounts=[f"{vol}:/g3"])
        t.hd("volume", "rm", "-f", vol, check=False)
    ok = bool(rows) and all(r[1] for r in rows)
    doc["result"] = {"ok": ok, "passed": sum(1 for r in rows if r[1]), "total": len(rows),
                     "duration_s": round(time.time() - t0, 1)}
    write(out / "tenant-c.json", doc)
    (out / "tenant-c.md").write_text(tenant_c_markdown(doc), encoding="utf-8")
    log(f"tenant C: {doc['result']['passed']}/{len(rows)} bước PASS ({doc['result']['duration_s']} s); bảng: {out / 'tenant-c.md'}")
    return 0 if ok else 1


def tenant_c_markdown(doc: dict) -> str:
    m = doc["meta"]
    label = ("functional — client cùng host Docker với Headscale (HS-24)" if m.get("same_host")
             else "client trên host khác host Headscale")
    lines = [f"### E2E tenant C (`{m['slug']}`) — {doc['result']['passed']}/{doc['result']['total']} bước PASS", "",
             f"- Môi trường `{m['env']}` (`{m['domain']}`), {m['started']} UTC, {doc['result']['duration_s']} s; nhãn: {label}",
             "", "| Bước | Kết quả | Chi tiết |", "|---|---|---|"]
    for name, ok, detail in doc["steps"]:
        lines.append(f"| {name} | {'PASS' if ok else '**FAIL**'} | {detail.replace('|', '/')} |")
    return "\n".join(lines) + "\n"
