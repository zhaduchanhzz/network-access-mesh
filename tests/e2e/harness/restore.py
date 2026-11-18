"""V-11 on the dev/CI stack (P3-T11, §17.4 "Mất Noise key", §22.4 V-11) — FUNCTIONAL measurements with real clients.

  E2E-59  restore of an OLDER snapshot of tenant-a (same Noise key — what a restore from a backup does): a cold
          snapshot of data/, then a node and a pre-auth key created after it, then the snapshot restored in place
          (Headscale stopped, data/ replaced, started): the two official clients registered before the snapshot
          reconnect WITHOUT a new login — same node id and machine key, Headscale sees both online again, each client
          sees the other — time measured; the node and the pre-auth key created after the snapshot are gone (a device
          registered after a backup must enroll again — §17.2 step 7)
  E2E-60  the Noise key of tenant-a REPLACED (data/ otherwise unchanged — the case the start guard of §11.4 refuses
          on an activated instance): what the clients do is observed and recorded (online at Headscale, BackendState
          and peers, up to 90 s after the start), then the original key is put back and both clients recover; the case
          passes when the original key restores service — the observation is the V-11 measurement

Reconnection is judged against a known baseline: test-allow-intra on tenant-a (a1 and a2 see each other), set before
the cases; the policy tenant-a had is put back afterwards. Both run last (they restart tenant-a's Headscale) and leave
tenant-a as they found it. Standard library only.
"""
from __future__ import annotations

import json
import os
import time

import checks
from stack import Stack, StackError, log

SLUG = "tenant-a"
A = ("a1", "a2")
POLICY_DIR = "/etc/mg-e2e"         # st.work/policies inside the Headscale containers (stack.py)
SAVED_POLICY = "restore-e2e-saved.hujson"


def hs_name(st: Stack) -> str:
    return st.name(f"hs-{SLUG}")


def wait_hs(st: Stack, timeout: float = 120) -> float:
    """Headscale of tenant-a answers its CLI again; returns the seconds it took."""
    t0 = time.time()

    def up():
        p = st.headscale(SLUG, "nodes", "list", "-o", "json", check=False, timeout=20)
        return p.returncode == 0
    if not checks.wait(up, timeout, every=1.0):
        raise StackError(f"hs-{SLUG} không phản hồi sau {timeout}s")
    return time.time() - t0


def stop_hs(st: Stack) -> None:
    st.docker("stop", "-t", "60", hs_name(st), timeout=120)


def start_hs(st: Stack) -> float:
    st.docker("start", hs_name(st))
    return wait_hs(st)


def data_mount(st: Stack) -> str:
    return f"{st.work}:/w"


def nodes(st: Stack) -> dict[str, dict]:
    out = json.loads(st.headscale(SLUG, "nodes", "list", "-o", "json").stdout or "[]") or []
    return {n["name"]: n for n in out}


def peers_ok(st: Stack) -> dict[str, str] | None:
    """Both clients Running and each one sees the other — or None."""
    try:
        s = {c: checks.status(st, c) for c in A}
    except (StackError, ValueError):
        return None
    if any(x.get("BackendState") != "Running" for x in s.values()):
        return None
    ips = {c: checks.ip4(s[c]["Self"]) for c in A}
    for c, other in (("a1", "a2"), ("a2", "a1")):
        if not any(ips[other] in (p.get("TailscaleIPs") or []) for p in checks.peers(s[c])):
            return None
    return {c: s[c]["BackendState"] for c in A}


def online_at_hs(st: Stack, names: list[str]) -> bool:
    try:
        ns = nodes(st)
    except (StackError, ValueError):
        return False
    return all(ns.get(n, {}).get("online") for n in names)


def reconnected(st: Stack, names: list[str]) -> bool:
    """The clients are back on THIS Headscale: online in its node list (a live map session) and seeing each other."""
    return online_at_hs(st, names) and bool(peers_ok(st))


def baseline(st: Stack) -> list[str]:
    """a1/a2 see each other under test-allow-intra; returns the names of tenant-a's nodes online at Headscale."""
    checks.wait_running(st, A)
    if not checks.wait(lambda: peers_ok(st), 120, every=2.0):
        raise StackError("a1/a2 không thấy nhau dưới test-allow-intra (mốc trước khi đo)")
    names = [n for n, v in nodes(st).items() if v.get("online")]
    if len(names) < len(A):
        raise StackError(f"Headscale của {SLUG} chỉ thấy {names} online (mốc trước khi đo)")
    return names


def observe(st: Stack, names: list[str]) -> str:
    out = []
    for c in A:
        try:
            s = checks.status(st, c)
            out.append(f"{c}={s.get('BackendState')}/{len(checks.peers(s))} peer")
        except (StackError, ValueError) as e:
            out.append(f"{c}=? ({str(e)[:60]})")
    try:
        ns = nodes(st)
        out.append("online ở Headscale: " + ", ".join(f"{n}={bool(ns.get(n, {}).get('online'))}" for n in names))
    except (StackError, ValueError) as e:
        out.append(f"node list: ? ({str(e)[:60]})")
    return ", ".join(out)


def check_restore_old_snapshot(r, st: Stack) -> None:
    names = baseline(st)
    before = {n["name"]: (n["id"], n["machine_key"]) for n in nodes(st).values()}
    users = json.loads(st.headscale(SLUG, "users", "list", "-o", "json").stdout or "[]") or []
    user = users[0]["name"]
    # 1. cold snapshot (Headscale stopped — the upstream backup advice; the platform's backup is VACUUM INTO)
    stop_hs(st)
    st.helper("rm -rf /w/snap59 && cp -a /w/data/tenant-a /w/snap59", data_mount(st))
    start_hs(st)
    if not checks.wait(lambda: reconnected(st, names), 180, every=2.0):
        raise StackError("a1/a2 không nối lại sau khi chụp (restart thường)")
    # 2. after the snapshot: a node (debug create-node + auth register) and a pre-auth key
    auth = "hskey-authreq-" + os.urandom(12).hex()
    st.headscale(SLUG, "debug", "create-node", "--user", user, "--name", "late59", "--key", auth, "-o", "json")
    st.headscale(SLUG, "auth", "register", "--auth-id", auth, "--user", user, "-o", "json")
    uid = str(users[0]["id"])
    k = json.loads(st.headscale(SLUG, "preauthkeys", "create", "-u", uid, "-e", "15m", "-o", "json").stdout)
    st.secret_values.add(k["key"])
    late_ok = "late59" in nodes(st)
    # 3. restore the snapshot in place (Headscale stopped, data/ replaced, started)
    stop_hs(st)
    st.helper("rm -rf /w/data/tenant-a/* && cp -a /w/snap59/. /w/data/tenant-a/ && rm -rf /w/snap59", data_mount(st))
    t0 = time.time()
    up = start_hs(st)
    ok = checks.wait(lambda: reconnected(st, names), 180, every=2.0)
    reconnect = time.time() - t0
    after = nodes(st)
    keys = json.loads(st.headscale(SLUG, "preauthkeys", "list", "-o", "json").stdout or "[]") or []
    kept = all((after.get(n, {}).get("id"), after.get(n, {}).get("machine_key")) == v for n, v in before.items())
    key_gone = all(x.get("id") != k.get("id") for x in keys)
    good = bool(ok) and late_ok and "late59" not in after and kept and key_gone
    log(f"E2E-59: Headscale up {up:.1f}s, clients reconnected {reconnect:.1f}s after the start ({ok})")
    r.add("E2E-59", "V-11: restore bản chụp CŨ hơn (cùng Noise key) — client đăng ký trước bản chụp nối lại không cần đăng "
          "nhập lại; node và pre-auth key tạo sau bản chụp không còn", good,
          f"Headscale lên {up:.1f}s; {', '.join(names)} online ở Headscale + a1/a2 Running và thấy nhau sau {reconnect:.1f}s "
          f"({bool(ok)}); node trước bản chụp giữ nguyên id + machine key (không đăng nhập lại): {kept}; late59 trước restore: "
          f"{late_ok}, sau: {'late59' in after}; pre-auth key tạo sau bản chụp còn: {not key_gone}")


def check_noise_key_changed(r, st: Stack) -> None:
    names = baseline(st)
    stop_hs(st)
    st.helper("cp -p /w/data/tenant-a/noise_private.key /w/noise60.orig && "
              "k=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \\n') && printf 'privkey:%s' \"$k\" > /w/data/tenant-a/noise_private.key && "
              "chown 30001:30001 /w/data/tenant-a/noise_private.key && chmod 0600 /w/data/tenant-a/noise_private.key", data_mount(st))
    try:
        start_hs(st)
        t0 = time.time()
        with_new = checks.wait(lambda: reconnected(st, names), 90, every=3.0)
        new_secs = time.time() - t0
        seen = observe(st, names)
    finally:
        stop_hs(st)
        st.helper("cp -p /w/noise60.orig /w/data/tenant-a/noise_private.key && rm -f /w/noise60.orig", data_mount(st))
        start_hs(st)
    t1 = time.time()
    back = checks.wait(lambda: reconnected(st, names), 180, every=2.0)
    recover = time.time() - t1
    outcome = (f"Noise key mới: {'client nối lại (online ở Headscale, thấy nhau)' if with_new else 'client KHÔNG nối lại được'} "
               f"sau {new_secs:.0f}s ({seen})")
    log(f"E2E-60: {outcome}; original key back: recovered in {recover:.1f}s ({bool(back)})")
    r.add("E2E-60", "V-11: Noise key bị thay (data/ giữ nguyên) — quan sát hành vi client; đặt lại key gốc ⇒ client phục "
          "hồi (start guard của §11.4 chặn trường hợp này trên instance đã kích hoạt)", bool(back),
          f"{outcome}; đặt lại key gốc ⇒ {', '.join(names)} online ở Headscale + a1/a2 thấy nhau sau {recover:.1f}s ({bool(back)})")


def run_all(r, st: Stack, guarded) -> None:
    saved = st.work / "policies" / SAVED_POLICY
    saved.write_text(st.headscale(SLUG, "policy", "get").stdout, encoding="utf-8")
    os.chmod(saved, 0o644)
    try:
        st.headscale(SLUG, "policy", "set", "-f", f"{POLICY_DIR}/test-allow-intra.hujson")
        guarded(r, "E2E-59", check_restore_old_snapshot, st)
        guarded(r, "E2E-60", check_noise_key_changed, st)
    finally:
        p = st.headscale(SLUG, "policy", "set", "-f", f"{POLICY_DIR}/{SAVED_POLICY}", check=False)
        if p.returncode != 0:
            log(f"E2E-59/60: không đặt lại được policy cũ của {SLUG}: {st.redact(p.stderr)[-300:]}")
        saved.unlink(missing_ok=True)
