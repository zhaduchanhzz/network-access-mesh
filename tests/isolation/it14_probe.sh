#!/bin/sh
# IT-14 (P1-T12c) — chạy BÊN TRONG container thử gắn vào network của một tenant (busybox: nc, wget, nslookup, ip).
# Biến môi trường: OWN (IP Headscale của chính tenant), EDGE_T (IP của edge trên network này), GW (gateway bridge của
# network này — IP của host), OTHER (IP Headscale tenant khác), PG, CS (PostgreSQL, CrowdSec), LANHOST, HOSTLAN,
# ADD_ROUTES=1 (chế độ (ii): thêm route qua edge và qua host trước khi thử — cần NET_ADMIN).
# Mỗi dòng: PASS|FAIL <tên> <kết quả>. Thoát 0 khi mọi mục đúng kỳ vọng.
fail=0
say() { if [ "$1" = ok ]; then echo "PASS $2: $3"; else echo "FAIL $2: $3"; fail=1; fi; }
tcp() {  # <name> <host> <port> — expect NOT connected
  out=$(nc -w 3 "$2" "$3" </dev/null 2>&1); rc=$?
  case "$out" in
    *refused*) r=refused ;; *unreachable*|*"No route"*) r=unreachable ;; *"timed out"*|*imeout*) r=timeout ;;
    *) if [ $rc -eq 0 ]; then r=CONNECTED; else r="failed(rc=$rc ${out:-no output})"; fi ;;
  esac
  [ "$r" = CONNECTED ] && say bad "$1 $2:$3" "$r" || say ok "$1 $2:$3" "$r"
}
# busybox wget: thành công in "HTTP/1.1 200 OK" (-S), lỗi in "server returned error: HTTP/1.1 403 Forbidden"
http_status() { wget -T 4 -S -O /dev/null "$1" 2>&1 | grep -oE 'HTTP/1\.[01] [0-9]{3}' | tail -1 | cut -d' ' -f2; }

if [ "${ADD_ROUTES:-0}" = 1 ]; then
  ip route add 10.249.0.0/16 via "$EDGE_T" 2>&1 && echo "route 10.249.0.0/16 via edge $EDGE_T"
  ip route add 10.250.0.0/16 via "$EDGE_T" 2>&1 && echo "route 10.250.0.0/16 via edge $EDGE_T"
  ip route add default via "$GW" 2>&1 && echo "route default via host $GW"
fi
echo "--- routes: $(ip route | tr '\n' ';')"

# own Headscale: reachable on its own network; /metrics 200, /debug/* must not be served (PL-15)
s=$(http_status "http://$OWN:9090/metrics"); [ "$s" = 200 ] && say ok "own hs :9090/metrics" "$s" || say bad "own hs :9090/metrics" "$s"
s=$(http_status "http://$OWN:9090/debug/policy"); [ "$s" = 403 ] && say ok "own hs :9090/debug/policy" "$s" || say bad "own hs :9090/debug/policy (expect 403)" "$s"
# edge via its IP on THIS network: no listener may answer there
for p in 80 443 8081 9091 2019; do tcp "edge-on-tenant-net" "$EDGE_T" "$p"; done
# edge listener IPs on other networks (reachable only through the edge's interface on this network)
tcp "edge public" 10.249.0.2 443; tcp "edge public" 10.249.0.2 80
tcp "edge admin" 10.249.2.2 8081; tcp "edge metrics" 10.249.3.2 9091
# other tenant, core services, host, LAN, Internet
tcp "other tenant hs" "$OTHER" 8080; tcp "other tenant hs" "$OTHER" 9090
tcp "postgres" "$PG" 5432; tcp "crowdsec lapi" "$CS" 8080; tcp "crowdsec metrics" "$CS" 6060
for p in 22 80 443; do tcp "host via bridge gw" "$GW" "$p"; done
for p in 22 80 443; do tcp "host LAN IP" "$HOSTLAN" "$p"; done
tcp "LAN host" "$LANHOST" 22; tcp "LAN host" "$LANHOST" 8006
tcp "Internet" 1.1.1.1 443; tcp "Internet" 8.8.8.8 53
# DNS: own network names resolve, nothing else does (embedded DNS must not forward from an internal network)
nslookup "hs-$OWNSLUG" >/dev/null 2>&1 && say ok "dns own alias hs-$OWNSLUG" resolves || say bad "dns own alias hs-$OWNSLUG" "no answer"
for n in "hs-$OTHERSLUG" example.com api.github.com; do
  out=$(nslookup "$n" 2>&1); if echo "$out" | grep -qE "^Address: [0-9]" && ! echo "$out" | grep -qE "^Address: 127\.0\.0\.11"; then
    say bad "dns $n" "RESOLVED"; else say ok "dns $n" "no answer"; fi
done
exit $fail
