#!/bin/bash
# Read-only discovery (Appendix A.2 / A.3 of the master plan). Changes nothing. Skips the items that
# would reveal the public IP to a third party (A.2 #11, #13).
s() { echo "## $1"; }
s "1 os/kernel/arch"; lsb_release -ds 2>/dev/null; uname -srm; dpkg --print-architecture
s "2 cpu/ram"; nproc; lscpu | grep -E '^(Model name|Virtualization|Hypervisor vendor)' ; free -h | head -3
s "3 disk"; df -hT -x tmpfs -x devtmpfs -x efivarfs | sed 1d
s "4 network"; ip -br addr | grep -v '^lo'; ip route show default; echo "ipv6 global:"; ip -6 addr show scope global | grep inet || echo "  none"
s "5 resolver"; resolvectl status 2>/dev/null | grep -E 'Current DNS|DNS Servers' | sort -u
s "6 docker"; command -v docker >/dev/null && { docker --version; docker compose version 2>/dev/null; sudo cat /etc/docker/daemon.json 2>/dev/null || echo "no daemon.json"; } || echo "docker not installed"
s "8 running services (count + non-default)"; systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}' | tr '\n' ' '; echo
s "9 listeners"; sudo ss -Htulpn | awk '{print $1, $5, $7}' | sed 's/users:((//; s/,pid=[0-9]*,fd=[0-9]*))//'
s "10 firewall"; sudo ufw status 2>/dev/null | head -1; echo "nft rules: $(sudo nft list ruleset 2>/dev/null | grep -c -E '^\s+(ip|tcp|udp|ct|iif|oif|meta|counter|accept|drop|reject)')"; echo "iptables INPUT policy: $(sudo iptables -S INPUT 2>/dev/null | head -1)"
s "15 time"; timedatectl show -p NTPSynchronized -p Timezone 2>/dev/null
s "16 sshd"; sudo sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication) '
s "17 sysctl"; sysctl net.ipv4.ip_forward net.core.rmem_max net.core.wmem_max fs.inotify.max_user_instances 2>/dev/null
s "18 patches/LSM"; echo "apparmor: $(sudo aa-status --enabled 2>/dev/null && echo enabled || echo disabled)"; echo "unattended-upgrades: $(systemctl is-active unattended-upgrades)"; echo "upgradable: $(apt list --upgradable 2>/dev/null | grep -c upgradable)"
s "sudo for this user"; sudo -l -U "$(id -un)" 2>/dev/null | sed -n '/may run/,$p' | sed 1d
