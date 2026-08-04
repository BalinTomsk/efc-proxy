#!/bin/sh
# cproxy-firewall.sh - only the addresses listed in the allow file may reach the published cproxy port.
# Rules live in DOCKER-USER (the one chain Docker-published ports honor; ufw/INPUT is bypassed by Docker NAT).
# PUB_IF is the public interface; the VPC interface and SSH (host INPUT chain) are deliberately untouched,
# so applying this can never lock out droplet administration.
# Allow file: one IPv4 address or CIDR per line, '#' comments allowed. Real deploy addresses stay on the
# host (the file is not tracked in git), so this script carries no deployment IPs.
set -e
PUB_IF="${PUB_IF:-eth0}"
ALLOW_FILE="${ALLOW_FILE:-/usr/local/etc/cproxy-firewall.allow}"

if [ ! -r "$ALLOW_FILE" ]; then
  iptables -F DOCKER-USER                              # fail CLOSED: no allow file -> nobody reaches the containers
  iptables -A DOCKER-USER -i "$PUB_IF" -j DROP         # (SSH is unaffected; restore the file and rerun to reopen)
  iptables -A DOCKER-USER -j RETURN
  echo "cproxy-firewall: allow file $ALLOW_FILE missing/unreadable - applied drop-all" >&2
  exit 1
fi

iptables -F DOCKER-USER                                                                    # chain is owned by this script; start clean
iptables -A DOCKER-USER -i "$PUB_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN  # replies to container-initiated outbound (image pulls etc.)
while IFS= read -r line || [ -n "$line" ]; do
  addr="${line%%#*}"                                                                       # strip trailing comments
  addr=$(printf '%s' "$addr" | tr -d ' \t\r')
  [ -n "$addr" ] && iptables -A DOCKER-USER -i "$PUB_IF" -s "$addr" -j RETURN              # allowed caller
done < "$ALLOW_FILE"
iptables -A DOCKER-USER -i "$PUB_IF" -j DROP                                               # everyone else: no access to published containers
iptables -A DOCKER-USER -j RETURN                                                          # non-public-interface traffic continues normal processing

if command -v ip6tables >/dev/null 2>&1; then                                              # v6: Docker publishes [::] too - close it even without a global IPv6
  ip6tables -F DOCKER-USER 2>/dev/null || true
  ip6tables -A DOCKER-USER -i "$PUB_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null || true
  ip6tables -A DOCKER-USER -i "$PUB_IF" -j DROP 2>/dev/null || true
  ip6tables -A DOCKER-USER -j RETURN 2>/dev/null || true
fi
