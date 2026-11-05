#!/bin/sh
# Brings up wg0 and lets VPN peers reach the monitoring network (Grafana, Prometheus)
# and nothing else. Uses `wg setconf` instead of wg-quick: wg-quick writes sysctls,
# which the read-only container may not do (ip_forward is set via compose `sysctls`).
set -eu

: "${WG_ADDRESS:?set WG_ADDRESS, e.g. 10.8.0.1/24}"
: "${WG_ALLOWED_DEST:?set WG_ALLOWED_DEST, e.g. 172.30.0.0/24}"
conf=/etc/wireguard/wg0.conf
[ -r "$conf" ] || { echo "error: $conf missing (see deploy/wireguard/wg0.conf.example)" >&2; exit 1; }

ip link add wg0 type wireguard
wg setconf wg0 "$conf"
ip address add "$WG_ADDRESS" dev wg0
ip link set wg0 up

# Default-deny forwarding; peers may open new connections only towards the monitoring
# subnet. Everything else (backend, edge, the internet) stays unreachable via the VPN.
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i wg0 -d "$WG_ALLOWED_DEST" -j ACCEPT
# Services see the connection as coming from this container, so replies need no route.
iptables -t nat -A POSTROUTING -d "$WG_ALLOWED_DEST" -j MASQUERADE

echo "wg0 up on $WG_ADDRESS; peers may reach $WG_ALLOWED_DEST"
exec sleep infinity
