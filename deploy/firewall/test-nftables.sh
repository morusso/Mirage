#!/bin/sh
# Functional test of nftables.conf in throwaway network namespaces. Needs Linux and
# root; on macOS/CI run it in a privileged container:
#
#   docker run --rm --privileged -v "$PWD/deploy/firewall:/fw:ro" alpine \
#       sh -c 'apk add -q nftables iproute2 socat && sh /fw/test-nftables.sh'
#
# The container's own namespace plays the host (router); `caddy`, `app` and
# `internet` are namespaces wired to it like the Docker edge network and the
# outside world. Nothing here touches the real host's network.
set -u
fw_dir="$(dirname "$0")"
fails=0

ok()   { echo "PASS  $1"; }
bad()  { echo "FAIL  $1"; fails=$((fails + 1)); }
# expect <allow|block> <ns> <port> <description>
expect() {
	if ip netns exec "$2" nc -w 2 -z 203.0.113.2 "$3" 2>/dev/null; then got=allow; else got=block; fi
	[ "$got" = "$1" ] && ok "$4" || bad "$4 (expected $1, got $got)"
}
host_expect() {
	if nc -w 2 -z 203.0.113.2 "$2" 2>/dev/null; then got=allow; else got=block; fi
	[ "$got" = "$1" ] && ok "$3" || bad "$3 (expected $1, got $got)"
}

# --- topology: router(=this ns) with br0 172.28.0.0/24 and an "internet" ns ---
ip link add br0 type bridge && ip addr add 172.28.0.1/24 dev br0 && ip link set br0 up
for spec in caddy:2 app:3; do
	ns=${spec%%:*}; n=${spec##*:}
	ip netns add "$ns"
	ip link add "v-$ns" type veth peer name "p-$ns"
	ip link set "p-$ns" netns "$ns" name eth0
	ip link set "v-$ns" master br0 up
	ip -n "$ns" addr add "172.28.0.$n/24" dev eth0
	ip -n "$ns" link set eth0 up
	ip -n "$ns" link set lo up
	ip -n "$ns" route add default via 172.28.0.1
done
ip netns add internet
ip link add v-net type veth peer name p-net
ip link set p-net netns internet name eth0
ip addr add 203.0.113.1/24 dev v-net && ip link set v-net up
ip -n internet addr add 203.0.113.2/24 dev eth0
ip -n internet link set eth0 up && ip -n internet link set lo up
ip -n internet route add default via 203.0.113.1
sysctl -qw net.ipv4.ip_forward=1

for port in 53 80 443 5432; do
	# fork: a listener that serves one probe and re-listens races with the next probe,
	# which would turn "allow" checks flaky and "block" checks into false passes.
	ip netns exec internet socat TCP-LISTEN:$port,fork,reuseaddr SYSTEM:true &
done
sleep 1

# --- before the firewall: everything works (proves the topology and the probes) ---
expect allow app   443 "baseline: app reaches the internet without rules"
host_expect allow  443 "baseline: host reaches the internet without rules"

nft -f "$fw_dir/nftables.conf" || { echo "nftables.conf failed to load"; exit 1; }
nft -f "$fw_dir/nftables.conf" && ok "reloading the ruleset is idempotent"

echo "--- containers ---"
expect allow caddy 443  "caddy -> internet:443 (ACME/OCSP)"
expect allow caddy 53   "caddy -> internet:53 tcp (DNS)"
expect block caddy 80   "caddy -> internet:80 is blocked"
expect block caddy 5432 "caddy -> internet:5432 is blocked"
expect block app   443  "app -> internet:443 is blocked"
expect block app   80   "app -> internet:80 is blocked"
expect block app   5432 "app -> internet:5432 is blocked"

echo "--- host ---"
host_expect block 443 "host -> unlisted address:443 is blocked"
nft add element inet mirage_egress allowed_https_v4 '{ 203.0.113.2 }'
host_expect allow 443 "host -> allow-listed address:443"
host_expect block 80  "host -> allow-listed address:80 is still blocked"
host_expect block 5432 "host -> allow-listed address:5432 is still blocked"

kill $(jobs -p) 2>/dev/null
[ "$fails" -eq 0 ] && echo "ALL PASSED" || echo "$fails FAILED"
exit "$fails"
