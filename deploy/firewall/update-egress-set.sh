#!/bin/sh
# Resolve deploy/firewall/egress-hosts.txt and replace the contents of
# `inet mirage_egress allowed_https_v4`. Needs root and a loaded nftables.conf.
set -eu

hosts_file="${1:-$(dirname "$0")/egress-hosts.txt}"
table="inet mirage_egress"
set_name="allowed_https_v4"

nft list set $table $set_name >/dev/null 2>&1 || {
	echo "nftables.conf is not loaded" >&2
	exit 1
}

addrs=$(
	sed 's/#.*//' "$hosts_file" | awk 'NF {print $1}' | while read -r host; do
		# Names that fail to resolve are skipped, not fatal: one flaky API must
		# not lock out the others.
		getent ahostsv4 "$host" | awk '{print $1}' | sort -u ||
			echo "warning: cannot resolve $host" >&2
	done | sort -u | paste -sd, -
)

nft flush set $table $set_name
if [ -n "$addrs" ]; then
	nft add element $table $set_name "{ $addrs }"
fi
echo "allowed_https_v4: ${addrs:-<empty>}"
