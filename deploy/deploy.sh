#!/bin/sh
# Deploy (or update) Mirage on the VPS. Run as root from anywhere:
#   deploy/deploy.sh            full deploy
#   deploy/deploy.sh --check    only validate deploy/.env (no root, no Docker needed)
#
# Order matters: images are fetched while the host may still reach registries, then
# the egress firewall is (re)loaded, and only then do the containers start.
set -eu

deploy_dir=$(cd "$(dirname "$0")" && pwd)
repo_dir=$(dirname "$deploy_dir")
env_file="$deploy_dir/.env"
compose="docker compose -f $deploy_dir/docker-compose.yml --env-file $env_file"

die() { echo "error: $*" >&2; exit 1; }
step() { echo "==> $*"; }

check_env() {
	[ -f "$env_file" ] || die "$env_file not found (copy deploy/.env.example)"
	# A world-readable .env leaks the database password to every local user.
	mode=$(stat -c %a "$env_file" 2>/dev/null || stat -f %Lp "$env_file")
	case $mode in
		600 | 400) ;;
		*) die "$env_file has mode $mode; run: chmod 600 $env_file" ;;
	esac
	value() { sed -n "s/^$1=//p" "$env_file" | tail -n 1; }
	domain=$(value MIRAGE_DOMAIN)
	password=$(value POSTGRES_PASSWORD)
	[ -n "$domain" ] || die "MIRAGE_DOMAIN is empty"
	case $domain in
		localhost | *example.com | *example.org) die "MIRAGE_DOMAIN=$domain is a placeholder" ;;
	esac
	[ -n "$password" ] || die "POSTGRES_PASSWORD is empty"
	[ "${#password}" -ge 16 ] || die "POSTGRES_PASSWORD is shorter than 16 characters"
	echo "ok: $env_file"
}

if [ "${1:-}" = "--check" ]; then
	check_env
	exit 0
fi

[ "$(id -u)" -eq 0 ] || die "run as root (loads nftables rules, installs systemd units)"
for cmd in docker nft systemctl curl; do
	command -v "$cmd" >/dev/null || die "$cmd is not installed"
done
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 plugin is missing"
check_env
domain=$(sed -n 's/^MIRAGE_DOMAIN=//p' "$env_file" | tail -n 1)

step "Fetching images"
# With the whitelist loaded the host cannot reach registries; open only the host's
# own egress for the duration of the pull/build. Container-to-container rules stay.
if nft list table inet mirage_egress >/dev/null 2>&1; then
	nft 'add chain inet mirage_egress output { policy accept; }'
fi
$compose pull --ignore-buildable --quiet
$compose build --quiet

step "Loading egress firewall"
nft -f "$repo_dir/deploy/firewall/nftables.conf"
"$repo_dir/deploy/firewall/update-egress-set.sh"

step "Installing systemd units (firewall at boot, hourly allow-list refresh)"
for unit in "$deploy_dir"/systemd/*; do
	sed "s|@REPO@|$repo_dir|g" "$unit" >"/etc/systemd/system/$(basename "$unit")"
done
systemctl daemon-reload
systemctl enable mirage-firewall.service mirage-egress-refresh.timer >/dev/null
systemctl start mirage-egress-refresh.timer

step "Starting containers"
$compose up -d --remove-orphans --wait --wait-timeout 180

step "Smoke test"
# Resolve the name to this machine so the check works before DNS has propagated.
status=$(curl -ks -o /dev/null -w '%{http_code}' --max-time 10 \
	--resolve "$domain:443:127.0.0.1" "https://$domain/") || die "no HTTPS answer for $domain"
[ "$status" = "404" ] || [ "$status" = "200" ] || die "unexpected HTTP status $status"
echo "HTTPS answers with $status"
$compose ps --format 'table {{.Service}}\t{{.Status}}'
echo "Done. Check the request reached Postgres:"
echo "  $compose exec postgres psql -U mirage -d mirage -c 'select ts, ip, path from requests order by id desc limit 5'"
