#!/bin/sh
# Download the tier 1 model into the Ollama volume. Run as root on the VPS:
#   deploy/ollama/pull-model.sh              model from deploy/.env (MIRAGE_LLM_LOCAL__MODEL)
#   deploy/ollama/pull-model.sh qwen2.5:3b   an explicit model
#
# The ollama service sits on an internal network and cannot reach the registry, so the
# pull runs in a throwaway container on the host network while the host's own egress is
# opened for the duration (the same trade deploy.sh makes for image pulls). The egress
# whitelist is restored on exit, also on failure. Models are large (a 7B Q4 is ~4.7 GB).
set -eu

deploy_dir=$(cd "$(dirname "$0")/.." && pwd)
env_file="$deploy_dir/.env"

die() { echo "error: $*" >&2; exit 1; }
value() { [ -f "$env_file" ] && sed -n "s/^$1=//p" "$env_file" | tail -n 1 || true; }

[ "$(id -u)" -eq 0 ] || die "run as root (changes the host egress rules while pulling)"
for cmd in docker nft; do
	command -v "$cmd" >/dev/null || die "$cmd is not installed"
done

model=${1:-$(value MIRAGE_LLM_LOCAL__MODEL)}
model=${model:-qwen2.5:7b}
version=$(value OLLAMA_VERSION)
version=${version:-0.12.6}
# The name ends up on a command line inside the container: keep it to what Ollama allows.
case $model in
	*[!A-Za-z0-9._:/-]* | "") die "invalid model name: $model" ;;
esac

restore_egress() {
	if nft list table inet mirage_egress >/dev/null 2>&1; then
		nft -f "$deploy_dir/firewall/nftables.conf"
		"$deploy_dir/firewall/update-egress-set.sh" >/dev/null
	fi
}
trap restore_egress EXIT INT TERM

echo "==> Pulling $model with ollama/ollama:$version"
if nft list table inet mirage_egress >/dev/null 2>&1; then
	nft 'add chain inet mirage_egress output { policy accept; }'
fi
docker run --rm --network host \
	-v mirage-ollama-models:/models -e OLLAMA_MODELS=/models -e HOME=/tmp \
	--entrypoint sh "ollama/ollama:$version" -c '
		ollama serve >/dev/null 2>&1 &
		server=$!
		for _ in $(seq 1 30); do ollama list >/dev/null 2>&1 && break; sleep 1; done
		ollama pull "$0"
		status=$?
		kill "$server" 2>/dev/null
		exit "$status"
	' "$model"

echo "==> Done. Models in the volume:"
docker run --rm -v mirage-ollama-models:/models alpine ls /models/manifests/registry.ollama.ai/library 2>/dev/null || true
