# VPN access to Grafana and Prometheus

Neither is published. Operators connect with WireGuard (UDP `MIRAGE_WG_PORT`, default 51820)
and then open `http://172.30.0.x:3000` (Grafana) or `:9090` (Prometheus); find the
addresses with `docker inspect`. Peers can reach only the monitoring subnet.

1. `cp deploy/wireguard/wg0.conf.example deploy/wireguard/wg0.conf && chmod 600 deploy/wireguard/wg0.conf`
2. Put a server private key in it; add one `[Peer]` per operator (`AllowedIPs = 10.8.0.N/32`).
3. Client config: `Address = 10.8.0.N/32`, `AllowedIPs = 172.30.0.0/24, 10.8.0.0/24`,
   `Endpoint = <MIRAGE_DOMAIN>:51820`, `PersistentKeepalive = 25`.

The host needs the `wireguard` kernel module (built in since Linux 5.6).
