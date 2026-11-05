FROM alpine:3.20
RUN apk add --no-cache wireguard-tools iptables iproute2
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
