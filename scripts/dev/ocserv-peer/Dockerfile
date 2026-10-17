# A throwaway Cisco AnyConnect-compatible gateway (ocserv) for testing Wombat's OpenConnect
# engine. Used by scripts/dev/ocserv-peer.sh; nothing here is for production.
FROM debian:trixie-slim
RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends ocserv openssl iproute2 iputils-ping procps \
    && rm -rf /var/lib/apt/lists/*
COPY start.sh /start.sh
CMD ["/bin/sh", "/start.sh"]
