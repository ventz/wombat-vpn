# A reference AmneziaWG peer for scripts/dev/test-peer.sh --awg: upstream amneziawg-go
# (unpatched, like a real server) and the awg tool from amneziawg-tools. Test use only; the
# GPLv2 tools are never linked into or copied into Wombat.
FROM golang:1.25-alpine AS build
RUN apk add --no-cache git make bash gcc musl-dev linux-headers
ARG AWG_GO=v3.1.20260828
ARG AWG_TOOLS=v3.1.20260812
RUN git clone --depth 1 --branch "$AWG_GO" https://github.com/amnezia-vpn/amneziawg-go /src/go \
    && cd /src/go && CGO_ENABLED=0 go build -o /out/amneziawg-go .
RUN git clone --depth 1 --branch "$AWG_TOOLS" https://github.com/amnezia-vpn/amneziawg-tools /src/tools \
    && make -C /src/tools/src && ls /src/tools/src && cp /src/tools/src/wg /out/awg

FROM alpine:3.22
RUN apk add --no-cache iproute2
COPY --from=build /out/ /usr/local/bin/
