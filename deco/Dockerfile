# syntax=docker/dockerfile:1

# TP-Link Deco read-only pusher agent for NetPulse.
# Builds the local source of this repository (deco/cmd/deco-pusher) the same
# way the release workflow does (.github/workflows/release.yml): a pure-Go
# static binary with the version stamped into main.Version.
#
# Build (context = repository root):
#   docker build -t netpulse-deco-agent:latest -f deco/Dockerfile .
#   docker build --build-arg VERSION=0.2.0 \
#     -t netpulse-deco-agent:0.2.0 -f deco/Dockerfile .
#
# The agent is configured entirely via environment variables
# (DECO_HOST, DECO_PASSWORD, DECO_INSECURE, NETPULSE_SERVER, NETPULSE_TOKEN, ...)
# and pushes to the NetPulse server; it exposes no ports of its own.
#
# Note: the Deco portal serves a self-signed certificate, so certificate
# verification is OFF by default (insecure). To verify against a trusted CA,
# set DECO_INSECURE=0 and provide the CA (see deco/cmd/deco-pusher/main.go).
# Run one instance per Deco mesh from a host that can reach the Deco's LAN.

ARG GO_VERSION=1.26

# Builder-native under multi-arch buildx (same pattern as the netpulse
# Dockerfile): the binary is cross-compiled with GOOS/GOARCH, so the same
# stage serves both the amd64 and the arm64 image builds.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder
ARG VERSION=0.0.0-docker
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
      -ldflags "-s -w -X main.Version=${VERSION}" \
      -o /out/deco-pusher ./deco/cmd/deco-pusher

FROM gcr.io/distroless/static-debian12
ARG VERSION=0.0.0-docker
LABEL org.opencontainers.image.title="netpulse-deco-agent" \
      org.opencontainers.image.description="Read-only TP-Link Deco pusher agent for NetPulse" \
      org.opencontainers.image.source="https://github.com/gnacho/netpulse-integrations" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=builder /out/deco-pusher /usr/local/bin/deco-pusher
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/deco-pusher"]
