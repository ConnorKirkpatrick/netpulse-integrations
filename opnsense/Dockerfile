# syntax=docker/dockerfile:1

# OPNsense read-only pusher agent for NetPulse.
# Builds the local source of this repository (opnsense/cmd/opnsense-pusher)
# the same way the release workflow does (.github/workflows/release.yml):
# a pure-Go static binary with the version stamped into main.Version.
#
# Build (context = repository root):
#   docker build -t netpulse-opnsense-agent:latest -f opnsense/Dockerfile .
#   docker build --build-arg VERSION=0.2.0 \
#     -t netpulse-opnsense-agent:0.2.0 -f opnsense/Dockerfile .
#
# The agent is configured entirely via environment variables
# (OPNSENSE_HOST, OPNSENSE_USER, OPNSENSE_PASS, NETPULSE_SERVER, NETPULSE_TOKEN, ...)
# and pushes to the NetPulse server; it exposes no ports of its own.

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
      -o /out/opnsense-pusher ./opnsense/cmd/opnsense-pusher

FROM gcr.io/distroless/static-debian12
ARG VERSION=0.0.0-docker
LABEL org.opencontainers.image.title="netpulse-opnsense-agent" \
      org.opencontainers.image.description="Read-only OPNsense pusher agent for NetPulse" \
      org.opencontainers.image.source="https://github.com/gnacho/netpulse-integrations" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=builder /out/opnsense-pusher /usr/local/bin/opnsense-pusher
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/opnsense-pusher"]
