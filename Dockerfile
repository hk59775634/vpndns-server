# syntax=docker/dockerfile:1
# VPN DNS SERVER — vpndns-server（需外置 Redis + 挂载配置）
# 多架构：buildx 传入 TARGET*；在 $BUILDPLATFORM 上交叉编译以加速 amd64 主机构建。
FROM --platform=$BUILDPLATFORM golang:1.22-bookworm AS build
ARG TARGETOS=linux
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN case "$TARGETARCH" in \
      arm) \
        case "$TARGETVARIANT" in v6) export GOARM=6 ;; *) export GOARM=7 ;; esac \
        ;; \
    esac && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/vpndns-server ./cmd/server

FROM alpine:3.19
ARG VERSION=dev
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/vpndns-server /usr/local/bin/vpndns-server
ENV CONFIG=/etc/vpndns/config.yaml
EXPOSE 53/tcp 53/udp 8053/tcp 8080/tcp
LABEL org.opencontainers.image.title="vpndns-server" \
      org.opencontainers.image.description="Smart DNS resolver: DoH, GeoIP, Redis cache, admin UI" \
      org.opencontainers.image.source="https://github.com/hk59775634/vpndns-server" \
      org.opencontainers.image.url="https://hub.docker.com/r/hk59775634/vpndns-server" \
      org.opencontainers.image.version="${VERSION}"
ENTRYPOINT ["/usr/local/bin/vpndns-server"]
