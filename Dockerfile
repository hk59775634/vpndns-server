# syntax=docker/dockerfile:1
# VPN DNS CDN — vpndns-server（需外置 Redis + 挂载配置）
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/vpndns-server ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/vpndns-server /usr/local/bin/vpndns-server
# 默认配置路径；可通过 -config 或环境变量 CONFIG 覆盖
ENV CONFIG=/etc/vpndns/config.yaml
EXPOSE 53/tcp 53/udp 8053/tcp 8080/tcp
ENTRYPOINT ["/usr/local/bin/vpndns-server"]
