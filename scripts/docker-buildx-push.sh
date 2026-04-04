#!/usr/bin/env bash
# 构建并推送 linux/amd64 + linux/arm64 多架构镜像到 Docker Hub（需已 docker login）
set -euo pipefail
IMAGE="${IMAGE:-hk59775634/vpndns-server:latest}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT"
if ! docker buildx version >/dev/null 2>&1; then
	echo "需要 Docker Buildx，请升级 Docker Desktop / 安装 buildx 插件。" >&2
	exit 1
fi

BUILDER="${BUILDER:-vpndns-multiarch}"
if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
	docker buildx create --name "$BUILDER" --driver docker-container --bootstrap
fi
docker buildx use "$BUILDER"

echo "==> buildx build --platform linux/amd64,linux/arm64 --push $IMAGE"
docker buildx build \
	--platform linux/amd64,linux/arm64 \
	-t "$IMAGE" \
	-f Dockerfile \
	--push \
	.

echo "==> done: $IMAGE"
