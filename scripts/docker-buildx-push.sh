#!/usr/bin/env bash
# 多架构镜像构建并推送 Docker Hub（需已 docker login）
# 平台默认：linux/amd64, linux/arm64, linux/arm/v7（与 Release 二进制一致）
#
# 用法：
#   VERSION=v1.0.1 ./scripts/docker-buildx-push.sh    # 打 tag v1.0.1 + latest 并推送
#   ./scripts/docker-buildx-push.sh                   # 仅推送 latest
# 环境变量：
#   IMAGE   默认 hk59775634/vpndns-server
#   PLATFORMS  覆盖平台列表
#   BUILDER buildx builder 名称，默认 vpndns-multiarch
set -euo pipefail

IMAGE="${IMAGE:-hk59775634/vpndns-server}"
VERSION="${VERSION:-}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64,linux/arm/v7}"
BUILDER="${BUILDER:-vpndns-multiarch}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! docker buildx version >/dev/null 2>&1; then
	echo "需要 Docker Buildx。" >&2
	exit 1
fi

if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
	docker buildx create --name "$BUILDER" --driver docker-container --bootstrap
fi
docker buildx use "$BUILDER"

TAG_ARGS=( -t "${IMAGE}:latest" )
if [[ -n "$VERSION" ]]; then
	[[ "$VERSION" == v* ]] || VERSION="v${VERSION}"
	TAG_ARGS+=( -t "${IMAGE}:${VERSION}" )
fi

echo "==> buildx --platform $PLATFORMS push ${TAG_ARGS[*]}"

docker buildx build \
	--platform "$PLATFORMS" \
	"${TAG_ARGS[@]}" \
	--build-arg "VERSION=${VERSION:-dev}" \
	-f Dockerfile \
	--push \
	.

echo "==> done"
echo "    docker pull ${IMAGE}:latest"
[[ -n "$VERSION" ]] && echo "    docker pull ${IMAGE}:${VERSION}"
