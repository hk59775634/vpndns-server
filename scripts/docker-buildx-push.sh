#!/usr/bin/env bash
# 构建并推送多架构镜像到 Docker Hub（需已 docker login）
#
# === 版本标签策略（正式发版请遵守）===
# - 每次发版必须同时得到两个标签：`:vX.Y.Z`（与 Git / GitHub Release 一致）与 `:latest`。
# - `:vX.Y.Z` 一旦推送即作为历史版本保留在 Hub，后续新版本再推新的 v 标签；勿删除旧标签，便于回滚与对照。
# - 仅更新尝鲜/CI 时可不设 VERSION（只推 :latest），但不计入「正式版本」。
#
# 平台默认：linux/amd64, linux/arm64, linux/arm/v7（与 Release 二进制一致）
#
# 用法：
#   VERSION=v1.0.3 ./scripts/docker-buildx-push.sh
#   USE_GIT_TAG=1 ./scripts/docker-buildx-push.sh    # VERSION 取当前仓库最新 git 标签（如 v1.0.1）
#   ./scripts/docker-buildx-push.sh                  # 仅 :latest（会打印警告）
#
# 环境变量：IMAGE、PLATFORMS、BUILDER、USE_GIT_TAG
set -euo pipefail

IMAGE="${IMAGE:-hk59775634/vpndns-server}"
VERSION="${VERSION:-}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64,linux/arm/v7}"
BUILDER="${BUILDER:-vpndns-multiarch}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ "${USE_GIT_TAG:-}" == "1" && -z "$VERSION" ]]; then
	VERSION=$(git describe --tags --abbrev=0 2>/dev/null || true)
	if [[ -z "$VERSION" ]]; then
		echo "USE_GIT_TAG=1 但未找到 git 标签。" >&2
		exit 1
	fi
	echo "==> VERSION 来自 git: $VERSION"
fi

if [[ -z "$VERSION" ]]; then
	echo "警告：未设置 VERSION。将只推送 ${IMAGE}:latest，不会在 Hub 上新增 vX.Y.Z 版本标签。" >&2
	echo "      正式发版请执行: VERSION=v1.x.x $0   或   USE_GIT_TAG=1 $0" >&2
fi

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
if [[ -n "$VERSION" ]]; then
	echo "    正式标签: docker pull ${IMAGE}:${VERSION}"
	echo "    最新跟踪: docker pull ${IMAGE}:latest"
	echo "    （本轮 :${VERSION} 与 :latest 指向同一 manifest；请在 Hub 长期保留各历史 v* 标签勿删，便于回滚）"
else
	echo "    docker pull ${IMAGE}:latest"
fi
