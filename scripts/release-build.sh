#!/usr/bin/env bash
# 交叉编译多架构二进制并打包到 dist/，供 GitHub Releases 上传。
# 用法: ./scripts/release-build.sh v1.0.0
# 或:   RELEASE_VERSION=v1.0.0 ./scripts/release-build.sh
#
# 本机 Go 较旧（如 1.18）交叉编译 darwin 等目标可能失败，可用官方镜像构建：
#   RELEASE_USE_DOCKER=1 ./scripts/release-build.sh v1.0.0
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-${RELEASE_VERSION:-}}"
if [[ -z "$VERSION" ]]; then
	echo "用法: $0 <版本标签，如 v1.0.0>" >&2
	echo "  或设置环境变量 RELEASE_VERSION=v1.0.0" >&2
	exit 1
fi
[[ "$VERSION" == v* ]] || VERSION="v${VERSION}"

# 在容器内用较新 Go 构建（需已安装 Docker）
if [[ "${RELEASE_USE_DOCKER:-}" == "1" && "${RELEASE_DOCKER_INNER:-}" != "1" ]]; then
	_vq=$(printf '%q' "$VERSION")
	exec docker run --rm \
		-e RELEASE_DOCKER_INNER=1 \
		-v "$ROOT:/src" -w /src \
		golang:1.22-bookworm \
		bash -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq zip >/dev/null && chmod +x scripts/release-build.sh && ./scripts/release-build.sh ${_vq}"
fi

DIST="${DIST:-$ROOT/dist}"
rm -rf "$DIST"
mkdir -p "$DIST"

LDFLAGS='-s -w'
export CGO_ENABLED=0

need_zip() {
	if ! command -v zip >/dev/null 2>&1; then
		echo "需要 zip 命令打包 Windows 发行包（例如: apt-get install -y zip）" >&2
		exit 1
	fi
}

archive_unix() {
	local dir=$1 name=$2 tgz=$3
	tar -czf "$tgz" -C "$dir" "$name"
}

archive_win() {
	local dir=$1 exe=$2 zipfile=$3
	need_zip
	( cd "$dir" && zip -q "$zipfile" "$exe" )
	mv "$dir/$zipfile" "$DIST/$zipfile"
}

build_target() {
	local goos=$1 goarch=$2 goarm=${3:-}
	local name="vpndns-server"
	local outdir
	outdir="$(mktemp -d "${TMPDIR:-/tmp}/vpndns-build.XXXXXX")"

	if [[ "$goos" == "windows" ]]; then
		name="${name}.exe"
	fi

	local pkg="vpndns-server_${VERSION}_${goos}_${goarch}"
	if [[ -n "$goarm" ]]; then
		pkg="${pkg}v${goarm}"
	fi

	echo "==> GOOS=$goos GOARCH=$goarch ${goarm:+GOARM=$goarm }-> ${pkg}"

	if [[ -n "$goarm" ]]; then
		GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" go build -trimpath -ldflags="$LDFLAGS" -o "$outdir/$name" ./cmd/server
	else
		GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="$LDFLAGS" -o "$outdir/$name" ./cmd/server
	fi

	if [[ "$goos" == "windows" ]]; then
		archive_win "$outdir" "$name" "${pkg}.zip"
	else
		archive_unix "$outdir" "$name" "$DIST/${pkg}.tar.gz"
	fi
	rm -rf "$outdir"
}

# linux / darwin / windows：amd64、arm64
for goos in linux darwin windows; do
	for goarch in amd64 arm64; do
		build_target "$goos" "$goarch"
	done
done

# 常见 32 位 ARM（树莓派等）
build_target linux arm 7

(
	cd "$DIST"
	: > SHA256SUMS.txt
	shopt -s nullglob
	for f in *.tar.gz *.zip; do
		sha256sum "$f" >> SHA256SUMS.txt
	done
)

echo "产物目录: $DIST"
ls -la "$DIST"
