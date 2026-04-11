#!/usr/bin/env bash
# 将 docs/DOCKERHUB-OVERVIEW.md 同步为 Docker Hub 仓库的 Full description（Overview 正文）。
#
# 依赖：curl、jq
# 凭据（二选一，用于 hub.docker.com 登录 JWT）：
#   - DOCKERHUB_USERNAME（默认 hk59775634）+ DOCKERHUB_PASSWORD（Docker Hub 账户密码），或
#   - 部分环境可使用 Personal Access Token 作为密码（以 Docker Hub 当前策略为准）。
#
# 用法：
#   DOCKERHUB_PASSWORD=*** ./scripts/dockerhub-update-overview.sh
#   DOCKERHUB_OVERVIEW_FILE=docs/custom.md ./scripts/dockerhub-update-overview.sh
set -euo pipefail

USER="${DOCKERHUB_USERNAME:-hk59775634}"
REPO="${DOCKERHUB_REPO:-vpndns-server}"
PASS="${DOCKERHUB_PASSWORD:-${DOCKER_PASSWORD:-}}"
FILE="${DOCKERHUB_OVERVIEW_FILE:-docs/DOCKERHUB-OVERVIEW.md}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f "$FILE" ]]; then
	echo "文件不存在: $FILE" >&2
	exit 1
fi
if [[ -z "$PASS" ]]; then
	echo "请设置 DOCKERHUB_PASSWORD（或 DOCKER_PASSWORD）后重试。" >&2
	echo "亦可手动：Docker Hub → Repositories → $USER/$REPO → Edit → 将 $FILE 全文粘贴到 Overview。" >&2
	exit 1
fi

BYTES=$(wc -c <"$FILE" | tr -d ' ')
if [[ "$BYTES" -gt 25000 ]]; then
	echo "错误：Overview 超过 Docker Hub 约 25KB 限制（当前 ${BYTES} 字节）。" >&2
	exit 1
fi

TOKEN=$(curl -sf -H "Content-Type: application/json" \
	-d "{\"username\":\"${USER}\",\"password\":\"${PASS}\"}" \
	https://hub.docker.com/v2/users/login/ | jq -r .token)

if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
	echo "登录 Docker Hub 失败（请检查用户名与密码/PAT）。" >&2
	exit 1
fi

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
jq -Rs '{full_description: .}' <"$FILE" >"$TMP"

HTTP=$(curl -sS -o /dev/null -w '%{http_code}' -X PATCH \
	-H "Authorization: JWT ${TOKEN}" \
	-H "Content-Type: application/json" \
	-d @"$TMP" \
	"https://hub.docker.com/v2/repositories/${USER}/${REPO}/")

if [[ "$HTTP" != "200" ]]; then
	echo "PATCH 失败，HTTP $HTTP（需具备该仓库的编辑权限）。" >&2
	exit 1
fi

echo "==> Docker Hub Overview 已更新: https://hub.docker.com/r/${USER}/${REPO}"
