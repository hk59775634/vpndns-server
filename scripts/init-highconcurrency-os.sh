#!/usr/bin/env bash
# 根据仓库内《高并发系统优化说明.md》初始化操作系统侧调优，写入持久配置（重启后仍生效）。
# 可重复执行：先检测持久文件与运行时再决定是否写入、是否 sysctl、是否 daemon-reload。
#
# 用法:
#   sudo ./scripts/init-highconcurrency-os.sh
#   sudo ./scripts/init-highconcurrency-os.sh --sysctl-only
#   sudo ./scripts/init-highconcurrency-os.sh --apply-runtime   # 仅把已落盘的 sysctl 刷到内核（文件未改时也可用）
#   sudo ./scripts/init-highconcurrency-os.sh --takeover        # 接管已存在但无本脚本标记的配置文件（先备份再覆盖）
#   sudo ./scripts/init-highconcurrency-os.sh -h
#
# 若使用 `sh scripts/...` 调用，shebang 不会生效；dash 不支持 pipefail，故自动改由 bash 执行。
if [ -z "${BASH_VERSION-}" ]; then
	exec bash "$0" "$@"
fi
set -euo pipefail

MARKER="# managed-by: vpndns init-highconcurrency-os.sh"
SYSCTL_MAIN="/etc/sysctl.d/99-vpndns-highconcurrency.conf"
SYSCTL_CONNTRACK="/etc/sysctl.d/99-vpndns-conntrack.conf"
LIMITS_PAM="/etc/security/limits.d/99-vpndns-nofile.conf"
SYSTEMD_MANAGER_D="/etc/systemd/system.conf.d"
SYSTEMD_DROPIN="${SYSTEMD_MANAGER_D}/99-vpndns-default-limits.conf"

NOFILE_LIMIT="1048576"
FILE_MAX="2097152"
CONNTRACK_MAX="1048576"

SYSCTL_ONLY=false
APPLY_RUNTIME=false
TAKEOVER=false

usage() {
	sed -n '2,12p' "$0"
	exit 0
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	-h | --help) usage ;;
	--sysctl-only) SYSCTL_ONLY=true ;;
	--apply-runtime) APPLY_RUNTIME=true ;;
	--takeover) TAKEOVER=true ;;
	*)
		echo "未知参数: $1" >&2
		sed -n '2,12p' "$0" >&2
		exit 1
		;;
	esac
	shift
done

if [[ "$(id -u)" -ne 0 ]]; then
	echo "请使用 root 执行: sudo $0" >&2
	exit 1
fi

# ---------- 工具 ----------

# 文件是否由本脚本管理：不存在，或含 MARKER
is_managed_file() {
	local f=$1
	[[ ! -f "$f" ]] && return 0
	grep -qF "$MARKER" "$f" 2>/dev/null
}

# 非本脚本管理的已存在文件：默认中止，避免多次执行搞混
assert_managed_or_takeover() {
	local f=$1
	is_managed_file "$f" && return 0
	if [[ "$TAKEOVER" != true ]]; then
		echo "[中止] 以下文件已存在且不含本脚本标记，为避免覆盖他人配置已停止: $f" >&2
		echo "        若确认要覆盖，请先备份后使用: $0 --takeover ..." >&2
		exit 2
	fi
	local bak="${f}.foreign.bak.$(date +%Y%m%d%H%M%S)"
	cp -a "$f" "$bak"
	echo "[takeover] 已备份外置配置 -> $bak"
	return 0
}

# 写入 f：与 stdin 内容一致则跳过（不备份、不触碰）；有变化才备份再写入。返回 0=已写入 1=未变化
write_if_changed() {
	local f=$1
	local tmp
	tmp="$(mktemp)"
	cat >"$tmp"
	if [[ -f "$f" ]] && cmp -s "$tmp" "$f"; then
		rm -f "$tmp"
		echo "[skip] 内容与目标一致，跳过写入: $f"
		return 1
	fi
	if [[ -f "$f" ]]; then
		cp -a "$f" "${f}.bak.$(date +%Y%m%d%H%M%S)"
	fi
	install -m 0644 -o root -g root "$tmp" "$f"
	rm -f "$tmp"
	echo "[ok] 已写入: $f"
	return 0
}

# 规范化 sysctl 多值（tab/多空格 -> 单空格）
_normalize_sysctl_val() {
	echo "$1" | tr '\t' ' ' | tr -s ' ' | sed 's/^ //;s/ $//'
}

# 检测主 sysctl 集运行时值是否已满足目标（满足则无需为了运行时再去 sysctl -p）
runtime_main_ok() {
	local cur a b
	cur=$(sysctl -n fs.file-max 2>/dev/null) || return 1
	[[ "${cur}" -ge "${FILE_MAX}" ]] || return 1

	sysctl -n net.core.rmem_max 2>/dev/null | grep -qx '8388608' || return 1
	sysctl -n net.core.wmem_max 2>/dev/null | grep -qx '8388608' || return 1
	sysctl -n net.core.rmem_default 2>/dev/null | grep -qx '262144' || return 1
	sysctl -n net.core.wmem_default 2>/dev/null | grep -qx '262144' || return 1
	sysctl -n net.core.netdev_max_backlog 2>/dev/null | grep -qx '16384' || return 1
	sysctl -n net.core.somaxconn 2>/dev/null | grep -qx '4096' || return 1
	sysctl -n net.ipv4.tcp_max_syn_backlog 2>/dev/null | grep -qx '8192' || return 1
	sysctl -n net.ipv4.tcp_tw_reuse 2>/dev/null | grep -qx '1' || return 1

	a=$(_normalize_sysctl_val "$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null || echo '')")
	[[ "$a" == "1024 65535" ]] || return 1
	return 0
}

runtime_conntrack_ok() {
	[[ -r /proc/sys/net/netfilter/nf_conntrack_max ]] || return 0
	local cur
	cur=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null) || return 1
	[[ "${cur}" -ge "${CONNTRACK_MAX}" ]]
}

apply_sysctl_files() {
	local err=0
	if [[ -f "$SYSCTL_MAIN" ]]; then
		echo "[apply] sysctl -p $SYSCTL_MAIN"
		sysctl -p "$SYSCTL_MAIN" || err=1
	fi
	if [[ -f "$SYSCTL_CONNTRACK" ]] && [[ -r /proc/sys/net/netfilter/nf_conntrack_max ]]; then
		echo "[apply] sysctl -p $SYSCTL_CONNTRACK"
		sysctl -p "$SYSCTL_CONNTRACK" || err=1
	fi
	return "$err"
}

render_sysctl_main() {
	cat <<EOF
${MARKER}
# 参见仓库: 高并发系统优化说明.md

# 全局限额：避免进程 nofile 足够仍因 file-max 失败
fs.file-max = ${FILE_MAX}

# 套接字接收/发送缓冲上限（需 >= 应用 setsockopt；本服务 UDP 约 4MiB）
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# 网卡入队 backlog
net.core.netdev_max_backlog = 16384

# TCP DoH / 管理端口
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192

# 大量短连接场景（行为随内核版本而异，生产前请查阅发行版说明）
net.ipv4.tcp_tw_reuse = 1

# 本机作为客户端访问上游时的临时端口范围
net.ipv4.ip_local_port_range = 1024 65535
EOF
}

# ---------- 1) sysctl 主文件 ----------

WROTE_SYSCTL_MAIN=false
assert_managed_or_takeover "$SYSCTL_MAIN"
if render_sysctl_main | write_if_changed "$SYSCTL_MAIN"; then
	WROTE_SYSCTL_MAIN=true
fi

# ---------- 2) conntrack（仅模块已加载时写 drop-in；未加载不写新文件，避免无意义条目）----------

WROTE_SYSCTL_CT=false
if [[ -r /proc/sys/net/netfilter/nf_conntrack_max ]]; then
	assert_managed_or_takeover "$SYSCTL_CONNTRACK"
	if write_if_changed "$SYSCTL_CONNTRACK" <<EOF
${MARKER}
# 高 QPS 下防 conntrack 表打满（按内存与策略调整）
net.netfilter.nf_conntrack_max = ${CONNTRACK_MAX}
EOF
	then
		WROTE_SYSCTL_CT=true
	fi
else
	if [[ -f "$SYSCTL_CONNTRACK" ]]; then
		if is_managed_file "$SYSCTL_CONNTRACK"; then
			echo "[info] nf_conntrack 未加载，保留已落盘的 ${SYSCTL_CONNTRACK}（重启后若加载模块仍会生效）"
		else
			echo "[info] nf_conntrack 未加载，且 ${SYSCTL_CONNTRACK} 非本脚本管理，未改动"
		fi
	fi
fi

# ---------- 3) 决定是否执行 sysctl -p（仅刷本脚本 drop-in，避免无谓的全量 sysctl --system）----------

RUNTIME_MAIN_OK=false
if runtime_main_ok; then
	RUNTIME_MAIN_OK=true
	echo "[check] 主 sysctl 运行时已满足目标"
else
	echo "[check] 主 sysctl 运行时与目标不一致（或不可读）"
fi

RUNTIME_CT_OK=false
if runtime_conntrack_ok; then
	RUNTIME_CT_OK=true
	echo "[check] conntrack 运行时已满足目标或未启用"
else
	echo "[check] conntrack 运行时尚未达到目标"
fi

SHOULD_APPLY_SYSCTL=false
if [[ "$WROTE_SYSCTL_MAIN" == true || "$WROTE_SYSCTL_CT" == true ]]; then
	SHOULD_APPLY_SYSCTL=true
	echo "[plan] 持久文件有更新，将应用本脚本 sysctl drop-in"
elif [[ "$APPLY_RUNTIME" == true ]]; then
	SHOULD_APPLY_SYSCTL=true
	echo "[plan] 指定了 --apply-runtime，将应用本脚本 sysctl drop-in"
elif [[ "$RUNTIME_MAIN_OK" == false || "$RUNTIME_CT_OK" == false ]]; then
	echo "[hint] 持久配置可能已在磁盘中正确，但运行时尚未同步。"
	echo "       若需立即生效（不改文件）请执行: $0 --apply-runtime"
fi

if [[ "$SHOULD_APPLY_SYSCTL" == true ]]; then
	if ! apply_sysctl_files; then
		echo "[warn] 部分 sysctl 应用失败（可能被其他配置覆盖或内核不支持某项）" >&2
	fi
	# 再验一次
	if runtime_main_ok; then echo "[verify] 主 sysctl 运行时已满足"; else echo "[warn] 主 sysctl 仍有偏差，请检查是否被其他 sysctl.d 覆盖"; fi
	if runtime_conntrack_ok; then echo "[verify] conntrack 已满足或未启用"; else echo "[warn] conntrack 未达标"; fi
fi

if [[ "$SYSCTL_ONLY" == true ]]; then
	echo "[done] --sysctl-only 结束。"
	exit 0
fi

# ---------- 4) limits.d ----------

WROTE_LIMITS=false
assert_managed_or_takeover "$LIMITS_PAM"
if write_if_changed "$LIMITS_PAM" <<EOF
${MARKER}
* soft nofile ${NOFILE_LIMIT}
* hard nofile ${NOFILE_LIMIT}
root soft nofile ${NOFILE_LIMIT}
root hard nofile ${NOFILE_LIMIT}
EOF
then
	WROTE_LIMITS=true
fi

# ---------- 5) systemd Manager 默认 LimitNOFILE ----------

WROTE_SYSTEMD=false
install -d -m 0755 -o root -g root "$SYSTEMD_MANAGER_D"
assert_managed_or_takeover "$SYSTEMD_DROPIN"
if write_if_changed "$SYSTEMD_DROPIN" <<EOF
${MARKER}
# 与 deploy/vpndns-server.service 中 LimitNOFILE 对齐；未单独配置的服务也可继承
[Manager]
DefaultLimitNOFILE=${NOFILE_LIMIT}:${NOFILE_LIMIT}
EOF
then
	WROTE_SYSTEMD=true
fi

if [[ "$WROTE_SYSTEMD" == true ]] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload
	echo "[ok] systemd drop-in 有变更，已执行 daemon-reload"
elif command -v systemctl >/dev/null 2>&1; then
	echo "[skip] systemd drop-in 无变化，未执行 daemon-reload"
fi

# ---------- 小结 ----------

echo "[done] 本次变更: sysctl主文件=${WROTE_SYSCTL_MAIN} conntrack=${WROTE_SYSCTL_CT} limits=${WROTE_LIMITS} systemd=${WROTE_SYSTEMD} 已刷运行时=${SHOULD_APPLY_SYSCTL}"
echo "      服务 unit 仍建议显式 LimitNOFILE=${NOFILE_LIMIT}（见 deploy/vpndns-server.service）"
