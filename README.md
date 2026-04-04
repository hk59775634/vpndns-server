# VPN DNS SERVER

智能 DNS：国内/海外双上游、白名单、Redis 缓存、DoH、VIP 映射、GeoIP 分流与 Web 控制台。

**源码仓库：** [github.com/hk59775634/vpndns-server](https://github.com/hk59775634/vpndns-server)

**预编译二进制：** [GitHub Releases](https://github.com/hk59775634/vpndns-server/releases)（多架构压缩包与 `SHA256SUMS.txt`）。维护者打包：`RELEASE_USE_DOCKER=1 ./scripts/release-build.sh v1.x.x`（需 Docker；本机 Go 1.22+ 也可直接执行该脚本）。

## 功能摘要

- 监听：UDP/TCP DNS、DoH（可选 TLS，支持**证书文件路径**或 **PEM 内联**）
- 管理 UI + REST API（`listen.admin`）
- VIP 映射：`mapper.api_url` 为空时，Redis 未命中后使用**本机公网出口 IP**（可配置探测 URL，默认 `https://api.ipify.org`）
- GeoIP：中国 CIDR 列表；**IPv4 采用合并区间 + 二分查找**加速（大规模 CIDR 下显著优于线性扫描）
- 统计：进程内计数 + **可选 Redis 持久化**；**Prometheus** `/metrics`
- 缓存预热：启动时按配置域名预解析
- 配置热加载（fsnotify）与 UI 全量编辑

## 快速开始

```bash
git clone https://github.com/hk59775634/vpndns-server.git
cd vpndns-server
cp configs/config.example.yaml configs/config.yaml
# 编辑 configs/config.yaml（Redis、上游、证书等）
go build -o vpndns-server ./cmd/server
./vpndns-server -config configs/config.yaml
# 或：export CONFIG=configs/config.yaml && ./vpndns-server
```

配置文件路径：**`-config <path>`** 优先，其次环境变量 **`CONFIG`**，默认 `configs/config.yaml`。

依赖：**Redis**。仓库内请使用 **`configs/config.example.yaml`** 复制为 `configs/config.yaml`；**勿将含私钥与密钥的 `config.yaml` 提交到 Git**（已在 `.gitignore` 中忽略）。Docker Compose 可参考 `configs/docker-compose.config.yaml`。

## 文档

| 文档 | 说明 |
|------|------|
| [CHANGELOG.md](CHANGELOG.md) | 版本更新日志 |
| [docs/API.md](docs/API.md) | REST API 列表 |
| [docs/DEPLOY.md](docs/DEPLOY.md) | 部署与 systemd（含 `deploy/vpndns-server.service` 用法） |
| [docs/PROMETHEUS.md](docs/PROMETHEUS.md) | Prometheus / Grafana |

## 关于 Bloom Filter 与 GeoIP

当前实现使用 **IPv4 区间合并 + 二分查找** 做大陆网段命中，保证结果与全量 CIDR 匹配一致。Bloom Filter 若用于「可能在中国」的粗筛，在 CIDR 粒度下易产生假阴性，故未作为默认路径；若后续引入分层数据（例如国家级粗粒度集合 + 精确校验），可在该层叠加 Bloom。

## 许可证

按项目需要自行补充。
