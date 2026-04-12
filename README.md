# VPN DNS SERVER

智能 DNS：国内/海外双上游、白名单、Redis 缓存、DoH、VIP 映射、GeoIP 分流与 Web 控制台。

| 资源 | 链接 |
|------|------|
| 源码 | [https://github.com/hk59775634/vpndns-server](https://github.com/hk59775634/vpndns-server) |
| 预编译二进制 | [GitHub Releases](https://github.com/hk59775634/vpndns-server/releases)（`SHA256SUMS.txt`） |
| 容器镜像 | [Docker Hub — hk59775634/vpndns-server](https://hub.docker.com/r/hk59775634/vpndns-server)（`linux/amd64`、`arm64`、`arm/v7`） |
| Hub Overview 源文件 | 仓库内 [docs/DOCKERHUB-OVERVIEW.md](docs/DOCKERHUB-OVERVIEW.md)（可粘贴到 Hub 或使用 `scripts/dockerhub-update-overview.sh` 同步） |

**版本标签：** 每个正式版同时推送 **`:vX.Y.Z`** 与 **`:latest`**；生产建议固定 **`image: …:v1.0.6`**。维护者发版：`docker login` 后 `VERSION=v1.x.x ./scripts/docker-buildx-push.sh`；二进制打包：`RELEASE_USE_DOCKER=1 ./scripts/release-build.sh v1.x.x`（需 Docker；本机 Go 1.22+ 也可直接跑该脚本）。

```bash
docker pull hk59775634/vpndns-server:v1.0.6
# docker compose up -d   # 见 docker-compose.yml
```

## 功能摘要

- **DNS / DoH**：UDP/TCP DNS；DoH 可选 TLS（证书文件或 PEM 内联）
  - **RFC 8484（Cloudflare 类）**：`POST /dns-query`，`application/dns-message`
  - **Google JSON**：`GET /resolve?name=&type=`，`application/dns-json`（与 [Google 公共 DNS JSON](https://developers.google.com/speed/public-dns/docs/doh/json) 形态兼容）
- **管理**：Web UI + REST API（`listen.admin`）
- **VIP 映射**：`mapper.api_url` 非空时走 HTTP 查询；**留空时不再用本机公网探测填充 `vip:*` 映射**（仅 Redis 命中或解析 VIP 本身），避免误占 `default_cn_ecs` 保底路径
- **GeoIP**：中国 CIDR；IPv4 **区间合并 + 二分查找**
- **观测**：进程内统计、可选 Redis 持久化、Prometheus **`/metrics`**
- **其它**：缓存预热、配置热加载（fsnotify）、UI 全量编辑

## 快速开始

```bash
git clone https://github.com/hk59775634/vpndns-server.git
cd vpndns-server
cp configs/config.example.yaml configs/config.yaml
# 编辑 configs/config.yaml
go build -o vpndns-server ./cmd/server
./vpndns-server -config configs/config.yaml
```

| 配置来源 | 说明 |
|----------|------|
| **`-config <path>`** | 最高优先级 |
| **`CONFIG` 环境变量** | 次之 |
| 默认 | 仓库内运行时：`configs/config.yaml`（相对工作目录） |

**部署 / 测试常用路径：** **`/etc/vpndns/config.yaml`**（与 `deploy/vpndns-server.service` 一致）。

```bash
sudo mkdir -p /etc/vpndns
sudo cp configs/config.example.yaml /etc/vpndns/config.yaml
sudo chmod 600 /etc/vpndns/config.yaml
sudo vpndns-server -config /etc/vpndns/config.yaml
```

依赖 **Redis**。勿将含密钥的 `config.yaml` 提交到 Git（已 `.gitignore`）。Compose 示例：`configs/docker-compose.config.yaml`；完整部署见 **[docs/DEPLOY.md](docs/DEPLOY.md)**。

## 压测参考（非承诺）

下列数字受 **上游、Redis、缓存命中、`rate_limit`、CPU** 等影响，**不是 SLA**。使用 **`/etc/vpndns/config.yaml`** 时，**`-addr` / `-url` 必须与配置中的 `listen.udp`、`listen.doh` 一致**，勿照搬示例端口。

### UDP/53 — `cmd/udpbench`

对指定 **`host:port`** 发送 **UDP** DNS 查询，粗测单机吞吐。

| 模式 | 说明 | 典型用法 |
|------|------|----------|
| **flood** | `-qps 0`，多 worker 并发 `Exchange`，尽力打满 | `-w 400 -qps 0` |
| **定 QPS** | 全局 `rate.Limiter` + 多 worker，避免单 worker 被 RTT 拖死 | `-qps 100000 -w 8000 -timeout 15s` |

```bash
go build -o udpbench ./cmd/udpbench
./udpbench -addr 127.0.0.1:53 -domain example.com. -d 30s -w 400 -qps 0
./udpbench -addr 127.0.0.1:53 -domain example.com. -d 40s -qps 100000 -w 8000 -timeout 15s
```

**一次粗测（仅供参考）：** 环回、重复查询同域名、**已放宽** `rate_limit.qps_per_ip`：

| 场景 | 成功 QPS（约） | 备注 |
|------|----------------|------|
| 尽力打满 | **3.3 万 ～ 4 万+** | 与业务比例强相关 |
| 目标 **10 万** QPS | **未达到** | 延迟明显上升；更高需多实例、LB、更强硬件等 |

### DoH — `cmd/dohbench`

与 `udpbench` 相同：**`-qps 0` flood** 或 **`-qps N` 定目标速率**，多 worker 并发 HTTP。用 **`-style`** 区分服务端点。

| `-style` | 说明 | 典型 `-url` |
|----------|------|-------------|
| **`rfc8484`**（默认） | **POST** `application/dns-message`（RFC 8484 / Cloudflare 类） | `http://127.0.0.1:8053/dns-query` |
| **`google`** | **GET** `application/dns-json`（`/resolve`） | `http://127.0.0.1:8053/resolve` 或根 URL（工具会补 `/resolve`） |

```bash
go build -o dohbench ./cmd/dohbench
./dohbench -style rfc8484 -url http://127.0.0.1:8053/dns-query -domain example.com. -d 30s -w 200 -qps 0
./dohbench -style google   -url http://127.0.0.1:8053/resolve   -domain example.com. -d 30s -w 200 -qps 0
./dohbench -style rfc8484 -url https://127.0.0.1:8053/dns-query -domain example.com. -d 20s -w 200 -qps 0 -k
./dohbench -style rfc8484 -url http://127.0.0.1:8053/dns-query -domain example.com. -d 40s -qps 5000 -w 500 -timeout 20s
```

启用 **`doh_auth`** 时加 **`-token <bearer>`**。

**一次粗测（仅供参考）：** 服务使用仓库内 **`configs/bench-100k.yaml`**（放宽 `rate_limit`、DoH **`:18553` 明文**），查询 **`example.com.` A**，**flood**、**200** workers、**15s**。若改用 **`/etc/vpndns/config.yaml`**，下表仅作量级参考，**端口多为 `:8053`**，与 bench 配置的 `:18553` 不同。

| 样式 | 成功 QPS（约） | 平均成功延迟（约） |
|------|----------------|---------------------|
| `rfc8484` `POST /dns-query` | **~7.9k** | **~25ms** |
| `google` `GET /resolve` | **~8.9k** | **~22ms** |

**对比：** DoH 经 TCP/TLS + HTTP，同硬件下单机 QPS 通常 **低于** UDP/53；与 HTTP/2、TLS、上游路径有关。

## 文档

| 文档 | 说明 |
|------|------|
| [CHANGELOG.md](CHANGELOG.md) | 版本更新 |
| [docs/API.md](docs/API.md) | REST API |
| [docs/DEPLOY.md](docs/DEPLOY.md) | 部署与 systemd |
| [docs/PROMETHEUS.md](docs/PROMETHEUS.md) | Prometheus / Grafana |

## 关于 Bloom Filter 与 GeoIP

当前使用 **IPv4 区间合并 + 二分查找** 命中大陆网段，与全量 CIDR 结果一致。Bloom Filter 在 CIDR 粒度下易产生假阴性，故未作默认路径。

## 许可证

按项目需要自行补充。
