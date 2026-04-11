# 部署指南

源码仓库：**[https://github.com/hk59775634/vpndns-server](https://github.com/hk59775634/vpndns-server)**。生产与集成测试建议统一使用 **`/etc/vpndns/config.yaml`**（下文 §3、systemd 示例与此一致）。

Docker Hub 仓库 **Overview** 正文源文件见 **[DOCKERHUB-OVERVIEW.md](./DOCKERHUB-OVERVIEW.md)**；可用 `DOCKERHUB_PASSWORD=… ./scripts/dockerhub-update-overview.sh` 推送到 Hub（需 `curl`/`jq`）。

## 1. 环境要求

- Linux（推荐）或类 Unix
- **Redis** 5+（持久化白名单、DNS 缓存、VIP 映射、可选统计持久化）
- 可写配置路径（热加载与 UI 保存）

## 2. 编译

```bash
git clone https://github.com/hk59775634/vpndns-server.git
cd vpndns-server
go build -ldflags="-s -w" -o vpndns-server ./cmd/server
sudo install -m 0755 vpndns-server /usr/local/bin/
```

## 3. 配置

复制并编辑：

```bash
sudo mkdir -p /etc/vpndns
sudo cp configs/config.example.yaml /etc/vpndns/config.yaml
# 若你已在仓库内维护好 configs/config.yaml，也可改为复制该文件
sudo chmod 600 /etc/vpndns/config.yaml
```

关键项：

- `redis.*`：地址与密码
- `listen.*`：DNS / DoH / 管理端口
- `cn_dns` / `out_dns`：至少各一条上游
- `mapper.api_url`：可留空。**留空时**不调用映射 API，也**不会**用本机公网探测去写 VIP→realIP（仅 Redis `vip:*` 命中或回退为解析 VIP 字面 IP）；需要外呼映射时请填写 **GET** API（查询参数 `ip`）。`mapper.public_ip_probe_url` 仍可在配置中存在，但不再用于上述 VIP 回填。
- DoH TLS：`listen.doh_tls: true` 且任选其一  
  - `listen.tls_cert` + `listen.tls_key`（文件路径）  
  - `listen.tls_cert_pem` + `listen.tls_key_pem`（YAML 多行 PEM）

配置文件路径（优先级从高到低）：

1. 命令行 **`-config <path>`**（例：`vpndns-server -config /etc/vpndns/config.yaml`）
2. 环境变量 **`CONFIG`**
3. 默认 **`configs/config.yaml`**（相对当前工作目录）

## 4. systemd

仓库提供示例单元 **`deploy/vpndns-server.service`**，用于以 **systemd** 托管进程：开机自启、崩溃自动拉起（`Restart=on-failure`）、以及高并发所需的 **`LimitNOFILE=1048576`**（与 `scripts/init-highconcurrency-os.sh`、文档《高并发系统优化说明》一致思路）。

### 4.1 单元文件在做什么

| 段 / 指令 | 作用 |
|-----------|------|
| `After=network-online.target` / `Wants=network-online.target` | 尽量在网络就绪后再启动（上游/Redis 需可达时更稳）。 |
| `Environment=CONFIG=/etc/vpndns/config.yaml` | 通过环境变量指定配置文件（见上文「配置路径优先级」：`CONFIG` 为第二优先级）。 |
| `ExecStart=/usr/local/bin/vpndns-server` | 启动命令；未写 `-config` 时使用 `CONFIG`。也可改为显式 `ExecStart=/usr/local/bin/vpndns-server -config /etc/vpndns/config.yaml`（`-config` 优先级高于 `CONFIG`）。 |
| `Restart=on-failure` / `RestartSec=5` | 异常退出后 5 秒重试。 |
| `LimitNOFILE=1048576` | 进程文件描述符软/硬上限，**高 QPS 建议保留或按需加大**；仍需保证系统侧 `fs.file-max` 等足够（见《高并发系统优化说明》）。 |
| `# User=` / `# Group=` | 默认注释掉即以 root 运行；生产建议取消注释并改为专用用户，且保证该用户对配置与 TLS 私钥有读权限。 |

服务名由单元文件名决定：复制为 `/etc/systemd/system/vpndns-server.service` 后，unit 名为 **`vpndns-server`**。

### 4.2 安装与启用（首次）

1. 按 §2 将二进制安装到 **`/usr/local/bin/vpndns-server`**（或修改单元里 `ExecStart` 为实际路径）。  
2. 按 §3 准备好 **`/etc/vpndns/config.yaml`**，并与单元中的 **`CONFIG`** 或 **`ExecStart -config`** 一致。  
3. 安装单元并重载、启动：

```bash
sudo cp deploy/vpndns-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable vpndns-server    # 开机自启
sudo systemctl start vpndns-server     # 立即启动
```

4. 查看状态与日志：

```bash
systemctl status vpndns-server
journalctl -u vpndns-server -f
```

### 4.3 修改配置后

- 若只改了 **YAML 文件**：本服务支持 **配置热加载**（fsnotify），多数情况下 **无需** `systemctl restart`；监听地址等需重启进程的项除外。  
- 若改了 **单元文件**（`ExecStart`、`Environment`、`LimitNOFILE` 等）：

```bash
sudo systemctl daemon-reload
sudo systemctl restart vpndns-server
```

### 4.4 用 drop-in 覆盖（推荐）

尽量不直接改 `/etc/systemd/system/vpndns-server.service`，而用 **`systemctl edit`** 生成覆盖片段，便于升级仓库时重新 `cp` 示例文件而不丢本地改动：

```bash
sudo systemctl edit vpndns-server
```

在打开的编辑器中写入例如：

```ini
[Service]
Environment=CONFIG=/etc/vpndns/prod.yaml
LimitNOFILE=2097152
```

保存后执行 `sudo systemctl daemon-reload && sudo systemctl restart vpndns-server`。

### 4.5 停用与卸载

```bash
sudo systemctl disable --now vpndns-server
sudo rm /etc/systemd/system/vpndns-server.service
# 若曾使用 systemctl edit，可一并删除 /etc/systemd/system/vpndns-server.service.d/
sudo systemctl daemon-reload
```

## 5. Docker Hub 与 Compose

官方多架构镜像（**linux/amd64、linux/arm64、linux/arm/v7**）：

- **Docker Hub：** [hk59775634/vpndns-server](https://hub.docker.com/r/hk59775634/vpndns-server)
- **源码 / Issue：** [https://github.com/hk59775634/vpndns-server](https://github.com/hk59775634/vpndns-server)

**标签策略：** 每次正式发版同时推送 **`:vX.Y.Z`** 与 **`:latest`**（见 `scripts/docker-buildx-push.sh` 顶部说明）。**`:v*`** 标签长期保留，不在 Hub 上删除旧版本，便于回滚与审计；生产请在 Compose/K8s 中写死 `image: ...:v1.0.5` 等。

```bash
# 固定版本（推荐生产）
docker pull hk59775634/vpndns-server:v1.0.5

# 最新构建（与当前主线发版一致）
docker pull hk59775634/vpndns-server:latest
```

容器内需 **外置 Redis**，并将 **`CONFIG`** 指向挂载的配置文件（默认 `/etc/vpndns/config.yaml`）。仓库根目录 **`docker-compose.yml`** 提供 Redis + `vpndns` 的示例（默认映射 DNS 到主机 **5353**，避免绑定主机 53 需 root）：

```bash
docker compose up -d
# dig @127.0.0.1 -p 5353 example.com
```

维护者构建并推送（**必须带 VERSION**，以同时得到 `vX.Y.Z` 与 `latest`）：

```bash
docker login
VERSION=v1.0.5 ./scripts/docker-buildx-push.sh
# 或当前目录已打 git 标签时：
# USE_GIT_TAG=1 ./scripts/docker-buildx-push.sh
```

## 6. 防火墙与安全

- 仅对可信网络开放 DNS/DoH；管理端口建议仅内网或 SSH 隧道
- 生产务必设置 `admin.api_key`，并为 DoH 配置 TLS + 可选 `doh_auth`

### 6.1 每 IP 限速（`rate_limit`）

在 **`config.yaml` → `rate_limit`** 中配置（支持热加载）：

| 字段 | 含义 |
|------|------|
| **`qps_per_ip`** | 每个源 IP 的令牌桶补充速率（可持续 QPS）。**`0` = 关闭每 IP 限速**（不限）。未写该项时由程序默认（当前为 **500**）。 |
| **`burst`** | 桶容量，即允许的突发查询条数上限。**在 `qps_per_ip > 0` 时，`0` = 不限制突发**（实现为极大桶深）。在 **`qps_per_ip` 为 0** 时本字段无意义。未写时默认 **1000**。 |
| **`per_ip_limiter_idle_minutes`** | 某 IP 长时间无请求后回收其限流状态；`≤0` 时按内置默认（20 分钟）。 |

**示例 — 完全关闭每 IP 限速：**

```yaml
rate_limit:
    qps_per_ip: 0
    burst: 0
```

**示例 — 限制平均 2000/s，但允许极大突发：**

```yaml
rate_limit:
    qps_per_ip: 2000
    burst: 0
```

修改后若已启用配置热加载，一般无需重启；也可在控制台保存配置或 `reload` 触发。

**说明**：这与 **`resolver.global_resolve_qps`**（全局限流）不同；全局限流为进程级，见配置中 `global_resolve_qps` / `global_resolve_burst`（其中 **`global_resolve_qps: 0` 表示关闭**）。

## 7. 升级

```bash
sudo systemctl stop vpndns-server
# 替换二进制
sudo systemctl start vpndns-server
```

配置兼容时可直接启动；监听/Redis 变更通常需重启进程。

## 8. 监控

见 [PROMETHEUS.md](PROMETHEUS.md)。控制台「监控面板」可查看 `/api/v1/meta` 与 `/metrics` 链接。
