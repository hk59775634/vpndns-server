# vpndns-server

**智能 DNS**：国内/海外双上游、白名单、Redis 缓存、DoH（RFC 8484 + Google JSON）、VIP 映射、GeoIP 分流与 Web 管理控制台。

## 源码与发行

| 资源 | 链接 |
|------|------|
| **GitHub 源码** | [https://github.com/hk59775634/vpndns-server](https://github.com/hk59775634/vpndns-server) |
| **Release 与二进制** | [https://github.com/hk59775634/vpndns-server/releases](https://github.com/hk59775634/vpndns-server/releases) |
| **部署文档** | 仓库内 [docs/DEPLOY.md](https://github.com/hk59775634/vpndns-server/blob/main/docs/DEPLOY.md) |

**镜像标签**：每个正式版推送 **`:vX.Y.Z`** 与 **`:latest`**。生产环境请固定版本号，例如 **`hk59775634/vpndns-server:v1.0.5`**，勿仅依赖 `:latest`。

**平台**：`linux/amd64`、`linux/arm64`、`linux/arm/v7`。

---

## Docker 快速部署

### 1. 仅拉取镜像（自行编排）

```bash
docker pull hk59775634/vpndns-server:v1.0.5
```

容器内需挂载 **配置文件**（YAML），并保证进程能访问 **Redis**（与同 compose 中的 `redis` 服务或外部 Redis）。

启动示例（请按实际路径修改配置与 Redis 地址）：

```bash
docker run -d --name vpndns --restart unless-stopped \
  -p 5353:53/udp -p 5353:53/tcp -p 8053:8053 -p 8080:8080 \
  -v /path/to/your/config.yaml:/etc/vpndns/config.yaml:ro \
  hk59775634/vpndns-server:v1.0.5
```

配置模板可从 GitHub 复制：[configs/config.example.yaml](https://github.com/hk59775634/vpndns-server/blob/main/configs/config.example.yaml)。生产建议路径 **`/etc/vpndns/config.yaml`**，详见 DEPLOY 文档。

### 2. Docker Compose（仓库自带示例）

克隆仓库后使用根目录 **`docker-compose.yml`**（内含 Redis + vpndns，默认映射主机 **5353** DNS、**8053** DoH、**8080** 管理端）：

```bash
git clone https://github.com/hk59775634/vpndns-server.git
cd vpndns-server
# 编辑 configs/docker-compose.config.yaml（Redis、上游、listen 等）
docker compose up -d
```

默认将示例配置挂载为容器内 **`/etc/vpndns/config.yaml`**。升级镜像版本时，将 compose 中 **`image:`** 改为目标 **`hk59775634/vpndns-server:vX.Y.Z`** 后执行 `docker compose pull && docker compose up -d`。

### 3. 配置要点（简要）

- **`redis.*`**：地址与密码（Compose 示例中 Redis 服务名一般为 **`redis`**）。
- **`listen.*`**：DNS / DoH / 管理端口与可选 TLS。
- **`cn_dns` / `out_dns`**：至少各配置一条上游；HTTPS 上游可选 **`doh_mode`**：`auto` / `rfc8484` / `json_get`（Google JSON 须 `…/url` 以 **`/resolve`** 结尾）。

更多字段说明见 **`configs/config.example.yaml`** 与 **[docs/DEPLOY.md](https://github.com/hk59775634/vpndns-server/blob/main/docs/DEPLOY.md)**（含 systemd、目录权限、高并发建议等）。

---

## 维护者构建多架构镜像

在已 **`docker login`** 的机器上，于源码根目录执行（将版本号替换为实际发版号）：

```bash
VERSION=v1.0.5 ./scripts/docker-buildx-push.sh
```

脚本会同时推送 **`:vX.Y.Z`** 与 **`:latest`**。详见仓库 **`scripts/docker-buildx-push.sh`** 头部说明。
