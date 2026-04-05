# 更新日志

本文件记录 **vpndns-server** 各版本的用户可见变更。语义化版本：`MAJOR.MINOR.PATCH`。

## [未发布]

### 新增

- `cmd/udpbench`：UDP/53 压测小工具（`-qps` 定目标速率或多 worker flood）。
- DoH：**Google JSON** `GET /resolve?name=&type=`（`application/dns-json`），与 [Google 公共 DNS JSON](https://developers.google.com/speed/public-dns/docs/doh/json) 形态兼容；与既有 **RFC 8484** `POST /dns-query` 共用鉴权、限流与解析路径。
- `cmd/dohbench`：支持 `-style rfc8484|google` 分别压测上述两种端点；`README` 含 `bench-100k.yaml` 下本机粗测 QPS 参考。

### 文档

- `README.md`：增加 **UDP/53 QPS 压测参考**，说明 `cmd/udpbench` 用法与一次本机粗测结论（非性能承诺）。
- `README.md`：DoH 双标准说明与 **DoH 压测参考**（`cmd/dohbench`、两种 style 及粗测表）。
- `README.md`、`docs/DEPLOY.md`、`deploy/vpndns-server.service`：源码地址统一为 **https://github.com/hk59775634/vpndns-server**；测试/部署推荐 **`/etc/vpndns/config.yaml`**，并说明与 `listen.*` 对应的压测参数。

## [1.0.1] — 2026-04-04

### 性能

- **上游查询合并**：新增 `resolver.coalesce_upstream`（默认 `true`）。对相同 ECS 缓存维度与上游 ECS 参数的并发 **CN / OUT** 查询使用 `singleflight` 合并为单次回源，减轻缓存未命中时的惊群。合并执行使用基于 `query_timeout_ms` 的独立 deadline；若需完全按客户端 `context` 取消上游，可设为 `false`。
- **每 IP 限流分片**：`rate_limit` 仍为每 IP 令牌桶，内部按客户端 IP 哈希拆成 **256** 把分片锁，降低极高并发下原全局互斥锁的热点。
- **Redis 连接池可配置**：`redis.pool_size`、`redis.min_idle_conns`、`redis.pool_fifo`（默认与此前行为一致：256 / 32 / FIFO）。**修改后需重启进程** 方可生效。
- **Mapper HTTP 连接池可配置**：`mapper.http_max_idle_conns`、`mapper.http_max_idle_conns_per_host`（默认 **128** / **32**），热加载配置时会重建外呼 `api_url` 的 HTTP 客户端。

### 行为

- **解析超时**：UDP/TCP DNS 对单次解析使用 `query_timeout_ms` 再加 **300ms** 余量的 `context` 调用 `Resolve`，避免在慢上游或排队时协程长时间悬挂。DoH 在请求 `context` 与 `query_timeout_ms` 之间取更紧的截止时间。

### 文档与示例

- `configs/config.example.yaml` 补充上述新字段说明。

### 容器镜像（Docker Hub）

- 官方镜像：[hub.docker.com/r/hk59775634/vpndns-server](https://hub.docker.com/r/hk59775634/vpndns-server)
- 平台：**linux/amd64**、**linux/arm64**、**linux/arm/v7**。
- **标签策略：** 每个正式版本同时推送 **`:vX.Y.Z`** 与 **`:latest`**（`VERSION=v1.x.x ./scripts/docker-buildx-push.sh` 或 `USE_GIT_TAG=1`）；**历史 `v*` 标签保留在 Hub**，便于固定版本与回滚。
- `scripts/docker-buildx-push.sh` 头部约定上述策略；未设置 `VERSION` 时仅推 `latest` 并打印警告。
- `Dockerfile` 增加 OCI `org.opencontainers.image.*` 标签（源码、说明、版本），便于与 [GitHub 仓库](https://github.com/hk59775634/vpndns-server) 关联。

---

## [1.0.0] — 2026-04-04

- 首个带 **GitHub Releases** 多架构预编译二进制（见 Release 资产与 `SHA256SUMS.txt`）。
- 构建脚本：`scripts/release-build.sh`（可选 `RELEASE_USE_DOCKER=1` 在 Docker 内用 Go 1.22 交叉编译）。
