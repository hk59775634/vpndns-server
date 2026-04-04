# 更新日志

本文件记录 **vpndns-server** 各版本的用户可见变更。语义化版本：`MAJOR.MINOR.PATCH`。

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
- 平台：**linux/amd64**、**linux/arm64**、**linux/arm/v7**；标签 **`latest`** 与 **`v1.0.1`** 等与 Git 标签一致（由 `VERSION=v1.x.x ./scripts/docker-buildx-push.sh` 推送）。
- `Dockerfile` 增加 OCI `org.opencontainers.image.*` 标签（源码、说明、版本），便于与 [GitHub 仓库](https://github.com/hk59775634/vpndns-server) 关联。

---

## [1.0.0] — 2026-04-04

- 首个带 **GitHub Releases** 多架构预编译二进制（见 Release 资产与 `SHA256SUMS.txt`）。
- 构建脚本：`scripts/release-build.sh`（可选 `RELEASE_USE_DOCKER=1` 在 Docker 内用 Go 1.22 交叉编译）。
