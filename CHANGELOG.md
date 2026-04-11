# 更新日志

本文件记录 **vpndns-server** 各版本的用户可见变更。语义化版本：`MAJOR.MINOR.PATCH`。

## [未发布]

（尚无条目。）

## [1.0.4] — 2026-04-11

### 上游与 DoH

- 每个 HTTPS 上游可配置 **`doh_mode`**：`auto`（按 URL 是否以 `/resolve` 判断）、`rfc8484`（POST 二进制）、`json_get`（Google JSON GET，URL 须为 `…/resolve`）。
- 管理台上游表增加 **DoH 方式** 下拉框；`configs/config.example.yaml` 补充说明与示例。
- **`json_get` 查询日志**：记录发往上游的完整 GET URL（`name`、`type`、`edns_client_subnet` 等），控制台「查询过程」中展示 `cn_upstream_request_url` / `out_upstream_request_url`。
- **Google JSON `/resolve`**：固定附加 **`disable_dnssec=true`**，解析响应中的 **`edns_client_subnet`** 作为 Google 实际使用的 ECS 范围；**Redis ECS 缓存键**优先使用该回显（规范化后），无效（如 **`/0`**）时回退为请求参数或 `FromClientOrIP`。
- **Redis `dns:ecsmap:*`**：记录「发往 Google 的 `edns_client_subnet` 字符串 → 规范化后的回显范围」，便于后续请求命中与 Google 聚合一致的 ECS 缓存桶。

### 查询日志与解析

- 解析失败（SERVFAIL、上游错误等）仍写入 **`ResolveTrace`**（`ErrWithTrace`）：含客户端传输、ECS 前奏及失败原因；过载等无解析前奏时回退为仅传输层信息。
- 启动/保存配置时校验：`doh_mode` 为 `json_get` 时 URL 路径须以 **`/resolve`** 结尾。
- **国内上游合并键**：`singleflight` 使用 `cache.QTypeString` 与 Redis 键一致，避免 QTYPE 命名分叉。
- 抽取 **`queryCNWithECSTrace`**；读路径缓存键变量更名为 **`lookupECSKey`**（与写入 **`storeKey`** 区分）。

### 文档与镜像

- `README.md`、`docs/DEPLOY.md`、`docker-compose.yml`、脚本示例：示例镜像版本 **v1.0.4**。
- 新增 **`docs/resolve-query-logic.md`**：智能解析主路径、ECS 缓存与上游说明（含附录：已做/未采纳的优化项）。

## [1.0.3] — 2026-04-06

### 控制台

- Web 管理界面：云控制台风格布局（`#1677FF` 主色、可折叠侧栏、顶栏节点信息、用户菜单）；白名单数据表 + 右侧抽屉编辑/查看；统一 `openConfirm` 确认框；DNS 缓存表展示域名/类型/TTL/来源（由键名解析）。样式见 `cmd/server/web/static/css/console.css`，说明见 `docs/admin-ui-console.md`。

### 文档

- `docs/admin-ui-console.md`：控制台静态资源与组件结构说明。
- `README.md`、`docs/DEPLOY.md`、`docker-compose.yml`：示例镜像版本 **v1.0.3**。

## [1.0.2] — 2026-04-05

### 新增

- `cmd/udpbench`：UDP/53 压测小工具（`-qps` 定目标速率或多 worker flood）。
- DoH：**Google JSON** `GET /resolve?name=&type=`（`application/dns-json`），与 [Google 公共 DNS JSON](https://developers.google.com/speed/public-dns/docs/doh/json) 形态兼容；与既有 **RFC 8484** `POST /dns-query` 共用鉴权、限流与解析路径。
- `cmd/dohbench`：支持 `-style rfc8484|google` 分别压测上述两种端点；`README` 含 `bench-100k.yaml` 下本机粗测 QPS 参考。

### 文档

- `README.md`：**UDP/53** 与 **DoH** 压测说明（`udpbench` / `dohbench`、粗测结论，非性能承诺）。
- `README.md`：DoH 双标准（RFC 8484 + Google JSON）与资源链接表；结构优化便于 GitHub 阅读。
- `README.md`、`docs/DEPLOY.md`、`deploy/vpndns-server.service`：源码 **https://github.com/hk59775634/vpndns-server**；测试/部署推荐 **`/etc/vpndns/config.yaml`**，并说明与 `listen.*` 对应的压测参数。
- `README.md`、`docs/DEPLOY.md`、`docker-compose.yml`：示例固定版本号更新为 **v1.0.2**。

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
