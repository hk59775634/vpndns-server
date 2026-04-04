# REST API 说明

基址：`http://<admin监听>/api/v1/`（与 Web 控制台同端口）。

若配置了 `admin.api_key`，除特别声明外请求需带头：

```http
X-API-Key: <your-key>
```

## 健康与元数据

| 方法 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| GET | `/api/v1/health` | 无 | `{"status":"ok"}` |
| GET | `/api/v1/meta` | 是 | 运行元数据：配置路径、监听、GeoIP 条目数、统计 Redis 键、DoH TLS 方式等 |

## Prometheus

| 方法 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| GET | `/metrics` | **无** | Prometheus 文本指标（与 admin 同端口） |

## 配置

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/config` | 返回当前完整 JSON 配置 |
| PUT | `/api/v1/config` | 写入 JSON，校验后保存 YAML 并热更新 |
| POST | `/api/v1/config/reload` | 从磁盘重新加载 YAML |

## 白名单

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/whitelist` | Redis 集合成员列表（JSON 数组） |
| POST | `/api/v1/whitelist` | body: `{"patterns":["a.com","*.b.com"]}` |
| DELETE | `/api/v1/whitelist` | body: `{"patterns":["a.com"]}` 按条删除；`{"query":"子串"}` 删除所有包含该子串的成员（返回 `removed`）；`{"all":true}` 清空整个集合（返回 `removed`） |
| GET | `/api/v1/whitelist/stats` | `{"count": N}` SCARD |
| POST | `/api/v1/whitelist/subscribe/pull` | 按**已保存配置**的订阅 URL 立即拉取，返回解析/新增条数等 |

## 缓存与日志

| 方法 | 路径 | 说明 |
|------|------|------|
| DELETE | `/api/v1/cache?pattern=dns:*` | 按模式删 Redis 键（默认 `dns:*`） |
| GET | `/api/v1/logs` | 查询日志分页列表（JSON） |
| DELETE | `/api/v1/logs` | 清空全部查询日志：`max_entries>0` 时删除 Redis 列表键；否则清空进程内缓冲 |
| GET | `/api/v1/stats` | 仪表盘同源计数快照 |
| POST | `/api/v1/stats/reset` | 进程内计数器归零、运行时间重新计时、删除 `stats.redis_key` 对应 HASH、清零异步日志丢弃计数 |

## GeoIP

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/geoip/refresh` | 立即重新下载中国 CIDR |

## 错误

未授权：`401`；校验失败：`400` 及文本正文；资源错误：`5xx`。
