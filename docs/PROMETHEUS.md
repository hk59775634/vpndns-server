# Prometheus / Grafana

## 抓取配置

管理 HTTP 服务（`listen.admin`）同时提供指标，**无需 API Key**：

```yaml
scrape_configs:
  - job_name: vpndns
    scrape_interval: 15s
    static_configs:
      - targets: ['127.0.0.1:8080']   # 改为实际 admin 地址
    metrics_path: /metrics
```

若 admin 仅绑定内网，将 `targets` 改为内网 IP 或通过 `relabel` / 联邦采集。

## 指标前缀

均为 `vpndns_*`，例如：

- `vpndns_dns_queries_total`
- `vpndns_blocked_blacklist_total` / `vpndns_blocked_whitelist_total`
- `vpndns_cache_hits_total`
- `vpndns_resolved_cn_total` / `vpndns_resolved_out_total`
- `vpndns_resolve_errors_total`
- `vpndns_rate_limited_total`
- `vpndns_geoip_chnroute_entries`
- `vpndns_uptime_seconds`

类型为 **Gauge**（反映当前累计计数器快照，与进程生命周期一致；配合 `increase()` 可算速率）。

## Grafana

1. 添加 Prometheus 数据源  
2. 新建 Dashboard，添加图表：  
   - `rate(vpndns_dns_queries_total[5m])`  
   - `increase(vpndns_blocked_whitelist_total[1h])` 等  

## 告警示例（Prometheus）

```yaml
groups:
  - name: vpndns
    rules:
      - alert: VPNDNSResolveErrorsHigh
        expr: increase(vpndns_resolve_errors_total[5m]) > 50
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: DNS 解析错误升高
```

按业务量调整阈值。

## 持久化统计与 Prometheus

进程内计数在重启后归零；若开启 `stats.persist_interval_seconds` 与 `stats.redis_key`，启动时会从 Redis 恢复计数再累计。Prometheus 仍抓取当前进程导出的瞬时值，长期趋势以 Prometheus TSDB 为准。
