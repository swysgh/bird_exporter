# bird_exporter

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

一个轻量级的 [BIRD](https://bird.network.cz/) 路由守护进程 Prometheus 导出器。

通过 **Unix 域套接字** 直接与 BIRD 通信（而不是 fork `birdc` 子进程），在每次 Prometheus 抓取时按需采集指标，无后台轮询循环。单文件实现，仅依赖 Prometheus 客户端库。

## 特性

- 🚀 **直连套接字** — 不依赖 `birdc` 二进制，单次抓取内完成所有查询
- 📊 **BGP 监控** — 会话状态、邻居/本地 AS、按 ipv4/ipv6 通道分开的路由计数（imported / exported / preferred）
- 📡 **Babel 监控** — 邻居 RTT（毫秒），自动适配所有 Babel 实例命名
- 🔒 **可选 Bearer Token 认证** — 使用 constant-time 比较防止时序侧信道攻击
- ⏱️ **HTTP 超时保护** — ReadHeader / Read / Write / Idle 超时，防止慢连接耗尽 goroutine
- 🪶 **零配置依赖** — 编译产物为单一二进制，开箱即用

## 暴露指标

| 指标 | 类型 | Labels | 说明 |
|------|------|--------|------|
| `bird_up` | Gauge | — | BIRD 是否可达（1=可达, 0=不可达） |
| `bird_bgp_up` | Gauge | `name` | BGP 会话是否 Established（1=是, 0=否） |
| `bird_bgp_neighbor_as` | Gauge | `name` | BGP 邻居 AS 号 |
| `bird_bgp_local_as` | Gauge | `name` | BGP 本地 AS 号 |
| `bird_channel_routes_imported` | Gauge | `name`, `channel` | 通道导入的路由数（channel=`ipv4`/`ipv6`） |
| `bird_channel_routes_exported` | Gauge | `name`, `channel` | 通道导出的路由数 |
| `bird_channel_routes_preferred` | Gauge | `name`, `channel` | 通道优选的路由数 |
| `bird_babel_neighbor_rtt_ms` | Gauge | `neighbor_ip`, `interface` | Babel 邻居 RTT（毫秒） |

## 编译

```bash
go build -o bird_exporter .
```

## 使用

```bash
./bird_exporter [参数]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-listen` | `:9557` | Prometheus 抓取指标的监听地址 |
| `-socket` | `/var/run/bird/bird.ctl` | BIRD 控制套接字路径 |
| `-token` | （空） | Bearer Token，留空表示不启用认证 |

示例：

```bash
# 无认证
./bird_exporter -listen :9557 -socket /var/run/bird/bird.ctl

# 启用认证
./bird_exporter -token your-secret-token
```

## 验证

```bash
curl http://localhost:9557/metrics
```

启用认证时：

```bash
curl -H "Authorization: Bearer your-secret-token" http://localhost:9557/metrics
```

## Prometheus 配置

```yaml
scrape_configs:
  - job_name: bird
    scrape_interval: 30s
    static_configs:
      - targets: ['localhost:9557']
    # 启用认证时需携带 token
    authorization:
      type: Bearer
      credentials: your-secret-token
```

## systemd 部署

参考 [`prom_exporter.service`](prom_exporter.service)，将编译好的二进制路径填入 `ExecStart`：

```ini
[Unit]
Description=Prometheus Exporter for BIRD Routing Protocol (BGP + Babel)
After=network.target bird.service

[Service]
Type=simple
ExecStart=/path/to/bird_exporter -token=your-secret-token
Restart=always
RestartSec=5

NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/run/bird
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

部署：

```bash
sudo cp prom_exporter.service /etc/systemd/system/bird_exporter.service
sudo systemctl daemon-reload
sudo systemctl enable --now bird_exporter
```

## 与 BIRD 的通信

`bird_exporter` 连接到 BIRD 控制套接字并发送明文命令：

- `show protocols all` — 采集 BGP 协议详情
- `show babel neighbors` — 采集 Babel 邻居（不带协议名参数，兼容所有 Babel 实例）

套接字读取遵循 BIRD 协议行格式（`NNNX<data>` 状态码 + continuation 行），使用 `bufio.Reader` 逐行解析。每次查询设置 10 秒超时。

## 技术细节

- **解析方式**：全部使用 `strings` 包解析，无正则表达式，可读性与性能俱佳
- **指标采集**：实现 `prometheus.Collector` 接口，在 `Collect()` 中按需采集，无缓存
- **错误处理**：BGP 查询失败时将 `bird_up` 置 0 并提前返回；Babel 查询失败仅记录日志，不影响其他指标

## License

MIT
