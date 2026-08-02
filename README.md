# bird_exporter

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://go.dev/)
[![Prometheus](https://img.shields.io/badge/Prometheus-Compatible-E6522C?logo=prometheus)](https://prometheus.io/)
[![Grafana](https://img.shields.io/badge/Grafana-Dashboard-F46800?logo=grafana)](https://grafana.com/)

Prometheus Exporter for [BIRD](https://bird.network.cz/) Internet Routing Daemon — 通过 Unix 域套接字直接与 BIRD 通信，采集并暴露 BGP 和 Babel 协议的关键监控指标。

## 功能特性

- **直接连接 BIRD 控制套接字** — 通过 Unix 域套接字与 BIRD 通信，无需调用 `birdc` 子进程，低开销、高可靠
- **BGP 会话状态监控** — 采集每个 BGP 协议的会话状态（Established / Connect / Active / …），附带邻居 AS 号和本地 AS 号
- **BGP 路由计数** — 按 ipv4 / ipv6 通道分别记录 imported / exported / preferred 路由数量
- **BGP Route Change Stats** — 统计每个通道的 import/export updates/withdraws 在各阶段（received / rejected / filtered / ignored / accepted）的计数
- **Babel 邻居 RTT** — 采集 Babel 邻居的往返延迟（毫秒）
- **BIRD 可达性探测** — 通过 `bird_up` 指标快速判断 BIRD 守护进程是否正常响应
- **按需采集** — 每次 Prometheus 抓取时实时查询，没有后台轮询循环
- **Bearer Token 认证** — 可选的安全认证，使用 constant-time 比较防止时序侧信道攻击
- **Grafana 仪表盘** — 内置 Grafana Dashboard JSON，导入即用

## 指标列表

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| [`bird_up`](bird_exporter.go:447) | Gauge | `hostname` | BIRD 是否可达（1 = 可达，0 = 不可达） |
| [`bird_hostname`](bird_exporter.go:477) | Gauge | `hostname` | BIRD 守护进程的主机名（Info 指标，始终为 1） |
| [`bird_bgp_up`](bird_exporter.go:412) | Gauge | `hostname`, `name` | BGP 会话状态（1 = Established，0 = 其他） |
| [`bird_bgp_neighbor_as`](bird_exporter.go:417) | Gauge | `hostname`, `name` | BGP 邻居 AS 号 |
| [`bird_bgp_local_as`](bird_exporter.go:422) | Gauge | `hostname`, `name` | BGP 本地 AS 号 |
| [`bird_channel_routes_imported`](bird_exporter.go:427) | Gauge | `hostname`, `name`, `channel` | 该 BGP 通道导入的路由数量 |
| [`bird_channel_routes_exported`](bird_exporter.go:432) | Gauge | `hostname`, `name`, `channel` | 该 BGP 通道导出的路由数量 |
| [`bird_channel_routes_preferred`](bird_exporter.go:437) | Gauge | `hostname`, `name`, `channel` | 该 BGP 通道优选的路由数量 |
| [`bird_route_changes_received`](bird_exporter.go:452) | Gauge | `hostname`, `name`, `channel`, `direction`, `type` | 收到的路由更新/撤销总数 |
| [`bird_route_changes_rejected`](bird_exporter.go:457) | Gauge | `hostname`, `name`, `channel`, `direction`, `type` | 被拒绝的路由更新/撤销数 |
| [`bird_route_changes_filtered`](bird_exporter.go:462) | Gauge | `hostname`, `name`, `channel`, `direction`, `type` | 被过滤的路由更新/撤销数 |
| [`bird_route_changes_ignored`](bird_exporter.go:467) | Gauge | `hostname`, `name`, `channel`, `direction`, `type` | 被忽略的路由更新/撤销数 |
| [`bird_route_changes_accepted`](bird_exporter.go:472) | Gauge | `hostname`, `name`, `channel`, `direction`, `type` | 被接受的路由更新/撤销数 |
| [`bird_babel_neighbor_rtt_ms`](bird_exporter.go:442) | Gauge | `hostname`, `neighbor_ip`, `interface` | Babel 邻居往返延迟（毫秒） |

> **`direction`** 标签取值：`import` / `export`  
> **`type`** 标签取值：`updates` / `withdraws`

## 快速开始

### 下载 & 编译

```bash
git clone https://github.com/swysgh/bird_exporter.git
cd bird_exporter
go build -o bird_exporter .
```

### 命令行参数

```bash
./bird_exporter -h
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| [`-listen`](bird_exporter.go:42) | `:9557` | Prometheus 抓取指标的监听地址 |
| [`-socket`](bird_exporter.go:43) | `/var/run/bird/bird.ctl` | BIRD 控制套接字路径 |
| [`-token`](bird_exporter.go:44) | `""`（空 = 不启用） | Bearer Token 认证 |

### 运行示例

```bash
# 基本用法
./bird_exporter

# 指定监听端口和 BIRD 套接字路径
./bird_exporter -listen :9557 -socket /var/run/bird/bird.ctl

# 启用 Bearer Token 认证
./bird_exporter -token "your-secret-token"
```

### 使用 systemd 服务

项目提供了 [`prom_exporter.service`](prom_exporter.service) 模板，按需修改后部署到 `/etc/systemd/system/`：

```bash
# 1. 复制二进制文件
cp bird_exporter /usr/bin/bird_exporter

# 2. 修改 service 文件中的 -token 参数（可选）
vim prom_exporter.service

# 3. 安装并启用服务
cp prom_exporter.service /etc/systemd/system/bird_exporter.service
systemctl daemon-reload
systemctl enable --now bird_exporter
```

## Prometheus 配置

在 `prometheus.yml` 中添加采集目标：

```yaml
scrape_configs:
  - job_name: 'bird'
    static_configs:
      - targets: ['localhost:9557']
    # 如启用了 Token 认证，取消注释：
    # authorization:
    #   credentials: 'your-secret-token'
```

## Grafana 仪表盘

项目提供了开箱即用的 Grafana Dashboard 定义文件 [`grafana-dashboard.json`](grafana-dashboard.json)，包含以下面板：

### BIRD 概览
- **BIRD 可达性** — 显示 BIRD 守护进程是否正常运行
- **Babel 邻居数** — 当前 Babel 邻居数量统计
- **BGP 异常会话数** — 非 Established 状态的 BGP 会话数量
- **BGP Established 会话数** — 正常建立的 BGP 会话数量

### BGP 路由统计
- **导入路由数（imported）** — 按通道的时间序列图
- **导出路由数（exported）** — 按通道的时间序列图
- **优选路由数（preferred）** — 按通道的时间序列图
- **Route Changes Accepted 速率** — 每秒 accepted 路由变化速率

### BGP 详细信息表
- **BGP 会话详情表** — 协议名、状态、邻居 AS、本地 AS 一览表
- **BGP 状态** — 每个 BGP 协议的状态卡片

### Babel 邻居
- **Babel 邻居 RTT** — 各邻居往返延迟的时间序列
- **Babel 邻居 RTT（当前值）** — 各邻居当前 RTT 值

**导入方式**：在 Grafana 中进入 **Dashboards → New → Import**，粘贴 `grafana-dashboard.json` 内容或上传文件。

## 架构

```
┌──────────────┐    HTTP /metrics     ┌──────────────┐
│  Prometheus  │ ◄────────────────── │  bird_exporter │
│   Server     │    scrape :9557      │   (Go 程序)    │
└──────────────┘                      └──────┬───────┘
                                             │
                                    Unix Domain Socket
                                    /var/run/bird/bird.ctl
                                             │
                                    ┌────────▼────────┐
                                    │  BIRD Daemon     │
                                    │  (bird / bird6)  │
                                    └─────────────────┘
```

## 开发

### 环境要求

- Go 1.25+

### 构建

```bash
go build -o bird_exporter .
```

### 项目结构

```
bird_exporter/
├── bird_exporter.go          # 主程序（BGP/Babel 解析 + Prometheus Collector）
├── go.mod                    # Go 模块定义
├── go.sum                    # 依赖校验和
├── prom_exporter.service     # systemd 服务模板
├── grafana-dashboard.json    # Grafana 仪表盘（Grafana 13+ 兼容）
└── README.md                 # 本文件
```

## 许可

MIT License