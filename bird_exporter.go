// Package main 实现 BIRD 路由守护进程的 Prometheus 导出器。
//
// 通过 Unix 域套接字直接与 BIRD 通信（而不是调用 birdc 子进程），
// 暴露以下 Prometheus 指标：
//
//   - BGP 会话状态（Established / Connect / Active / ...）
//   - BGP 邻居 AS 号 / 本地 AS 号
//   - BGP 通道状态（ipv4 / ipv6 分开）
//   - BGP 路由数量（ipv4 / ipv6 分开：imported / exported / preferred）
//   - Babel 邻居 RTT（毫秒）
//   - BIRD 整体可达性
//
// 指标在每次 Prometheus 抓取时按需采集，没有后台轮询循环。
//
// 用法：
//
//	bird_exporter [-listen :9557] [-socket /var/run/bird/bird.ctl]
package main

import (
	"bufio"
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ---------------------------------------------------------------------------
// 命令行参数
// ---------------------------------------------------------------------------

var (
	listenAddr = flag.String("listen", ":9557", "Prometheus 抓取指标的监听地址")
	socketPath = flag.String("socket", "/var/run/bird/bird.ctl", "BIRD 控制套接字路径")
	bearerToken = flag.String("token", "", "Bearer Token，留空表示不启用认证")
)

// bearerAuthMiddleware 包装一个 HTTP Handler，要求请求携带正确的 Bearer Token。
// 使用 constant-time 比较防止时序侧信道攻击。
func bearerAuthMiddleware(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	tokenBytes := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		provided := []byte(auth[7:])
		if subtle.ConstantTimeCompare(provided, tokenBytes) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// BIRD 控制套接字协议
// ---------------------------------------------------------------------------

// runBirdc 连接到 BIRD 控制套接字，发送一条命令，并返回去掉状态码前缀的响应文本。
//
// BIRD 协议行格式：
//   - 状态行：NNNX<data>，NNNN 是 4 位状态码，X 是分隔符：
//       ' ' (空格) → 最后一行，响应结束
//       '-' (减号) → 后续还有数据行
//       '+' (加号) → 新增数据行
//   - Continuation 行：以单个空格开头，表示前一行的延续。
//     第一个空格是 continuation marker，剩余部分保持原缩进。
func runBirdc(command string) (string, error) {
	conn, err := net.Dial("unix", *socketPath)
	if err != nil {
		return "", fmt.Errorf("连接 BIRD 套接字失败: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReader(conn)

	// 读取并丢弃横幅行
	if _, err := br.ReadString('\n'); err != nil {
		return "", fmt.Errorf("读取横幅失败: %w", err)
	}

	// 发送命令
	if _, err := fmt.Fprintf(conn, "%s\n", command); err != nil {
		return "", fmt.Errorf("发送命令失败: %w", err)
	}

	var sb strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if sb.Len() > 0 {
				break
			}
			return "", fmt.Errorf("读取响应失败: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")

		// Continuation 行：以单个空格开头，去掉第一个空格后保留剩余数据
		if len(line) > 0 && line[0] == ' ' {
			sb.WriteString(line[1:])
			sb.WriteByte('\n')
			continue
		}

		if len(line) < 4 {
			break
		}

		// 状态行：去掉 "NNNX" 前缀（4 位状态码 + 1 位分隔符）
		if len(line) > 5 {
			sb.WriteString(line[5:])
		}
		sb.WriteByte('\n')

		// 分隔符为空格表示最后一行，响应结束
		if len(line) >= 5 && line[4] == ' ' {
			break
		}
	}
	return sb.String(), nil
}

// ---------------------------------------------------------------------------
// BGP 协议解析
// ---------------------------------------------------------------------------

// bgpProtocol 保存单个 BGP 协议实例的解析结果。
// 会话状态为整体，路由计数按 ipv4/ipv6 通道分开。
type bgpProtocol struct {
	name       string
	bgpState   string                 // Established / Connect / Active / ...
	neighborAS int
	localAS    int
	channels   map[string]*bgpChannel // key 为 "ipv4" / "ipv6"
}

// bgpChannel 保存单个通道的路由计数（不含通道状态）。
type bgpChannel struct {
	imported  int
	exported  int
	preferred int
}

// parseBGPProtocols 解析 "show protocols all" 的输出，提取所有 BGP 协议块。
// 会话状态取"BGP state:"行，路由计数按 ipv4/ipv6 通道分开记录。
func parseBGPProtocols(output string) []bgpProtocol {
	var protocols []bgpProtocol
	var cur *bgpProtocol
	var curCh *bgpChannel

	for raw := range strings.SplitSeq(output, "\n") {
		trimmed := strings.TrimSpace(raw)

		if trimmed == "" || strings.HasPrefix(trimmed, "BIRD ") {
			continue
		}

		// 检测新的 BGP 协议摘要行：<name> BGP --- ...
		fields := strings.Fields(trimmed)
		if len(fields) >= 3 && fields[1] == "BGP" && fields[2] == "---" {
			if cur != nil {
				protocols = append(protocols, *cur)
			}
			cur = &bgpProtocol{
				name:     fields[0],
				channels: make(map[string]*bgpChannel),
			}
			curCh = nil
			continue
		}

		if cur == nil {
			continue
		}

		// BGP 状态行
		if strings.HasPrefix(trimmed, "BGP state:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				cur.bgpState = strings.TrimSpace(parts[1])
			}
			continue
		}

		switch {
		case strings.HasPrefix(trimmed, "Neighbor AS:"):
			cur.neighborAS = parseIntAfterColon(trimmed)

		case strings.HasPrefix(trimmed, "Local AS:"):
			cur.localAS = parseIntAfterColon(trimmed)

		case strings.HasPrefix(trimmed, "Channel ipv4"):
			curCh = &bgpChannel{}
			cur.channels["ipv4"] = curCh

		case strings.HasPrefix(trimmed, "Channel ipv6"):
			curCh = &bgpChannel{}
			cur.channels["ipv6"] = curCh

		case curCh != nil && strings.HasPrefix(trimmed, "Routes:"):
			parseRouteCounts(trimmed, curCh)
		}
	}

	if cur != nil {
		protocols = append(protocols, *cur)
	}
	return protocols
}

// parseRouteCounts 从 "Routes:" 行提取 imported / exported / preferred 三个数值。
// 格式："Routes: 1091 imported, 14 exported, 3 preferred"
func parseRouteCounts(line string, ch *bgpChannel) {
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		if v, err := strconv.Atoi(fields[1]); err == nil {
			ch.imported = v
		}
	}
	if len(fields) >= 4 {
		if v, err := strconv.Atoi(fields[3]); err == nil {
			ch.exported = v
		}
	}
	if len(fields) >= 6 {
		if v, err := strconv.Atoi(fields[5]); err == nil {
			ch.preferred = v
		}
	}
}

func parseIntAfterColon(s string) int {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) < 2 {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0
	}
	return n
}

// ---------------------------------------------------------------------------
// Babel 邻居解析
// ---------------------------------------------------------------------------

type babelNeighbor struct {
	ip            string
	interfaceName string
	rttMs         float64
}

// parseBabelNeighbors 解析 "show babel neighbors <proto>" 的输出。
//
// 期望格式：
//   babel1:
//   IP address                Interface  Metric Routes Hellos Expires Auth  RTT (ms)
//   fe80::7                   wg2hham       192     11     16   3.032 No     134.435
//
// RTT 是最后一个字段，直接用 fields[len-1] 获取，避免列索引偏移。
func parseBabelNeighbors(output string) []babelNeighbor {
	lines := strings.Split(output, "\n")

	headerIdx := -1
	for i, ln := range lines {
		if strings.Contains(ln, "RTT") && strings.Contains(ln, "IP address") {
			headerIdx = i
			break
		}
	}
	if headerIdx == -1 {
		return nil
	}

	var neighbors []babelNeighbor
	for j := headerIdx + 1; j < len(lines); j++ {
		trimmed := strings.TrimSpace(lines[j])
		if trimmed == "" {
			break
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			continue
		}
		rttStr := fields[len(fields)-1]
		rtt, err := strconv.ParseFloat(rttStr, 64)
		if err != nil {
			continue
		}
		neighbors = append(neighbors, babelNeighbor{
			ip:            fields[0],
			interfaceName: fields[1],
			rttMs:         rtt,
		})
	}
	return neighbors
}

// ---------------------------------------------------------------------------
// Collector —— 实现 prometheus.Collector 接口
// ---------------------------------------------------------------------------

type birdCollector struct {
	socketPath string

	bgpUpDesc            *prometheus.Desc
	bgpNeighborASDesc    *prometheus.Desc
	bgpLocalASDesc       *prometheus.Desc
	routesImportedDesc   *prometheus.Desc
	routesExportedDesc   *prometheus.Desc
	routesPreferredDesc  *prometheus.Desc
	babelRTTDesc         *prometheus.Desc
	birdUpDesc           *prometheus.Desc
}

func newBirdCollector(socketPath string) *birdCollector {
	return &birdCollector{
		socketPath: socketPath,

		bgpUpDesc: prometheus.NewDesc(
			"bird_bgp_up",
			"BGP 会话状态：1 = Established，0 = 其他",
			[]string{"name"}, nil,
		),
		bgpNeighborASDesc: prometheus.NewDesc(
			"bird_bgp_neighbor_as",
			"BGP 邻居 AS 号",
			[]string{"name"}, nil,
		),
		bgpLocalASDesc: prometheus.NewDesc(
			"bird_bgp_local_as",
			"BGP 本地 AS 号",
			[]string{"name"}, nil,
		),
		routesImportedDesc: prometheus.NewDesc(
			"bird_channel_routes_imported",
			"该 BGP 通道导入的路由数量",
			[]string{"name", "channel"}, nil,
		),
		routesExportedDesc: prometheus.NewDesc(
			"bird_channel_routes_exported",
			"该 BGP 通道导出的路由数量",
			[]string{"name", "channel"}, nil,
		),
		routesPreferredDesc: prometheus.NewDesc(
			"bird_channel_routes_preferred",
			"该 BGP 通道优选的路由数量",
			[]string{"name", "channel"}, nil,
		),
		babelRTTDesc: prometheus.NewDesc(
			"bird_babel_neighbor_rtt_ms",
			"Babel 邻居往返延迟（毫秒）",
			[]string{"neighbor_ip", "interface"}, nil,
		),
		birdUpDesc: prometheus.NewDesc(
			"bird_up",
			"BIRD 是否可达：1 = 可达，0 = 不可达",
			nil, nil,
		),
	}
}

func (c *birdCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.bgpUpDesc
	ch <- c.bgpNeighborASDesc
	ch <- c.bgpLocalASDesc
	ch <- c.routesImportedDesc
	ch <- c.routesExportedDesc
	ch <- c.routesPreferredDesc
	ch <- c.babelRTTDesc
	ch <- c.birdUpDesc
}

func (c *birdCollector) Collect(ch chan<- prometheus.Metric) {
	// ---- BGP ----
	bgpOutput, err := runBirdc("show protocols all")
	if err != nil {
		log.Printf("BIRD 查询失败: %v", err)
		ch <- prometheus.MustNewConstMetric(c.birdUpDesc, prometheus.GaugeValue, 0)
		return
	}

	ch <- prometheus.MustNewConstMetric(c.birdUpDesc, prometheus.GaugeValue, 1)

	protocols := parseBGPProtocols(bgpOutput)
	for _, p := range protocols {
		ch <- prometheus.MustNewConstMetric(c.bgpUpDesc, prometheus.GaugeValue,
			boolToFloat(p.bgpState == "Established"), p.name)

		ch <- prometheus.MustNewConstMetric(c.bgpNeighborASDesc, prometheus.GaugeValue,
			float64(p.neighborAS), p.name)

		ch <- prometheus.MustNewConstMetric(c.bgpLocalASDesc, prometheus.GaugeValue,
			float64(p.localAS), p.name)

		// 每个通道的路由计数（ipv4/ipv6 分开）
		for chName, chData := range p.channels {
			ch <- prometheus.MustNewConstMetric(c.routesImportedDesc, prometheus.GaugeValue,
				float64(chData.imported), p.name, chName)
			ch <- prometheus.MustNewConstMetric(c.routesExportedDesc, prometheus.GaugeValue,
				float64(chData.exported), p.name, chName)
			ch <- prometheus.MustNewConstMetric(c.routesPreferredDesc, prometheus.GaugeValue,
				float64(chData.preferred), p.name, chName)
		}
	}

	// ---- Babel ----
	// 使用通用查询（不指定协议名），兼容所有 Babel 实例命名
	babelOutput, err := runBirdc("show babel neighbors")
	if err != nil {
		log.Printf("Babel 邻居查询失败: %v", err)
	} else {
		for _, n := range parseBabelNeighbors(babelOutput) {
			ch <- prometheus.MustNewConstMetric(c.babelRTTDesc, prometheus.GaugeValue,
				n.rttMs, n.ip, n.interfaceName)
		}
	}
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	flag.Parse()

	if _, err := os.Stat(*socketPath); err != nil {
		log.Printf("警告: BIRD 套接字 %s 不存在: %v", *socketPath, err)
	}

	collector := newBirdCollector(*socketPath)
	reg := prometheus.NewRegistry()
	reg.MustRegister(collector)

	metricsHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	http.Handle("/metrics", bearerAuthMiddleware(*bearerToken, metricsHandler))
	log.Printf("监听 %s/metrics  (BIRD 套接字: %s)", *listenAddr, *socketPath)
	if *bearerToken != "" {
		log.Println("已启用 Bearer Token 认证")
	} else {
		log.Println("未启用认证")
	}
	// 使用带有超时设置的 HTTP Server，防止慢连接耗尽 goroutine
	srv := &http.Server{
		Addr:              *listenAddr,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
