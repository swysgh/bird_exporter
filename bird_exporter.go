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
	routeChanges routeChangeStats
}

// routeChangeStats 保存 Route change stats 表格的 4 行 × 5 列数据。
// 行：Import updates / Import withdraws / Export updates / Export withdraws。
// 列：received, rejected, filtered, ignored, accepted。
// 数值为 -1 表示该单元格为 "---"（不可用）。
type routeChangeStats struct {
	ImportUpdates   [5]int // [received, rejected, filtered, ignored, accepted]
	ImportWithdraws [5]int
	ExportUpdates   [5]int
	ExportWithdraws [5]int
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
	
		case curCh != nil && strings.HasPrefix(trimmed, "Route change stats:"):
			// 仅表头行，数据在后续行；无需处理
			continue
	
		case curCh != nil && strings.HasPrefix(trimmed, "Import updates:"):
			curCh.routeChanges.ImportUpdates = parseRouteChangeDataLine(trimmed)
	
		case curCh != nil && strings.HasPrefix(trimmed, "Import withdraws:"):
			curCh.routeChanges.ImportWithdraws = parseRouteChangeDataLine(trimmed)
	
		case curCh != nil && strings.HasPrefix(trimmed, "Export updates:"):
			curCh.routeChanges.ExportUpdates = parseRouteChangeDataLine(trimmed)
	
		case curCh != nil && strings.HasPrefix(trimmed, "Export withdraws:"):
			curCh.routeChanges.ExportWithdraws = parseRouteChangeDataLine(trimmed)
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

// parseRouteChangeDataLine 解析 "Route change stats" 表格中的一行数据。
// 行格式: "  Import updates:           3055          0          0        315       2740"
// 第 1 个字段是标签（如 "Import updates:"），之后 5 个字段是数字或 "---"。
// 返回 5 个值的数组；"---" 转换为 -1。
func parseRouteChangeDataLine(line string) [5]int {
	var vals [5]int
	for i := range vals {
		vals[i] = -1 // 默认不可用
	}
	fields := strings.Fields(line)
	// 取最后 5 个字段作为数据列，避免标签（如 "Import updates:"）被拆成多个词导致偏移
	if len(fields) < 6 {
		return vals
	}
	dataFields := fields[len(fields)-5:]
	for i := 0; i < 5; i++ {
		if dataFields[i] == "---" {
			vals[i] = -1
		} else if n, err := strconv.Atoi(dataFields[i]); err == nil {
			vals[i] = n
		}
	}
	return vals
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

// parseHostname 从 "show status" 输出中提取 Hostname 行。
// 期望格式: " Hostname is homeserver"
func parseHostname(output string) string {
	for line := range strings.SplitSeq(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Hostname is ") {
			return strings.TrimPrefix(trimmed, "Hostname is ")
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Collector —— 实现 prometheus.Collector 接口
// ---------------------------------------------------------------------------

type birdCollector struct {
	socketPath string
	hostname   string // 在首次成功 Collect 时缓存

	bgpUpDesc            *prometheus.Desc
	bgpNeighborASDesc    *prometheus.Desc
	bgpLocalASDesc       *prometheus.Desc
	routesImportedDesc   *prometheus.Desc
	routesExportedDesc   *prometheus.Desc
	routesPreferredDesc  *prometheus.Desc
	babelRTTDesc         *prometheus.Desc
	birdUpDesc           *prometheus.Desc
	// Route change stats：按 stat 分成独立指标，便于直接查询。
	// 每个指标用 direction + type 标签区分 import/export、updates/withdraws。
	routeChangesReceivedDesc  *prometheus.Desc
	routeChangesRejectedDesc  *prometheus.Desc
	routeChangesFilteredDesc  *prometheus.Desc
	routeChangesIgnoredDesc   *prometheus.Desc
	routeChangesAcceptedDesc  *prometheus.Desc
	// Hostname（Info 指标，只带 hostname 标签）
	hostnameDesc *prometheus.Desc
}

func newBirdCollector(socketPath string) *birdCollector {
	return &birdCollector{
		socketPath: socketPath,

		bgpUpDesc: prometheus.NewDesc(
			"bird_bgp_up",
			"BGP 会话状态：1 = Established，0 = 其他",
			[]string{"hostname", "name"}, nil,
		),
		bgpNeighborASDesc: prometheus.NewDesc(
			"bird_bgp_neighbor_as",
			"BGP 邻居 AS 号",
			[]string{"hostname", "name"}, nil,
		),
		bgpLocalASDesc: prometheus.NewDesc(
			"bird_bgp_local_as",
			"BGP 本地 AS 号",
			[]string{"hostname", "name"}, nil,
		),
		routesImportedDesc: prometheus.NewDesc(
			"bird_channel_routes_imported",
			"该 BGP 通道导入的路由数量",
			[]string{"hostname", "name", "channel"}, nil,
		),
		routesExportedDesc: prometheus.NewDesc(
			"bird_channel_routes_exported",
			"该 BGP 通道导出的路由数量",
			[]string{"hostname", "name", "channel"}, nil,
		),
		routesPreferredDesc: prometheus.NewDesc(
			"bird_channel_routes_preferred",
			"该 BGP 通道优选的路由数量",
			[]string{"hostname", "name", "channel"}, nil,
		),
		babelRTTDesc: prometheus.NewDesc(
			"bird_babel_neighbor_rtt_ms",
			"Babel 邻居往返延迟（毫秒）",
			[]string{"hostname", "neighbor_ip", "interface"}, nil,
		),
		birdUpDesc: prometheus.NewDesc(
			"bird_up",
			"BIRD 是否可达：1 = 可达，0 = 不可达",
			[]string{"hostname"}, nil,
		),
		routeChangesReceivedDesc: prometheus.NewDesc(
			"bird_route_changes_received",
			"BGP Route change stats - received（收到的路由更新/撤销总数）",
			[]string{"hostname", "name", "channel", "direction", "type"}, nil,
		),
		routeChangesRejectedDesc: prometheus.NewDesc(
			"bird_route_changes_rejected",
			"BGP Route change stats - rejected（被拒绝的路由更新/撤销数）",
			[]string{"hostname", "name", "channel", "direction", "type"}, nil,
		),
		routeChangesFilteredDesc: prometheus.NewDesc(
			"bird_route_changes_filtered",
			"BGP Route change stats - filtered（被过滤的路由更新/撤销数）",
			[]string{"hostname", "name", "channel", "direction", "type"}, nil,
		),
		routeChangesIgnoredDesc: prometheus.NewDesc(
			"bird_route_changes_ignored",
			"BGP Route change stats - ignored（被忽略的路由更新/撤销数）",
			[]string{"hostname", "name", "channel", "direction", "type"}, nil,
		),
		routeChangesAcceptedDesc: prometheus.NewDesc(
			"bird_route_changes_accepted",
			"BGP Route change stats - accepted（被接受的路由更新/撤销数）",
			[]string{"hostname", "name", "channel", "direction", "type"}, nil,
		),
		hostnameDesc: prometheus.NewDesc(
			"bird_hostname",
			"BIRD 守护进程的主机名（来自 show status），始终为 1",
			[]string{"hostname"}, nil,
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
	ch <- c.routeChangesReceivedDesc
	ch <- c.routeChangesRejectedDesc
	ch <- c.routeChangesFilteredDesc
	ch <- c.routeChangesIgnoredDesc
	ch <- c.routeChangesAcceptedDesc
	ch <- c.hostnameDesc
}

// fetchHostname 从 BIRD 查询 hostname 并缓存到 collector。
// 仅在首次或上次失败时重新查询。
func (c *birdCollector) fetchHostname() {
	if c.hostname != "" {
		return // 已缓存
	}
	statusOutput, err := runBirdc("show status")
	if err != nil {
		log.Printf("show status 查询失败: %v", err)
		return
	}
	if h := parseHostname(statusOutput); h != "" {
		c.hostname = h
	}
}

func (c *birdCollector) Collect(ch chan<- prometheus.Metric) {
	// 获取 hostname 并缓存
	c.fetchHostname()

	// ---- BGP ----
	bgpOutput, err := runBirdc("show protocols all")
	if err != nil {
		log.Printf("BIRD 查询失败: %v", err)
		ch <- prometheus.MustNewConstMetric(c.birdUpDesc, prometheus.GaugeValue, 0, c.hostname)
		return
	}

	ch <- prometheus.MustNewConstMetric(c.birdUpDesc, prometheus.GaugeValue, 1, c.hostname)

	protocols := parseBGPProtocols(bgpOutput)
	for _, p := range protocols {
		ch <- prometheus.MustNewConstMetric(c.bgpUpDesc, prometheus.GaugeValue,
			boolToFloat(p.bgpState == "Established"), c.hostname, p.name)

		ch <- prometheus.MustNewConstMetric(c.bgpNeighborASDesc, prometheus.GaugeValue,
			float64(p.neighborAS), c.hostname, p.name)

		ch <- prometheus.MustNewConstMetric(c.bgpLocalASDesc, prometheus.GaugeValue,
			float64(p.localAS), c.hostname, p.name)

		// 每个通道的路由计数（ipv4/ipv6 分开）
		for chName, chData := range p.channels {
			ch <- prometheus.MustNewConstMetric(c.routesImportedDesc, prometheus.GaugeValue,
				float64(chData.imported), c.hostname, p.name, chName)
			ch <- prometheus.MustNewConstMetric(c.routesExportedDesc, prometheus.GaugeValue,
				float64(chData.exported), c.hostname, p.name, chName)
			ch <- prometheus.MustNewConstMetric(c.routesPreferredDesc, prometheus.GaugeValue,
				float64(chData.preferred), c.hostname, p.name, chName)

			// Route change stats（按 stat 分成 5 个独立指标）
			emitRouteChangeStats(ch, c, c.hostname, p.name, chName, chData.routeChanges)
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
				n.rttMs, c.hostname, n.ip, n.interfaceName)
		}
	}

	// ---- Hostname（Info 指标，始终带 hostname 标签） ----
	if c.hostname != "" {
		ch <- prometheus.MustNewConstMetric(c.hostnameDesc, prometheus.GaugeValue, 1, c.hostname)
	}
}

// emitRouteChangeStats 将 routeChangeStats 按 stat 分别输出到 5 个独立指标。
// 每个指标用 direction（import/export）和 type（updates/withdraws）标签区分。
// 值为 -1 时表示该单元格不可用（---），跳过输出。
func emitRouteChangeStats(ch chan<- prometheus.Metric, c *birdCollector, hostname, name, channel string, rc routeChangeStats) {
	dirs := []string{"import", "import", "export", "export"}
	types := []string{"updates", "withdraws", "updates", "withdraws"}
	// descs[j] 对应 received/rejected/filtered/ignored/accepted 的 Desc
	descs := []*prometheus.Desc{
		c.routeChangesReceivedDesc,
		c.routeChangesRejectedDesc,
		c.routeChangesFilteredDesc,
		c.routeChangesIgnoredDesc,
		c.routeChangesAcceptedDesc,
	}
	rows := [][5]int{rc.ImportUpdates, rc.ImportWithdraws, rc.ExportUpdates, rc.ExportWithdraws}

	for i, row := range rows {
		for j, val := range row {
			if val < 0 {
				continue // --- 不可用，跳过
			}
			ch <- prometheus.MustNewConstMetric(descs[j], prometheus.GaugeValue,
				float64(val), hostname, name, channel, dirs[i], types[i])
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
