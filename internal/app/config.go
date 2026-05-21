package app

import (
	"bufio"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"power-ebpf/internal/bpfgen"
	"power-ebpf/internal/httptrace"

	"github.com/tjfoc/gmsm/sm4"
)

type Config struct {
	IfName               string
	SrcIP                string
	DstIP                string
	SrcPort              uint
	DstPort              uint
	EnableTLS            bool   // 是否启用 TLS 明文采集，默认关闭
	TLSLibPath           string // 逗号分隔的 libssl 路径覆盖项，空时自动发现
	TLSComm              string // uprobes 目标进程名，默认 nginx
	DisableKernelFilter  bool   // 是否禁用内核态过滤 ，默认不禁用
	DisableUserTuple     bool   // 是否禁用用户态过滤 ，默认禁用
	CaptureBytes         int    // 内核侧每个请求/响应最大采集字节数，默认32KB
	PerfPages            int    // perf buffer 页数，默认64页
	BatchSize            int    // 批量大小 ，默认100
	WorkerCount          int    // 工作线程数 ，默认最多8个
	WorkerQueueSize      int    // 每个解析 worker 的缓冲队列深度，0 表示自动调优
	RedisWorkers         int
	RedisQueueSize       int           // Redis 队列大小 ，默认4096
	RetryQueueSize       int           // tuple 重试队列大小，0 表示自动调优
	FlushInterval        time.Duration // 刷新间隔 ，默认200毫秒
	LogInterval          time.Duration // 日志间隔 ，默认5秒
	PrintHTTP            bool          // 是否打印HTTP请求/响应 ，默认打印
	PrintSummary         bool          // 是否打印摘要 ，默认打印
	DebugKernel          bool          // 是否打印内核态调试信息 ，默认不打印
	ResponseStallTimeout time.Duration
	TransactionTTL       time.Duration // 事务超时时间 ，默认2分钟
	MaxMessageBytes      int
	RedisAddr            string // Redis地址 ，默认空
	RedisPassword        string
	RedisDB              int           // RedisDB ，默认0
	RedisKeyPrefix       string        // RedisKeyPrefix ，默认http-trace
	RedisTTL             time.Duration // RedisTTL ，默认24小时
}

// ResolvedFilter 同时保存：
// 1. 下发给内核 map 的 best-effort 过滤规则。
// 2. 用户态补偿过滤规则，用来修正 socket 层 ifindex 不稳定、请求/响应方向翻转的问题。
type ResolvedFilter struct {
	Kernel       bpfgen.HttpTraceFilterConfig
	IfName       string
	InterfaceIPs map[string]struct{}
	SrcIP        string
	DstIP        string
	SrcPort      uint16
	DstPort      uint16
}

type FilterReason string

const (
	FilterReasonPass  FilterReason = "pass"
	FilterReasonIP    FilterReason = "ip"
	FilterReasonPort  FilterReason = "port"
	FilterReasonIface FilterReason = "ifname"
)

const (
	SM4Key = "4gppTsa7bJUKc76t" // 16字节
	SM4IV  = "T465lnDSeDSfXe6a"
)

type runtimeResourcePlan struct {
	CPUCount          int
	MemAvailableBytes uint64
	MemAvailableKnown bool
	EventBytes        uintptr
	PerfPages         int
	PerfBufferBytes   int
	PerfTotalBytes    uint64
	WorkerCount       int
	WorkerQueueSize   int
	WorkerQueueBytes  uint64
	RedisWorkers      int
	RedisQueueSize    int
	RetryQueueSize    int
}

type resourceTier struct {
	maxWorkers         int
	maxRedisWorkers    int
	defaultPerfPages   int
	minPerfPages       int
	perfBudgetBytes    uint64
	workerQueueBudget  uint64
	maxWorkerQueueSize int
	defaultRedisQueue  int
	maxRedisQueue      int
	defaultRetryQueue  int
	maxRetryQueue      int
}

// 默认运行参数。
func DefaultConfig() Config {
	return Config{
		EnableTLS:            false,
		TLSComm:              "nginx",
		CaptureBytes:         32 * 1024,
		DisableKernelFilter:  false,
		DisableUserTuple:     true,
		PerfPages:            64,
		BatchSize:            100,
		WorkerCount:          min(runtime.NumCPU(), 8),
		WorkerQueueSize:      0,
		RedisWorkers:         min(max(1, runtime.NumCPU()/2), 4),
		RedisQueueSize:       4096,
		RetryQueueSize:       0,
		FlushInterval:        200 * time.Millisecond,
		LogInterval:          5 * time.Second,
		PrintHTTP:            true,
		PrintSummary:         true,
		DebugKernel:          false,
		ResponseStallTimeout: 500 * time.Millisecond,
		TransactionTTL:       10 * time.Minute,
		MaxMessageBytes:      32 * 1024,
		RedisKeyPrefix:       "http-trace",
		RedisTTL:             24 * time.Hour,
	}
}

// PerfBufferBytes 把 perf buffer 页数转换成字节数。
func (c Config) PerfBufferBytes() int {
	if c.PerfPages <= 0 {
		return 64 * os.Getpagesize()
	}
	return c.PerfPages * os.Getpagesize()
}

func (c Config) normalizedForHost() (Config, runtimeResourcePlan) {
	memAvailable, known := readMemAvailableBytes()
	return normalizeRuntimeConfig(c, runtime.NumCPU(), memAvailable, known)
}

func normalizeRuntimeConfig(c Config, cpuCount int, memAvailable uint64, memKnown bool) (Config, runtimeResourcePlan) {
	if cpuCount <= 0 {
		cpuCount = 1
	}
	if c.CaptureBytes <= 0 {
		c.CaptureBytes = 32 * 1024
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 100
	}
	if c.MaxMessageBytes <= 0 {
		c.MaxMessageBytes = c.CaptureBytes
	}
	if c.ResponseStallTimeout <= 0 {
		c.ResponseStallTimeout = 500 * time.Millisecond
	}
	if c.TransactionTTL <= 0 {
		c.TransactionTTL = 10 * time.Minute
	}

	tier := pickResourceTier(memAvailable, memKnown)

	workerCount := c.WorkerCount
	if workerCount <= 0 {
		workerCount = min(cpuCount, 8)
	}
	workerCount = clampInt(workerCount, 1, min(cpuCount, tier.maxWorkers))
	c.WorkerCount = workerCount

	perfPages := c.PerfPages
	if perfPages <= 0 {
		perfPages = tier.defaultPerfPages
	}
	maxPerfPages := maxPerfPagesForBudget(cpuCount, os.Getpagesize(), tier.perfBudgetBytes, tier.minPerfPages)
	perfPages = clampInt(perfPages, tier.minPerfPages, maxPerfPages)
	c.PerfPages = perfPages

	queueFloor := max(c.BatchSize*2, 128)
	if tier.maxWorkerQueueSize > 0 && queueFloor > tier.maxWorkerQueueSize {
		queueFloor = tier.maxWorkerQueueSize
	}
	queueDefault := max(c.BatchSize*8, queueFloor)
	if tier.maxWorkerQueueSize > 0 && queueDefault > tier.maxWorkerQueueSize {
		queueDefault = tier.maxWorkerQueueSize
	}
	workerQueueSize := c.WorkerQueueSize
	if workerQueueSize <= 0 {
		workerQueueSize = queueDefault
	}
	eventBytes := int(unsafe.Sizeof(httptrace.Event{}))
	maxWorkerQueue := maxWorkerQueueSizeForBudget(workerCount, eventBytes, tier.workerQueueBudget, queueFloor, tier.maxWorkerQueueSize)
	workerQueueSize = clampInt(workerQueueSize, queueFloor, maxWorkerQueue)
	c.WorkerQueueSize = workerQueueSize

	redisWorkers := c.RedisWorkers
	if redisWorkers <= 0 {
		redisWorkers = min(max(1, cpuCount/2), 4)
	}
	redisWorkers = clampInt(redisWorkers, 1, tier.maxRedisWorkers)
	c.RedisWorkers = redisWorkers

	redisQueueSize := c.RedisQueueSize
	if redisQueueSize <= 0 {
		redisQueueSize = tier.defaultRedisQueue
	}
	redisQueueSize = clampInt(redisQueueSize, 256, tier.maxRedisQueue)
	c.RedisQueueSize = redisQueueSize

	retryQueueSize := c.RetryQueueSize
	if retryQueueSize <= 0 {
		retryQueueSize = tier.defaultRetryQueue
	}
	retryQueueSize = clampInt(retryQueueSize, 128, tier.maxRetryQueue)
	c.RetryQueueSize = retryQueueSize

	plan := runtimeResourcePlan{
		CPUCount:          cpuCount,
		MemAvailableBytes: memAvailable,
		MemAvailableKnown: memKnown,
		EventBytes:        uintptr(eventBytes),
		PerfPages:         c.PerfPages,
		PerfBufferBytes:   c.PerfBufferBytes(),
		PerfTotalBytes:    uint64(c.PerfBufferBytes()) * uint64(cpuCount),
		WorkerCount:       c.WorkerCount,
		WorkerQueueSize:   c.WorkerQueueSize,
		WorkerQueueBytes:  uint64(c.WorkerCount) * uint64(c.WorkerQueueSize) * uint64(eventBytes),
		RedisWorkers:      c.RedisWorkers,
		RedisQueueSize:    c.RedisQueueSize,
		RetryQueueSize:    c.RetryQueueSize,
	}
	return c, plan
}

func pickResourceTier(memAvailable uint64, known bool) resourceTier {
	switch {
	case known && memAvailable <= 512<<20:
		return resourceTier{
			maxWorkers:         2,
			maxRedisWorkers:    1,
			defaultPerfPages:   16,
			minPerfPages:       8,
			perfBudgetBytes:    8 << 20,
			workerQueueBudget:  4 << 20,
			maxWorkerQueueSize: 256,
			defaultRedisQueue:  512,
			maxRedisQueue:      2048,
			defaultRetryQueue:  256,
			maxRetryQueue:      1024,
		}
	case known && memAvailable <= 1<<30:
		return resourceTier{
			maxWorkers:         4,
			maxRedisWorkers:    2,
			defaultPerfPages:   32,
			minPerfPages:       8,
			perfBudgetBytes:    16 << 20,
			workerQueueBudget:  8 << 20,
			maxWorkerQueueSize: 512,
			defaultRedisQueue:  1024,
			maxRedisQueue:      4096,
			defaultRetryQueue:  512,
			maxRetryQueue:      2048,
		}
	case known && memAvailable <= 2<<30:
		return resourceTier{
			maxWorkers:         6,
			maxRedisWorkers:    3,
			defaultPerfPages:   64,
			minPerfPages:       16,
			perfBudgetBytes:    32 << 20,
			workerQueueBudget:  16 << 20,
			maxWorkerQueueSize: 768,
			defaultRedisQueue:  2048,
			maxRedisQueue:      8192,
			defaultRetryQueue:  1024,
			maxRetryQueue:      4096,
		}
	default:
		return resourceTier{
			maxWorkers:         8,
			maxRedisWorkers:    4,
			defaultPerfPages:   64,
			minPerfPages:       16,
			perfBudgetBytes:    64 << 20,
			workerQueueBudget:  32 << 20,
			maxWorkerQueueSize: 1024,
			defaultRedisQueue:  4096,
			maxRedisQueue:      8192,
			defaultRetryQueue:  2048,
			maxRetryQueue:      8192,
		}
	}
}

func maxPerfPagesForBudget(cpuCount, pageSize int, budget uint64, floor int) int {
	if cpuCount <= 0 || pageSize <= 0 || budget == 0 {
		return max(floor, 16)
	}
	perCPUBytes := uint64(cpuCount) * uint64(pageSize)
	pages := int(budget / perCPUBytes)
	if pages < floor {
		return floor
	}
	return pages
}

func maxWorkerQueueSizeForBudget(workerCount, eventBytes int, budget uint64, floor, hardCap int) int {
	if workerCount <= 0 || eventBytes <= 0 || budget == 0 {
		return max(floor, hardCap)
	}
	size := int(budget / uint64(workerCount) / uint64(eventBytes))
	if size < floor {
		size = floor
	}
	if hardCap > 0 && size > hardCap {
		size = hardCap
	}
	return size
}

func clampInt(v, low, high int) int {
	if low > high {
		low, high = high, low
	}
	if v < low {
		return low
	}
	if v > high {
		return high
	}
	return v
}

func readMemAvailableBytes() (uint64, bool) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return value * 1024, true
	}
	return 0, false
}

func (p runtimeResourcePlan) Summary() string {
	mem := "unknown"
	if p.MemAvailableKnown {
		mem = formatBytesIEC(p.MemAvailableBytes)
	}
	return fmt.Sprintf(
		"cpus=%d mem_available=%s perf_pages=%d perf_per_cpu=%s perf_total=%s workers=%d worker_queue=%d worker_queue_mem=%s redis_workers=%d redis_queue=%d retry_queue=%d event_size=%d",
		p.CPUCount,
		mem,
		p.PerfPages,
		formatBytesIEC(uint64(p.PerfBufferBytes)),
		formatBytesIEC(p.PerfTotalBytes),
		p.WorkerCount,
		p.WorkerQueueSize,
		formatBytesIEC(p.WorkerQueueBytes),
		p.RedisWorkers,
		p.RedisQueueSize,
		p.RetryQueueSize,
		p.EventBytes,
	)
}

func formatBytesIEC(v uint64) string {
	const unit = 1024
	if v < unit {
		return fmt.Sprintf("%dB", v)
	}
	div, exp := uint64(unit), 0
	for n := v / unit; n >= unit && exp < 5; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(v)/float64(div), "KMGTPE"[exp])
}

// 配置内核态过滤
func (c Config) BuildFilter() (bpfgen.HttpTraceFilterConfig, error) {
	var filter bpfgen.HttpTraceFilterConfig

	if c.IfName != "" {
		iface, err := net.InterfaceByName(c.IfName)
		if err != nil {
			return filter, fmt.Errorf("resolve interface %q: %w", c.IfName, err)
		}
		filter.Ifindex = uint32(iface.Index)
	}

	if c.SrcIP != "" {
		v, err := ipv4ToBE(c.SrcIP)
		if err != nil {
			return filter, fmt.Errorf("parse src-ip: %w", err)
		}
		filter.SrcIp = v
	}

	if c.DstIP != "" {
		v, err := ipv4ToBE(c.DstIP)
		if err != nil {
			return filter, fmt.Errorf("parse dst-ip: %w", err)
		}
		filter.DstIp = v
	}

	if c.SrcPort > 0 {
		filter.SrcPort = uint16(c.SrcPort)
	}
	if c.DstPort > 0 {
		filter.DstPort = uint16(c.DstPort)
	}
	if c.CaptureBytes > 0 {
		filter.RequestCaptureBytes = uint32(c.CaptureBytes)
		filter.ResponseCaptureBytes = uint32(c.CaptureBytes)
	}

	return filter, nil
}

// ResolveFilter 除了内核 filter，还会解析 ifname 的 IPv4 地址集合。
// 因为在 sock_sendmsg/sock_recvmsg 上拿到的 ifindex 更接近 bind_dev_if，
// 对“本机访问本机”或未显式 bind 设备的连接经常是 0，所以用户态需要再补一层过滤。
func (c Config) ResolveFilter() (ResolvedFilter, error) {
	kernel, err := c.BuildFilter()
	if err != nil {
		return ResolvedFilter{}, err
	}

	filter := ResolvedFilter{
		Kernel:  kernel,
		IfName:  c.IfName,
		SrcIP:   canonicalIPv4(c.SrcIP),
		DstIP:   canonicalIPv4(c.DstIP),
		SrcPort: uint16(c.SrcPort),
		DstPort: uint16(c.DstPort),
	}

	if c.IfName == "" {
		return filter, nil
	}

	iface, err := net.InterfaceByName(c.IfName)
	if err != nil {
		return ResolvedFilter{}, fmt.Errorf("resolve interface %q: %w", c.IfName, err)
	}
	ips, err := interfaceIPv4Set(iface)
	if err != nil {
		return ResolvedFilter{}, fmt.Errorf("resolve interface %q ipv4: %w", c.IfName, err)
	}
	filter.InterfaceIPs = ips
	return filter, nil
}

// Match 是用户态兜底过滤：
// - src/dst 同时给出时按“链路对称”处理，允许请求/响应方向翻转。
// - 只给一边时，按“任意一端命中这个值”处理，更符合端口/IP 过滤直觉。
// - src/dst 给成同一个值时，也按“任意一端命中这个值”处理，适合服务端口过滤。
// - ifname 通过接口 IPv4 做补偿，避免 bind_dev_if=0 时把流量误过滤掉。
func (f ResolvedFilter) Match(event httptrace.Event) bool {
	ok, _ := f.MatchDetail(event)
	return ok
}

func (f ResolvedFilter) MatchDetail(event httptrace.Event) (bool, FilterReason) {
	if !matchIPPair(f.SrcIP, f.DstIP, event.SrcIP, event.DstIP) {
		return false, FilterReasonIP
	}
	if !matchPortPair(f.SrcPort, f.DstPort, event.SrcPort, event.DstPort) {
		return false, FilterReasonPort
	}
	if len(f.InterfaceIPs) > 0 {
		if _, ok := f.InterfaceIPs[event.SrcIP]; ok {
			return true, FilterReasonPass
		}
		if _, ok := f.InterfaceIPs[event.DstIP]; ok {
			return true, FilterReasonPass
		}
		return false, FilterReasonIface
	}
	return true, FilterReasonPass
}

func (f ResolvedFilter) Summary() string {
	var ips []string
	for ip := range f.InterfaceIPs {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return fmt.Sprintf(
		"ifname=%q ifindex=%d iface_ipv4=%s src_ip=%q dst_ip=%q src_port=%d dst_port=%d",
		f.IfName,
		f.Kernel.Ifindex,
		strings.Join(ips, ","),
		f.SrcIP,
		f.DstIP,
		f.SrcPort,
		f.DstPort,
	)
}

func canonicalIPv4(raw string) string {
	if raw == "" {
		return ""
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return raw
	}
	ip = ip.To4()
	if ip == nil {
		return raw
	}
	return ip.String()
}

func interfaceIPv4Set(iface *net.Interface) (map[string]struct{}, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	ips := make(map[string]struct{})
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		ip = ip.To4()
		if ip == nil {
			continue
		}
		ips[ip.String()] = struct{}{}
	}
	return ips, nil
}

func matchIPPair(filterSrc, filterDst, src, dst string) bool {
	switch {
	case filterSrc != "" && filterDst != "":
		if filterSrc == filterDst {
			return src == filterSrc || dst == filterSrc
		}
		return (src == filterSrc && dst == filterDst) || (src == filterDst && dst == filterSrc)
	case filterSrc != "":
		return src == filterSrc || dst == filterSrc
	case filterDst != "":
		return src == filterDst || dst == filterDst
	default:
		return true
	}
}

func matchPortPair(filterSrc, filterDst, src, dst uint16) bool {
	switch {
	case filterSrc != 0 && filterDst != 0:
		if filterSrc == filterDst {
			return src == filterSrc || dst == filterSrc
		}
		return (src == filterSrc && dst == filterDst) || (src == filterDst && dst == filterSrc)
	case filterSrc != 0:
		return src == filterSrc || dst == filterSrc
	case filterDst != 0:
		return src == filterDst || dst == filterDst
	default:
		return true
	}
}

func ipv4ToBE(raw string) (uint32, error) {
	ip := net.ParseIP(raw)
	if ip == nil {
		return 0, fmt.Errorf("invalid ip %q", raw)
	}
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("ip %q is not ipv4", raw)
	}
	return binary.BigEndian.Uint32(ip), nil
}

func SM4Decrypt(cipherText string) (string, error) {
	key := []byte(SM4Key)
	iv := []byte(SM4IV)
	cipherData, _ := base64.StdEncoding.DecodeString(cipherText)
	// 创建sm4解密器
	block, err := sm4.NewCipher(key)
	if err != nil {
		return "", err
	}
	//CBC解密模式
	blockMode := cipher.NewCBCDecrypter(block, iv)
	plainData := make([]byte, len(cipherData))
	blockMode.CryptBlocks(plainData, cipherData)
	plainData, err = pkcs7UnPadding(plainData)
	return string(plainData), err
}

// 去除填充
func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	unPadding := int(data[length-1])
	if unPadding > length {
		return nil, errors.New("unpadding error")
	}
	return data[:length-unPadding], nil
}

// SM4Encrypt 加密
func SM4Encrypt(plainText string) (string, error) {
	key := []byte(SM4Key)
	iv := []byte(SM4IV)
	plainData := []byte(plainText)
	plainData = pkcs7Padding(plainData, sm4.BlockSize)

	block, err := sm4.NewCipher(key)
	if err != nil {
		return "", err
	}

	blockMode := cipher.NewCBCEncrypter(block, iv) // 这里修复了
	cipherData := make([]byte, len(plainData))
	blockMode.CryptBlocks(cipherData, plainData)

	return base64.StdEncoding.EncodeToString(cipherData), nil
}

// 填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}
