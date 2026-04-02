package app

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"power-ebpf/internal/bpfgen"
	"power-ebpf/internal/httptrace"
)

type Config struct {
	IfName               string
	SrcIP                string
	DstIP                string
	SrcPort              uint
	DstPort              uint
	CaptureBytes         int
	PerfPages            int
	BatchSize            int
	WorkerCount          int
	RedisWorkers         int
	RedisQueueSize       int
	FlushInterval        time.Duration
	LogInterval          time.Duration
	PrintHTTP            bool
	PrintSummary         bool
	DebugKernel          bool
	ResponseStallTimeout time.Duration
	TransactionTTL       time.Duration
	MaxMessageBytes      int
	RedisAddr            string
	RedisPassword        string
	RedisDB              int
	RedisKeyPrefix       string
	RedisTTL             time.Duration
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

// 默认运行参数。
func DefaultConfig() Config {
	return Config{
		CaptureBytes:         10 * 1024,
		PerfPages:            256,
		BatchSize:            100,
		WorkerCount:          runtime.NumCPU(),
		RedisWorkers:         max(1, runtime.NumCPU()/2),
		RedisQueueSize:       8192,
		FlushInterval:        200 * time.Millisecond,
		LogInterval:          5 * time.Second,
		PrintHTTP:            true,
		PrintSummary:         true,
		DebugKernel:          false,
		ResponseStallTimeout: 500 * time.Millisecond,
		TransactionTTL:       2 * time.Minute,
		MaxMessageBytes:      10 * 1024,
		RedisKeyPrefix:       "http-trace",
		RedisTTL:             24 * time.Hour,
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// PerfBufferBytes 把 perf buffer 页数转换成字节数。
func (c Config) PerfBufferBytes() int {
	if c.PerfPages <= 0 {
		return 64 * os.Getpagesize()
	}
	return c.PerfPages * os.Getpagesize()
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
		filter.CaptureBytes = uint32(c.CaptureBytes)
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
	if !matchIPPair(f.SrcIP, f.DstIP, event.SrcIP, event.DstIP) {
		return false
	}
	if !matchPortPair(f.SrcPort, f.DstPort, event.SrcPort, event.DstPort) {
		return false
	}
	if len(f.InterfaceIPs) > 0 {
		if _, ok := f.InterfaceIPs[event.SrcIP]; ok {
			return true
		}
		if _, ok := f.InterfaceIPs[event.DstIP]; ok {
			return true
		}
		return false
	}
	return true
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
