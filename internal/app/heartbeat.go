package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"

	"power-ebpf/internal/bpfgen"
	"power-ebpf/internal/httptrace"
)

const (
	collectModeBypass = "BYPASS"
	heartbeatPath     = "/v2/dataCollectClient/heartbeat.shtml"
	// heartbeatInterval      = 30 * time.Second
	previousDayReportTTL   = 5 * time.Minute
	heartbeatTimeLayout    = "2006-01-02 15:04:05"
	dataCollectDisabledBit = 1 << 10
)

type heartbeatRuntime struct {
	endpoint     string
	clientID     string
	preferIfName string
	httpClient   *http.Client

	mu                  sync.Mutex
	nodeInfo            heartbeatNodeInfo
	sendFullReport      bool
	fullReportReason    heartbeatFullReportReason
	lastHeartbeatTime   time.Time
	previousDayTraffic  *heartbeatTrafficStat
	previousDayDeadline time.Time
}

type heartbeatFullReportReason uint8

const (
	heartbeatFullReportNone heartbeatFullReportReason = iota
	heartbeatFullReportRestart
	heartbeatFullReportManualRefresh
)

// 节点信息
type heartbeatNodeInfo struct {
	Hostname      string
	ClientIP      string
	OSType        string
	OSVersion     string
	SystemModel   string
	CPUCores      string
	CPUModel      string
	MemorySize    string
	DiskSize      string
	KernelVersion string
	StartupTime   string
}

type heartbeatTrafficStat struct {
	InputCount  uint64 `json:"inputCount"`
	OutputCount uint64 `json:"outputCount"`
	InputBytes  uint64 `json:"inputBytes"`
	OutputBytes uint64 `json:"outputBytes"`
}

// 心跳请求体
type heartbeatRequest struct {
	ClientID               string                `json:"clientId"`
	CollectMode            string                `json:"collectMode"`
	Hostname               string                `json:"hostname,omitempty"`
	ClientIP               string                `json:"clientIp,omitempty"`
	OSType                 string                `json:"osType,omitempty"`
	OSVersion              string                `json:"osVersion,omitempty"`
	SystemModel            string                `json:"systemModel,omitempty"`
	CPUCores               string                `json:"cpuCores,omitempty"`
	CPUModel               string                `json:"cpuModel,omitempty"`
	MemorySize             string                `json:"memorySize,omitempty"`
	DiskSize               string                `json:"diskSize,omitempty"`
	KernelVersion          string                `json:"kernelVersion,omitempty"`
	DataCollectEnabled     int                   `json:"dataCollectEnabled"`
	StartupTime            string                `json:"startupTime,omitempty"`
	LastHeartbeatTime      string                `json:"lastHeartbeatTime"`
	IsRestart              bool                  `json:"isRestart"`
	TrafficStat            *heartbeatTrafficStat `json:"trafficStat"`
	PreviousDayTrafficStat *heartbeatTrafficStat `json:"previousDayTrafficStat,omitempty"`
}

type heartbeatResponseEnvelope struct {
	ErrCode string `json:"errCode"`
	ErrMsg  string `json:"errMsg"`
	Data    struct {
		DataCollectEnabled int  `json:"dataCollectEnabled"`
		NeedRefresh        bool `json:"needRefresh"`
	} `json:"data"`
}

func newHeartbeatRuntime(cfg Config, startTime time.Time) (*heartbeatRuntime, error) {
	if strings.TrimSpace(cfg.HeartbeatServer) == "" {
		return nil, nil
	}
	endpoint, err := normalizeHeartbeatEndpoint(cfg.HeartbeatServer)
	if err != nil {
		return nil, fmt.Errorf("normalize heartbeat server: %w", err)
	}
	clientID, err := readMachineID()
	if err != nil {
		return nil, fmt.Errorf("read /sys/class/dmi/id/product_uuid: %w", err)
	}

	info, infoErr := collectHeartbeatNodeInfo(cfg.IfName, startTime)
	if infoErr != nil {
		log.Printf("collect initial heartbeat node info error: %v", infoErr)
	}

	return &heartbeatRuntime{
		endpoint:         endpoint,
		clientID:         clientID,
		preferIfName:     cfg.IfName,
		httpClient:       &http.Client{Timeout: 10 * time.Second},
		nodeInfo:         info,
		sendFullReport:   true,
		fullReportReason: heartbeatFullReportRestart,
	}, nil
}

func (s *Service) heartbeatLoop(ctx context.Context, filterMap *ebpf.Map, tlsConfigMap *ebpf.Map) error {
	if s == nil || s.heartbeat == nil {
		return nil
	}

	errorCount := 0
	heartbeatInterval := 30 * time.Second
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if err := s.sendHeartbeat(ctx, filterMap, tlsConfigMap); err != nil {
				log.Printf("heartbeat error: %v", err)
				errorCount++
				// 失败4次2分钟，退化到60秒上报间隔
				if errorCount >= 4 {
					heartbeatInterval = 60 * time.Second
				}
			} else {
				errorCount = 0
				heartbeatInterval = 30 * time.Second
			}
			timer.Reset(heartbeatInterval)
		}
	}
}

func (s *Service) sendHeartbeat(ctx context.Context, filterMap *ebpf.Map, tlsConfigMap *ebpf.Map) error {
	if s == nil || s.heartbeat == nil {
		return nil
	}

	now := time.Now()
	payload, fullReport := s.heartbeat.buildRequest(now, s.collectEnabled.Load(), s.stats.trafficStatSnapshot())
	// 发送请求
	resp, err := s.heartbeat.post(ctx, payload)
	if err != nil {
		return err
	}

	if resp.ErrCode != "" && resp.ErrCode != "0" {
		return fmt.Errorf("heartbeat rejected errCode=%s errMsg=%s", resp.ErrCode, resp.ErrMsg)
	}

	enabled := resp.Data.DataCollectEnabled != 0
	if previous := s.collectEnabled.Swap(enabled); previous != enabled {
		log.Printf("heartbeat updated dataCollectEnabled=%d", boolToInt(enabled))
	}
	if err := s.syncCaptureLimitsToKernel(filterMap); err != nil {
		log.Printf("heartbeat sync kernel collect state error: %v", err)
	}
	if tlsConfigMap != nil {
		if err := s.installTLSConfig(tlsConfigMap); err != nil {
			log.Printf("heartbeat sync tls collect state error: %v", err)
		}
	}
	// 重新获取硬件信息  NeedRefresh=true
	if resp.Data.NeedRefresh {
		if err := s.heartbeat.refreshNodeInfo(); err != nil {
			log.Printf("refresh heartbeat node info error: %v", err)
		}
	}
	s.heartbeat.markSuccess(now, fullReport)
	return nil
}

func (h *heartbeatRuntime) buildRequest(now time.Time, collectEnabled bool, traffic heartbeatTrafficStat) (heartbeatRequest, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if ip, err := detectClientIP(h.preferIfName); err == nil && ip != "" {
		h.nodeInfo.ClientIP = ip
	}

	fullReport := h.sendFullReport
	payload := heartbeatRequest{
		ClientID:           h.clientID,
		CollectMode:        collectModeBypass,
		ClientIP:           h.nodeInfo.ClientIP,
		DataCollectEnabled: boolToInt(collectEnabled),
		LastHeartbeatTime:  formatHeartbeatTime(h.lastHeartbeatTime),
		IsRestart:          fullReport && h.fullReportReason == heartbeatFullReportRestart,
		TrafficStat:        nil,
	}
	// 开启采集  上报TrafficStat数据
	if collectEnabled {
		current := traffic
		payload.TrafficStat = &current
	}
	if fullReport {
		payload.Hostname = h.nodeInfo.Hostname
		payload.OSType = h.nodeInfo.OSType
		payload.OSVersion = h.nodeInfo.OSVersion
		payload.SystemModel = h.nodeInfo.SystemModel
		payload.CPUCores = h.nodeInfo.CPUCores
		payload.CPUModel = h.nodeInfo.CPUModel
		payload.MemorySize = h.nodeInfo.MemorySize
		payload.DiskSize = h.nodeInfo.DiskSize
		payload.KernelVersion = h.nodeInfo.KernelVersion
		payload.StartupTime = h.nodeInfo.StartupTime
	}
	if h.previousDayTraffic != nil && !now.After(h.previousDayDeadline) {
		previous := *h.previousDayTraffic
		payload.PreviousDayTrafficStat = &previous
	}
	return payload, fullReport
}

func (h *heartbeatRuntime) post(ctx context.Context, payload heartbeatRequest) (heartbeatResponseEnvelope, error) {
	var response heartbeatResponseEnvelope

	body, err := json.Marshal(payload)
	if err != nil {
		return response, fmt.Errorf("marshal heartbeat payload: %w", err)
	}
	log.Printf("heartbeat request endpoint=%s body=%s", h.endpoint, string(body))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, bytes.NewReader(body))
	if err != nil {
		return response, fmt.Errorf("build heartbeat request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		log.Printf("heartbeat request failed endpoint=%s err=%v", h.endpoint, err)
		return response, fmt.Errorf("post heartbeat: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("heartbeat read response failed endpoint=%s status=%d err=%v", h.endpoint, resp.StatusCode, err)
		return response, fmt.Errorf("read heartbeat response: %w", err)
	}
	log.Printf("heartbeat response endpoint=%s status=%d body=%s", h.endpoint, resp.StatusCode, string(respBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return response, fmt.Errorf("heartbeat http status=%d", resp.StatusCode)
	}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return response, fmt.Errorf("decode heartbeat response: %w", err)
	}
	return response, nil
}

func (h *heartbeatRuntime) markSuccess(now time.Time, fullReport bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.lastHeartbeatTime = now
	if fullReport {
		h.sendFullReport = false
		h.fullReportReason = heartbeatFullReportNone
	}
	if h.previousDayTraffic != nil && now.After(h.previousDayDeadline) {
		h.previousDayTraffic = nil
	}
}

func (h *heartbeatRuntime) refreshNodeInfo() error {
	info, err := collectHeartbeatNodeInfo(h.preferIfName, time.Now())
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sendFullReport = true
	h.fullReportReason = heartbeatFullReportManualRefresh
	if err == nil {
		if h.nodeInfo.StartupTime != "" {
			info.StartupTime = h.nodeInfo.StartupTime
		}
		h.nodeInfo = info
	}
	return err
}

func (h *heartbeatRuntime) setPreviousDayTraffic(stat heartbeatTrafficStat, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()

	previous := stat
	h.previousDayTraffic = &previous
	h.previousDayDeadline = now.Add(previousDayReportTTL)
}

// 0点重置，flushTicker 最快是 250ms 一次
// 逻辑：采集的日期和当前日期不一致，则换天了
func (s *Service) RolloverDaily(now time.Time, objs *bpfgen.LoadedObjects) {
	if s == nil || objs == nil {
		return
	}

	currentDay := localDayStamp(now)
	if currentDay == s.currentStatsDay {
		return
	}
	// 加 dailyMu 锁和二次判断，所以即使多个 ticker 同时撞上，也只会真正执行一次
	s.dailyMu.Lock()
	defer s.dailyMu.Unlock()
	if currentDay == s.currentStatsDay {
		return
	}

	previousDay := s.currentStatsDay
	previousTraffic := s.stats.trafficStatSnapshot()
	s.logStatsSnapshot(fmt.Sprintf("daily-total[%s]", previousDay), objs)
	if err := resetKernelStats(objs.KernelStatsMap); err != nil {
		log.Printf("reset kernel stats error: %v", err)
	}
	s.stats.resetDailyCounters()
	if s.assembler != nil {
		s.assembler.ResetCounters()
	}
	if s.heartbeat != nil {
		s.heartbeat.setPreviousDayTraffic(previousTraffic, now)
	}
	s.currentStatsDay = currentDay
	log.Printf("daily stats rollover complete previous_day=%s current_day=%s", previousDay, currentDay)
}

func (s *stats) trafficStatSnapshot() heartbeatTrafficStat {
	if s == nil {
		return heartbeatTrafficStat{}
	}
	return heartbeatTrafficStat{
		InputCount:  s.requests.Load(),
		OutputCount: s.responses.Load(),
		InputBytes:  s.inputBytes.Load(),
		OutputBytes: s.outputBytes.Load(),
	}
}

func (s *stats) resetDailyCounters() {
	if s == nil {
		return
	}

	resetAtomicU64(
		&s.perfReceived,
		&s.perfLost,
		&s.perfLostRecords,
		&s.requests,
		&s.responses,
		&s.inputBytes,
		&s.outputBytes,
		&s.redisWrites,
		&s.redisFailures,
		&s.parseFailures,
		&s.evicted,
		&s.userFiltered,
		&s.tupleResolved,
		&s.tupleMiss,
		&s.stallFlushes,
		&s.filterReq,
		&s.filterResp,
		&s.filterUnknown,
		&s.filterByIP,
		&s.filterByPort,
		&s.filterByIface,
		&s.resolverCache,
		&s.resolverProc,
		&s.updateReqWorker,
		&s.updateRespWorker,
		&s.updateRespStalled,
		&s.updateReqEvicted,
		&s.updateRespEvicted,
		&s.retryQueued,
		&s.retryResolved,
		&s.retryDropped,
		&s.retryOverflow,
		&s.tuplePassThrough,
		&s.chainPassThrough,
		&s.workerBackpressure,
		&s.recordsRead,
		&s.decodeNs,
		&s.resolveNs,
		&s.resolveProcNs,
		&s.resolveProcSlow,
		&s.filterNs,
		&s.dispatchNs,
		&s.dispatchBlockNs,
		&s.dispatchBlocked,
		&s.workerQueuePeak,
		&s.shutdownFlushes,
	)
	s.perfLostLogLastNs.Store(0)

	s.sourceMu.Lock()
	s.rawBySource = nil
	s.updatesBySource = nil
	s.sourceMu.Unlock()

	s.perfLostMu.Lock()
	s.perfLostByCPU = nil
	s.perfLostMu.Unlock()
}

func resetAtomicU64(fields ...*atomic.Uint64) {
	for _, field := range fields {
		if field != nil {
			field.Swap(0)
		}
	}
}

// 重置内核态数据
func resetKernelStats(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	key := uint32(0)
	values := make([]bpfgen.HttpTraceKernelStats, ebpf.MustPossibleCPU())
	return m.Update(&key, values, ebpf.UpdateAny)
}

func traceObservedBytes(msg *httptrace.ParsedMessage) uint64 {
	if msg == nil {
		return 0
	}
	return msg.ObservedMessageBytes
}

func localDayStamp(t time.Time) string {
	return t.In(time.Local).Format("2006-01-02")
}

// 1 true 0 false
func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func formatHeartbeatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.In(time.Local).Format(heartbeatTimeLayout)
}

func normalizeHeartbeatEndpoint(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("empty heartbeat server")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid heartbeat server %q", raw)
	}
	if !strings.HasSuffix(parsed.Path, heartbeatPath) {
		basePath := strings.TrimRight(parsed.Path, "/")
		parsed.Path = basePath + heartbeatPath
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

// 获取客户端ID
func readMachineID() (string, error) {
	// 克隆机器id重复
	data, _ := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if string(data) == "" {
		data, _ = os.ReadFile("/etc/machine-id")
	}
	if string(data) == "" {
		return "", fmt.Errorf("machine-id is empty")
	}
	value := strings.TrimSpace(string(data))
	return value, nil
}

// 节点信息获取
func collectHeartbeatNodeInfo(preferIfName string, startTime time.Time) (heartbeatNodeInfo, error) {
	info := heartbeatNodeInfo{
		OSType:      detectOSType(),
		CPUCores:    strconv.Itoa(runtime.NumCPU()),
		StartupTime: formatHeartbeatTime(startTime),
	}

	var errs []string
	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	} else {
		errs = append(errs, fmt.Sprintf("hostname: %v", err))
	}
	if ip, err := detectClientIP(preferIfName); err == nil {
		info.ClientIP = ip
	} else {
		errs = append(errs, fmt.Sprintf("client ip: %v", err))
	}
	if version, err := readOSVersion(); err == nil {
		info.OSVersion = version
	} else {
		errs = append(errs, fmt.Sprintf("os version: %v", err))
	}
	if kernelVersion, machine, err := readKernelVersionAndMachine(); err == nil {
		info.KernelVersion = kernelVersion
		info.SystemModel = machine
	} else {
		errs = append(errs, fmt.Sprintf("kernel version: %v", err))
	}
	if model, err := readSystemModel(); err == nil && model != "" {
		info.SystemModel = model
	}
	if cpuModel, err := readCPUModel(); err == nil {
		info.CPUModel = cpuModel
	} else {
		errs = append(errs, fmt.Sprintf("cpu model: %v", err))
	}
	if memorySize, err := readMemorySize(); err == nil {
		info.MemorySize = memorySize
	} else {
		errs = append(errs, fmt.Sprintf("memory: %v", err))
	}
	if diskSize, err := readDiskSize(); err == nil {
		info.DiskSize = diskSize
	} else {
		errs = append(errs, fmt.Sprintf("disk: %v", err))
	}
	if len(errs) > 0 {
		return info, fmt.Errorf(strings.Join(errs, "; "))
	}
	return info, nil
}

func detectOSType() string {
	switch runtime.GOOS {
	case "linux":
		return "Linux"
	case "darwin":
		return "Darwin"
	case "windows":
		return "Windows"
	default:
		return strings.ToUpper(runtime.GOOS)
	}
}

func detectClientIP(preferIfName string) (string, error) {
	if preferIfName != "" {
		if iface, err := net.InterfaceByName(preferIfName); err == nil {
			if ip, ok := firstIPv4FromInterface(iface); ok {
				return ip, nil
			}
		}
	}
	// 不指定网卡获取ip流程
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	type candidate struct {
		score int
		name  string
		ip    string
	}
	candidates := make([]candidate, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ip, ok := firstIPv4FromInterface(&iface)
		if !ok {
			continue
		}
		candidates = append(candidates, candidate{
			score: interfacePriority(iface.Name),
			name:  iface.Name,
			ip:    ip,
		})
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no non-loopback IPv4 address found")
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score < candidates[j].score
		}
		return candidates[i].name < candidates[j].name
	})
	return candidates[0].ip, nil
}

func firstIPv4FromInterface(iface *net.Interface) (string, bool) {
	if iface == nil {
		return "", false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", false
	}
	for _, addr := range addrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		default:
			continue
		}
		ip = ip.To4()
		if ip == nil || !ip.IsGlobalUnicast() {
			continue
		}
		return ip.String(), true
	}
	return "", false
}

func interfacePriority(name string) int {
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "eth"),
		strings.HasPrefix(lower, "ens"),
		strings.HasPrefix(lower, "eno"),
		strings.HasPrefix(lower, "enp"),
		strings.HasPrefix(lower, "bond"),
		strings.HasPrefix(lower, "em"):
		return 0
	case strings.HasPrefix(lower, "docker"),
		strings.HasPrefix(lower, "veth"),
		strings.HasPrefix(lower, "cni"),
		strings.HasPrefix(lower, "flannel"),
		strings.HasPrefix(lower, "virbr"),
		strings.HasPrefix(lower, "br-"),
		strings.HasPrefix(lower, "tun"),
		strings.HasPrefix(lower, "tap"):
		return 20
	default:
		return 10
	}
}

func readOSVersion() (string, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		values[parts[0]] = strings.Trim(parts[1], `"`)
	}
	if pretty := strings.TrimSpace(values["PRETTY_NAME"]); pretty != "" {
		return pretty, nil
	}
	name := strings.TrimSpace(values["NAME"])
	version := strings.TrimSpace(values["VERSION"])
	if name == "" && version == "" {
		return "", fmt.Errorf("PRETTY_NAME/NAME/VERSION not found")
	}
	if version == "" {
		return name, nil
	}
	if name == "" {
		return version, nil
	}
	return name + " " + version, nil
}

func readSystemModel() (string, error) {
	candidates := []string{
		"/sys/devices/virtual/dmi/id/product_name",
		"/sys/class/dmi/id/product_name",
	}
	versionFiles := []string{
		"/sys/devices/virtual/dmi/id/product_version",
		"/sys/class/dmi/id/product_version",
	}
	model := ""
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		model = strings.TrimSpace(string(data))
		if model != "" && model != "None" {
			break
		}
	}
	if model == "" {
		return "", fmt.Errorf("system model not found")
	}
	for _, path := range versionFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		version := strings.TrimSpace(string(data))
		if version != "" && version != "None" && version != model {
			return model + " " + version, nil
		}
	}
	return model, nil
}

func readCPUModel() (string, error) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", err
	}
	for _, key := range []string{"model name", "Hardware", "Processor"} {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			if strings.TrimSpace(parts[0]) != key {
				continue
			}
			value := strings.TrimSpace(parts[1])
			if value != "" {
				return value, nil
			}
		}
	}
	return "", fmt.Errorf("cpu model not found")
}

func readMemorySize() (string, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		totalKB, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return "", err
		}
		return formatBytesBase10(totalKB * 1024), nil
	}
	return "", fmt.Errorf("MemTotal not found")
}

func readDiskSize() (string, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return "", err
	}
	total := uint64(stat.Blocks) * uint64(stat.Bsize)
	return formatBytesBase10(total), nil
}

func readKernelVersionAndMachine() (string, string, error) {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return "", "", err
	}
	release := int8ArrayString(uts.Release[:])
	machine := int8ArrayString(uts.Machine[:])
	if release == "" {
		return "", "", fmt.Errorf("kernel release is empty")
	}
	return release, machine, nil
}

func int8ArrayString(raw []int8) string {
	var b strings.Builder
	for _, item := range raw {
		if item == 0 {
			break
		}
		b.WriteByte(byte(item))
	}
	return b.String()
}

func formatBytesBase10(bytes uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	value := float64(bytes)
	unit := 0
	for value >= 1000 && unit < len(units)-1 {
		value /= 1000
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d%s", bytes, units[unit])
	}
	if value >= 10 {
		return fmt.Sprintf("%.0f%s", math.Round(value), units[unit])
	}
	return fmt.Sprintf("%.1f%s", value, units[unit])
}
