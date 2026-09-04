package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"power-ebpf/internal/bpfgen"
	"power-ebpf/internal/httptrace"
	"power-ebpf/internal/storage"
	"power-ebpf/internal/tlstrace"
)

const (
	flagStart           = 1 << 0
	flagEnd             = 1 << 1
	flagCaptureTrunc    = 1 << 2
	flagControl         = 1 << 4
	flagClose           = 1 << 5
	flagSizeOnly        = 1 << 6
	flagCaptureBoundary = 1 << 7

	kernelDebugFlagSnapshot             = 1 << 0
	kernelDebugFlagLegacySendPrimaryTCP = 1 << 8
	kernelDebugFlagLegacyRecvPrimaryTCP = 1 << 9
	redisQueuePermitBytes               = 64 << 10
	maxEventPayloadBytes                = 4095
)

var errRedisWriteQueueFull = errors.New("redis write queue is full")

type redisWriteItem struct {
	update  httptrace.Update
	permits int
}

// redisWriteQueue 有两类上限：channel 限制排队记录数，permits 限制排队中和处理中的记录所保留的字节数。
// 仅限制记录数并不安全，因为单个采集前缀可能达到数 MiB。
type redisWriteQueue struct {
	ch       chan redisWriteItem
	permits  chan struct{}
	maxBytes uint64
	bytes    atomic.Uint64
	peak     atomic.Uint64
	blocked  atomic.Uint64
}

func newRedisWriteQueue(recordCapacity, byteBudget int) *redisWriteQueue {
	if recordCapacity < 1 {
		recordCapacity = 1
	}
	if byteBudget < redisQueuePermitBytes {
		byteBudget = redisQueuePermitBytes
	}
	permitCapacity := (byteBudget + redisQueuePermitBytes - 1) / redisQueuePermitBytes
	return &redisWriteQueue{
		ch:       make(chan redisWriteItem, recordCapacity),
		permits:  make(chan struct{}, permitCapacity),
		maxBytes: uint64(permitCapacity * redisQueuePermitBytes),
	}
}

func estimateRedisUpdateBytes(update httptrace.Update) uint64 {
	// Save 将文档编码为 JSON，此时排队更新仍引用原始正文。正文字节按三份预留，
	// 覆盖原始正文、编码缓冲区以及分配器增长/Redis 客户端复制的开销。
	const metadataBytes = 16 << 10
	bytes := uint64(metadataBytes)
	if request := update.Trace.Request; request != nil {
		bytes += 3 * uint64(len(request.Body))
	}
	if response := update.Trace.Response; response != nil {
		bytes += 3 * uint64(len(response.Body))
	}
	return bytes
}

func (q *redisWriteQueue) permitsFor(update httptrace.Update) int {
	if q == nil {
		return 0
	}
	permits := (estimateRedisUpdateBytes(update) + redisQueuePermitBytes - 1) / redisQueuePermitBytes
	if permits == 0 {
		permits = 1
	}
	if permits > uint64(cap(q.permits)) {
		// 单条记录即使超过配置预算也仍会写入，但必须等待其他写入完成后再处理，
		// 不会在内存中无限复制。
		permits = uint64(cap(q.permits))
	}
	return int(permits)
}

// Redis 队列满时改为立即丢弃 Redis 副本并记录 redis_dropped，不再阻塞 HTTP worker 和 perf reader
func (q *redisWriteQueue) enqueue(ctx context.Context, update httptrace.Update) error {
	if q == nil {
		return nil
	}
	permits := q.permitsFor(update)
	for i := 0; i < permits; i++ {
		select {
		case q.permits <- struct{}{}:
			continue
		default:
			q.releasePermits(i)
			q.blocked.Add(1)
			return errRedisWriteQueueFull
		}
	}
	reserved := uint64(permits * redisQueuePermitBytes)
	current := q.bytes.Add(reserved)
	updateAtomicMax(&q.peak, current)
	item := redisWriteItem{update: update, permits: permits}
	select {
	case <-ctx.Done():
		q.release(permits)
		return ctx.Err()
	case q.ch <- item:
		return nil
	default:
		q.release(permits)
		q.blocked.Add(1)
		return errRedisWriteQueueFull
	}
}

func (q *redisWriteQueue) releasePermits(permits int) {
	if q == nil || permits <= 0 {
		return
	}
	for i := 0; i < permits; i++ {
		<-q.permits
	}
}

func (q *redisWriteQueue) release(permits int) {
	if q == nil || permits <= 0 {
		return
	}
	q.releasePermits(permits)
	q.bytes.Add(^uint64(permits*redisQueuePermitBytes - 1))
}

type Service struct {
	cfg                      Config
	filter                   ResolvedFilter
	assembler                *httptrace.Assembler
	store                    *storage.RedisStore
	resolver                 *socketResolver
	stats                    *stats
	heartbeat                *heartbeatRuntime
	resourcePlan             runtimeResourcePlan
	hookStrategy             bpfgen.HookStrategy
	lastRequestCaptureLimit  uint32
	lastResponseCaptureLimit uint32
	lastFilterDebugFlags     uint32
	lastTLSFlags             uint32
	lastDebugSnapshotSeq     uint64
	startTime                time.Time
	currentStatsDay          string
	collectEnabled           atomic.Bool
	dailyMu                  sync.Mutex
	runtimeMu                sync.RWMutex
	primaryPerfPerCPUBytes   int
	primaryPerfMaxMmapBytes  uint64
	primaryPerfCPUs          int
	tlsPerfPerCPUBytes       int
	tlsPerfMaxMmapBytes      uint64
	tlsPerfCPUs              int
	workerQueues             []chan httptrace.Event
	redisQueue               *redisWriteQueue
	retryQueue               chan struct{}
}

type stats struct {
	perfReceived       atomic.Uint64
	perfLost           atomic.Uint64
	requests           atomic.Uint64
	responses          atomic.Uint64
	inputBytes         atomic.Uint64
	outputBytes        atomic.Uint64
	redisWrites        atomic.Uint64
	redisFailures      atomic.Uint64
	redisDropped       atomic.Uint64
	parseFailures      atomic.Uint64
	evicted            atomic.Uint64
	userFiltered       atomic.Uint64
	tupleResolved      atomic.Uint64
	tupleMiss          atomic.Uint64
	stallFlushes       atomic.Uint64
	filterReq          atomic.Uint64
	filterResp         atomic.Uint64
	filterUnknown      atomic.Uint64
	filterByIP         atomic.Uint64
	filterByPort       atomic.Uint64
	filterByIface      atomic.Uint64
	resolverCache      atomic.Uint64
	resolverProc       atomic.Uint64
	updateReqWorker    atomic.Uint64
	updateRespWorker   atomic.Uint64
	updateRespStalled  atomic.Uint64
	updateReqEvicted   atomic.Uint64
	updateRespEvicted  atomic.Uint64
	retryQueued        atomic.Uint64
	retryResolved      atomic.Uint64
	retryDropped       atomic.Uint64
	retryOverflow      atomic.Uint64
	tuplePassThrough   atomic.Uint64
	chainPassThrough   atomic.Uint64
	workerBackpressure atomic.Uint64
	recordsRead        atomic.Uint64
	decodeNs           atomic.Uint64
	resolveNs          atomic.Uint64
	resolveProcNs      atomic.Uint64
	resolveProcSlow    atomic.Uint64
	filterNs           atomic.Uint64
	dispatchNs         atomic.Uint64
	dispatchBlockNs    atomic.Uint64
	dispatchBlocked    atomic.Uint64
	workerQueuePeak    atomic.Uint64
	shutdownFlushes    atomic.Uint64
	sourceMu           sync.Mutex
	rawBySource        map[string]sourceDirectionCounts
	updatesBySource    map[string]sourceUpdateCounts
	rawChainsByKey     map[string]*boundedChainSet
	updateChainsByKey  map[string]*boundedChainSet
	rawChainDetails    map[string]rawChainDetail
}

const (
	maxTrackedChainsPerKey = 65536
	maxRawChainDetails     = 2048
)

// boundedChainSet 仅用于诊断状态。raw/update 事件计数仍然精确；此集合避免高基数负载
// 一直保留所有 chain id，直到每日统计切换。
type boundedChainSet struct {
	ids      map[uint64]struct{}
	overflow uint64
}

func (s *boundedChainSet) add(id uint64) bool {
	if s == nil || id == 0 {
		return false
	}
	if s.ids == nil {
		s.ids = make(map[uint64]struct{})
	}
	if _, ok := s.ids[id]; ok {
		return false
	}
	if len(s.ids) >= maxTrackedChainsPerKey {
		s.overflow++
		return false
	}
	s.ids[id] = struct{}{}
	return true
}

func (s *boundedChainSet) contains(id uint64) bool {
	if s == nil {
		return false
	}
	_, ok := s.ids[id]
	return ok
}

func (s *boundedChainSet) count() (int, uint64) {
	if s == nil {
		return 0, 0
	}
	return len(s.ids), s.overflow
}

type sourceDirectionCounts struct {
	Request  uint64
	Response uint64
	Unknown  uint64
}

type sourceUpdateCounts struct {
	Request  uint64
	Response uint64
	Other    uint64
}

type rawChainDetail struct {
	Source    string
	Direction uint8
	ChainID   uint64
	SockID    uint64
	FD        int32
	Comm      string
	Prefix    string
}

type resolveRetryItem struct {
	event    httptrace.Event
	workerID int
}

var resolveRetryBackoffs = [...]time.Duration{
	10 * time.Millisecond,
	30 * time.Millisecond,
	100 * time.Millisecond,
}

func kernelDebugFlags(debug bool, strategy bpfgen.HookStrategy) uint32 {
	var flags uint32
	if debug {
		flags |= kernelDebugFlagSnapshot
	}
	switch strategy {
	case bpfgen.HookStrategyLegacyTCPSend:
		flags |= kernelDebugFlagLegacySendPrimaryTCP
	case bpfgen.HookStrategyLegacyTCPBoth, bpfgen.HookStrategyTCPOnly:
		flags |= kernelDebugFlagLegacySendPrimaryTCP
		flags |= kernelDebugFlagLegacyRecvPrimaryTCP
	}
	return flags
}

// 读取用户态下发的是否采集标志
func (s *Service) currentKernelDebugFlags() uint32 {
	flags := kernelDebugFlags(s.cfg.DebugKernel, s.hookStrategy)
	if !s.collectEnabled.Load() {
		flags |= dataCollectDisabledBit
	}
	return flags
}

func (s *Service) currentTLSFlags() uint32 {
	if s == nil || s.collectEnabled.Load() {
		return 0
	}
	return dataCollectDisabledBit
}

func (s *Service) currentCaptureLimits() (uint32, uint32, int) {
	if s == nil {
		return 32 * 1024, 32 * 1024, 32 * 1024
	}

	requestLimit := uint32(s.cfg.CaptureBytes)
	responseLimit := uint32(s.cfg.CaptureBytes)
	if s.store != nil {
		if v := s.store.RequestCaptureLimitBytes(); v > 0 {
			requestLimit = uint32(v)
		}
		if v := s.store.ResponseCaptureLimitBytes(); v > 0 {
			responseLimit = uint32(v)
		}
	}

	assemblerLimit := s.cfg.MaxMessageBytes
	if assemblerLimit <= 0 {
		assemblerLimit = s.cfg.CaptureBytes
	}
	if int(requestLimit) > assemblerLimit {
		assemblerLimit = int(requestLimit)
	}
	if int(responseLimit) > assemblerLimit {
		assemblerLimit = int(responseLimit)
	}
	if assemblerLimit <= 0 {
		assemblerLimit = 32 * 1024
	}
	return requestLimit, responseLimit, assemblerLimit
}

func NewService(cfg Config) (*Service, error) {
	cfg, plan := cfg.normalizedForHost()
	filter, err := cfg.ResolveFilter()
	if err != nil {
		return nil, err
	}
	var store *storage.RedisStore
	// redis地址空时不存储
	if cfg.RedisAddr != "" {
		if cfg.RedisPassword == "" {
			cfg.RedisPassword = "9/L16DcUm3zIJgui54F/hayuh/bsXcdLdv3De12EkH4="
		}
		redisPsw, err := SM4Decrypt(cfg.RedisPassword)
		store, err = storage.NewRedisStore(cfg.RedisAddr, redisPsw, cfg.RedisDB, cfg.RedisKeyPrefix, cfg.RedisTTL)
		if err != nil {
			return nil, err
		}
	} else {
		log.Printf("Redis 地址为空，不写入 Redis")
	}
	startTime := time.Now()
	heartbeat, err := newHeartbeatRuntime(cfg, startTime)
	if err != nil {
		return nil, err
	}
	log.Printf("运行时资源计划：%s", plan.Summary())
	svc := &Service{
		cfg:             cfg,
		filter:          filter,
		assembler:       httptrace.NewAssembler(cfg.MaxMessageBytes, cfg.TransactionTTL, cfg.ResponseStallTimeout),
		store:           store,
		resolver:        newSocketResolver(15 * time.Second),
		stats:           &stats{},
		heartbeat:       heartbeat,
		resourcePlan:    plan,
		startTime:       startTime,
		currentStatsDay: localDayStamp(startTime),
	}
	if svc.assembler != nil {
		_, _, assemblerLimit := svc.currentCaptureLimits()
		svc.assembler.SetMaxMessageBytes(assemblerLimit)
		svc.assembler.SetMaxRetainedBytes(cfg.AssemblerBufferBytes)
	}
	svc.assembler.SetDebugTLSQueue(cfg.DebugKernel)
	svc.collectEnabled.Store(true)
	return svc, nil
}

func (s *Service) Close() error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.Close()
}

func (s *Service) Run(ctx context.Context) error {
	// 移除内存锁限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	var (
		tlsObjs   *bpfgen.LoadedTLSObjects
		tlsLinks  []link.Link
		tlsReader *perf.Reader
	)

	log.Printf("正在加载 eBPF 对象...")
	stopLoadWatch := startPhaseWatch(ctx, "BPF 对象加载", 2*time.Second)
	objs, err := bpfgen.LoadObjects(nil)
	stopLoadWatch()
	if err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()
	log.Printf("eBPF 对象加载完成：variant=%s hook_strategy=%s", objs.Variant, objs.HookStrategy)
	s.hookStrategy = objs.HookStrategy

	// 内核态过滤，挂载点不能稳定获取，暂未开启内核态过滤
	if err := s.installFilter(objs); err != nil {
		return err
	}

	if err := s.syncCaptureLimitsToKernel(objs.FilterMap); err != nil {
		log.Printf("初始内核采集上限同步失败：%v", err)
	}
	log.Printf("已解析过滤规则：%s", s.filter.Summary())
	if s.cfg.DisableUserTuple {
		log.Printf("用户元组管道已禁用：跳过/proc元组解析和用户空间元组过滤器；redis/控制台输出在可用时保留内核元组")
	}

	stopAttachWatch := startPhaseWatch(ctx, "probe 挂载", 2*time.Second)
	links, err := attachAll(objs)
	stopAttachWatch()
	if err != nil {
		return err
	}
	defer closeAll(links)
	log.Printf("探针挂载完成")

	if s.cfg.EnableTLS {
		log.Printf("正在加载 TLS uprobe...")
		stopTLSLoadWatch := startPhaseWatch(ctx, "TLS 对象加载", 2*time.Second)
		tlsObjs, err = bpfgen.LoadTLSObjects(nil)
		stopTLSLoadWatch()
		if err != nil {
			return fmt.Errorf("load tls objects: %w", err)
		}
		defer tlsObjs.Close()

		if err := s.installTLSConfig(tlsObjs.TLSConfigMap); err != nil {
			return err
		}

		tlsLibPaths, err := tlstrace.ResolveLibraryPaths(tlstrace.DiscoveryOptions{
			ExplicitPaths: tlstrace.SplitCSVPaths(s.cfg.TLSLibPath),
			ProcessComm:   s.cfg.TLSComm,
		})
		if err != nil {
			return fmt.Errorf("resolve tls library paths: %w", err)
		}
		log.Printf("已解析 comm=%q 的 TLS 库：%s", tlstrace.ResolveTargetComm(s.cfg.TLSComm), strings.Join(tlsLibPaths, ","))

		stopTLSAttachWatch := startPhaseWatch(ctx, "TLS uprobe 挂载", 2*time.Second)
		tlsLinks, err = tlstrace.AttachAll(tlsObjs, tlsLibPaths)
		stopTLSAttachWatch()
		if err != nil {
			return fmt.Errorf("attach tls uprobes: %w", err)
		}
		defer closeAll(tlsLinks)

		// perf.NewReader 会为每个可能的 CPU 分配这块数据区域。TLS 和 socket reader 共用同一套
		// 有界的每 CPU 预算；如果在这里重复放大，TLS 模式会消耗已经全局分配的环形区的四倍内存。
		tlsReader, err = perf.NewReader(tlsObjs.Events, s.cfg.PerfBufferBytes())
		if err != nil {
			return fmt.Errorf("create tls perf reader: %w", err)
		}
		defer tlsReader.Close()
	}

	reader, err := perf.NewReader(objs.Events, s.cfg.PerfBufferBytes())
	if err != nil {
		return fmt.Errorf("create perf reader: %w", err)
	}
	defer reader.Close()

	// 启动redis写入器
	writeCh, writersDone := s.startRedisWriters()
	// 启动工作线程，将事件分发到对应的worker中，每个worker一个channel，用于接收事件
	workers, workersDone := s.startWorkers(writeCh)

	retrySem := make(chan struct{}, s.cfg.RetryQueueSize) // 重试队列，用于重试失败的事件
	s.setRuntimeDiagnostics(reader, int(objs.Events.MaxEntries()), tlsReader, func() int {
		if tlsObjs == nil {
			return 0
		}
		return int(tlsObjs.Events.MaxEntries())
	}(), workers, writeCh, retrySem)
	var retryWG sync.WaitGroup

	var wg sync.WaitGroup
	errCh := make(chan error, 4)

	wg.Add(1)
	go func() {
		defer wg.Done()
		// 启动读取循环，读取事件并分发到对应的worker中
		if err := s.readLoop(ctx, reader, workers, retrySem, &retryWG); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, perf.ErrClosed) {
			errCh <- err
		}
	}()

	if tlsReader != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.readLoop(ctx, tlsReader, workers, retrySem, &retryWG); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, perf.ErrClosed) {
				errCh <- err
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		var tlsConfigMap *ebpf.Map
		if tlsObjs != nil {
			tlsConfigMap = tlsObjs.TLSConfigMap
		}
		if err := s.logLoop(ctx, objs, tlsConfigMap, writeCh); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
	}()

	if s.heartbeat != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var tlsConfigMap *ebpf.Map
			if tlsObjs != nil {
				tlsConfigMap = tlsObjs.TLSConfigMap
			}
			if err := s.heartbeatLoop(ctx, objs.FilterMap, tlsConfigMap); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-errCh:
		runErr = err
	}

	reader.Close()
	if tlsReader != nil {
		tlsReader.Close()
	}
	wg.Wait()
	retryWG.Wait()
	for _, ch := range workers {
		close(ch)
	}
	workersDone.Wait()

	flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	updates, flushedStates := s.assembler.FlushAll()
	for _, update := range updates {
		s.handleUpdate(flushCtx, "shutdown", update, writeCh)
	}
	if len(updates) > 0 || flushedStates > 0 {
		s.stats.shutdownFlushes.Add(uint64(len(updates)))
		log.Printf("停止前刷新完成：states=%d updates=%d", flushedStates, len(updates))
	}

	if writeCh != nil {
		close(writeCh.ch)
	}
	writersDone.Wait()
	s.logStatsSnapshot("final", objs)
	return runErr
}

// installFilter 把内核侧过滤规则写入 map。
// 当前 tuple-cache 方案先只强化端口/IP 过滤，不在 socket hook 上强依赖 ifindex。
func (s *Service) installFilter(objs *bpfgen.LoadedObjects) error {
	key := uint32(0)
	kernelFilter := s.filter.Kernel
	// 获取当前采集限制,用于设置内核态过滤规则
	requestLimit, responseLimit, assemblerLimit := s.currentCaptureLimits()
	if s.assembler != nil {
		s.assembler.SetMaxMessageBytes(assemblerLimit)
	}
	// cfg.DisableKernelFilter=false 则不进行内核态过滤
	if s.cfg.DisableKernelFilter {
		log.Printf("按标志关闭内核端点过滤：perf 输出前跳过全部 IP/端口检查")
		kernelFilter.Ifindex = 0
		kernelFilter.SrcIp = 0
		kernelFilter.DstIp = 0
		kernelFilter.SrcPort = 0
		kernelFilter.DstPort = 0
		kernelFilter.RequestCaptureBytes = requestLimit
		kernelFilter.ResponseCaptureBytes = responseLimit
		kernelFilter.DebugFlags = s.currentKernelDebugFlags()
		if err := objs.FilterMap.Update(&key, &kernelFilter, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update filter map: %w", err)
		}
		s.lastRequestCaptureLimit = kernelFilter.RequestCaptureBytes
		s.lastResponseCaptureLimit = kernelFilter.ResponseCaptureBytes
		s.lastFilterDebugFlags = kernelFilter.DebugFlags
		return nil
	}
	if kernelFilter.Ifindex != 0 {
		log.Printf("五元组缓存模式不执行 ifname 过滤：socket 层 ifindex 可靠性不足")
	}
	kernelFilter.Ifindex = 0
	kernelFilter.RequestCaptureBytes = requestLimit
	kernelFilter.ResponseCaptureBytes = responseLimit
	kernelFilter.DebugFlags = s.currentKernelDebugFlags()
	if objs.HookStrategy == bpfgen.HookStrategyLegacySock ||
		objs.HookStrategy == bpfgen.HookStrategyLegacyTCPSend ||
		objs.HookStrategy == bpfgen.HookStrategyLegacyTCPBoth {
		// 4.x 上 sock 结构布局在不同发行版/回移内核间差异更大，
		// 改成用 inet_sock_set_state 维护 tuple cache，send/recv 路径优先查 cache 做端口/IP 过滤。
		// 这样 4.x 不再依赖收发现场直接读 sock_common 来做强过滤。
		log.Printf("检测到旧版 4.x 内核：优先使用基于五元组缓存的内核端口/IP 过滤，忽略 socket 层 ifname 过滤")
	}
	if err := objs.FilterMap.Update(&key, &kernelFilter, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update filter map: %w", err)
	}
	s.lastRequestCaptureLimit = kernelFilter.RequestCaptureBytes
	s.lastResponseCaptureLimit = kernelFilter.ResponseCaptureBytes
	s.lastFilterDebugFlags = kernelFilter.DebugFlags
	return nil
}

// 用户态同步 【 1. 内核采集限制 2. 内核采集开关 】 给 内核态
func (s *Service) syncCaptureLimitsToKernel(filterMap *ebpf.Map) error {
	if s == nil || filterMap == nil {
		return nil
	}

	requestLimit, responseLimit, assemblerLimit := s.currentCaptureLimits()
	if s.assembler != nil {
		s.assembler.SetMaxMessageBytes(assemblerLimit)
	}
	debugFlags := s.currentKernelDebugFlags()
	if requestLimit == s.lastRequestCaptureLimit &&
		responseLimit == s.lastResponseCaptureLimit &&
		debugFlags == s.lastFilterDebugFlags {
		return nil
	}

	key := uint32(0)
	kernelFilter := s.filter.Kernel
	if s.cfg.DisableKernelFilter {
		kernelFilter.Ifindex = 0
		kernelFilter.SrcIp = 0
		kernelFilter.DstIp = 0
		kernelFilter.SrcPort = 0
		kernelFilter.DstPort = 0
	}
	kernelFilter.RequestCaptureBytes = requestLimit
	kernelFilter.ResponseCaptureBytes = responseLimit
	kernelFilter.DebugFlags = debugFlags
	if err := filterMap.Update(&key, &kernelFilter, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update dynamic capture limits: %w", err)
	}

	s.lastRequestCaptureLimit = requestLimit
	s.lastResponseCaptureLimit = responseLimit
	s.lastFilterDebugFlags = debugFlags
	log.Printf("内核采集状态已更新：request=%dB response=%dB assembler=%dB enabled=%t", requestLimit, responseLimit, assemblerLimit, s.collectEnabled.Load())
	return nil
}

func (s *Service) installTLSConfig(configMap *ebpf.Map) error {
	if s == nil || configMap == nil {
		return nil
	}

	requestLimit, responseLimit, assemblerLimit := s.currentCaptureLimits()
	if s.assembler != nil {
		s.assembler.SetMaxMessageBytes(assemblerLimit)
	}

	var cfg bpfgen.TlsTraceConfig
	cfg.RequestCaptureBytes = requestLimit
	cfg.ResponseCaptureBytes = responseLimit
	cfg.Flags = s.currentTLSFlags()
	for i, r := range tlstrace.ResolveTargetComm(s.cfg.TLSComm) {
		if i >= len(cfg.Comm) {
			break
		}
		cfg.Comm[i] = int8(r)
	}

	key := uint32(0)
	s.lastTLSFlags = cfg.Flags
	if err := configMap.Update(&key, &cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update tls config map: %w", err)
	}
	log.Printf("TLS 采集状态已更新：request=%dB response=%dB assembler=%dB flags=%d", requestLimit, responseLimit, assemblerLimit, cfg.Flags)
	return nil
}

func (s *Service) startRedisWriters() (*redisWriteQueue, *sync.WaitGroup) {
	var wg sync.WaitGroup

	if s.store == nil {
		return nil, &wg
	}
	workerCount := s.cfg.RedisWorkers
	if workerCount <= 0 {
		workerCount = max(1, runtime.NumCPU()/2)
	}
	queueSize := s.cfg.RedisQueueSize
	if queueSize <= 0 {
		queueSize = max(256, s.resourcePlan.RedisQueueSize)
	}
	queue := newRedisWriteQueue(queueSize, s.cfg.RedisQueueBytes)
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for item := range queue.ch {
				// 超时
				saveCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				err := s.store.Save(saveCtx, item.update.Trace)
				cancel()
				queue.release(item.permits)
				if err != nil {
					s.stats.redisFailures.Add(1)
					log.Printf("[redis-worker=%d] 保存失败：%v", workerID, err)
					continue
				}
				s.stats.redisWrites.Add(1)
			}
		}(i)
	}
	return queue, &wg
}

// startWorkers 启动批量解析 worker。每个 worker 固定一个 OS 线程，减少高并发下的调度抖动。
func (s *Service) startWorkers(writeCh *redisWriteQueue) ([]chan httptrace.Event, *sync.WaitGroup) {
	workerCount := s.cfg.WorkerCount
	if workerCount <= 0 {
		workerCount = max(1, s.resourcePlan.WorkerCount)
	}
	queueSize := s.cfg.WorkerQueueSize
	if queueSize <= 0 {
		queueSize = max(s.cfg.BatchSize*2, s.resourcePlan.WorkerQueueSize)
	}

	var wg sync.WaitGroup
	workers := make([]chan httptrace.Event, workerCount)
	for i := 0; i < workerCount; i++ {
		// 启动期如果按 CPU 数创建超深队列，在多核老机器上会一次性吃掉大量内存。
		// 这里改成按可用内存自动收敛后的队列深度，优先保证进程稳定启动。
		workers[i] = make(chan httptrace.Event, queueSize)
		wg.Add(1)
		go s.workerLoop(i, workers[i], writeCh, &wg)
	}
	return workers, &wg
}

// setRuntimeDiagnostics记录实际性能读取器的容量和
// 用户空间队列。PerfReader。BufferSize是每个CPU的数据区域；这
// 内核mmap还为每个CPU包含一个元数据页。用于记录实际性能读取器的容量和用户空间队列的容量。
func (s *Service) setRuntimeDiagnostics(primary *perf.Reader, primaryCPUs int, tlsReader *perf.Reader, tlsCPUs int, workers []chan httptrace.Event, redisQueue *redisWriteQueue, retryQueue chan struct{}) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	s.primaryPerfCPUs = primaryCPUs
	if primary != nil {
		s.primaryPerfPerCPUBytes = primary.BufferSize()
		s.primaryPerfMaxMmapBytes = uint64(primary.BufferSize()+os.Getpagesize()) * uint64(max(primaryCPUs, 0))
	}
	s.tlsPerfCPUs = tlsCPUs
	if tlsReader != nil {
		s.tlsPerfPerCPUBytes = tlsReader.BufferSize()
		s.tlsPerfMaxMmapBytes = uint64(tlsReader.BufferSize()+os.Getpagesize()) * uint64(max(tlsCPUs, 0))
	}
	s.workerQueues = workers
	s.redisQueue = redisQueue
	s.retryQueue = retryQueue
	pageSize := os.Getpagesize()
	workerSlots := workerQueueCapacity(workers) * len(workers)
	workerStructBytes := uint64(workerSlots) * uint64(unsafe.Sizeof(httptrace.Event{}))
	workerPayloadBytes := uint64(workerSlots * maxEventPayloadBytes)
	log.Printf("运行时缓冲区实际容量(page_size=%d perf_data_pages_per_cpu=%d perf_mmap_pages_per_cpu=%d perf_data_per_cpu=%s perf_mmap_max=%s perf_cpu_slots=%d tls_perf_data_pages_per_cpu=%d tls_perf_mmap_pages_per_cpu=%d tls_perf_data_per_cpu=%s tls_perf_mmap_max=%s tls_perf_cpu_slots=%d worker_count=%d worker_queue_capacity=%d worker_queue_slots=%d worker_queue_struct_bytes=%s worker_queue_payload_upper=%s worker_queue_retained_upper=%s redis_queue_capacity=%d redis_queue_budget=%s retry_queue_capacity=%d event_struct_bytes=%d max_event_payload_bytes=%d)",
		pageSize,
		s.primaryPerfPerCPUBytes/pageSize,
		(s.primaryPerfPerCPUBytes+pageSize)/pageSize,
		formatBytesIEC(uint64(s.primaryPerfPerCPUBytes)),
		formatBytesIEC(s.primaryPerfMaxMmapBytes),
		s.primaryPerfCPUs,
		s.tlsPerfPerCPUBytes/pageSize,
		(s.tlsPerfPerCPUBytes+pageSize)/pageSize,
		formatBytesIEC(uint64(s.tlsPerfPerCPUBytes)),
		formatBytesIEC(s.tlsPerfMaxMmapBytes),
		s.tlsPerfCPUs,
		len(workers),
		workerQueueCapacity(workers),
		workerSlots,
		formatBytesIEC(workerStructBytes),
		formatBytesIEC(workerPayloadBytes),
		formatBytesIEC(workerStructBytes+workerPayloadBytes),
		redisQueueCapacity(redisQueue),
		formatBytesIEC(redisQueueBudget(redisQueue)),
		queueCapacity(retryQueue),
		unsafe.Sizeof(httptrace.Event{}), maxEventPayloadBytes,
	)
}

func workerQueueCapacity(queues []chan httptrace.Event) int {
	if len(queues) == 0 {
		return 0
	}
	return cap(queues[0])
}

func queueCapacity[T any](queue chan T) int {
	if queue == nil {
		return 0
	}
	return cap(queue)
}

func redisQueueCapacity(queue *redisWriteQueue) int {
	if queue == nil {
		return 0
	}
	return cap(queue.ch)
}

func redisQueueBytes(queue *redisWriteQueue) uint64 {
	if queue == nil {
		return 0
	}
	return queue.bytes.Load()
}

func redisQueueBudget(queue *redisWriteQueue) uint64 {
	if queue == nil {
		return 0
	}
	return queue.maxBytes
}

func redisQueuePeak(queue *redisWriteQueue) uint64 {
	if queue == nil {
		return 0
	}
	return queue.peak.Load()
}

func redisQueueBlocked(queue *redisWriteQueue) uint64 {
	if queue == nil {
		return 0
	}
	return queue.blocked.Load()
}

func (s *Service) logRuntimeDiagnostics(label string) {
	s.runtimeMu.RLock()
	defer s.runtimeMu.RUnlock()
	workerSlots, workerCapacity, workerMax := 0, 0, 0
	for _, queue := range s.workerQueues {
		if queue == nil {
			continue
		}
		n := len(queue)
		workerSlots += n
		workerCapacity += cap(queue)
		if n > workerMax {
			workerMax = n
		}
	}
	workerStructBytes := uint64(workerSlots) * uint64(unsafe.Sizeof(httptrace.Event{}))
	workerPayloadBytes := uint64(workerSlots * maxEventPayloadBytes)
	workerCapacityStructBytes := uint64(workerCapacity) * uint64(unsafe.Sizeof(httptrace.Event{}))
	workerCapacityPayloadBytes := uint64(workerCapacity * maxEventPayloadBytes)
	redisSlots, redisCapacity := 0, 0
	if s.redisQueue != nil {
		redisSlots, redisCapacity = len(s.redisQueue.ch), cap(s.redisQueue.ch)
	}
	pageSize := os.Getpagesize()
	log.Printf("%s 运行时资源使用情况(page_size=%d perf_data_pages_per_cpu=%d perf_mmap_pages_per_cpu=%d perf_data_per_cpu=%s perf_mmap_max=%s perf_cpu_slots=%d tls_perf_data_pages_per_cpu=%d tls_perf_mmap_pages_per_cpu=%d tls_perf_data_per_cpu=%s tls_perf_mmap_max=%s tls_perf_cpu_slots=%d worker_queue_slots=%d/%d worker_queue_struct_bytes=%s/%s worker_queue_payload_upper=%s/%s worker_queue_retained_upper=%s/%s worker_queue_max=%d redis_queue_slots=%d/%d redis_queue_bytes=%s/%s redis_queue_peak=%s redis_queue_blocked=%d retry_queue_slots=%d/%d perf_received=%d perf_lost=%d worker_backpressure=%d dispatch_blocked=%d)",
		label,
		pageSize,
		s.primaryPerfPerCPUBytes/pageSize,
		(s.primaryPerfPerCPUBytes+pageSize)/pageSize,
		formatBytesIEC(uint64(s.primaryPerfPerCPUBytes)),
		formatBytesIEC(s.primaryPerfMaxMmapBytes),
		s.primaryPerfCPUs,
		s.tlsPerfPerCPUBytes/pageSize,
		(s.tlsPerfPerCPUBytes+pageSize)/pageSize,
		formatBytesIEC(uint64(s.tlsPerfPerCPUBytes)),
		formatBytesIEC(s.tlsPerfMaxMmapBytes),
		s.tlsPerfCPUs,
		workerSlots, workerCapacity,
		formatBytesIEC(workerStructBytes), formatBytesIEC(workerCapacityStructBytes),
		formatBytesIEC(workerPayloadBytes), formatBytesIEC(workerCapacityPayloadBytes),
		formatBytesIEC(workerStructBytes+workerPayloadBytes), formatBytesIEC(workerCapacityStructBytes+workerCapacityPayloadBytes), workerMax,
		redisSlots, redisCapacity,
		formatBytesIEC(redisQueueBytes(s.redisQueue)), formatBytesIEC(redisQueueBudget(s.redisQueue)), formatBytesIEC(redisQueuePeak(s.redisQueue)), redisQueueBlocked(s.redisQueue),
		retryQueueUsage(s.retryQueue), queueCapacity(s.retryQueue),
		s.stats.perfReceived.Load(), s.stats.perfLost.Load(), s.stats.workerBackpressure.Load(), s.stats.dispatchBlocked.Load(),
	)
}

func logProcessMemory(label string) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	log.Printf("%s 进程内存使用情况(rss=%s heap_alloc=%s heap_inuse=%s heap_idle=%s heap_released=%s heap_objects=%d stack_inuse=%s goroutines=%d gc=%d)",
		label,
		formatBytesIEC(processRSSBytes()),
		formatBytesIEC(mem.HeapAlloc),
		formatBytesIEC(mem.HeapInuse),
		formatBytesIEC(mem.HeapIdle),
		formatBytesIEC(mem.HeapReleased),
		mem.HeapObjects,
		formatBytesIEC(mem.StackInuse),
		runtime.NumGoroutine(),
		mem.NumGC,
	)
}

func processRSSBytes() uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "VmRSS:" {
			continue
		}
		kilobytes, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kilobytes << 10
	}
	return 0
}

func retryQueueUsage(queue chan struct{}) int {
	if queue == nil {
		return 0
	}
	return len(queue)
}

// workerLoop 负责批量调用 assembler、打印解析结果、落 Redis。
func (s *Service) workerLoop(workerID int, ch <-chan httptrace.Event, writeCh *redisWriteQueue, wg *sync.WaitGroup) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer wg.Done()

	batch := make([]httptrace.Event, 0, s.cfg.BatchSize)
	flushTicker := time.NewTicker(s.cfg.FlushInterval)
	defer flushTicker.Stop()

	flush := func() {
		for _, event := range batch {
			// 聚合入口
			updates, err := s.assembler.Process(event)
			if err != nil {
				s.stats.parseFailures.Add(1)
				log.Printf("[worker=%d] 处理事件失败：%v", workerID, err)
				continue
			}
			for _, update := range updates {
				s.handleUpdate(context.Background(), fmt.Sprintf("worker=%d", workerID), update, writeCh)
			}
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-flushTicker.C:
			if len(batch) > 0 {
				flush()
			}
		case event, ok := <-ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, event)
			if len(batch) >= s.cfg.BatchSize {
				flush()
			}
		}
	}
}

func (s *Service) printHTTPTraceTag(tag string, update httptrace.Update) {
	view := struct {
		Kind            string                `json:"kind"`
		ChainID         uint64                `json:"chain_id"`
		PID             uint32                `json:"pid"`
		FD              int32                 `json:"fd"`
		Comm            string                `json:"comm"`
		CaptureSource   string                `json:"capture_source,omitempty"`
		SrcIP           string                `json:"src_ip"`
		DstIP           string                `json:"dst_ip"`
		SrcPort         uint16                `json:"src_port"`
		DstPort         uint16                `json:"dst_port"`
		RequestTrunc    bool                  `json:"request_truncated,omitempty"`
		ResponseTrunc   bool                  `json:"response_truncated,omitempty"`
		ResponseLatency *float64              `json:"response_latency_ms,omitempty"` //请求开始到响应开始
		Request         *consoleParsedMessage `json:"request,omitempty"`
		Response        *consoleParsedMessage `json:"response,omitempty"`
	}{
		Kind:            update.Kind,
		ChainID:         update.Trace.ChainID,
		PID:             update.Trace.PID,
		FD:              update.Trace.FD,
		Comm:            update.Trace.Comm,
		CaptureSource:   update.Trace.CaptureSource,
		SrcIP:           update.Trace.SrcIP,
		DstIP:           update.Trace.DstIP,
		SrcPort:         update.Trace.SrcPort,
		DstPort:         update.Trace.DstPort,
		RequestTrunc:    update.Trace.RequestTruncated,
		ResponseTrunc:   update.Trace.ResponseTruncated,
		ResponseLatency: update.Trace.ResponseLatency,
		Request:         newConsoleParsedMessage(update.Trace.Request),
		Response:        newConsoleParsedMessage(update.Trace.Response),
	}
	body, err := json.Marshal(view)
	if err != nil {
		log.Printf("[%s] 序列化控制台追踪信息失败：%v", tag, err)
		return
	}
	log.Printf("[%s] HTTP=%s", tag, string(body))
}

func (s *Service) handleUpdate(ctx context.Context, tag string, update httptrace.Update, writeCh *redisWriteQueue) {
	update.Trace = s.enrichTraceTupleForOutput(update.Trace)
	update.Trace = s.sanitizeTraceForOutput(update.Trace)
	s.stats.recordUpdateSource(update.Trace.CaptureSource, update.Kind, update.Trace.ChainID)
	// 统计请求次数、请求大小
	if update.Kind == "request" {
		s.stats.requests.Add(1)
		s.stats.inputBytes.Add(traceObservedBytes(update.Trace.Request))
	}
	// 统计响应次数、响应大小
	if update.Kind == "response" {
		s.stats.responses.Add(1)
		s.stats.outputBytes.Add(traceObservedBytes(update.Trace.Response))
	}
	if tag == "stalled" && update.Kind == "response" {
		s.stats.stallFlushes.Add(1)
	}
	s.recordUpdatePath(tag, update.Kind)
	if s.cfg.DebugKernel {
		s.logAssemblyDiagnostic(tag, update)
	}
	if s.cfg.PrintSummary {
		log.Printf("[%s] %s", tag, update.Trace.SummaryLine())
	}
	if s.cfg.PrintHTTP {
		s.printHTTPTraceTag(tag, update)
	}
	if writeCh != nil {
		if err := writeCh.enqueue(ctx, update); errors.Is(err, errRedisWriteQueueFull) {
			s.stats.redisDropped.Add(1)
		} else if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[%s] Redis 写入入队失败：%v", tag, err)
		}
	}
}

func (s *Service) logAssemblyDiagnostic(tag string, update httptrace.Update) {
	switch update.Kind {
	case "request":
		if update.Trace.Request == nil || !update.Trace.RequestTruncated {
			return
		}
		log.Printf(
			"[%s] 请求诊断：chain=%d source=%s truncated=%t body_bytes=%d observed=%d consumed=%d content_length=%d chunked=%t body_partial=%t",
			tag,
			update.Trace.ChainID,
			update.Trace.CaptureSource,
			update.Trace.RequestTruncated,
			messageBodySize(update.Trace.Request),
			update.Trace.Request.ObservedMessageBytes,
			update.Trace.Request.ConsumedBytes,
			update.Trace.Request.ContentLength,
			update.Trace.Request.Chunked,
			update.Trace.Request.BodyPartial,
		)
	case "response":
		if update.Trace.Response == nil {
			return
		}
		if !(update.Trace.ResponseTruncated || update.Trace.Response.BodyPartial || tag == "stalled") {
			return
		}
		reason := "assembled_partial"
		if tag == "stalled" {
			reason = "stalled_flush"
		}
		log.Printf(
			"[%s] 响应诊断：chain=%d reason=%s source=%s truncated=%t status=%d chunked=%t body_partial=%t body_bytes=%d observed=%d consumed=%d content_length=%d",
			tag,
			update.Trace.ChainID,
			reason,
			update.Trace.CaptureSource,
			update.Trace.ResponseTruncated,
			update.Trace.Response.StatusCode,
			update.Trace.Response.Chunked,
			update.Trace.Response.BodyPartial,
			messageBodySize(update.Trace.Response),
			update.Trace.Response.ObservedMessageBytes,
			update.Trace.Response.ConsumedBytes,
			update.Trace.Response.ContentLength,
		)
	}
}

func (s *Service) enrichTraceTupleForOutput(trace httptrace.TraceDocument) httptrace.TraceDocument {
	event := httptrace.Event{
		PID:     trace.PID,
		FD:      trace.FD,
		SockID:  trace.SockID,
		SrcIP:   trace.SrcIP,
		DstIP:   trace.DstIP,
		SrcPort: trace.SrcPort,
		DstPort: trace.DstPort,
	}
	switch trace.Kind {
	case "request":
		event.Direction = httptrace.DirectionRequest
	case "response":
		event.Direction = httptrace.DirectionResponse
	}

	// 内核 tuple 已经完整时，优先信任事件本身，再按方向做 request 的 src/dst 翻转。
	// 这里不要再用 /proc 当前 fd 反查结果覆盖，否则高并发下 fd 复用会把旧请求误写成新的 loopback 连接。
	if !missingTuple(event) {
		if event.Direction == httptrace.DirectionRequest {
			event.SrcIP, event.DstIP = event.DstIP, event.SrcIP
			event.SrcPort, event.DstPort = event.DstPort, event.SrcPort
		}
		trace.SrcIP = event.SrcIP
		trace.DstIP = event.DstIP
		trace.SrcPort = event.SrcPort
		trace.DstPort = event.DstPort
		return trace
	}

	resolvedByResolver := false
	if s != nil && s.resolver != nil && trace.PID != 0 && trace.FD >= 0 {
		key := socketKey{pid: trace.PID, fd: trace.FD, sockID: trace.SockID}
		if tuple, ok := s.resolver.lookupCache(key); ok {
			event = applyResolvedTuple(event, tuple)
			resolvedByResolver = true
		}
	}

	if missingTuple(event) {
		return trace
	}

	if !resolvedByResolver && event.Direction == httptrace.DirectionRequest && !missingTuple(event) {
		event.SrcIP, event.DstIP = event.DstIP, event.SrcIP
		event.SrcPort, event.DstPort = event.DstPort, event.SrcPort
	}
	trace.SrcIP = event.SrcIP
	trace.DstIP = event.DstIP
	trace.SrcPort = event.SrcPort
	trace.DstPort = event.DstPort
	return trace
}

// 判断 IP 是否为空
func isZeroTraceIP(ip string) bool {
	ip = strings.TrimSpace(ip)
	return ip == "" || ip == "0.0.0.0" || ip == "::"
}

// 定位来源ip没采集到的原因
func (s *Service) missingSrcIPMarker(trace httptrace.TraceDocument) string {
	switch {
	case strings.HasPrefix(trace.CaptureSource, "tls_"):
		// TLS 路径本身没有 socket tuple ，http场景不涉及
		return "missing:tls_no_tuple"
	case s != nil && s.cfg.DisableUserTuple:
		// 用户态 tuple 反查被关闭
		return "missing:user_tuple_disabled"
	case trace.PID == 0 || trace.FD < 0:
		// 没有 socket 标识
		return "missing:no_socket_identity"
	case trace.SrcPort != 0 || trace.DstPort != 0:
		// 内核 tuple 提取失败
		return "missing:kernel_port_only_or_resolver_miss"
	default:
		// 内核 tuple 提取失败
		return "missing:kernel_tuple_extract_failed"
	}
}

// sanitizeTraceForOutput 只在最终输出到控制台/Redis前做最后修饰。
// 如果来源 IP 仍然缺失，就给出一个可观测的原因标记，方便线上区分：
// 1. 内核只拿到了端口，没有拿到 IP。
// 2. 用户态 tuple 反查被关闭。
// 3. TLS 路径本身没有 socket tuple。
func (s *Service) sanitizeTraceForOutput(trace httptrace.TraceDocument) httptrace.TraceDocument {
	if isZeroTraceIP(trace.SrcIP) {
		trace.SrcIP = s.missingSrcIPMarker(trace)
	}
	return trace
}

// 记录过滤事件
func (s *Service) recordFilterDrop(direction uint8, reason FilterReason) {
	switch direction {
	case httptrace.DirectionRequest:
		s.stats.filterReq.Add(1)
	case httptrace.DirectionResponse:
		s.stats.filterResp.Add(1)
	default:
		s.stats.filterUnknown.Add(1)
	}

	switch reason {
	case FilterReasonIP:
		s.stats.filterByIP.Add(1)
	case FilterReasonPort:
		s.stats.filterByPort.Add(1)
	case FilterReasonIface:
		s.stats.filterByIface.Add(1)
	}
}

func (s *Service) recordUpdatePath(tag, kind string) {
	switch tag {
	case "stalled":
		if kind == "response" {
			s.stats.updateRespStalled.Add(1)
		}
	case "evicted":
		if kind == "request" {
			s.stats.updateReqEvicted.Add(1)
		}
		if kind == "response" {
			s.stats.updateRespEvicted.Add(1)
		}
	default:
		if strings.HasPrefix(tag, "worker=") {
			if kind == "request" {
				s.stats.updateReqWorker.Add(1)
			}
			if kind == "response" {
				s.stats.updateRespWorker.Add(1)
			}
		}
	}
}

type consoleParsedMessage struct {
	StartLine            string            `json:"start_line"` // 起始行
	Version              string            `json:"version,omitempty"`
	Method               string            `json:"method,omitempty"`                 // 方法
	URL                  string            `json:"url,omitempty"`                    // URL
	StatusCode           int               `json:"status_code,omitempty"`            // 状态码
	Reason               string            `json:"reason,omitempty"`                 // 原因
	Headers              map[string]string `json:"headers,omitempty"`                // 头
	Body                 string            `json:"body,omitempty"`                   // body
	BodySizeBytes        int               `json:"body_size_bytes,omitempty"`        // body 字节数
	ObservedMessageBytes uint64            `json:"observed_message_bytes,omitempty"` // 观察到的消息字节数
	ContentLength        int64             `json:"content_length,omitempty"`         // 内容长度
	TransferEncoding     string            `json:"transfer_encoding,omitempty"`      // 传输编码
	Chunked              bool              `json:"chunked,omitempty"`                // 是否是 chunked
	BodyPartial          bool              `json:"body_partial,omitempty"`           // 是否是部分 body
}

func newConsoleParsedMessage(msg *httptrace.ParsedMessage) *consoleParsedMessage {
	if msg == nil {
		return nil
	}
	return &consoleParsedMessage{
		StartLine:            msg.StartLine,
		Version:              msg.Version,
		Method:               msg.Method,
		URL:                  msg.URL,
		StatusCode:           msg.StatusCode,
		Reason:               msg.Reason,
		Headers:              msg.Headers,
		Body:                 msg.Body,
		BodySizeBytes:        messageBodySize(msg),
		ObservedMessageBytes: msg.ObservedMessageBytes,
		ContentLength:        msg.ContentLength,
		TransferEncoding:     msg.TransferEncoding,
		Chunked:              msg.Chunked,
		BodyPartial:          msg.BodyPartial,
	}
}

func messageBodySize(msg *httptrace.ParsedMessage) int {
	if msg == nil {
		return 0
	}
	if msg.BodySizeBytes > 0 {
		return msg.BodySizeBytes
	}
	return len(msg.Body)
}

// 解析五元组
func (s *Service) resolveEvent(event httptrace.Event) (httptrace.Event, resolveSource) {
	if s.cfg.DisableUserTuple {
		return event, resolveBypass
	}
	// 开启补偿解析
	resolved, source := s.resolver.Resolve(event)
	if source == resolveMiss {
		return event, source
	}

	s.stats.tupleResolved.Add(1)
	if source == resolveFromCache {
		s.stats.resolverCache.Add(1)
	}
	if source == resolveFromProc {
		s.stats.resolverProc.Add(1)
	}
	return resolved, source
}

func updateAtomicMax(dst *atomic.Uint64, value uint64) {
	for {
		current := dst.Load()
		if value <= current {
			return
		}
		if dst.CompareAndSwap(current, value) {
			return
		}
	}
}

func shouldRetryResolve(event httptrace.Event) bool {
	if event.Direction == httptrace.DirectionUnknown {
		return false
	}
	if event.FD < 0 || !missingTuple(event) {
		return false
	}
	if event.Flags&flagControl != 0 {
		return false
	}
	return true
}

// 将事件重试解析，放入重试队列，用于重试失败的事件
func (s *Service) enqueueRetry(ctx context.Context, retrySem chan struct{}, retryWG *sync.WaitGroup, workers []chan httptrace.Event, event httptrace.Event, workerID int) bool {
	if retrySem == nil || !shouldRetryResolve(event) {
		return false
	}
	item := resolveRetryItem{
		event:    event,
		workerID: workerID,
	}
	select {
	case <-ctx.Done():
		return false
	case retrySem <- struct{}{}:
		s.stats.retryQueued.Add(1)
		retryWG.Add(1)
		go func() {
			defer retryWG.Done()
			defer func() { <-retrySem }()
			s.resolveWithRetry(ctx, item, workers)
		}()
		return true
	default:
		s.stats.retryOverflow.Add(1)
		return false
	}
}

// 事件分发，将事件分发到对应的worker中
// ctx：上下文
// event：事件
// worker：worker通道
// 返回：错误
func (s *Service) dispatchEvent(ctx context.Context, event httptrace.Event, worker chan<- httptrace.Event) error {
	newRawChain := s.stats.recordRawSourceEvent(event)
	// https 明细日志
	if s.cfg.DebugKernel && newRawChain && strings.HasPrefix(event.Source, "tls_") {
		log.Printf(
			"TLS 原始链路：source=%s dir=%d chain=%d sock=%d fd=%d seq=%d observed=%d comm=%s prefix=%q",
			event.Source,
			event.Direction,
			event.ChainID,
			event.SockID,
			event.FD,
			event.SeqHint,
			event.ObservedMessageBytes,
			event.Comm,
			summarizePayloadPrefix(event.Payload, 48),
		)
	}
	if s.shouldSuppressSocketEventForTLS(event) {
		return nil
	}
	if !s.cfg.DisableUserTuple {
		startFilter := time.Time{}
		if s.cfg.DebugKernel {
			startFilter = time.Now()
		}
		ok, reason := s.filter.MatchDetail(event)
		if s.cfg.DebugKernel {
			s.stats.filterNs.Add(uint64(time.Since(startFilter)))
		}
		if !ok {
			if s.shouldPassThroughFilteredEvent(event, reason) {
				// 极少量事件在 /proc 反查还没成功时，会带着空五元组走到这里。
				// 另外，4.19 上也会出现“首个 fragment 命中过滤，后续 fragment 五元组补全抖动导致端口临时不匹配”的情况。
				// 对已经存在中的 chain，后续 fragment 不应再因为一次瞬时端口失配被直接误杀，否则会把整条调用链截断。
			} else {
				count := s.stats.userFiltered.Add(1)
				s.recordFilterDrop(event.Direction, reason)
				if count <= 5 {
					log.Printf(
						"用户态过滤事件：chain=%d dir=%d source=%s fd=%d ifindex=%d %s:%d -> %s:%d comm=%s",
						event.ChainID,
						event.Direction,
						event.Source,
						event.FD,
						event.IfIndex,
						event.SrcIP,
						event.SrcPort,
						event.DstIP,
						event.DstPort,
						event.Comm,
					)
				}
				return nil
			}
		}
	}

	s.stats.perfReceived.Add(1)
	updateAtomicMax(&s.stats.workerQueuePeak, uint64(len(worker)))

	sendStart := time.Time{}
	if s.cfg.DebugKernel {
		sendStart = time.Now()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case worker <- event:
		if s.cfg.DebugKernel {
			s.stats.dispatchNs.Add(uint64(time.Since(sendStart)))
		}
		return nil
	default:
		s.stats.workerBackpressure.Add(1)
		s.stats.dispatchBlocked.Add(1)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case worker <- event:
		if s.cfg.DebugKernel {
			blocked := time.Since(sendStart)
			s.stats.dispatchNs.Add(uint64(blocked))
			s.stats.dispatchBlockNs.Add(uint64(blocked))
		}
		return nil
	}
}

func sourceDirectionKey(source string, direction uint8) string {
	if source == "" {
		source = "unknown"
	}
	switch direction {
	case httptrace.DirectionRequest:
		return source + ":req"
	case httptrace.DirectionResponse:
		return source + ":resp"
	default:
		return source + ":unk"
	}
}

func sourceUpdateKey(source, kind string) string {
	if source == "" {
		source = "unknown"
	}
	switch kind {
	case "request":
		return source + ":req"
	case "response":
		return source + ":resp"
	default:
		return source + ":other"
	}
}

func (s *stats) recordRawSourceEvent(event httptrace.Event) bool {
	if s == nil {
		return false
	}
	source := event.Source
	if source == "" {
		source = "unknown"
	}
	newChain := false
	s.sourceMu.Lock()
	if s.rawBySource == nil {
		s.rawBySource = make(map[string]sourceDirectionCounts)
	}
	counts := s.rawBySource[source]
	switch event.Direction {
	case httptrace.DirectionRequest:
		counts.Request++
	case httptrace.DirectionResponse:
		counts.Response++
	default:
		counts.Unknown++
	}
	s.rawBySource[source] = counts
	if event.ChainID != 0 {
		if s.rawChainsByKey == nil {
			s.rawChainsByKey = make(map[string]*boundedChainSet)
		}
		key := sourceDirectionKey(source, event.Direction)
		if s.rawChainsByKey[key] == nil {
			s.rawChainsByKey[key] = &boundedChainSet{}
		}
		newChain = s.rawChainsByKey[key].add(event.ChainID)
		if newChain && strings.HasPrefix(source, "tls_") {
			if s.rawChainDetails == nil {
				s.rawChainDetails = make(map[string]rawChainDetail)
			}
			if len(s.rawChainDetails) < maxRawChainDetails {
				detailKey := fmt.Sprintf("%s:%d", key, event.ChainID)
				s.rawChainDetails[detailKey] = rawChainDetail{
					Source:    source,
					Direction: event.Direction,
					ChainID:   event.ChainID,
					SockID:    event.SockID,
					FD:        event.FD,
					Comm:      event.Comm,
					Prefix:    summarizePayloadPrefix(event.Payload, 48),
				}
			}
		}
	}
	s.sourceMu.Unlock()
	return newChain
}

func (s *stats) recordUpdateSource(source, kind string, chainID uint64) {
	if s == nil {
		return
	}
	if source == "" {
		source = "unknown"
	}
	s.sourceMu.Lock()
	if s.updatesBySource == nil {
		s.updatesBySource = make(map[string]sourceUpdateCounts)
	}
	counts := s.updatesBySource[source]
	switch kind {
	case "request":
		counts.Request++
	case "response":
		counts.Response++
	default:
		counts.Other++
	}
	s.updatesBySource[source] = counts
	if chainID != 0 {
		if s.updateChainsByKey == nil {
			s.updateChainsByKey = make(map[string]*boundedChainSet)
		}
		key := sourceUpdateKey(source, kind)
		if s.updateChainsByKey[key] == nil {
			s.updateChainsByKey[key] = &boundedChainSet{}
		}
		s.updateChainsByKey[key].add(chainID)
	}
	s.sourceMu.Unlock()
}

func (s *stats) rawSourceSummary() string {
	if s == nil {
		return "none"
	}
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	if len(s.rawBySource) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(s.rawBySource))
	for key := range s.rawBySource {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		counts := s.rawBySource[key]
		parts = append(parts, fmt.Sprintf("%s(req=%d,resp=%d,unk=%d)", key, counts.Request, counts.Response, counts.Unknown))
	}
	return strings.Join(parts, " ")
}

func (s *stats) updateSourceSummary() string {
	if s == nil {
		return "none"
	}
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	if len(s.updatesBySource) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(s.updatesBySource))
	for key := range s.updatesBySource {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		counts := s.updatesBySource[key]
		parts = append(parts, fmt.Sprintf("%s(req=%d,resp=%d,other=%d)", key, counts.Request, counts.Response, counts.Other))
	}
	return strings.Join(parts, " ")
}

func (s *stats) rawSourceChainSummary() string {
	if s == nil {
		return "none"
	}
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	if len(s.rawChainsByKey) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(s.rawChainsByKey))
	for key := range s.rawChainsByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		count, overflow := s.rawChainsByKey[key].count()
		parts = append(parts, fmt.Sprintf("%s=%d(+%d)", key, count, overflow))
	}
	return strings.Join(parts, " ")
}

func (s *stats) updateSourceChainSummary() string {
	if s == nil {
		return "none"
	}
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	if len(s.updateChainsByKey) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(s.updateChainsByKey))
	for key := range s.updateChainsByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		count, overflow := s.updateChainsByKey[key].count()
		parts = append(parts, fmt.Sprintf("%s=%d(+%d)", key, count, overflow))
	}
	return strings.Join(parts, " ")
}

// rawTLSChainDetailSummary 打印 TLS 链路详情
func (s *stats) rawTLSChainDetailSummary() string {
	if s == nil {
		return "none"
	}
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	if len(s.rawChainDetails) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(s.rawChainDetails))
	for key := range s.rawChainDetails {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		detail := s.rawChainDetails[key]
		dir := "unk"
		switch detail.Direction {
		case httptrace.DirectionRequest:
			dir = "req"
		case httptrace.DirectionResponse:
			dir = "resp"
		}
		parts = append(parts, fmt.Sprintf("%s:%s(chain=%d sock=%d fd=%d comm=%s prefix=%q)",
			detail.Source,
			dir,
			detail.ChainID,
			detail.SockID,
			detail.FD,
			detail.Comm,
			detail.Prefix,
		))
	}
	return strings.Join(parts, " ")
}

// rawTLSMissingUpdateSummary 列出“已经进入用户态 raw 统计，但还没有产出 update”的 TLS chain。
// 这能直接把问题边界钉在用户态聚合：
// - 如果 raw 已经有 chain，但 update 没有，就不是内核 perf 丢样本；
// - 再结合 prefix/sock/fd，就能看出缺口更偏 request 还是 response。
func (s *stats) rawTLSMissingUpdateSummary(limit int) string {
	if s == nil {
		return "none"
	}
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	if len(s.rawChainDetails) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(s.rawChainDetails))
	for key := range s.rawChainDetails {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	capHint := len(keys)
	if limit > 0 && limit < capHint {
		capHint = limit
	}
	parts := make([]string, 0, capHint)
	for _, key := range keys {
		detail := s.rawChainDetails[key]
		updateKey := sourceDirectionKey(detail.Source, detail.Direction)
		if chains := s.updateChainsByKey[updateKey]; chains != nil {
			if chains.contains(detail.ChainID) {
				continue
			}
		}
		dir := "unk"
		switch detail.Direction {
		case httptrace.DirectionRequest:
			dir = "req"
		case httptrace.DirectionResponse:
			dir = "resp"
		}
		parts = append(parts, fmt.Sprintf("%s:%s(chain=%d sock=%d fd=%d comm=%s prefix=%q)",
			detail.Source,
			dir,
			detail.ChainID,
			detail.SockID,
			detail.FD,
			detail.Comm,
			detail.Prefix,
		))
		if limit > 0 && len(parts) >= limit {
			break
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}

func summarizePayloadPrefix(payload []byte, limit int) string {
	if limit <= 0 || len(payload) == 0 {
		return ""
	}
	if len(payload) < limit {
		limit = len(payload)
	}
	buf := make([]byte, 0, limit)
	for _, b := range payload[:limit] {
		switch b {
		case '\r':
			buf = append(buf, '\\', 'r')
		case '\n':
			buf = append(buf, '\\', 'n')
		case '\t':
			buf = append(buf, '\\', 't')
		default:
			if b < 0x20 || b > 0x7e {
				buf = append(buf, '.')
			} else {
				buf = append(buf, b)
			}
		}
	}
	return string(buf)
}

func (s *Service) shouldSuppressSocketEventForTLS(event httptrace.Event) bool {
	if s == nil || !s.cfg.EnableTLS || !s.cfg.SuppressSocketForTLS {
		return false
	}
	if event.Comm == "" {
		return false
	}
	if strings.HasPrefix(event.Source, "tls_") {
		return false
	}
	return event.Comm == tlstrace.ResolveTargetComm(s.cfg.TLSComm)
}

func (s *Service) shouldPassThroughFilteredEvent(event httptrace.Event, reason FilterReason) bool {
	_ = reason
	if event.Direction == httptrace.DirectionUnknown {
		return false
	}
	if event.Flags&flagControl != 0 {
		return false
	}
	// 五元组暂时没补全时先默认放行，等 /proc 反查或后续 fragment 补全后再收敛。
	// 这样重新打开端口/网卡/IP 过滤时，不会因为瞬时缺字段把真实请求直接误杀掉。
	if missingTuple(event) {
		s.stats.tuplePassThrough.Add(1)
		return true
	}
	if s.assembler != nil && s.assembler.HasState(event.ChainID) {
		s.stats.chainPassThrough.Add(1)
		return true
	}
	return false
}

func (s *Service) resolveWithRetry(ctx context.Context, item resolveRetryItem, workers []chan httptrace.Event) {
	event := item.event

	for _, delay := range resolveRetryBackoffs {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		resolved, source := s.resolveEvent(event)
		if source == resolveMiss {
			continue
		}
		s.stats.retryResolved.Add(1)
		_ = s.dispatchEvent(ctx, resolved, workers[item.workerID%len(workers)])
		return
	}

	if event.FD >= 0 && missingTuple(event) {
		s.stats.tupleMiss.Add(1)
	}
	s.stats.retryDropped.Add(1)
	_ = s.dispatchEvent(ctx, event, workers[item.workerID%len(workers)])
}

// readLoop 从 perf buffer 拉取原始事件，解码后做 tuple 补全、过滤和分发。
// 这里尽量保持主循环轻量：少量第一次反查失败的关键事件会进入短暂重试队列，避免把 request/response 起始 fragment 过早丢掉。
func (s *Service) readLoop(ctx context.Context, reader *perf.Reader, workers []chan httptrace.Event, retrySem chan struct{}, retryWG *sync.WaitGroup) error {
	// 循环读取 perf buffer 中的事件
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read perf buffer: %w", err)
		}
		if record.LostSamples != 0 {
			lostAfter := s.stats.perfLost.Add(record.LostSamples)
			lostBefore := lostAfter - record.LostSamples
			// 保留首次丢失和每 1000 个样本的边界提示，避免 perf 环形缓冲区持续溢出时刷屏。
			if lostAfter <= 10 || lostAfter/1000 != lostBefore/1000 {
				log.Printf("perf 环形缓冲区丢失样本：samples=%d total_lost=%d cpu=%d", record.LostSamples, lostAfter, record.CPU)
			}
			continue
		}
		s.stats.recordsRead.Add(1)

		startDecode := time.Time{}
		if s.cfg.DebugKernel {
			startDecode = time.Now()
		}
		raw, err := decodeRawEvent(record.RawSample)
		if err != nil {
			s.stats.parseFailures.Add(1)
			log.Printf("解码原始事件失败：%v", err)
			continue
		}
		if s.cfg.DebugKernel {
			s.stats.decodeNs.Add(uint64(time.Since(startDecode)))
		}

		event := normalizeEvent(raw)
		if s.cfg.DebugKernel {
			s.logKernelFragment(record.CPU, raw, event)
		}
		startResolve := time.Time{}
		if s.cfg.DebugKernel {
			startResolve = time.Now()
		}
		event, source := s.resolveEvent(event)
		// 内核日志打印
		if s.cfg.DebugKernel {
			resolveCost := time.Since(startResolve)
			s.stats.resolveNs.Add(uint64(resolveCost))
			if source == resolveFromProc {
				s.stats.resolveProcNs.Add(uint64(resolveCost))
				if resolveCost >= time.Millisecond {
					s.stats.resolveProcSlow.Add(1)
				}
			}
		}
		workerID := record.CPU % len(workers)

		if source == resolveMiss && s.enqueueRetry(ctx, retrySem, retryWG, workers, event, workerID) {
			continue
		}
		if source == resolveMiss && event.FD >= 0 && missingTuple(event) {
			s.stats.tupleMiss.Add(1)
		}
		if err := s.dispatchEvent(ctx, event, workers[workerID]); err != nil {
			return err
		}
	}
}

func (s *Service) logKernelFragment(cpu int, raw bpfgen.HttpTraceHttpEvent, event httptrace.Event) {
	if strings.HasPrefix(event.Source, "tls_") {
		if event.Flags&flagControl != 0 {
			log.Printf(
				"内核 TLS 控制事件：cpu=%d chain=%d source=%s flags=%s fd=%d seq=%d",
				cpu,
				event.ChainID,
				event.Source,
				formatEventFlags(event.Flags),
				event.FD,
				event.SeqHint,
			)
			return
		}
		log.Printf(
			"内核 TLS 事件：cpu=%d chain=%d dir=%d source=%s frag=%d payload=%d total=%d observed=%d flags=%s fd=%d seq=%d prefix=%q",
			cpu,
			event.ChainID,
			event.Direction,
			event.Source,
			event.FragIdx,
			raw.PayloadLen,
			raw.TotalLen,
			event.ObservedMessageBytes,
			formatEventFlags(event.Flags),
			event.FD,
			event.SeqHint,
			summarizePayloadPrefix(event.Payload, 64),
		)
		return
	}
	if event.Flags&flagControl != 0 {
		log.Printf(
			"内核控制事件：cpu=%d chain=%d source=%s flags=%s fd=%d seq=%d",
			cpu,
			event.ChainID,
			event.Source,
			formatEventFlags(event.Flags),
			event.FD,
			event.SeqHint,
		)
		return
	}
	if event.Direction != httptrace.DirectionResponse {
		if event.Flags&flagSizeOnly != 0 {
			log.Printf(
				"内核仅大小事件：cpu=%d chain=%d dir=%d source=%s observed=%d flags=%s fd=%d seq=%d",
				cpu,
				event.ChainID,
				event.Direction,
				event.Source,
				event.ObservedMessageBytes,
				formatEventFlags(event.Flags),
				event.FD,
				event.SeqHint,
			)
		}
		return
	}
	if event.Flags&flagSizeOnly != 0 {
		log.Printf(
			"内核响应仅大小事件：cpu=%d chain=%d source=%s observed=%d flags=%s fd=%d seq=%d",
			cpu,
			event.ChainID,
			event.Source,
			event.ObservedMessageBytes,
			formatEventFlags(event.Flags),
			event.FD,
			event.SeqHint,
		)
		return
	}
	log.Printf(
		"内核响应片段：cpu=%d chain=%d source=%s frag=%d payload=%d total=%d observed=%d flags=%s fd=%d seq=%d",
		cpu,
		event.ChainID,
		event.Source,
		event.FragIdx,
		raw.PayloadLen,
		raw.TotalLen,
		event.ObservedMessageBytes,
		formatEventFlags(event.Flags),
		event.FD,
		event.SeqHint,
	)
}

// logLoop 周期性打印内核采集统计和用户态解析统计。
// 这里的 request_fragments/response_fragments 是按 HTTP 语义分类后的 fragment 数，
// 不是完整请求/响应条数；真正成功解析出来的条数看 user(requests/responses)。
// send_calls/recv_calls 仍然是 kprobe/kretprobe 被触发的 syscall 次数。
func (s *Service) logLoop(ctx context.Context, objs *bpfgen.LoadedObjects, tlsConfigMap *ebpf.Map, writeCh *redisWriteQueue) error {
	statsTicker := time.NewTicker(s.cfg.LogInterval)
	defer statsTicker.Stop()
	captureTicker := time.NewTicker(5 * time.Second)
	defer captureTicker.Stop()
	stallInterval := s.cfg.ResponseStallTimeout / 2
	if stallInterval <= 0 || stallInterval > 250*time.Millisecond {
		stallInterval = 250 * time.Millisecond
	}
	flushTicker := time.NewTicker(stallInterval)
	defer flushTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-captureTicker.C:
			s.RolloverDaily(time.Now(), objs)
			if err := s.syncCaptureLimitsToKernel(objs.FilterMap); err != nil {
				log.Printf("同步内核采集上限失败：%v", err)
			}
			if tlsConfigMap != nil {
				if err := s.installTLSConfig(tlsConfigMap); err != nil {
					log.Printf("同步 TLS 配置失败：%v", err)
				}
			}
		case <-flushTicker.C:
			s.RolloverDaily(time.Now(), objs)
			updates := s.assembler.FlushStalled(time.Now())
			for _, update := range updates {
				s.handleUpdate(ctx, "stalled", update, writeCh)
			}
		case <-statsTicker.C:
			s.RolloverDaily(time.Now(), objs)
			// 在周期统计前再做一轮 stalled flush，尽量减少“统计时刻刚好还没刷掉”的尾部差值。
			stalledUpdates := s.assembler.FlushStalled(time.Now())
			for _, update := range stalledUpdates {
				s.handleUpdate(ctx, "stalled", update, writeCh)
			}
			evictUpdates, evicted := s.assembler.EvictExpired(time.Now())
			for _, update := range evictUpdates {
				s.handleUpdate(ctx, "evicted", update, writeCh)
			}
			if evicted > 0 {
				s.stats.evicted.Add(uint64(evicted))
			}
			s.logStatsSnapshot("periodic", objs)
		}
	}
}

func (s *Service) logStatsSnapshot(label string, objs *bpfgen.LoadedObjects) {
	kstats, err := readKernelStats(objs.KernelStatsMap)
	if err != nil {
		log.Printf("读取内核统计失败：%v", err)
		return
	}
	asmStats := s.assembler.Snapshot()
	log.Printf(
		"%s 统计信息：kernel(send_calls=%d recv_calls=%d request_fragments=%d response_fragments=%d filtered=%d perf_errors=%d truncations=%d capture_limit_hits=%d boundary_events=%d size_final_events=%d informational_responses=%d) user(perf_received=%d lost=%d requests=%d responses=%d redis=%d redis_failures=%d redis_dropped=%d parse_failures=%d evicted=%d user_filtered=%d tuple_resolved=%d tuple_miss=%d pending_req=%d pending_resp=%d pending_no_resp=%d req_buf_states=%d resp_buf_states=%d assembler_retained=%d assembler_budget=%d assembler_drops=%d assembler_states=%d/%d assembler_state_drops=%d stalled_flush=%d evict_flush=%d orphan_resp=%d promoted_req=%d deferred_resp=%d)",
		label,
		kstats.SendCalls,
		kstats.RecvCalls,
		kstats.SendEvents,
		kstats.RecvEvents,
		kstats.Filtered,
		kstats.PerfErrors,
		kstats.Truncations,
		kstats.CaptureLimitHits,
		kstats.CaptureBoundaryEvents,
		kstats.SizeFinalEvents,
		kstats.InformationalResponses,
		s.stats.perfReceived.Load(),
		s.stats.perfLost.Load(),
		s.stats.requests.Load(),
		s.stats.responses.Load(),
		s.stats.redisWrites.Load(),
		s.stats.redisFailures.Load(),
		s.stats.redisDropped.Load(),
		s.stats.parseFailures.Load(),
		s.stats.evicted.Load(),
		s.stats.userFiltered.Load(),
		s.stats.tupleResolved.Load(),
		s.stats.tupleMiss.Load(),
		asmStats.PendingRequests,
		asmStats.PendingResponses,
		asmStats.PendingNoRespBytes,
		asmStats.RequestBufferStates,
		asmStats.ResponseBufferStates,
		asmStats.RetainedBytes,
		asmStats.MaxRetainedBytes,
		asmStats.BufferDrops,
		asmStats.ActiveTraceStates,
		asmStats.MaxActiveTraceStates,
		asmStats.StateDrops,
		asmStats.StalledResponseFlushes,
		asmStats.EvictedFlushes,
		asmStats.OrphanResponses,
		asmStats.PromotedRequests,
		asmStats.DeferredResponses,
	)
	log.Printf(
		"%s 用户态调试统计(filter_req=%d filter_resp=%d filter_unknown=%d filter_ip=%d filter_port=%d filter_ifname=%d resolver_cache=%d resolver_entries=%d resolver_proc=%d resolver_miss=%d retry_queued=%d retry_resolved=%d retry_dropped=%d retry_overflow=%d tuple_passthrough=%d chain_passthrough=%d worker_backpressure=%d upd_req_worker=%d upd_resp_worker=%d upd_resp_stalled=%d upd_req_evicted=%d upd_resp_evicted=%d shutdown_flush=%d)",
		label,
		s.stats.filterReq.Load(),
		s.stats.filterResp.Load(),
		s.stats.filterUnknown.Load(),
		s.stats.filterByIP.Load(),
		s.stats.filterByPort.Load(),
		s.stats.filterByIface.Load(),
		s.stats.resolverCache.Load(),
		s.resolver.cacheEntries(),
		s.stats.resolverProc.Load(),
		s.stats.tupleMiss.Load(),
		s.stats.retryQueued.Load(),
		s.stats.retryResolved.Load(),
		s.stats.retryDropped.Load(),
		s.stats.retryOverflow.Load(),
		s.stats.tuplePassThrough.Load(),
		s.stats.chainPassThrough.Load(),
		s.stats.workerBackpressure.Load(),
		s.stats.updateReqWorker.Load(),
		s.stats.updateRespWorker.Load(),
		s.stats.updateRespStalled.Load(),
		s.stats.updateReqEvicted.Load(),
		s.stats.updateRespEvicted.Load(),
		s.stats.shutdownFlushes.Load(),
	)
	s.logRuntimeDiagnostics(label)
	logProcessMemory(label)
	log.Printf("%s 来源原始统计(%s)", label, s.stats.rawSourceSummary())
	log.Printf("%s 来源更新统计(%s)", label, s.stats.updateSourceSummary())
	// raw/update chain 统计用于对比：
	// raw 反映“内核 perf 事件层面”看到了多少唯一 chain，
	// update 反映“用户态聚合后真正产出的文档层面”保留了多少唯一 chain。
	log.Printf("%s 来源链路原始统计(%s)", label, s.stats.rawSourceChainSummary())
	log.Printf("%s 来源链路更新统计(%s)", label, s.stats.updateSourceChainSummary())
	// 仅输出 TLS raw chain 的首包概要，帮助排查同一 TLS 会话里
	// request/response 起链是否异常、是否混入了可疑 duplicate/phantom request。
	// log.Printf("%s TLS 原始链路(%s)", label, s.stats.rawTLSChainDetailSummary())
	if missing := s.stats.rawTLSMissingUpdateSummary(24); missing != "none" {
		log.Printf("%s TLS 原始链路缺少更新(%s)", label, missing)
	}
	if asmStats.PendingRequests > 0 {
		if detail := s.assembler.DebugTLSPendingQueueSummary(time.Now(), 16); detail != "none" {
			log.Printf("%s TLS 待处理队列(%s)", label, detail)
		}
	}
	if asmStats.RequestBufferStates > 0 || asmStats.ResponseBufferStates > 0 {
		if detail := s.assembler.DebugTLSPendingStateSummary(time.Now(), 16); detail != "none" {
			log.Printf("%s TLS 缓冲状态(%s)", label, detail)
		}
	}
	if s.cfg.DebugKernel {
		recordsRead := s.stats.recordsRead.Load()
		resolveProcCount := s.stats.resolverProc.Load()
		dispatchBlocked := s.stats.dispatchBlocked.Load()
		log.Printf(
			"%s 用户态处理阶段(records_read=%d decode_avg_us=%.2f resolve_avg_us=%.2f resolve_proc_avg_us=%.2f resolve_proc_slow=%d filter_avg_us=%.2f dispatch_avg_us=%.2f dispatch_blocked=%d dispatch_block_avg_us=%.2f worker_queue_peak=%d)",
			label,
			recordsRead,
			avgMicros(s.stats.decodeNs.Load(), recordsRead),
			avgMicros(s.stats.resolveNs.Load(), recordsRead),
			avgMicros(s.stats.resolveProcNs.Load(), resolveProcCount),
			s.stats.resolveProcSlow.Load(),
			avgMicros(s.stats.filterNs.Load(), recordsRead),
			avgMicros(s.stats.dispatchNs.Load(), s.stats.perfReceived.Load()),
			dispatchBlocked,
			avgMicros(s.stats.dispatchBlockNs.Load(), dispatchBlocked),
			s.stats.workerQueuePeak.Load(),
		)
		log.Printf(
			"%s 内核调试统计(sock_send_hits=%d tcp_send_hits=%d sock_recv_hits=%d tcp_recv_hits=%d recv_store_ok=%d recv_store_no_iter=%d recv_store_meta_fail=%d recv_ret_no_meta=%d recv_dir_request=%d recv_dir_response=%d recv_dir_unknown=%d recv_fallback_local=%d recv_fallback_keepalive=%d send_no_req_chain=%d send_resp_start=%d send_resp_continue=%d send_resp_reqactive=%d send_iter_empty=%d tuple_ipv4_ok=%d tuple_ipv6_portonly=%d tuple_extract_fail=%d prefix_second_iov=%d prefix_trimmed=%d send_size_only=%d recv_size_only=%d send_guard_dups=%d send_guard_upgrades=%d recv_guard_dups=%d recv_guard_upgrades=%d iter_ubuf=%d iter_iovec=%d iter_kvec=%d iter_bvec=%d iter_unsupported=%d iter_load_fail=%d)",
			label,
			kstats.SockSendHits,
			kstats.TcpSendHits,
			kstats.SockRecvHits,
			kstats.TcpRecvHits,
			kstats.RecvStoreOk,
			kstats.RecvStoreNoIter,
			kstats.RecvStoreMetaFail,
			kstats.RecvRetNoMeta,
			kstats.RecvDirRequest,
			kstats.RecvDirResponse,
			kstats.RecvDirUnknown,
			kstats.RecvFallbackLocal,
			kstats.RecvFallbackKeepalive,
			kstats.SendNoReqChain,
			kstats.SendRespStart,
			kstats.SendRespContinue,
			kstats.SendRespReqactive,
			kstats.SendIterEmpty,
			kstats.TupleIpv4Ok,
			kstats.TupleIpv6Portonly,
			kstats.TupleExtractFail,
			kstats.PrefixSecondIov,
			kstats.PrefixTrimmed,
			kstats.SendSizeOnlyEvents,
			kstats.RecvSizeOnlyEvents,
			kstats.SendGuardDuplicates,
			kstats.SendGuardUpgrades,
			kstats.RecvGuardDuplicates,
			kstats.RecvGuardUpgrades,
			kstats.IterUbuf,
			kstats.IterIovec,
			kstats.IterKvec,
			kstats.IterBvec,
			kstats.IterUnsupported,
			kstats.IterLoadFail,
		)
		log.Printf(
			"%s 内核五元组缓存(updates=%d deletes=%d hits=%d misses=%d)",
			label,
			kstats.TupleCacheUpdates,
			kstats.TupleCacheDeletes,
			kstats.TupleCacheHits,
			kstats.TupleCacheMisses,
		)
	}
}

// attachAll 统一挂载 kprobe/kretprobe/tracepoint，并打印挂载成功信息。
// 当前策略是：
// - 4.x 继续走 sock_sendmsg + sock_recvmsg/kretprobe(sock_recvmsg)，兼容老 ABI。
// - 5.15+/6.x 改成 tcp_sendmsg + tcp_recvmsg/kretprobe(tcp_recvmsg)，避开 6.x 上更敏感的 sock_* verifier 路径。
// - 所有 variant 都复用同一个 perf event 结构，用户态聚合/解析逻辑不需要分叉。
func attachAll(objs *bpfgen.LoadedObjects) ([]link.Link, error) {
	var attached []link.Link

	required := make([]struct {
		symbols []string
		ret     bool
		prog    *ebpf.Program
	}, 0, 3)

	if objs.HookStrategy == bpfgen.HookStrategyLegacySock {
		log.Printf("使用旧版 socket 挂载策略：4.x 优先使用 sock_sendmsg/sock_recvmsg，并规避 __sock_* ABI 差异")
		required = append(required,
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"sock_sendmsg"}, prog: objs.KprobeSockSendmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"sock_recvmsg"}, prog: objs.KprobeSockRecvmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"sock_recvmsg"}, ret: true, prog: objs.KretprobeSockRecvmsg},
		)
	} else if objs.HookStrategy == bpfgen.HookStrategyLegacyTCPSend {
		log.Printf("使用旧版混合挂载策略：4.x 保留 sock_recvmsg，并在 sock_sendmsg 无法提供稳定正文的厂商内核上将响应主路径切换为 tcp_sendmsg")
		required = append(required,
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_sendmsg"}, prog: objs.KprobeTcpSendmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"sock_recvmsg"}, prog: objs.KprobeSockRecvmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"sock_recvmsg"}, ret: true, prog: objs.KretprobeSockRecvmsg},
		)
	} else if objs.HookStrategy == bpfgen.HookStrategyLegacyTCPBoth {
		log.Printf("使用旧版 TCP 挂载策略：在 socket 层 sk 提取不稳定的厂商 4.x 内核上，请求和响应均依赖 tcp_recvmsg/tcp_sendmsg")
		required = append(required,
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_sendmsg"}, prog: objs.KprobeTcpSendmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_recvmsg"}, prog: objs.KprobeTcpRecvmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_recvmsg"}, ret: true, prog: objs.KretprobeTcpRecvmsg},
		)
	} else {
		log.Printf("使用纯 TCP 挂载策略：5.15+/6.x 上请求和响应均依赖 tcp_recvmsg/tcp_sendmsg")
		required = append(required,
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_sendmsg"}, prog: objs.KprobeTcpSendmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_recvmsg"}, prog: objs.KprobeTcpRecvmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_recvmsg"}, ret: true, prog: objs.KretprobeTcpRecvmsg},
		)
	}

	for _, item := range required {
		l, err := attachOne(item.symbols, item.ret, item.prog)
		if err != nil {
			closeAll(attached)
			return nil, err
		}
		attached = append(attached, l)
	}

	optionalKprobes := []struct {
		symbols []string
		ret     bool
		prog    *ebpf.Program
	}{
		{symbols: []string{"tcp_close"}, prog: objs.KprobeTcpClose},
	}
	if objs.HookStrategy == bpfgen.HookStrategyLegacySock {
		optionalKprobes = append(optionalKprobes,
			// response 默认仍以 sock_sendmsg 为主，这里把 tcp_sendmsg 当补充路径，
			// 用来覆盖 Nginx/部分 TCP 发送栈里 sock_sendmsg 看不全的响应场景。
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_sendmsg"}, prog: objs.KprobeTcpSendmsg},
			// request 默认仍以 sock_recvmsg 为主，这里把 tcp_recvmsg 当补充路径；
			// 4.19 的某些 Nginx/内核组合会把读路径更多暴露在 tcp_recvmsg 上，
			// 这里补挂后可以继续统计 observed_message_bytes，但不再重复搬 payload。
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_recvmsg"}, prog: objs.KprobeTcpRecvmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_recvmsg"}, ret: true, prog: objs.KretprobeTcpRecvmsg},
		)
		optionalKprobes = append(optionalKprobes,
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_v4_connect"}, prog: objs.KprobeTcpV4Connect},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_v4_connect"}, ret: true, prog: objs.KretprobeTcpV4Connect},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_v6_connect"}, prog: objs.KprobeTcpV6Connect},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_v6_connect"}, ret: true, prog: objs.KretprobeTcpV6Connect},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"inet_csk_accept"}, ret: true, prog: objs.KretprobeInetCskAccept},
		)
		log.Printf("已启用旧版五元组缓存回退：使用 tcp_v4/tcp_v6_connect 和 inet_csk_accept 替代 inet_sock_set_state")
	}
	if objs.HookStrategy == bpfgen.HookStrategyLegacyTCPSend {
		optionalKprobes = append(optionalKprobes,
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"sock_sendmsg"}, prog: objs.KprobeSockSendmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_recvmsg"}, prog: objs.KprobeTcpRecvmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_recvmsg"}, ret: true, prog: objs.KretprobeTcpRecvmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_v4_connect"}, prog: objs.KprobeTcpV4Connect},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_v4_connect"}, ret: true, prog: objs.KretprobeTcpV4Connect},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_v6_connect"}, prog: objs.KprobeTcpV6Connect},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_v6_connect"}, ret: true, prog: objs.KretprobeTcpV6Connect},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"inet_csk_accept"}, ret: true, prog: objs.KretprobeInetCskAccept},
		)
		log.Printf("已启用旧版五元组缓存回退：使用 tcp_v4/tcp_v6_connect 和 inet_csk_accept 替代 inet_sock_set_state")
	}
	if objs.HookStrategy == bpfgen.HookStrategyLegacyTCPBoth {
		optionalKprobes = append(optionalKprobes,
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"sock_sendmsg"}, prog: objs.KprobeSockSendmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"sock_recvmsg"}, prog: objs.KprobeSockRecvmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"sock_recvmsg"}, ret: true, prog: objs.KretprobeSockRecvmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_v4_connect"}, prog: objs.KprobeTcpV4Connect},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_v4_connect"}, ret: true, prog: objs.KretprobeTcpV4Connect},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_v6_connect"}, prog: objs.KprobeTcpV6Connect},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"tcp_v6_connect"}, ret: true, prog: objs.KretprobeTcpV6Connect},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"inet_csk_accept"}, ret: true, prog: objs.KretprobeInetCskAccept},
		)
		log.Printf("已启用旧版五元组缓存回退：使用 tcp_v4/tcp_v6_connect 和 inet_csk_accept 替代 inet_sock_set_state")
	}
	if objs.HookStrategy == bpfgen.HookStrategyTCPOnly {
		log.Printf("已默认启用纯 TCP 采集：跳过 sock_* 探针，并保持相同的 perf 事件和用户态解析契约")
	}
	for _, item := range optionalKprobes {
		l, err := attachOne(item.symbols, item.ret, item.prog)
		if err == nil {
			attached = append(attached, l)
			continue
		}
		log.Printf("跳过可选 kprobe %v：%v", item.symbols, err)
	}

	tracepoints := []struct {
		group string
		name  string
		prog  *ebpf.Program
	}{
		{group: "syscalls", name: "sys_enter_sendto", prog: objs.TracepointSysEnterSendto},
		{group: "syscalls", name: "sys_enter_sendmsg", prog: objs.TracepointSysEnterSendmsg},
		{group: "syscalls", name: "sys_enter_write", prog: objs.TracepointSysEnterWrite},
		{group: "syscalls", name: "sys_enter_writev", prog: objs.TracepointSysEnterWritev},
		{group: "syscalls", name: "sys_enter_recvfrom", prog: objs.TracepointSysEnterRecvfrom},
		{group: "syscalls", name: "sys_enter_recvmsg", prog: objs.TracepointSysEnterRecvmsg},
		{group: "syscalls", name: "sys_enter_read", prog: objs.TracepointSysEnterRead},
		{group: "syscalls", name: "sys_enter_readv", prog: objs.TracepointSysEnterReadv},
	}
	if objs.HookStrategy != bpfgen.HookStrategyLegacySock &&
		objs.HookStrategy != bpfgen.HookStrategyLegacyTCPSend &&
		objs.HookStrategy != bpfgen.HookStrategyLegacyTCPBoth {
		tracepoints = append([]struct {
			group string
			name  string
			prog  *ebpf.Program
		}{
			{group: "sock", name: "inet_sock_set_state", prog: objs.TracepointSockInetSockSetState},
		}, tracepoints...)
	}
	// 多个挂载点挂载
	for _, tp := range tracepoints {
		l, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			log.Printf("跳过 tracepoint %s/%s：%v", tp.group, tp.name, err)
			continue
		}
		attached = append(attached, l)
	}

	return attached, nil
}

func attachOne(symbols []string, ret bool, prog *ebpf.Program) (link.Link, error) {
	if prog == nil {
		return nil, fmt.Errorf("program handle is nil for symbols %v", symbols)
	}
	var errs []string
	for _, symbol := range symbols {
		var (
			l   link.Link
			err error
		)
		if ret {
			l, err = link.Kretprobe(symbol, prog, nil)
		} else {
			l, err = link.Kprobe(symbol, prog, nil)
		}
		if err == nil {
			if ret {
				log.Printf("已挂载 kretprobe：%s", symbol)
			} else {
				log.Printf("已挂载 kprobe：%s", symbol)
			}
			return l, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", symbol, err))
	}
	return nil, fmt.Errorf("attach %v: %s", symbols, strings.Join(errs, "; "))
}

func closeAll(items []link.Link) {
	for _, item := range items {
		item.Close()
	}
}

func cStringInt8(raw []int8) string {
	var b strings.Builder
	for _, c := range raw {
		if c == 0 {
			break
		}
		b.WriteByte(byte(c))
	}
	return b.String()
}

// startPhaseWatch 在启动的关键阶段周期性打印心跳，避免旧内核上长时间 verifier
// 或 attach 阻塞时看起来像“完全没运行”。
func startPhaseWatch(ctx context.Context, phase string, interval time.Duration) func() {
	if interval <= 0 {
		interval = 2 * time.Second
	}

	done := make(chan struct{})
	var once sync.Once

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				log.Printf("%s 仍在处理中……", phase)
			}
		}
	}()

	return func() {
		once.Do(func() {
			close(done)
		})
	}
}

// decodeRawEvent 按内核 struct http_event 的内存布局把 perf 样本解码成 Go 结构体。
func decodeRawEvent(sample []byte) (bpfgen.HttpTraceHttpEvent, error) {
	var event bpfgen.HttpTraceHttpEvent
	size := int(unsafe.Sizeof(event))
	if len(sample) < size {
		return event, fmt.Errorf("sample too small: got %d want %d", len(sample), size)
	}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&event)), size)
	copy(buf, sample[:size])
	return event, nil
}

// 内核态原始事件转换成更适合用户态处理的结构。
func normalizeEvent(raw bpfgen.HttpTraceHttpEvent) httptrace.Event {
	// raw.TsNs 来自内核 bpf_ktime_get_ns()，它是单调时钟（自开机以来的 ns），
	// 不是 Unix 墙钟时间。
	// 之前直接 time.Unix(0, raw.TsNs) 会把事件时间落到 1970 附近，进而让
	// TLS pending/stall/age 判断几乎立刻触发，表现成 request 被过早 flush，
	// 最终比真实样本数多记请求。
	// 这里改为使用“用户态收到 perf 事件时”的墙钟时间作为 Event.Timestamp。
	// raw.TsNs 仍然保留在 Event.TsNS 中，仅用于调试/排序线索，不再参与墙钟语义。
	ts := time.Now()
	payloadLen := int(raw.PayloadLen)
	if payloadLen > len(raw.Payload) {
		payloadLen = len(raw.Payload)
	}
	return httptrace.Event{
		Timestamp:            ts,
		TsNS:                 raw.TsNs,
		ChainID:              raw.ChainId,
		SockID:               raw.SockId,
		SeqHint:              raw.SeqHint,
		ObservedMessageBytes: raw.ObservedMessageBytes,
		PID:                  raw.Pid,
		TID:                  raw.Tid,
		FD:                   raw.Fd,
		IfIndex:              raw.Ifindex,
		SrcIP:                formatIPv4(raw.SrcIp),
		DstIP:                formatIPv4(raw.DstIp),
		SrcPort:              raw.SrcPort,
		DstPort:              raw.DstPort,
		FragIdx:              raw.FragIdx,
		Direction:            raw.Direction,
		Flags:                raw.Flags,
		Source:               captureSourceName(raw.Source),
		Comm:                 cString(raw.Comm[:]),
		Payload:              append([]byte(nil), raw.Payload[:payloadLen]...),
	}
}

func captureSourceName(raw uint8) string {
	switch raw {
	case 1:
		return "sock_sendmsg"
	case 2:
		return "tcp_sendmsg"
	case 3:
		return "sock_recvmsg"
	case 4:
		return "tcp_recvmsg"
	case 5:
		return "tcp_close"
	case 6:
		return "tls_ssl_read"
	case 7:
		return "tls_ssl_write"
	case 8:
		return "tls_ssl_read_ex"
	case 9:
		return "tls_ssl_write_ex"
	case 10:
		return "tls_ssl_close"
	default:
		return "unknown"
	}
}

func formatEventFlags(flags uint8) string {
	parts := make([]string, 0, 5)
	if flags&flagStart != 0 {
		parts = append(parts, "start")
	}
	if flags&flagEnd != 0 {
		parts = append(parts, "end")
	}
	if flags&flagCaptureTrunc != 0 {
		parts = append(parts, "capture_trunc")
	}
	if flags&flagControl != 0 {
		parts = append(parts, "control")
	}
	if flags&flagClose != 0 {
		parts = append(parts, "close")
	}
	if flags&flagSizeOnly != 0 {
		parts = append(parts, "size_only")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}

func formatIPv4(raw uint32) string {
	ip := net.IPv4(byte(raw), byte(raw>>8), byte(raw>>16), byte(raw>>24))
	return ip.String()
}

func cString(raw []int8) string {
	var b strings.Builder
	for _, c := range raw {
		if c == 0 {
			break
		}
		b.WriteByte(byte(c))
	}
	return b.String()
}

func avgMicros(total, count uint64) float64 {
	if count == 0 {
		return 0
	}
	return float64(total) / float64(count) / 1000.0
}

// readKernelStats 汇总 per-cpu 统计，便于观察内核态有没有命中 hook、有没有被过滤掉。
func readKernelStats(m *ebpf.Map) (bpfgen.HttpTraceKernelStats, error) {
	var total bpfgen.HttpTraceKernelStats
	key := uint32(0)
	possibleCPU := ebpf.MustPossibleCPU()
	values := make([]bpfgen.HttpTraceKernelStats, possibleCPU)

	if err := m.Lookup(&key, &values); err != nil {
		return total, err
	}
	for _, v := range values {
		total.SendCalls += v.SendCalls
		total.RecvCalls += v.RecvCalls
		total.SendEvents += v.SendEvents
		total.RecvEvents += v.RecvEvents
		total.Filtered += v.Filtered
		total.PerfErrors += v.PerfErrors
		total.Truncations += v.Truncations
		total.CloseEvents += v.CloseEvents
		total.SockSendHits += v.SockSendHits
		total.TcpSendHits += v.TcpSendHits
		total.SockRecvHits += v.SockRecvHits
		total.TcpRecvHits += v.TcpRecvHits
		total.RecvStoreOk += v.RecvStoreOk
		total.RecvStoreNoIter += v.RecvStoreNoIter
		total.RecvStoreMetaFail += v.RecvStoreMetaFail
		total.RecvRetNoMeta += v.RecvRetNoMeta
		total.RecvDirRequest += v.RecvDirRequest
		total.RecvDirResponse += v.RecvDirResponse
		total.RecvDirUnknown += v.RecvDirUnknown
		total.RecvFallbackLocal += v.RecvFallbackLocal
		total.RecvFallbackKeepalive += v.RecvFallbackKeepalive
		total.SendNoReqChain += v.SendNoReqChain
		total.SendRespStart += v.SendRespStart
		total.SendRespContinue += v.SendRespContinue
		total.SendRespReqactive += v.SendRespReqactive
		total.SendIterEmpty += v.SendIterEmpty
		total.TupleIpv4Ok += v.TupleIpv4Ok
		total.TupleIpv6Portonly += v.TupleIpv6Portonly
		total.TupleExtractFail += v.TupleExtractFail
		total.TupleCacheUpdates += v.TupleCacheUpdates
		total.TupleCacheDeletes += v.TupleCacheDeletes
		total.TupleCacheHits += v.TupleCacheHits
		total.TupleCacheMisses += v.TupleCacheMisses
		total.PrefixSecondIov += v.PrefixSecondIov
		total.PrefixTrimmed += v.PrefixTrimmed
		total.SendSizeOnlyEvents += v.SendSizeOnlyEvents
		total.RecvSizeOnlyEvents += v.RecvSizeOnlyEvents
		total.SendGuardDuplicates += v.SendGuardDuplicates
		total.SendGuardUpgrades += v.SendGuardUpgrades
		total.RecvGuardDuplicates += v.RecvGuardDuplicates
		total.RecvGuardUpgrades += v.RecvGuardUpgrades
		total.IterUbuf += v.IterUbuf
		total.IterIovec += v.IterIovec
		total.IterKvec += v.IterKvec
		total.IterBvec += v.IterBvec
		total.IterUnsupported += v.IterUnsupported
		total.IterLoadFail += v.IterLoadFail
		total.CaptureLimitHits += v.CaptureLimitHits
		total.CaptureBoundaryEvents += v.CaptureBoundaryEvents
		total.SizeFinalEvents += v.SizeFinalEvents
		total.InformationalResponses += v.InformationalResponses
	}
	return total, nil
}
