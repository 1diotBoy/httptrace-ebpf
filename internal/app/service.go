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
	flagStart        = 1 << 0
	flagEnd          = 1 << 1
	flagCaptureTrunc = 1 << 2
	flagControl      = 1 << 4
	flagClose        = 1 << 5
	flagSizeOnly     = 1 << 6

	kernelDebugFlagSnapshot             = 1 << 0
	kernelDebugFlagLegacySendPrimaryTCP = 1 << 8
	kernelDebugFlagLegacyRecvPrimaryTCP = 1 << 9
)

type Service struct {
	cfg                      Config
	filter                   ResolvedFilter
	assembler                *httptrace.Assembler
	store                    *storage.RedisStore
	resolver                 *socketResolver
	stats                    *stats
	resourcePlan             runtimeResourcePlan
	hookStrategy             bpfgen.HookStrategy
	lastRequestCaptureLimit  uint32
	lastResponseCaptureLimit uint32
	lastDebugSnapshotSeq     uint64
}

type stats struct {
	perfReceived       atomic.Uint64
	perfLost           atomic.Uint64
	requests           atomic.Uint64
	responses          atomic.Uint64
	redisWrites        atomic.Uint64
	redisFailures      atomic.Uint64
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
		log.Printf("redis 地址为空， 不存储到redis ...")
	}
	log.Printf("runtime resource plan: %s", plan.Summary())
	return &Service{
		cfg:          cfg,
		filter:       filter,
		assembler:    httptrace.NewAssembler(cfg.MaxMessageBytes, cfg.TransactionTTL, cfg.ResponseStallTimeout),
		store:        store,
		resolver:     newSocketResolver(15 * time.Second),
		stats:        &stats{},
		resourcePlan: plan,
	}, nil
}

func (s *Service) Close() error {
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

	log.Printf("加载ebpf 对象...")
	stopLoadWatch := startPhaseWatch(ctx, "bpf object load", 2*time.Second)
	objs, err := bpfgen.LoadObjects(nil)
	stopLoadWatch()
	if err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()
	log.Printf("bpf objects loaded (variant=%s hook_strategy=%s)", objs.Variant, objs.HookStrategy)
	s.hookStrategy = objs.HookStrategy

	if err := s.installFilter(objs); err != nil {
		return err
	}
	if err := s.syncCaptureLimitsToKernel(objs.FilterMap); err != nil {
		log.Printf("initial kernel capture limit sync error: %v", err)
	}
	log.Printf("resolved filter: %s", s.filter.Summary())
	if s.cfg.DisableUserTuple {
		log.Printf("user tuple pipeline disabled: skip /proc tuple resolve and user-space tuple filter; redis/console output keeps kernel tuple when available")
	}

	stopAttachWatch := startPhaseWatch(ctx, "probe attach", 2*time.Second)
	links, err := attachAll(objs)
	stopAttachWatch()
	if err != nil {
		return err
	}
	defer closeAll(links)
	log.Printf("probe attach complete")

	if s.cfg.EnableTLS {
		log.Printf("loading tls uprobes...")
		stopTLSLoadWatch := startPhaseWatch(ctx, "tls object load", 2*time.Second)
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
		log.Printf("resolved tls libraries for comm=%q: %s", tlstrace.ResolveTargetComm(s.cfg.TLSComm), strings.Join(tlsLibPaths, ","))

		stopTLSAttachWatch := startPhaseWatch(ctx, "tls uprobe attach", 2*time.Second)
		tlsLinks, err = tlstrace.AttachAll(tlsObjs, tlsLibPaths)
		stopTLSAttachWatch()
		if err != nil {
			return fmt.Errorf("attach tls uprobes: %w", err)
		}
		defer closeAll(tlsLinks)

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

	writeCh, writersDone := s.startRedisWriters()
	workers, workersDone := s.startWorkers(writeCh)

	retrySem := make(chan struct{}, s.cfg.RetryQueueSize)
	var retryWG sync.WaitGroup

	var wg sync.WaitGroup
	errCh := make(chan error, 3)

	wg.Add(1)
	go func() {
		defer wg.Done()
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
		log.Printf("shutdown flush(states=%d updates=%d)", flushedStates, len(updates))
	}

	if writeCh != nil {
		close(writeCh)
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
	if s.cfg.DisableKernelFilter {
		log.Printf("kernel endpoint filter disabled by flag: all IP/port checks are skipped before perf output")
		kernelFilter.Ifindex = 0
		kernelFilter.SrcIp = 0
		kernelFilter.DstIp = 0
		kernelFilter.SrcPort = 0
		kernelFilter.DstPort = 0
		if s.cfg.CaptureBytes > 0 {
			kernelFilter.RequestCaptureBytes = uint32(s.cfg.CaptureBytes)
			kernelFilter.ResponseCaptureBytes = uint32(s.cfg.CaptureBytes)
		}
		kernelFilter.DebugFlags = kernelDebugFlags(s.cfg.DebugKernel, objs.HookStrategy)
		if err := objs.FilterMap.Update(&key, &kernelFilter, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update filter map: %w", err)
		}
		s.lastRequestCaptureLimit = kernelFilter.RequestCaptureBytes
		s.lastResponseCaptureLimit = kernelFilter.ResponseCaptureBytes
		return nil
	}
	if kernelFilter.Ifindex != 0 {
		log.Printf("ifname filter is not enforced in kernel tuple-cache mode: socket-layer ifindex is not reliable enough")
	}
	kernelFilter.Ifindex = 0
	kernelFilter.DebugFlags = kernelDebugFlags(s.cfg.DebugKernel, objs.HookStrategy)
	if objs.HookStrategy == bpfgen.HookStrategyLegacySock ||
		objs.HookStrategy == bpfgen.HookStrategyLegacyTCPSend ||
		objs.HookStrategy == bpfgen.HookStrategyLegacyTCPBoth {
		// 4.x 上 sock 结构布局在不同发行版/回移内核间差异更大，
		// 改成用 inet_sock_set_state 维护 tuple cache，send/recv 路径优先查 cache 做端口/IP 过滤。
		// 这样 4.x 不再依赖收发现场直接读 sock_common 来做强过滤。
		log.Printf("legacy 4.x detected: prefer tuple-cache based kernel port/IP filter and ignore socket-layer ifname filter")
	}
	if err := objs.FilterMap.Update(&key, &kernelFilter, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update filter map: %w", err)
	}
	s.lastRequestCaptureLimit = kernelFilter.RequestCaptureBytes
	s.lastResponseCaptureLimit = kernelFilter.ResponseCaptureBytes
	return nil
}

func (s *Service) syncCaptureLimitsToKernel(filterMap *ebpf.Map) error {
	if s == nil || s.store == nil || filterMap == nil {
		return nil
	}

	requestLimit := uint32(s.store.RequestCaptureLimitBytes())
	responseLimit := uint32(s.store.ResponseCaptureLimitBytes())
	if requestLimit == 0 {
		requestLimit = uint32(s.cfg.CaptureBytes)
	}
	if responseLimit == 0 {
		responseLimit = uint32(s.cfg.CaptureBytes)
	}
	if requestLimit == s.lastRequestCaptureLimit && responseLimit == s.lastResponseCaptureLimit {
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
	kernelFilter.DebugFlags = kernelDebugFlags(s.cfg.DebugKernel, s.hookStrategy)
	if err := filterMap.Update(&key, &kernelFilter, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update dynamic capture limits: %w", err)
	}

	s.lastRequestCaptureLimit = requestLimit
	s.lastResponseCaptureLimit = responseLimit
	log.Printf("updated kernel capture limits request=%d response=%d", requestLimit, responseLimit)
	return nil
}

func (s *Service) installTLSConfig(configMap *ebpf.Map) error {
	if s == nil || configMap == nil {
		return nil
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

	var cfg bpfgen.TlsTraceConfig
	cfg.RequestCaptureBytes = requestLimit
	cfg.ResponseCaptureBytes = responseLimit
	for i, r := range tlstrace.ResolveTargetComm(s.cfg.TLSComm) {
		if i >= len(cfg.Comm) {
			break
		}
		cfg.Comm[i] = int8(r)
	}

	key := uint32(0)
	if err := configMap.Update(&key, &cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update tls config map: %w", err)
	}
	return nil
}

func (s *Service) startRedisWriters() (chan httptrace.Update, *sync.WaitGroup) {
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
	ch := make(chan httptrace.Update, queueSize)
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for update := range ch {
				// 超时
				saveCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				err := s.store.Save(saveCtx, update.Trace)
				cancel()
				if err != nil {
					s.stats.redisFailures.Add(1)
					log.Printf("[redis-worker=%d] save error: %v", workerID, err)
					continue
				}
				s.stats.redisWrites.Add(1)
			}
		}(i)
	}
	return ch, &wg
}

// startWorkers 启动批量解析 worker。每个 worker 固定一个 OS 线程，减少高并发下的调度抖动。
func (s *Service) startWorkers(writeCh chan<- httptrace.Update) ([]chan httptrace.Event, *sync.WaitGroup) {
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

// workerLoop 负责批量调用 assembler、打印解析结果、落 Redis。
func (s *Service) workerLoop(workerID int, ch <-chan httptrace.Event, writeCh chan<- httptrace.Update, wg *sync.WaitGroup) {
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
				log.Printf("[worker=%d] process error: %v", workerID, err)
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
		log.Printf("[%s] marshal console trace error: %v", tag, err)
		return
	}
	log.Printf("[%s] http=%s", tag, string(body))
}

func (s *Service) handleUpdate(ctx context.Context, tag string, update httptrace.Update, writeCh chan<- httptrace.Update) {
	update.Trace = s.enrichTraceTupleForOutput(update.Trace)
	update.Trace = s.sanitizeTraceForOutput(update.Trace)
	s.stats.recordUpdateSource(update.Trace.CaptureSource, update.Kind)
	if update.Kind == "request" {
		s.stats.requests.Add(1)
	}
	if update.Kind == "response" {
		s.stats.responses.Add(1)
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
		select {
		case <-ctx.Done():
			return
		case writeCh <- update:
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
			"[%s] request diag chain=%d source=%s truncated=%t body_bytes=%d observed=%d consumed=%d content_length=%d chunked=%t body_partial=%t",
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
			"[%s] response diag chain=%d reason=%s source=%s truncated=%t status=%d chunked=%t body_partial=%t body_bytes=%d observed=%d consumed=%d content_length=%d",
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
	if trace.PID == 0 || trace.FD < 0 {
		return trace
	}
	if (trace.SrcIP != "" && trace.SrcIP != "0.0.0.0" && trace.SrcPort != 0) &&
		(trace.DstIP != "" && trace.DstIP != "0.0.0.0" && trace.DstPort != 0) {
		return trace
	}

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

	resolved, source := s.resolver.Resolve(event)
	if source == resolveMiss || missingTuple(resolved) {
		return trace
	}
	trace.SrcIP = resolved.SrcIP
	trace.DstIP = resolved.DstIP
	trace.SrcPort = resolved.SrcPort
	trace.DstPort = resolved.DstPort
	return trace
}

// 关闭用户态 tuple 管线后，仍然保留内核侧已经采到的 src/dst ip/port。
// 这样可以在不走 /proc 反解析的情况下，直接把 tuple cache 或 best-effort 内核 tuple 输出到控制台和 Redis。
func (s *Service) sanitizeTraceForOutput(trace httptrace.TraceDocument) httptrace.TraceDocument {
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
	StartLine            string            `json:"start_line"`
	Version              string            `json:"version,omitempty"`
	Method               string            `json:"method,omitempty"`
	URL                  string            `json:"url,omitempty"`
	StatusCode           int               `json:"status_code,omitempty"`
	Reason               string            `json:"reason,omitempty"`
	Headers              map[string]string `json:"headers,omitempty"`
	Body                 string            `json:"body,omitempty"`
	BodySizeBytes        int               `json:"body_size_bytes,omitempty"`
	ObservedMessageBytes uint64            `json:"observed_message_bytes,omitempty"`
	ContentLength        int64             `json:"content_length,omitempty"`
	TransferEncoding     string            `json:"transfer_encoding,omitempty"`
	Chunked              bool              `json:"chunked,omitempty"`
	BodyPartial          bool              `json:"body_partial,omitempty"`
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

func (s *Service) dispatchEvent(ctx context.Context, event httptrace.Event, worker chan<- httptrace.Event) error {
	s.stats.recordRawSourceEvent(event.Source, event.Direction)
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
						"user filtered event chain=%d dir=%d source=%s fd=%d ifindex=%d %s:%d -> %s:%d comm=%s",
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

func (s *stats) recordRawSourceEvent(source string, direction uint8) {
	if s == nil {
		return
	}
	if source == "" {
		source = "unknown"
	}
	s.sourceMu.Lock()
	if s.rawBySource == nil {
		s.rawBySource = make(map[string]sourceDirectionCounts)
	}
	counts := s.rawBySource[source]
	switch direction {
	case httptrace.DirectionRequest:
		counts.Request++
	case httptrace.DirectionResponse:
		counts.Response++
	default:
		counts.Unknown++
	}
	s.rawBySource[source] = counts
	s.sourceMu.Unlock()
}

func (s *stats) recordUpdateSource(source, kind string) {
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

func (s *Service) shouldSuppressSocketEventForTLS(event httptrace.Event) bool {
	if s == nil || !s.cfg.EnableTLS {
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
			s.stats.perfLost.Add(record.LostSamples)
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
			log.Printf("decode raw event error: %v", err)
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
	if event.Flags&flagControl != 0 {
		log.Printf(
			"kernel control cpu=%d chain=%d source=%s flags=%s fd=%d seq=%d",
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
				"kernel size-only cpu=%d chain=%d dir=%d source=%s observed=%d flags=%s fd=%d seq=%d",
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
			"kernel response size-only cpu=%d chain=%d source=%s observed=%d flags=%s fd=%d seq=%d",
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
		"kernel response fragment cpu=%d chain=%d source=%s frag=%d payload=%d total=%d observed=%d flags=%s fd=%d seq=%d",
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
func (s *Service) logLoop(ctx context.Context, objs *bpfgen.LoadedObjects, tlsConfigMap *ebpf.Map, writeCh chan<- httptrace.Update) error {
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
			if err := s.syncCaptureLimitsToKernel(objs.FilterMap); err != nil {
				log.Printf("sync kernel capture limits error: %v", err)
			}
			if tlsConfigMap != nil {
				if err := s.installTLSConfig(tlsConfigMap); err != nil {
					log.Printf("sync tls config error: %v", err)
				}
			}
		case <-flushTicker.C:
			updates := s.assembler.FlushStalled(time.Now())
			for _, update := range updates {
				s.handleUpdate(ctx, "stalled", update, writeCh)
			}
		case <-statsTicker.C:
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
		log.Printf("read kernel stats error: %v", err)
		return
	}
	asmStats := s.assembler.Snapshot()
	log.Printf(
		"%s stats kernel(send_calls=%d recv_calls=%d request_fragments=%d response_fragments=%d filtered=%d perf_errors=%d truncations=%d) user(perf_received=%d lost=%d requests=%d responses=%d redis=%d redis_failures=%d parse_failures=%d evicted=%d user_filtered=%d tuple_resolved=%d tuple_miss=%d pending_req=%d pending_resp=%d pending_no_resp=%d req_buf_states=%d resp_buf_states=%d stalled_flush=%d evict_flush=%d orphan_resp=%d promoted_req=%d deferred_resp=%d)",
		label,
		kstats.SendCalls,
		kstats.RecvCalls,
		kstats.SendEvents,
		kstats.RecvEvents,
		kstats.Filtered,
		kstats.PerfErrors,
		kstats.Truncations,
		s.stats.perfReceived.Load(),
		s.stats.perfLost.Load(),
		s.stats.requests.Load(),
		s.stats.responses.Load(),
		s.stats.redisWrites.Load(),
		s.stats.redisFailures.Load(),
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
		asmStats.StalledResponseFlushes,
		asmStats.EvictedFlushes,
		asmStats.OrphanResponses,
		asmStats.PromotedRequests,
		asmStats.DeferredResponses,
	)
	log.Printf(
		"%s user debug(filter_req=%d filter_resp=%d filter_unknown=%d filter_ip=%d filter_port=%d filter_ifname=%d resolver_cache=%d resolver_proc=%d resolver_miss=%d retry_queued=%d retry_resolved=%d retry_dropped=%d retry_overflow=%d tuple_passthrough=%d chain_passthrough=%d worker_backpressure=%d upd_req_worker=%d upd_resp_worker=%d upd_resp_stalled=%d upd_req_evicted=%d upd_resp_evicted=%d shutdown_flush=%d)",
		label,
		s.stats.filterReq.Load(),
		s.stats.filterResp.Load(),
		s.stats.filterUnknown.Load(),
		s.stats.filterByIP.Load(),
		s.stats.filterByPort.Load(),
		s.stats.filterByIface.Load(),
		s.stats.resolverCache.Load(),
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
	log.Printf("%s source raw(%s)", label, s.stats.rawSourceSummary())
	log.Printf("%s source update(%s)", label, s.stats.updateSourceSummary())
	if s.cfg.DebugKernel {
		recordsRead := s.stats.recordsRead.Load()
		resolveProcCount := s.stats.resolverProc.Load()
		dispatchBlocked := s.stats.dispatchBlocked.Load()
		log.Printf(
			"%s user stage(records_read=%d decode_avg_us=%.2f resolve_avg_us=%.2f resolve_proc_avg_us=%.2f resolve_proc_slow=%d filter_avg_us=%.2f dispatch_avg_us=%.2f dispatch_blocked=%d dispatch_block_avg_us=%.2f worker_queue_peak=%d)",
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
			"%s kernel debug(sock_send_hits=%d tcp_send_hits=%d sock_recv_hits=%d tcp_recv_hits=%d recv_store_ok=%d recv_store_no_iter=%d recv_store_meta_fail=%d recv_ret_no_meta=%d recv_dir_request=%d recv_dir_response=%d recv_dir_unknown=%d recv_fallback_local=%d recv_fallback_keepalive=%d send_no_req_chain=%d send_resp_start=%d send_resp_continue=%d send_resp_reqactive=%d send_iter_empty=%d tuple_ipv4_ok=%d tuple_ipv6_portonly=%d tuple_extract_fail=%d prefix_second_iov=%d prefix_trimmed=%d send_size_only=%d recv_size_only=%d send_guard_dups=%d send_guard_upgrades=%d recv_guard_dups=%d recv_guard_upgrades=%d iter_ubuf=%d iter_iovec=%d iter_kvec=%d iter_bvec=%d iter_unsupported=%d iter_load_fail=%d)",
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
			"%s kernel tuple-cache(updates=%d deletes=%d hits=%d misses=%d)",
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
		log.Printf("using legacy socket hook strategy: prefer sock_sendmsg/sock_recvmsg on 4.x and avoid __sock_* ABI drift")
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
		log.Printf("using legacy hybrid hook strategy: keep sock_recvmsg on 4.x, but switch response primary path to tcp_sendmsg on vendor kernels where sock_sendmsg does not expose stable payload")
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
		log.Printf("using legacy tcp hook strategy: request/response both rely on tcp_recvmsg/tcp_sendmsg on vendor 4.x kernels where socket-layer sk extraction drifts")
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
		log.Printf("using tcp-only hook strategy: request/response both rely on tcp_recvmsg/tcp_sendmsg on 5.15+/6.x")
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
		log.Printf("legacy tuple-cache fallback enabled: use tcp_v4/tcp_v6_connect and inet_csk_accept instead of inet_sock_set_state")
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
		log.Printf("legacy tuple-cache fallback enabled: use tcp_v4/tcp_v6_connect and inet_csk_accept instead of inet_sock_set_state")
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
		log.Printf("legacy tuple-cache fallback enabled: use tcp_v4/tcp_v6_connect and inet_csk_accept instead of inet_sock_set_state")
	}
	if objs.HookStrategy == bpfgen.HookStrategyTCPOnly {
		log.Printf("tcp-only capture enabled by default: skip sock_* probes and keep the same perf event/user-space parser contract")
	}
	for _, item := range optionalKprobes {
		l, err := attachOne(item.symbols, item.ret, item.prog)
		if err == nil {
			attached = append(attached, l)
			continue
		}
		log.Printf("skip optional kprobe %v: %v", item.symbols, err)
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
			log.Printf("skip tracepoint %s/%s: %v", tp.group, tp.name, err)
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
				log.Printf("attached kretprobe: %s", symbol)
			} else {
				log.Printf("attached kprobe: %s", symbol)
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
				log.Printf("%s is still in progress...", phase)
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
	ts := time.Unix(0, int64(raw.TsNs))
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
	}
	return total, nil
}
