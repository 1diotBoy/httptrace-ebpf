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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"power-ebpf/internal/bpfgen"
	"power-ebpf/internal/httptrace"
	"power-ebpf/internal/storage"
)

const (
	flagStart        = 1 << 0
	flagCaptureTrunc = 1 << 2
	flagControl      = 1 << 4
	flagClose        = 1 << 5
)

type Service struct {
	cfg       Config
	filter    ResolvedFilter
	assembler *httptrace.Assembler
	store     *storage.RedisStore
	resolver  *socketResolver
	stats     *stats
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

func NewService(cfg Config) (*Service, error) {
	filter, err := cfg.ResolveFilter()
	if err != nil {
		return nil, err
	}
	store, err := storage.NewRedisStore(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB, cfg.RedisKeyPrefix, cfg.RedisTTL)
	if err != nil {
		return nil, err
	}
	return &Service{
		cfg:       cfg,
		filter:    filter,
		assembler: httptrace.NewAssembler(cfg.MaxMessageBytes, cfg.TransactionTTL, cfg.ResponseStallTimeout),
		store:     store,
		resolver:  newSocketResolver(15 * time.Second),
		stats:     &stats{},
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

	log.Printf("加载ebpf 对象...")
	stopLoadWatch := startPhaseWatch(ctx, "bpf object load", 2*time.Second)
	objs, err := bpfgen.LoadObjects(nil)
	stopLoadWatch()
	if err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()
	log.Printf("bpf objects loaded (variant=%s)", objs.Variant)

	if err := s.installFilter(objs); err != nil {
		return err
	}
	log.Printf("resolved filter: %s", s.filter.Summary())
	if s.cfg.DisableUserTuple {
		log.Printf("user tuple pipeline disabled: skip /proc tuple resolve and user-space tuple filter; redis/console output hides src/dst ip/port")
	}

	stopAttachWatch := startPhaseWatch(ctx, "probe attach", 2*time.Second)
	links, err := attachAll(objs)
	stopAttachWatch()
	if err != nil {
		return err
	}
	defer closeAll(links)
	log.Printf("probe attach complete")

	reader, err := perf.NewReader(objs.Events, s.cfg.PerfBufferBytes())
	if err != nil {
		return fmt.Errorf("create perf reader: %w", err)
	}
	defer reader.Close()

	writeCh, writersDone := s.startRedisWriters()
	workers, workersDone := s.startWorkers(writeCh)

	retrySem := make(chan struct{}, 32768)
	var retryWG sync.WaitGroup

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.readLoop(ctx, reader, workers, retrySem, &retryWG); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, perf.ErrClosed) {
			errCh <- err
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.logLoop(ctx, objs, writeCh); err != nil && !errors.Is(err, context.Canceled) {
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

// installFilter 把 best-effort 规则写入内核 map。
// 真正运行时还会叠加一层用户态补偿过滤，用来修正 socket 层 ifindex/方向翻转问题。
func (s *Service) installFilter(objs *bpfgen.LoadedObjects) error {
	key := uint32(0)
	kernelFilter := s.filter.Kernel
	if usesLegacySockABI() {
		// 4.x 上 sock 结构布局在不同发行版/回移内核间差异更大，
		// 内核态五元组提取并不总是可靠。这里保留端口过滤，
		// 但关闭 IP/ifname 相关的 endpoint 过滤：
		// - 端口在 4.x/双栈 socket 上仍然相对稳定，先在内核里挡掉一批无关流量；
		// - ifindex 在 socket hook 上更接近 bind_dev_if，老内核更不适合作为强过滤条件；
		// - IP 提取在 4.x 和双栈场景下也更容易受布局差异影响。
		kernelFilter.Ifindex = 0
		kernelFilter.SrcIp = 0
		kernelFilter.DstIp = 0
		if s.cfg.DisableUserTuple {
 			log.Printf("legacy 4.x detected: keep kernel port filter, disable kernel ip/ifname filter in tuple-free diagnostic mode")
		} else {
			log.Printf("legacy 4.x detected: keep kernel port filter, disable kernel ip/ifname filter; user space still补充 tuple filter")
		}
	}
	if err := objs.FilterMap.Update(&key, &kernelFilter, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update filter map: %w", err)
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
		queueSize = 8192
	}
	ch := make(chan httptrace.Update, queueSize)
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for update := range ch {
				saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
		workerCount = runtime.NumCPU()
	}

	var wg sync.WaitGroup
	workers := make([]chan httptrace.Event, workerCount)
	for i := 0; i < workerCount; i++ {
		// 解析 worker 的通道适当放大，优先吸收高并发下的瞬时突刺，
		// 避免 readLoop 因为下游短暂抖动被阻塞，进而放大 perf lost。
		workers[i] = make(chan httptrace.Event, s.cfg.BatchSize*64)
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
		ResponseLatency *float64              `json:"response_latency_ms,omitempty"`
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
	update.Trace = s.sanitizeTraceForOutput(update.Trace)
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

// 关闭五元组过滤时，不输出 src/dst ip/port
func (s *Service) sanitizeTraceForOutput(trace httptrace.TraceDocument) httptrace.TraceDocument {
	if !s.cfg.DisableUserTuple {
		return trace
	}
	trace.SrcIP = ""
	trace.DstIP = ""
	trace.SrcPort = 0
	trace.DstPort = 0
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
	StartLine        string            `json:"start_line"`
	Version          string            `json:"version,omitempty"`
	Method           string            `json:"method,omitempty"`
	URL              string            `json:"url,omitempty"`
	StatusCode       int               `json:"status_code,omitempty"`
	Reason           string            `json:"reason,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	Body             string            `json:"body,omitempty"`
	ContentLength    int64             `json:"content_length,omitempty"`
	TransferEncoding string            `json:"transfer_encoding,omitempty"`
	Chunked          bool              `json:"chunked,omitempty"`
	BodyPartial      bool              `json:"body_partial,omitempty"`
}

func newConsoleParsedMessage(msg *httptrace.ParsedMessage) *consoleParsedMessage {
	if msg == nil {
		return nil
	}
	return &consoleParsedMessage{
		StartLine:        msg.StartLine,
		Version:          msg.Version,
		Method:           msg.Method,
		URL:              msg.URL,
		StatusCode:       msg.StatusCode,
		Reason:           msg.Reason,
		Headers:          msg.Headers,
		Body:             msg.Body,
		ContentLength:    msg.ContentLength,
		TransferEncoding: msg.TransferEncoding,
		Chunked:          msg.Chunked,
		BodyPartial:      msg.BodyPartial,
	}
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

func (s *Service) shouldPassThroughFilteredEvent(event httptrace.Event, reason FilterReason) bool {
	if reason != FilterReasonPort || event.Direction == httptrace.DirectionUnknown {
		return false
	}
	if event.Flags&flagControl != 0 {
		return false
	}
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
		startResolve := time.Time{}
		if s.cfg.DebugKernel {
			startResolve = time.Now()
		}
		event, source := s.resolveEvent(event)
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

// logLoop 周期性打印内核采集统计和用户态解析统计。
// 这里的 request_fragments/response_fragments 是按 HTTP 语义分类后的 fragment 数，
// 不是完整请求/响应条数；真正成功解析出来的条数看 user(requests/responses)。
// send_calls/recv_calls 仍然是 kprobe/kretprobe 被触发的 syscall 次数。
func (s *Service) logLoop(ctx context.Context, objs *bpfgen.LoadedObjects, writeCh chan<- httptrace.Update) error {
	statsTicker := time.NewTicker(s.cfg.LogInterval)
	defer statsTicker.Stop()
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
			"%s kernel debug(sock_send_hits=%d tcp_send_hits=%d sock_recv_hits=%d tcp_recv_hits=%d recv_store_ok=%d recv_store_no_iter=%d recv_store_meta_fail=%d recv_ret_no_meta=%d recv_dir_request=%d recv_dir_response=%d recv_dir_unknown=%d recv_fallback_local=%d recv_fallback_keepalive=%d send_no_req_chain=%d send_resp_start=%d send_resp_continue=%d send_resp_reqactive=%d send_iter_empty=%d tuple_ipv4_ok=%d tuple_ipv6_portonly=%d tuple_extract_fail=%d)",
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
		)
	}
}

// attachAll 统一挂载 kprobe/kretprobe/tracepoint，并打印挂载成功信息。
// 当前策略是：
// - 请求固定走 sock_recvmsg/kretprobe(sock_recvmsg)，保持“应用层收到明文后再读”的语义。
// - 响应以 sock_sendmsg 为主，tcp_sendmsg 只做补充，专门覆盖 Nginx 等 TCP 发送路径。
// - 4.x 继续避开 ABI 更容易漂移的 __sock_*，但不退化到只剩 tcp_*。
func attachAll(objs *bpfgen.LoadedObjects) ([]link.Link, error) {
	var attached []link.Link
	legacySockABI := usesLegacySockABI()

	required := make([]struct {
		symbols []string
		ret     bool
		prog    *ebpf.Program
	}, 0, 3)

	if legacySockABI {
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
	} else {
		required = append(required,
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"__sock_sendmsg", "sock_sendmsg"}, prog: objs.KprobeSockSendmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"sock_recvmsg", "__sock_recvmsg"}, prog: objs.KprobeSockRecvmsg},
			struct {
				symbols []string
				ret     bool
				prog    *ebpf.Program
			}{symbols: []string{"sock_recvmsg", "__sock_recvmsg"}, ret: true, prog: objs.KretprobeSockRecvmsg},
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
		// response 默认仍以 sock_sendmsg 为主，这里把 tcp_sendmsg 当补充路径，
		// 用来覆盖 Nginx/部分 TCP 发送栈里 sock_sendmsg 看不全的响应场景。
		{symbols: []string{"tcp_sendmsg"}, prog: objs.KprobeTcpSendmsg},
	}
	if !legacySockABI {
		log.Printf("tcp_sendmsg supplement enabled by default: sock_sendmsg stays primary, tcp_sendmsg supplements nginx/TCP send path, and per-send dedupe guard is active")
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

// usesLegacySockABI 检测 4.x 风格的 socket API。
// 这类内核上真正容易漂移的是 __sock_sendmsg/__sock_recvmsg 的 ABI，
// 但 sock_sendmsg/sock_recvmsg 这一层依然更接近应用层 send/recv 语义。
// 因此 4.x 只需要避开 __sock_*，不需要退化成把 tcp_* 当主采集路径。
func usesLegacySockABI() bool {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return false
	}
	release := strings.TrimSpace(cStringInt8(uts.Release[:]))
	return strings.HasPrefix(release, "4.")
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
		Timestamp: ts,
		TsNS:      raw.TsNs,
		ChainID:   raw.ChainId,
		SockID:    raw.SockId,
		SeqHint:   raw.SeqHint,
		PID:       raw.Pid,
		TID:       raw.Tid,
		FD:        raw.Fd,
		IfIndex:   raw.Ifindex,
		SrcIP:     formatIPv4(raw.SrcIp),
		DstIP:     formatIPv4(raw.DstIp),
		SrcPort:   raw.SrcPort,
		DstPort:   raw.DstPort,
		FragIdx:   raw.FragIdx,
		Direction: raw.Direction,
		Flags:     raw.Flags,
		Source:    captureSourceName(raw.Source),
		Comm:      cString(raw.Comm[:]),
		Payload:   append([]byte(nil), raw.Payload[:payloadLen]...),
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
	default:
		return "unknown"
	}
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
	}
	return total, nil
}
