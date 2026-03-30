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
	stats     *stats
}

type stats struct {
	perfReceived  atomic.Uint64
	perfLost      atomic.Uint64
	requests      atomic.Uint64
	responses     atomic.Uint64
	redisWrites   atomic.Uint64
	parseFailures atomic.Uint64
	evicted       atomic.Uint64
	userFiltered  atomic.Uint64
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
		assembler: httptrace.NewAssembler(cfg.MaxMessageBytes, cfg.TransactionTTL),
		store:     store,
		stats:     &stats{},
	}, nil
}

func (s *Service) Close() error {
	return s.store.Close()
}

func (s *Service) Run(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	log.Printf("loading bpf objects...")
	stopLoadWatch := startPhaseWatch(ctx, "bpf object load", 2*time.Second)
	objs, err := bpfgen.LoadObjects(nil)
	stopLoadWatch()
	if err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()
	log.Printf("bpf objects loaded")

	if err := s.installFilter(objs); err != nil {
		return err
	}
	log.Printf("resolved filter: %s", s.filter.Summary())

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

	workers := s.startWorkers(ctx)
	defer func() {
		for _, ch := range workers {
			close(ch)
		}
	}()

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.readLoop(ctx, reader, workers); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, perf.ErrClosed) {
			errCh <- err
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.logLoop(ctx, objs); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		reader.Close()
		wg.Wait()
		return nil
	case err := <-errCh:
		reader.Close()
		wg.Wait()
		return err
	}
}

// installFilter 把 best-effort 规则写入内核 map。
// 真正运行时还会叠加一层用户态补偿过滤，用来修正 socket 层 ifindex/方向翻转问题。
func (s *Service) installFilter(objs *bpfgen.HttpTraceObjects) error {
	key := uint32(0)
	if err := objs.FilterMap.Update(&key, &s.filter.Kernel, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update filter map: %w", err)
	}
	return nil
}

// startWorkers 启动批量解析 worker。每个 worker 固定一个 OS 线程，减少高并发下的调度抖动。
func (s *Service) startWorkers(ctx context.Context) []chan httptrace.Event {
	workerCount := s.cfg.WorkerCount
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}

	workers := make([]chan httptrace.Event, workerCount)
	for i := 0; i < workerCount; i++ {
		workers[i] = make(chan httptrace.Event, s.cfg.BatchSize*4)
		go s.workerLoop(ctx, i, workers[i])
	}
	return workers
}

// workerLoop 负责批量调用 assembler、打印解析结果、落 Redis。
func (s *Service) workerLoop(ctx context.Context, workerID int, ch <-chan httptrace.Event) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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
				log.Printf("[worker=%d] %s", workerID, update.Trace.SummaryLine())
				if s.cfg.PrintHTTP {
					s.printHTTPTrace(workerID, update)
				}
				if err := s.store.Save(ctx, update.Trace); err != nil {
					log.Printf("[worker=%d] redis save error: %v", workerID, err)
					continue
				}
				s.stats.redisWrites.Add(1)
				if update.Kind == "request" {
					s.stats.requests.Add(1)
				}
				if update.Kind == "response" {
					s.stats.responses.Add(1)
				}
			}
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
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

func (s *Service) printHTTPTrace(workerID int, update httptrace.Update) {
	view := struct {
		Kind            string                `json:"kind"`
		ChainID         uint64                `json:"chain_id"`
		PID             uint32                `json:"pid"`
		FD              int32                 `json:"fd"`
		Comm            string                `json:"comm"`
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
		log.Printf("[worker=%d] marshal console trace error: %v", workerID, err)
		return
	}
	log.Printf("[worker=%d] http=%s", workerID, string(body))
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

// readLoop 从 perf buffer 拉取原始事件，解码后再应用一次用户态补偿过滤。
func (s *Service) readLoop(ctx context.Context, reader *perf.Reader, workers []chan httptrace.Event) error {
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

		raw, err := decodeRawEvent(record.RawSample)
		if err != nil {
			s.stats.parseFailures.Add(1)
			log.Printf("decode raw event error: %v", err)
			continue
		}

		event := normalizeEvent(raw)
		if !s.filter.Match(event) {
			count := s.stats.userFiltered.Add(1)
			if count <= 5 {
				log.Printf(
					"user filtered event chain=%d dir=%d ifindex=%d %s:%d -> %s:%d comm=%s",
					event.ChainID,
					event.Direction,
					event.IfIndex,
					event.SrcIP,
					event.SrcPort,
					event.DstIP,
					event.DstPort,
					event.Comm,
				)
			}
			continue
		}
		s.stats.perfReceived.Add(1)
		worker := workers[record.CPU%len(workers)]

		select {
		case <-ctx.Done():
			return ctx.Err()
		case worker <- event:
		}
	}
}

// logLoop 周期性打印内核采集统计和用户态解析统计。
// 这里的 request_fragments/response_fragments 是按 HTTP 语义分类后的 fragment 数，
// 不是完整请求/响应条数；真正成功解析出来的条数看 user(requests/responses)。
// send_calls/recv_calls 仍然是 kprobe/kretprobe 被触发的 syscall 次数。
func (s *Service) logLoop(ctx context.Context, objs *bpfgen.HttpTraceObjects) error {
	ticker := time.NewTicker(s.cfg.LogInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			evicted := s.assembler.EvictExpired(time.Now())
			if evicted > 0 {
				s.stats.evicted.Add(uint64(evicted))
			}
			kstats, err := readKernelStats(objs.KernelStatsMap)
			if err != nil {
				log.Printf("read kernel stats error: %v", err)
				continue
			}
			log.Printf(
				"stats kernel(send_calls=%d recv_calls=%d request_fragments=%d response_fragments=%d filtered=%d perf_errors=%d truncations=%d) user(perf_received=%d lost=%d requests=%d responses=%d redis=%d evicted=%d user_filtered=%d)",
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
				s.stats.evicted.Load(),
				s.stats.userFiltered.Load(),
			)
		}
	}
}

// attachAll 统一挂载 kprobe/kretprobe/tracepoint，并打印挂载成功信息。
func attachAll(objs *bpfgen.HttpTraceObjects) ([]link.Link, error) {
	var attached []link.Link

	required := []struct {
		symbols []string
		ret     bool
		prog    *ebpf.Program
	}{
		{symbols: []string{"__sock_sendmsg", "sock_sendmsg"}, prog: objs.KprobeSockSendmsg},
		{symbols: []string{"sock_recvmsg", "__sock_recvmsg"}, prog: objs.KprobeSockRecvmsg},
		{symbols: []string{"sock_recvmsg", "__sock_recvmsg"}, ret: true, prog: objs.KretprobeSockRecvmsg},
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
	for _, item := range optionalKprobes {
		l, err := attachOne(item.symbols, item.ret, item.prog)
		if err == nil {
			attached = append(attached, l)
		}
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

// normalizeEvent 把内核态原始事件转换成更适合用户态处理的结构。
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
		Comm:      cString(raw.Comm[:]),
		Payload:   append([]byte(nil), raw.Payload[:payloadLen]...),
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
	}
	return total, nil
}
