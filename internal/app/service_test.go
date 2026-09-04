package app

import (
	"context"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"power-ebpf/internal/bpfgen"
	"power-ebpf/internal/httptrace"
)

func TestRedisWriteQueueBoundsRetainedBytes(t *testing.T) {
	queue := newRedisWriteQueue(4, redisQueuePermitBytes)
	update := httptrace.Update{Trace: httptrace.TraceDocument{
		Request: &httptrace.ParsedMessage{Body: strings.Repeat("x", 8<<10)},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := queue.enqueue(ctx, update); err != nil {
		t.Fatalf("enqueue first update: %v", err)
	}

	if err := queue.enqueue(ctx, update); !errors.Is(err, errRedisWriteQueueFull) {
		t.Fatalf("second update should be dropped at byte budget, got %v", err)
	}

	first := <-queue.ch
	queue.release(first.permits)
	if got := queue.bytes.Load(); got != 0 {
		t.Fatalf("retained bytes after writer release: got %d want 0", got)
	}
	if got := queue.peak.Load(); got != redisQueuePermitBytes {
		t.Fatalf("queue peak: got %d want %d", got, redisQueuePermitBytes)
	}
}

func TestSocketResolverBoundsCacheEntries(t *testing.T) {
	resolver := newSocketResolver(time.Minute)
	resolver.maxEntries = 2
	tuple := cachedSocketTuple{localIP: "127.0.0.1", remoteIP: "127.0.0.2"}

	for id := uint64(1); id <= 3; id++ {
		resolver.storeCache(socketKey{pid: 1, fd: 1, sockID: id}, tuple)
	}
	if got := resolver.cacheEntries(); got != 2 {
		t.Fatalf("resolver cache entries: got %d want 2", got)
	}
}

func TestAssemblerBoundsTraceStatesAndSkipsUnknownSizeOnly(t *testing.T) {
	assembler := httptrace.NewAssembler(32<<10, time.Minute, time.Second)
	assembler.SetMaxActiveStates(2)
	for chainID := uint64(1); chainID <= 3; chainID++ {
		if _, err := assembler.Process(httptrace.Event{ChainID: chainID, Direction: httptrace.DirectionRequest, Payload: []byte("GET / HTTP/1.1\r\nHost: example\r\n")}); err != nil {
			t.Fatalf("process chain %d: %v", chainID, err)
		}
	}
	snapshot := assembler.Snapshot()
	if snapshot.ActiveTraceStates != 2 || snapshot.StateDrops != 1 {
		t.Fatalf("unexpected state limit snapshot: %+v", snapshot)
	}
	if _, err := assembler.Process(httptrace.Event{ChainID: 4, Direction: httptrace.DirectionRequest, Flags: 1 << 6}); err != nil {
		t.Fatalf("process size-only event: %v", err)
	}
	snapshot = assembler.Snapshot()
	if snapshot.ActiveTraceStates != 2 || snapshot.StateDrops != 1 {
		t.Fatalf("size-only event should not retain state: %+v", snapshot)
	}
}

func TestStatsBoundsDiagnosticChainSets(t *testing.T) {
	s := &stats{}
	for chainID := uint64(1); chainID <= maxTrackedChainsPerKey+10; chainID++ {
		s.recordRawSourceEvent(httptrace.Event{ChainID: chainID, Direction: httptrace.DirectionRequest, Source: "sock_sendmsg"})
		s.recordUpdateSource("sock_sendmsg", "request", chainID)
	}

	rawCount, rawOverflow := s.rawChainsByKey["sock_sendmsg:req"].count()
	if rawCount != maxTrackedChainsPerKey || rawOverflow != 10 {
		t.Fatalf("raw diagnostic set: count=%d overflow=%d", rawCount, rawOverflow)
	}
	updateCount, updateOverflow := s.updateChainsByKey["sock_sendmsg:req"].count()
	if updateCount != maxTrackedChainsPerKey || updateOverflow != 10 {
		t.Fatalf("update diagnostic set: count=%d overflow=%d", updateCount, updateOverflow)
	}
}

func TestFormatIPv4FromKernelNetworkOrderValue(t *testing.T) {
	const raw uint32 = 0xA104A8C0
	log.Println("原始地址：", raw)
	log.Println("IPv4 地址：", formatIPv4(raw))

	if got, want := formatIPv4(raw), "192.168.4.161"; got != want {
		t.Fatalf("formatIPv4 mismatch: got %q want %q", got, want)
	}
}

func TestCaptureSourceName(t *testing.T) {
	cases := map[uint8]string{
		0:  "unknown",
		1:  "sock_sendmsg",
		2:  "tcp_sendmsg",
		3:  "sock_recvmsg",
		4:  "tcp_recvmsg",
		5:  "tcp_close",
		6:  "tls_ssl_read",
		7:  "tls_ssl_write",
		8:  "tls_ssl_read_ex",
		9:  "tls_ssl_write_ex",
		10: "tls_ssl_close",
	}

	for raw, want := range cases {
		if got := captureSourceName(raw); got != want {
			t.Fatalf("captureSourceName(%d) = %q want %q", raw, got, want)
		}
	}
}

func TestShouldRetryResolve(t *testing.T) {
	if !shouldRetryResolve(httptrace.Event{
		Direction: httptrace.DirectionRequest,
		FD:        12,
		SrcIP:     "0.0.0.0",
		DstIP:     "0.0.0.0",
	}) {
		t.Fatalf("request event with missing tuple should enter retry path")
	}

	if shouldRetryResolve(httptrace.Event{
		Direction: httptrace.DirectionUnknown,
		FD:        12,
		SrcIP:     "0.0.0.0",
		DstIP:     "0.0.0.0",
	}) {
		t.Fatalf("unknown direction should not enter retry path")
	}

	if shouldRetryResolve(httptrace.Event{
		Direction: httptrace.DirectionResponse,
		FD:        -1,
		SrcIP:     "0.0.0.0",
		DstIP:     "0.0.0.0",
	}) {
		t.Fatalf("invalid fd should not enter retry path")
	}
}

func TestDispatchEventPassesThroughMissingTupleRequest(t *testing.T) {
	svc := &Service{
		cfg:    DefaultConfig(),
		filter: ResolvedFilter{DstPort: 16210},
		stats:  &stats{},
	}
	ch := make(chan httptrace.Event, 1)
	event := httptrace.Event{
		ChainID:   1,
		FD:        10,
		Direction: httptrace.DirectionRequest,
		SrcIP:     "0.0.0.0",
		DstIP:     "0.0.0.0",
		SrcPort:   0,
		DstPort:   0,
	}

	if err := svc.dispatchEvent(context.Background(), event, ch); err != nil {
		t.Fatalf("dispatchEvent returned error: %v", err)
	}

	select {
	case got := <-ch:
		if got.ChainID != event.ChainID {
			t.Fatalf("unexpected event delivered: %#v", got)
		}
	default:
		t.Fatalf("expected unresolved request to be passed through")
	}

	if svc.stats.userFiltered.Load() != 0 {
		t.Fatalf("event should not be counted as filtered")
	}
}

func TestDispatchEventPassesThroughMissingTupleWithIPFilter(t *testing.T) {
	svc := &Service{
		cfg:    DefaultConfig(),
		filter: ResolvedFilter{DstIP: "192.168.4.161"},
		stats:  &stats{},
	}
	ch := make(chan httptrace.Event, 1)
	event := httptrace.Event{
		ChainID:   2,
		FD:        10,
		Direction: httptrace.DirectionRequest,
		SrcIP:     "0.0.0.0",
		DstIP:     "0.0.0.0",
		SrcPort:   0,
		DstPort:   0,
	}

	if err := svc.dispatchEvent(context.Background(), event, ch); err != nil {
		t.Fatalf("dispatchEvent returned error: %v", err)
	}

	select {
	case <-ch:
	default:
		t.Fatalf("expected unresolved request to be passed through even with IP filter")
	}

	if svc.stats.userFiltered.Load() != 0 {
		t.Fatalf("event should not be counted as filtered")
	}
}

func TestDispatchEventPassesThroughLegacyExistingChainFragment(t *testing.T) {
	svc := &Service{
		cfg:       DefaultConfig(),
		filter:    ResolvedFilter{DstPort: 16210},
		assembler: httptrace.NewAssembler(1<<20, time.Minute, 500*time.Millisecond),
		stats:     &stats{},
	}

	_, err := svc.assembler.Process(httptrace.Event{
		ChainID:   99,
		FD:        10,
		Direction: httptrace.DirectionRequest,
		Payload:   []byte("GET /x HTTP/1.1\r\nHost: example.com\r\n"),
	})
	if err != nil {
		t.Fatalf("seed assembler state failed: %v", err)
	}

	ch := make(chan httptrace.Event, 1)
	event := httptrace.Event{
		ChainID:   99,
		FD:        10,
		Direction: httptrace.DirectionResponse,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   50000,
		DstPort:   50001,
	}

	if err := svc.dispatchEvent(context.Background(), event, ch); err != nil {
		t.Fatalf("dispatchEvent returned error: %v", err)
	}

	select {
	case <-ch:
	default:
		t.Fatalf("expected existing-chain fragment to pass through")
	}
}

// 测试当 TLS 开启时，是否默认保留传统的 socket 事件
func TestDispatchEventKeepsLegacySocketEventForTLSCommByDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableTLS = true
	cfg.TLSComm = "nginx"

	svc := &Service{
		cfg:    cfg,
		filter: ResolvedFilter{},
		stats:  &stats{},
	}
	ch := make(chan httptrace.Event, 1)
	event := httptrace.Event{
		ChainID:   200,
		FD:        12,
		Direction: httptrace.DirectionRequest,
		Source:    "sock_recvmsg",
		Comm:      "nginx",
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
	}

	if err := svc.dispatchEvent(context.Background(), event, ch); err != nil {
		t.Fatalf("dispatchEvent returned error: %v", err)
	}

	select {
	case got := <-ch:
		if got.ChainID != event.ChainID || got.Source != event.Source {
			t.Fatalf("unexpected event delivered: %#v", got)
		}
	default:
		t.Fatalf("legacy socket event should be kept by default when TLS is enabled")
	}
}

func TestDispatchEventSuppressesLegacySocketEventForTLSCommWhenConfigured(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableTLS = true
	cfg.TLSComm = "nginx"
	cfg.SuppressSocketForTLS = true

	svc := &Service{
		cfg:    cfg,
		filter: ResolvedFilter{},
		stats:  &stats{},
	}
	ch := make(chan httptrace.Event, 1)
	event := httptrace.Event{
		ChainID:   201,
		FD:        12,
		Direction: httptrace.DirectionRequest,
		Source:    "sock_recvmsg",
		Comm:      "nginx",
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
	}

	if err := svc.dispatchEvent(context.Background(), event, ch); err != nil {
		t.Fatalf("dispatchEvent returned error: %v", err)
	}

	select {
	case got := <-ch:
		t.Fatalf("legacy socket event should be suppressed when configured: %#v", got)
	default:
	}
}

func TestDispatchEventKeepsTLSEventForTLSComm(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableTLS = true
	cfg.TLSComm = "nginx"
	cfg.SuppressSocketForTLS = true

	svc := &Service{
		cfg:    cfg,
		filter: ResolvedFilter{},
		stats:  &stats{},
	}
	ch := make(chan httptrace.Event, 1)
	event := httptrace.Event{
		ChainID:   202,
		FD:        12,
		Direction: httptrace.DirectionRequest,
		Source:    "tls_ssl_read",
		Comm:      "nginx",
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
	}

	if err := svc.dispatchEvent(context.Background(), event, ch); err != nil {
		t.Fatalf("dispatchEvent returned error: %v", err)
	}

	select {
	case got := <-ch:
		if got.ChainID != event.ChainID || got.Source != event.Source {
			t.Fatalf("unexpected event delivered: %#v", got)
		}
	default:
		t.Fatalf("tls event should not be suppressed")
	}
}

func TestResolveEventBypassesUserTuplePipeline(t *testing.T) {
	svc := &Service{
		cfg:      Config{DisableUserTuple: true},
		resolver: newSocketResolver(time.Second),
		stats:    &stats{},
	}

	event := httptrace.Event{
		PID:       123,
		FD:        7,
		Direction: httptrace.DirectionRequest,
		SrcIP:     "0.0.0.0",
		DstIP:     "0.0.0.0",
	}

	got, source := svc.resolveEvent(event)
	if source != resolveBypass {
		t.Fatalf("expected resolveBypass, got %v", source)
	}
	if got.PID != event.PID || got.FD != event.FD || got.Direction != event.Direction || got.SrcIP != event.SrcIP || got.DstIP != event.DstIP {
		t.Fatalf("event should stay unchanged when tuple pipeline disabled: got=%#v want=%#v", got, event)
	}
}

func TestDefaultConfigEnablesUserTuplePipeline(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.DisableUserTuple {
		t.Fatalf("default config should enable user tuple compensation")
	}
}

func TestResolveEventUsesResolverWhenTupleMissing(t *testing.T) {
	resolver := newSocketResolver(time.Second)
	key := socketKey{pid: 123, fd: 7, sockID: 88}
	resolver.storeCache(key, cachedSocketTuple{
		localIP:    "172.16.0.10",
		remoteIP:   "172.16.0.20",
		localPort:  8080,
		remotePort: 55000,
	})
	svc := &Service{
		cfg:      DefaultConfig(),
		resolver: resolver,
		stats:    &stats{},
	}

	event := httptrace.Event{
		PID:       123,
		FD:        7,
		SockID:    88,
		Direction: httptrace.DirectionRequest,
		SrcIP:     "0.0.0.0",
		DstIP:     "0.0.0.0",
	}

	got, source := svc.resolveEvent(event)
	if source != resolveFromCache {
		t.Fatalf("expected resolveFromCache, got %v", source)
	}
	if got.SrcIP != "172.16.0.20" || got.DstIP != "172.16.0.10" || got.SrcPort != 55000 || got.DstPort != 8080 {
		t.Fatalf("resolver tuple mismatch: got=%#v", got)
	}
}

func TestStartWorkersUsesResourceSizedQueue(t *testing.T) {
	svc := &Service{
		cfg:          Config{BatchSize: 100, WorkerCount: 2, WorkerQueueSize: 256, FlushInterval: time.Second},
		assembler:    httptrace.NewAssembler(1<<20, time.Minute, 500*time.Millisecond),
		stats:        &stats{},
		resourcePlan: runtimeResourcePlan{WorkerCount: 2, WorkerQueueSize: 256},
	}

	workers, wg := svc.startWorkers(nil)
	if len(workers) != 2 {
		t.Fatalf("worker count mismatch: got %d want %d", len(workers), 2)
	}
	for _, ch := range workers {
		if cap(ch) != 256 {
			t.Fatalf("worker queue cap mismatch: got %d want %d", cap(ch), 256)
		}
		close(ch)
	}
	wg.Wait()
}

func TestSanitizeTraceForOutputKeepsKernelTuple(t *testing.T) {
	svc := &Service{cfg: Config{DisableUserTuple: true}}
	trace := httptrace.TraceDocument{
		ChainID: 1,
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 1234,
		DstPort: 80,
	}

	got := svc.sanitizeTraceForOutput(trace)
	if got.SrcIP != trace.SrcIP || got.DstIP != trace.DstIP || got.SrcPort != trace.SrcPort || got.DstPort != trace.DstPort {
		t.Fatalf("kernel tuple fields should be preserved, got %#v want %#v", got, trace)
	}
}

func TestSanitizeTraceForOutputMarksMissingSrcIPWhenUserTupleDisabled(t *testing.T) {
	svc := &Service{cfg: Config{DisableUserTuple: true}}
	trace := httptrace.TraceDocument{
		ChainID: 1,
		SrcIP:   "0.0.0.0",
		DstIP:   "10.0.0.2",
		SrcPort: 1234,
		DstPort: 80,
	}

	got := svc.sanitizeTraceForOutput(trace)
	if got.SrcIP != "missing:user_tuple_disabled" {
		t.Fatalf("unexpected src_ip marker: %#v", got)
	}
}

func TestSanitizeTraceForOutputMarksMissingSrcIPForTLS(t *testing.T) {
	svc := &Service{cfg: DefaultConfig()}
	trace := httptrace.TraceDocument{
		ChainID:       2,
		CaptureSource: "tls_ssl_read",
		SrcIP:         "0.0.0.0",
		DstIP:         "10.0.0.2",
	}

	got := svc.sanitizeTraceForOutput(trace)
	if got.SrcIP != "missing:tls_no_tuple" {
		t.Fatalf("unexpected tls src_ip marker: %#v", got)
	}
}

func TestSanitizeTraceForOutputMarksMissingSrcIPForPortOnlyKernelTuple(t *testing.T) {
	svc := &Service{cfg: DefaultConfig()}
	trace := httptrace.TraceDocument{
		ChainID: 3,
		SrcIP:   "0.0.0.0",
		DstIP:   "10.0.0.2",
		SrcPort: 52344,
		DstPort: 8080,
	}

	got := svc.sanitizeTraceForOutput(trace)
	if got.SrcIP != "missing:kernel_port_only_or_resolver_miss" {
		t.Fatalf("unexpected port-only src_ip marker: %#v", got)
	}
}

func TestEnrichTraceTupleForOutputSwapsRequestTupleWithoutResolver(t *testing.T) {
	svc := &Service{}
	trace := httptrace.TraceDocument{
		Kind:    "request",
		SrcIP:   "10.0.0.2",
		DstIP:   "10.0.0.1",
		SrcPort: 8080,
		DstPort: 52344,
	}

	got := svc.enrichTraceTupleForOutput(trace)
	if got.SrcIP != "10.0.0.1" || got.DstIP != "10.0.0.2" || got.SrcPort != 52344 || got.DstPort != 8080 {
		t.Fatalf("request tuple should be normalized to client->server, got %#v", got)
	}
}

func TestEnrichTraceTupleForOutputKeepsResponseTupleWithoutResolver(t *testing.T) {
	svc := &Service{}
	trace := httptrace.TraceDocument{
		Kind:    "response",
		SrcIP:   "10.0.0.2",
		DstIP:   "10.0.0.1",
		SrcPort: 8080,
		DstPort: 52344,
	}

	got := svc.enrichTraceTupleForOutput(trace)
	if got.SrcIP != trace.SrcIP || got.DstIP != trace.DstIP || got.SrcPort != trace.SrcPort || got.DstPort != trace.DstPort {
		t.Fatalf("response tuple should stay server->client, got %#v want %#v", got, trace)
	}
}

func TestEnrichTraceTupleForOutputUsesResolverDirection(t *testing.T) {
	resolver := newSocketResolver(time.Second)
	key := socketKey{pid: 1234, fd: 9, sockID: 77}
	resolver.storeCache(key, cachedSocketTuple{
		localIP:    "172.16.0.10",
		remoteIP:   "172.16.0.20",
		localPort:  8080,
		remotePort: 55000,
	})
	svc := &Service{resolver: resolver}

	trace := httptrace.TraceDocument{
		Kind:   "request",
		PID:    1234,
		FD:     9,
		SockID: 77,
		SrcIP:  "0.0.0.0",
		DstIP:  "0.0.0.0",
	}

	got := svc.enrichTraceTupleForOutput(trace)
	if got.SrcIP != "172.16.0.20" || got.DstIP != "172.16.0.10" || got.SrcPort != 55000 || got.DstPort != 8080 {
		t.Fatalf("resolver-normalized tuple mismatch: got %#v", got)
	}
}

func TestEnrichTraceTupleForOutputPrefersCompleteKernelTupleOverResolver(t *testing.T) {
	resolver := newSocketResolver(time.Second)
	key := socketKey{pid: 1234, fd: 9, sockID: 77}
	resolver.storeCache(key, cachedSocketTuple{
		localIP:    "127.0.0.1",
		remoteIP:   "127.0.0.1",
		localPort:  8080,
		remotePort: 40000,
	})
	svc := &Service{resolver: resolver}

	trace := httptrace.TraceDocument{
		Kind:    "request",
		PID:     1234,
		FD:      9,
		SockID:  77,
		SrcIP:   "10.0.0.2",
		DstIP:   "10.0.0.1",
		SrcPort: 8080,
		DstPort: 52344,
	}

	got := svc.enrichTraceTupleForOutput(trace)
	if got.SrcIP != "10.0.0.1" || got.DstIP != "10.0.0.2" || got.SrcPort != 52344 || got.DstPort != 8080 {
		t.Fatalf("complete kernel tuple should win over resolver cache, got %#v", got)
	}
}

func TestEnrichTraceTupleForOutputDoesNotLateResolveProcOnCacheMiss(t *testing.T) {
	svc := &Service{resolver: newSocketResolver(time.Second)}
	trace := httptrace.TraceDocument{
		Kind:    "request",
		PID:     1234,
		FD:      9,
		SockID:  77,
		SrcIP:   "0.0.0.0",
		DstIP:   "0.0.0.0",
		SrcPort: 52344,
		DstPort: 8080,
	}

	got := svc.enrichTraceTupleForOutput(trace)
	if got.SrcIP != trace.SrcIP || got.DstIP != trace.DstIP || got.SrcPort != trace.SrcPort || got.DstPort != trace.DstPort {
		t.Fatalf("cache miss should keep original tuple placeholders, got %#v want %#v", got, trace)
	}
}

func TestNormalizeEventKeeps4096BytePayload(t *testing.T) {
	var raw bpfgen.HttpTraceHttpEvent
	raw.PayloadLen = uint16(len(raw.Payload))
	raw.TotalLen = raw.PayloadLen
	raw.Direction = httptrace.DirectionResponse
	for i := range raw.Payload {
		raw.Payload[i] = byte(i)
	}

	event := normalizeEvent(raw)
	if got, want := len(event.Payload), len(raw.Payload); got != want {
		t.Fatalf("payload length mismatch: got %d want %d", got, want)
	}
	if event.Payload[0] != raw.Payload[0] || event.Payload[len(event.Payload)-1] != raw.Payload[len(raw.Payload)-1] {
		t.Fatalf("payload bytes were not preserved")
	}
}
