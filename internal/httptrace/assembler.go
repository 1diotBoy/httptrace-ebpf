package httptrace

import (
	"bytes"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const minChunkedResponseStallTimeout = 5 * time.Second
const minConservativeResponseStallTimeout = 5 * time.Second

const (
	eventFlagEnd             = 1 << 1
	eventFlagCaptureTrunc    = 1 << 2
	eventFlagControl         = 1 << 4
	eventFlagClose           = 1 << 5
	eventFlagSizeOnly        = 1 << 6
	eventFlagCaptureBoundary = 1 << 7
	defaultMaxActiveStates   = 65536
)

// 事件结构体
type Event struct {
	Timestamp            time.Time
	TsNS                 uint64 // 时间戳纳秒
	ChainID              uint64 // 链ID
	SockID               uint64 // 套接字ID
	SeqHint              uint64 // 序列提示，用于排序
	ObservedMessageBytes uint64 // 观察到的消息字节数
	PID                  uint32 // 进程ID
	TID                  uint32 // 线程ID
	FD                   int32  // 文件描述符 ，-1表示未知，0表示标准输入，1表示标准输出，2表示标准错误
	IfIndex              uint32 // 接口索引
	SrcIP                string // 源IP
	DstIP                string // 目标IP
	SrcPort              uint16 // 源端口
	DstPort              uint16 // 目标端口
	FragIdx              uint16 // 分片索引
	Direction            uint8  // 方向
	Flags                uint8  // 标志
	Comm                 string // 进程名
	Source               string // 来源
	Payload              []byte // 负载
}

// 追踪文档结构体
type TraceDocument struct {
	Kind              string         `json:"kind"`
	ChainID           uint64         `json:"chain_id"`
	SockID            uint64         `json:"sock_id"`
	PID               uint32         `json:"pid"`
	TID               uint32         `json:"tid"`
	FD                int32          `json:"fd"`
	IfIndex           uint32         `json:"ifindex"`
	Comm              string         `json:"comm"`
	CaptureSource     string         `json:"capture_source,omitempty"`
	SrcIP             string         `json:"src_ip"`
	DstIP             string         `json:"dst_ip"`
	SrcPort           uint16         `json:"src_port"`
	DstPort           uint16         `json:"dst_port"`
	RequestTS         *time.Time     `json:"request_ts,omitempty"`
	ResponseTS        *time.Time     `json:"response_ts,omitempty"`         // 响应时间戳
	ResponseLatency   *float64       `json:"response_latency_ms,omitempty"` // 响应延迟时间，请求开始到响应开始
	Request           *ParsedMessage `json:"request,omitempty"`
	Response          *ParsedMessage `json:"response,omitempty"`
	RequestTruncated  bool           `json:"request_truncated"`
	ResponseTruncated bool           `json:"response_truncated"`
}

type Update struct {
	Kind  string
	Trace TraceDocument
}

type Assembler struct {
	shards            []stateShard
	tlsShards         []tlsSessionShard
	maxMessageBytes   atomic.Int64
	maxIdle           time.Duration
	responseStall     time.Duration
	debugTLSQueue     bool
	stalledFlushes    atomic.Uint64
	evictedFlushes    atomic.Uint64
	orphanResponses   atomic.Uint64
	promotedRequests  atomic.Uint64
	deferredResponses atomic.Uint64
	maxRetainedBytes  atomic.Int64
	retainedBytes     atomic.Int64
	bufferDrops       atomic.Uint64
	maxActiveStates   atomic.Int64
	activeStates      atomic.Int64
	stateDrops        atomic.Uint64
}

type stateShard struct {
	mu        sync.Mutex
	traces    map[uint64]*traceState
	closedTLS map[uint64]tlsClosedDirections
}

type tlsClosedDirections struct {
	request  bool
	response bool
	at       time.Time
}

type tlsSessionShard struct {
	mu       sync.Mutex
	sessions map[uint64]*tlsSessionState
}

type tlsSessionState struct {
	pending []pendingRequest
}

type traceState struct {
	base            TraceDocument
	requestStream   fragmentStream
	responseStream  fragmentStream
	lastUpdated     time.Time
	responseUpdated time.Time
	logicalSeq      uint64
	requestEmitted  bool
	pendingRequests []pendingRequest
	tlsAssigned     *pendingRequest
	requestSource   string
	responseSource  string
}

type fragmentStream struct {
	received        map[uint16][]byte
	release         func(int)
	nextFrag        uint16
	buffer          []byte
	observedBytes   uint64
	truncated       bool
	captureBoundary bool
	finalReady      bool
	firstTS         *time.Time
}

type pendingRequest struct {
	chainID           uint64
	requestTS         *time.Time
	request           *ParsedMessage
	requestMethod     string
	retainedBodyBytes int
	requestTruncated  bool
	emitted           bool
	requestSource     string
	requestBase       TraceDocument
}

type Snapshot struct {
	PendingRequests        int
	PendingResponses       int
	PendingNoRespBytes     int
	RequestBufferStates    int
	ResponseBufferStates   int
	StalledResponseFlushes uint64
	EvictedFlushes         uint64
	OrphanResponses        uint64
	PromotedRequests       uint64
	DeferredResponses      uint64
	RetainedBytes          uint64
	MaxRetainedBytes       uint64
	BufferDrops            uint64
	ActiveTraceStates      uint64
	MaxActiveTraceStates   uint64
	StateDrops             uint64
}

// NewAssembler 创建请求/响应聚合器。
// 按 chain_id 把多次 perf 事件重组成一条 HTTP 请求/响应，再交给 parser解析。
func NewAssembler(maxMessageBytes int, maxIdle, responseStall time.Duration) *Assembler {
	shards := make([]stateShard, 64)
	for i := range shards {
		shards[i].traces = make(map[uint64]*traceState)
		shards[i].closedTLS = make(map[uint64]tlsClosedDirections)
	}
	tlsShards := make([]tlsSessionShard, 64)
	for i := range tlsShards {
		tlsShards[i].sessions = make(map[uint64]*tlsSessionState)
	}
	if responseStall <= 0 {
		responseStall = 500 * time.Millisecond
	}
	asm := &Assembler{
		shards:        shards,
		tlsShards:     tlsShards,
		maxIdle:       maxIdle,
		responseStall: responseStall,
	}
	asm.SetMaxMessageBytes(maxMessageBytes)
	asm.SetMaxRetainedBytes(defaultRetainedBufferBudget(maxMessageBytes))
	asm.SetMaxActiveStates(defaultMaxActiveStates)
	return asm
}

func defaultRetainedBufferBudget(messageLimit int) int {
	if messageLimit <= 0 {
		messageLimit = 32 * 1024
	}
	// 请求和响应可能同时处于缓冲状态。为 32 组此类交互预留空间，
	// 同时限制因丢失事件导致的聚合器内存保留量。
	budget := messageLimit * 64
	if budget < 16<<20 {
		budget = 16 << 20
	}
	if budget > 64<<20 {
		budget = 64 << 20
	}
	return budget
}

// SetMaxRetainedBytes 限制所有未完成流保留的字节数。否则 perf 丢失事件可能导致
// 大量未完成的大消息一直存活到事务 TTL 到期。
func (a *Assembler) SetMaxRetainedBytes(limit int) {
	if a == nil {
		return
	}
	if limit <= 0 {
		limit = defaultRetainedBufferBudget(a.MaxMessageBytes())
	}
	a.maxRetainedBytes.Store(int64(limit))
}

func (a *Assembler) MaxRetainedBytes() int {
	if a == nil {
		return 0
	}
	return int(a.maxRetainedBytes.Load())
}

func (a *Assembler) reserveStreamBytes(size int) bool {
	if a == nil || size <= 0 {
		return true
	}
	limit := a.maxRetainedBytes.Load()
	for {
		current := a.retainedBytes.Load()
		if limit > 0 && current > limit-int64(size) {
			a.bufferDrops.Add(1)
			return false
		}
		if a.retainedBytes.CompareAndSwap(current, current+int64(size)) {
			return true
		}
	}
}

func (a *Assembler) releaseStreamBytes(size int) {
	if a == nil || size <= 0 {
		return
	}
	remaining := a.retainedBytes.Add(-int64(size))
	if remaining < 0 {
		a.retainedBytes.Store(0)
	}
}

func (a *Assembler) MaxMessageBytes() int {
	if a == nil {
		return 32 * 1024
	}
	v := int(a.maxMessageBytes.Load())
	if v <= 0 {
		return 32 * 1024
	}
	return v
}

func (a *Assembler) SetMaxMessageBytes(limit int) {
	if a == nil {
		return
	}
	if limit <= 0 {
		limit = 32 * 1024
	}
	a.maxMessageBytes.Store(int64(limit))
}

func (a *Assembler) SetDebugTLSQueue(debug bool) {
	if a == nil {
		return
	}
	a.debugTLSQueue = debug
}

func debugBufferPreview(data []byte, limit int) string {
	if limit <= 0 || len(data) == 0 {
		return ""
	}
	if len(data) > limit {
		data = data[:limit]
	}
	replacer := strings.NewReplacer("\r", "\\r", "\n", "\\n", "\x00", ".")
	return replacer.Replace(string(data))
}

func debugBufferSuffix(data []byte, limit int) string {
	if limit <= 0 || len(data) == 0 {
		return ""
	}
	if len(data) > limit {
		data = data[len(data)-limit:]
	}
	replacer := strings.NewReplacer("\r", "\\r", "\n", "\\n", "\x00", ".")
	return replacer.Replace(string(data))
}

func shouldDebugResponseDetail(msg *ParsedMessage, truncated bool) bool {
	if msg == nil {
		return false
	}
	if truncated || msg.BodyPartial || msg.Chunked || msg.StatusCode >= 400 {
		return true
	}
	if strings.Contains(msg.Body, `"errCode":"-100"`) || strings.Contains(msg.Body, "无权限") {
		return true
	}
	return false
}

func (a *Assembler) logResponseDecision(path string, state *traceState, msg *ParsedMessage, truncated bool) {
	if a == nil || !a.debugTLSQueue || state == nil || msg == nil {
		return
	}
	if !shouldDebugResponseDetail(msg, truncated) {
		return
	}
	buf := state.responseStream.buffer
	log.Printf(
		"响应解析路径：path=%s chain=%d sock=%d src=%s status=%d cl=%d te=%q conn=%q chunked=%t body_partial=%t truncated=%t stream_trunc=%t final_ready=%t observed=%d buf_len=%d consumed=%d body_bytes=%d raw_prefix=%q raw_suffix=%q body_preview=%q",
		path,
		state.base.ChainID,
		state.base.SockID,
		state.responseSource,
		msg.StatusCode,
		msg.ContentLength,
		msg.TransferEncoding,
		msg.Headers["Connection"],
		msg.Chunked,
		msg.BodyPartial,
		truncated,
		state.responseStream.truncated,
		state.responseStream.finalReady,
		state.responseStream.observedBytes,
		len(buf),
		msg.ConsumedBytes,
		len(msg.Body),
		debugBufferPreview(buf, 160),
		debugBufferSuffix(buf, 120),
		debugBufferPreview([]byte(msg.Body), 160),
	)
}

// Process 是用户态聚合的核心入口：
// 1. 根据 chain_id 找到事务状态。
// 2. 把 fragment 追加到 request/response 缓冲。
// 3. 尝试解析完整 HTTP。
// 4. 请求一旦完整就立即返回 update，响应完整后再返回完整链路 update。
func (a *Assembler) Process(event Event) ([]Update, error) {
	if event.ChainID == 0 {
		return nil, nil
	}

	shard := &a.shards[event.ChainID%uint64(len(a.shards))]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if closed, ok := shard.closedTLS[event.ChainID]; ok {
		if time.Since(closed.at) > a.maxIdle {
			delete(shard.closedTLS, event.ChainID)
		} else if (event.Direction == DirectionRequest && closed.request) ||
			(event.Direction == DirectionResponse && closed.response) {
			return nil, nil
		}
	}
	if isTLSSource(event.Source) {
		// TLS raw chain 的首片段如果根本不像 HTTP 请求起始行，
		// 说明这更像是被内核态误起出来的噪声 chain（常见前缀是 JS/CSS/body 碎片）。
		// 这类 chain 后续即便再来同 chain 的 response，也不应该参与真实业务配对，
		// 否则会把请求/响应数抬高，并污染最终落库结果。
		if event.Direction == DirectionRequest && event.FragIdx == 0 && len(event.Payload) > 0 && !looksLikeTLSRequestStart(event.Payload) {
			markClosedTLSRawChain(shard, event.ChainID, true, true)
			return nil, nil
		}
	}

	state := shard.traces[event.ChainID]
	if event.Flags&eventFlagControl != 0 && event.Flags&eventFlagClose != 0 {
		if state == nil {
			return nil, nil
		}
		state.lastUpdated = time.Now()
		return a.finalizeOnClose(state, shard, event.ChainID)
	}

	if state == nil {
		// 仅大小事件不包含可采集正文。在高 QPS 下，为已经丢失的链路创建状态，
		// 会让映射元数据一直保留到 TTL 到期。
		if event.Flags&eventFlagSizeOnly != 0 || !a.reserveTraceState() {
			if event.Flags&eventFlagSizeOnly == 0 {
				a.stateDrops.Add(1)
			}
			return nil, nil
		}
		state = &traceState{
			base: TraceDocument{
				ChainID:       event.ChainID,
				SockID:        event.SockID,
				PID:           event.PID,
				TID:           event.TID,
				FD:            event.FD,
				IfIndex:       event.IfIndex,
				Comm:          event.Comm,
				CaptureSource: event.Source,
				SrcIP:         event.SrcIP,
				DstIP:         event.DstIP,
				SrcPort:       event.SrcPort,
				DstPort:       event.DstPort,
			},
			requestStream:  fragmentStream{received: make(map[uint16][]byte), release: a.releaseStreamBytes},
			responseStream: fragmentStream{received: make(map[uint16][]byte), release: a.releaseStreamBytes},
			requestSource:  event.Source,
			responseSource: event.Source,
		}
		shard.traces[event.ChainID] = state
	}
	// 请求/响应的最终大小事件可能从相反的 socket 方向产生。它们只用于统计，
	// 不能替换从正文事件中获取的五元组。
	if event.Flags&eventFlagSizeOnly == 0 {
		refreshBaseTuple(&state.base, event)
	}
	state.lastUpdated = time.Now()
	switch event.Direction {
	case DirectionRequest:
		if event.Source != "" {
			state.requestSource = event.Source
		}
	case DirectionResponse:
		if event.Source != "" {
			state.responseSource = event.Source
		}
		state.responseUpdated = state.lastUpdated
	}

	// TLS 明文按每个内核 chain_id 跟踪一组逻辑交互。该 TLS 链路的请求一旦输出，
	// 同一链路后续的 SSL_read 分片就属于同一请求的过期后续片段，不能再次生成逻辑请求。
	if event.Direction == DirectionRequest && isTLSSource(event.Source) {
		if state.requestEmitted {
			return nil, nil
		}
		// 在首次请求更新输出前，截断的请求头之后如果出现明显只有正文的后续分片，
		// 仍然忽略它们，避免这些分片永久停留在队列中。
		if len(state.pendingRequests) > 0 && !looksLikeTLSRequestStart(event.Payload) {
			return nil, nil
		}
	}

	var stream *fragmentStream
	switch event.Direction {
	case DirectionRequest:
		stream = &state.requestStream
	case DirectionResponse:
		stream = &state.responseStream
	default:
		return nil, nil
	}

	if stream.firstTS == nil && event.Flags&eventFlagSizeOnly == 0 {
		ts := event.Timestamp
		stream.firstTS = &ts
	}
	if event.Direction == DirectionResponse && isTLSSource(state.responseSource) {
		_ = a.assignTLSPending(state)
	}
	if event.ObservedMessageBytes > stream.observedBytes {
		stream.observedBytes = event.ObservedMessageBytes
	}
	if event.Flags&eventFlagSizeOnly != 0 {
		if stream.captureBoundary && event.ObservedMessageBytes > uint64(len(stream.buffer)) {
			stream.truncated = true
		}
		if event.Flags&eventFlagEnd != 0 {
			stream.finalReady = true
			return a.tryEmitUpdates(state, shard, event.ChainID, false)
		}
		return nil, nil
	}
	if len(event.Payload) > 0 {
		if _, exists := stream.received[event.FragIdx]; !exists {
			if a.reserveStreamBytes(len(event.Payload)) {
				stream.received[event.FragIdx] = append([]byte(nil), event.Payload...)
			} else {
				// 保持统计事件继续流动，但当进程已经承受聚合器内存压力时，
				// 绝不继续无上限地保留正文。
				stream.truncated = true
				stream.captureBoundary = true
				stream.finalReady = true
			}
		}
	}
	if event.Flags&eventFlagCaptureTrunc != 0 {
		stream.truncated = true
	}
	if event.Flags&eventFlagCaptureBoundary != 0 {
		stream.captureBoundary = true
	}
	if !stream.truncated {
		stream.drain(a.MaxMessageBytes())
	} else {
		for frag := range stream.received {
			if frag < stream.nextFrag {
				stream.releaseBytes(len(stream.received[frag]))
				delete(stream.received, frag)
			}
		}
		stream.drain(a.MaxMessageBytes())
	}
	return a.tryEmitUpdates(state, shard, event.ChainID, false)
}

func refreshBaseTuple(base *TraceDocument, event Event) {
	if base == nil {
		return
	}
	if event.SrcIP != "" && event.SrcIP != "0.0.0.0" {
		base.SrcIP = event.SrcIP
	}
	if event.DstIP != "" && event.DstIP != "0.0.0.0" {
		base.DstIP = event.DstIP
	}
	if event.SrcPort != 0 {
		base.SrcPort = event.SrcPort
	}
	if event.DstPort != 0 {
		base.DstPort = event.DstPort
	}
	if event.IfIndex != 0 {
		base.IfIndex = event.IfIndex
	}
}

func (a *Assembler) FlushStalled(now time.Time) []Update {
	if a.responseStall <= 0 {
		return nil
	}

	updates := make([]Update, 0, 16)
	for i := range a.shards {
		shard := &a.shards[i]
		shard.mu.Lock()
		for chainID, state := range shard.traces {
			pendingCount := len(state.pendingRequests)
			if isTLSSource(state.responseSource) || isTLSSource(state.requestSource) {
				pendingCount = a.tlsPendingCount(state.base.SockID)
				if state.tlsAssigned != nil {
					pendingCount++
				}
			}
			if pendingCount == 0 || len(state.responseStream.buffer) == 0 || state.responseUpdated.IsZero() {
				continue
			}
			timeout := a.responseStall
			if timeout < minConservativeResponseStallTimeout && responseNeedsConservativeStall(state.responseStream.buffer) {
				timeout = minConservativeResponseStallTimeout
			}
			if now.Sub(state.responseUpdated) < timeout {
				continue
			}
			flushed := a.flushPartialResponse(state)
			if len(flushed) > 0 {
				updates = append(updates, flushed...)
				a.stalledFlushes.Add(uint64(len(flushed)))
			}
			if state.canDelete() {
				a.deleteTraceState(shard, chainID, state)
			}
		}
		shard.mu.Unlock()
	}
	updates = append(updates, a.flushStalledTLSPending(now)...)
	return updates
}

// EvictExpired 是周期性 idle eviction 的核心：
	// 1. 根据 last_updated 时间戳，移除超过 maxIdle 的状态。
// 2. 尝试解析完整 HTTP。
// 3. 请求一旦完整就立即返回 update，响应完整后再返回完整链路 update。
func (a *Assembler) EvictExpired(now time.Time) ([]Update, int) {
	evicted := 0
	updates := make([]Update, 0, 16)
	for i := range a.shards {
		shard := &a.shards[i]
		shard.mu.Lock()
		for chainID, closed := range shard.closedTLS {
			if now.Sub(closed.at) > a.maxIdle {
				delete(shard.closedTLS, chainID)
			}
		}
		for chainID, state := range shard.traces {
			if now.Sub(state.lastUpdated) <= a.maxIdle {
				continue
			}
			flushed, _ := a.tryEmitUpdates(state, shard, chainID, true)
			if len(flushed) > 0 {
				updates = append(updates, flushed...)
				a.evictedFlushes.Add(uint64(len(flushed)))
			}
			a.deleteTraceState(shard, chainID, state)
			evicted++
		}
		shard.mu.Unlock()
	}
	// TLS 待处理请求也必须遵守空闲时间上限。否则没有响应的请求会一直把已采集正文
	// 保留在会话 FIFO 中，直到进程退出。移除前会先输出请求；超过 maxIdle 后到达的响应
	// 会按孤立响应处理，避免无限制保留内存。
	tlsUpdates, tlsEvicted := a.evictExpiredTLSPending(now)
	updates = append(updates, tlsUpdates...)
	evicted += tlsEvicted
	return updates, evicted
}

// FlushAll 在进程退出前把所有残留状态按 EOF 语义做最后一次收尾。
// 这一步非常关键：如果 tracer 在压测结束后立刻退出，尾部仍在 assembler 里的 request/response
// 不会再等到下一次 stall/evict/tcp_close，自然也就不会出现在最终统计和 Redis 里。
func (a *Assembler) FlushAll() ([]Update, int) {
	updates := make([]Update, 0, 32)
	flushedStates := 0

	for i := range a.shards {
		shard := &a.shards[i]
		shard.mu.Lock()
		for chainID, state := range shard.traces {
			flushed, _ := a.tryEmitUpdates(state, shard, chainID, true)
			if len(flushed) > 0 {
				updates = append(updates, flushed...)
			}
			a.deleteTraceState(shard, chainID, state)
			flushedStates++
		}
		clear(shard.closedTLS)
		shard.mu.Unlock()
	}
	tlsUpdates, tlsFlushed := a.flushAllTLSPending()
	updates = append(updates, tlsUpdates...)
	flushedStates += tlsFlushed
	return updates, flushedStates
}

func (a *Assembler) flushStalledTLSPending(now time.Time) []Update {
	if a == nil || a.responseStall <= 0 {
		return nil
	}
	updates := make([]Update, 0, 8)
	for i := range a.tlsShards {
		shard := &a.tlsShards[i]
		shard.mu.Lock()
		for _, session := range shard.sessions {
			for idx := range session.pending {
				pending := &session.pending[idx]
				if pending.emitted || pending.requestTS == nil {
					continue
				}
				if now.Sub(*pending.requestTS) < a.responseStall {
					continue
				}
				if update, ok := emitPendingRequestUpdate(pending); ok {
					updates = append(updates, update)
				}
			}
		}
		shard.mu.Unlock()
	}
	return updates
}

func (a *Assembler) evictExpiredTLSPending(now time.Time) ([]Update, int) {
	if a == nil {
		return nil, 0
	}
	updates := make([]Update, 0, 8)
	evicted := 0
	for i := range a.tlsShards {
		shard := &a.tlsShards[i]
		shard.mu.Lock()
		for sockID, session := range shard.sessions {
			original := session.pending
			keep := original[:0]
			for _, pending := range original {
				if pending.requestTS == nil || now.Sub(*pending.requestTS) <= a.maxIdle {
					keep = append(keep, pending)
					continue
				}
				if update, ok := emitPendingRequestUpdate(&pending); ok {
					updates = append(updates, update)
				}
				evicted++
			}
			for idx := len(keep); idx < len(original); idx++ {
				original[idx] = pendingRequest{}
			}
			if len(keep) == 0 {
				delete(shard.sessions, sockID)
				continue
			}
			session.pending = keep
		}
		shard.mu.Unlock()
	}
	return updates, evicted
}

func (a *Assembler) flushAllTLSPending() ([]Update, int) {
	if a == nil {
		return nil, 0
	}
	updates := make([]Update, 0, 8)
	flushed := 0
	for i := range a.tlsShards {
		shard := &a.tlsShards[i]
		shard.mu.Lock()
		for sockID, session := range shard.sessions {
			for idx := range session.pending {
				if update, ok := emitPendingRequestUpdate(&session.pending[idx]); ok {
					updates = append(updates, update)
				}
				flushed++
			}
			delete(shard.sessions, sockID)
		}
		shard.mu.Unlock()
	}
	return updates, flushed
}

func (a *Assembler) Snapshot() Snapshot {
	var snap Snapshot

	for i := range a.shards {
		shard := &a.shards[i]
		shard.mu.Lock()
		for _, state := range shard.traces {
			snap.PendingRequests += len(state.pendingRequests)
			if len(state.requestStream.buffer) > 0 || len(state.requestStream.received) > 0 {
				snap.RequestBufferStates++
			}
			if len(state.responseStream.buffer) > 0 || len(state.responseStream.received) > 0 {
				snap.ResponseBufferStates++
			}
			if len(state.pendingRequests) > 0 {
				if len(state.responseStream.buffer) > 0 || len(state.responseStream.received) > 0 {
					snap.PendingResponses += len(state.pendingRequests)
				} else {
					snap.PendingNoRespBytes += len(state.pendingRequests)
				}
			}
		}
		shard.mu.Unlock()
	}
	for i := range a.tlsShards {
		shard := &a.tlsShards[i]
		shard.mu.Lock()
		for _, session := range shard.sessions {
			snap.PendingRequests += len(session.pending)
			snap.PendingNoRespBytes += len(session.pending)
		}
		shard.mu.Unlock()
	}
	snap.StalledResponseFlushes = a.stalledFlushes.Load()
	snap.EvictedFlushes = a.evictedFlushes.Load()
	snap.OrphanResponses = a.orphanResponses.Load()
	snap.PromotedRequests = a.promotedRequests.Load()
	snap.DeferredResponses = a.deferredResponses.Load()
	snap.RetainedBytes = uint64(maxInt64(a.retainedBytes.Load(), 0))
	snap.MaxRetainedBytes = uint64(maxInt64(a.maxRetainedBytes.Load(), 0))
	snap.BufferDrops = a.bufferDrops.Load()
	snap.ActiveTraceStates = uint64(maxInt64(a.activeStates.Load(), 0))
	snap.MaxActiveTraceStates = uint64(maxInt64(a.maxActiveStates.Load(), 0))
	snap.StateDrops = a.stateDrops.Load()
	return snap
}

func (a *Assembler) DebugTLSPendingStateSummary(now time.Time, limit int) string {
	if a == nil || limit == 0 {
		return "none"
	}
	type detail struct {
		chainID     uint64
		sockID      uint64
		requestSrc  string
		responseSrc string
		reqBufLen   int
		respBufLen  int
		reqRecv     int
		respRecv    int
		respAgeMs   int64
		tlsAssigned bool
		reqPrefix   string
		respPrefix  string
	}
	items := make([]detail, 0, limit)
	for i := range a.shards {
		shard := &a.shards[i]
		shard.mu.Lock()
		for _, state := range shard.traces {
			if !isTLSSource(state.requestSource) && !isTLSSource(state.responseSource) {
				continue
			}
			if len(state.requestStream.buffer) == 0 && len(state.responseStream.buffer) == 0 &&
				len(state.requestStream.received) == 0 && len(state.responseStream.received) == 0 {
				continue
			}
			age := int64(0)
			if !state.responseUpdated.IsZero() {
				age = now.Sub(state.responseUpdated).Milliseconds()
			}
			items = append(items, detail{
				chainID:     state.base.ChainID,
				sockID:      state.base.SockID,
				requestSrc:  state.requestSource,
				responseSrc: state.responseSource,
				reqBufLen:   len(state.requestStream.buffer),
				respBufLen:  len(state.responseStream.buffer),
				reqRecv:     len(state.requestStream.received),
				respRecv:    len(state.responseStream.received),
				respAgeMs:   age,
				tlsAssigned: state.tlsAssigned != nil,
				reqPrefix:   summarizeDebugPrefix(state.requestStream.buffer, 48),
				respPrefix:  summarizeDebugPrefix(state.responseStream.buffer, 48),
			})
		}
		shard.mu.Unlock()
	}
	if len(items) == 0 {
		return "none"
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].respBufLen != items[j].respBufLen {
			return items[i].respBufLen > items[j].respBufLen
		}
		if items[i].reqBufLen != items[j].reqBufLen {
			return items[i].reqBufLen > items[j].reqBufLen
		}
		return items[i].chainID < items[j].chainID
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("chain=%d sock=%d req_src=%s resp_src=%s req_buf=%d req_recv=%d resp_buf=%d resp_recv=%d resp_age_ms=%d assigned=%t req_prefix=%q resp_prefix=%q",
			item.chainID, item.sockID, item.requestSrc, item.responseSrc,
			item.reqBufLen, item.reqRecv, item.respBufLen, item.respRecv,
			item.respAgeMs, item.tlsAssigned, item.reqPrefix, item.respPrefix))
	}
	return strings.Join(parts, " | ")
}

func (a *Assembler) DebugTLSPendingQueueSummary(now time.Time, limit int) string {
	if a == nil || limit == 0 {
		return "none"
	}
	type detail struct {
		sockID        uint64
		chainID       uint64
		requestSource string
		emitted       bool
		ageMs         int64
		sig           string
		quality       int
		truncated     bool
		observed      uint64
		contentLength int64
		bodyPartial   bool
		startLine     string
	}
	items := make([]detail, 0, limit)
	for i := range a.tlsShards {
		shard := &a.tlsShards[i]
		shard.mu.Lock()
		for sockID, session := range shard.sessions {
			for _, pending := range session.pending {
				age := int64(0)
				if pending.requestTS != nil {
					age = now.Sub(*pending.requestTS).Milliseconds()
				}
				startLine := ""
				if pending.request != nil {
					startLine = pending.request.StartLine
				}
				items = append(items, detail{
					sockID:        sockID,
					chainID:       pending.chainID,
					requestSource: pending.requestSource,
					emitted:       pending.emitted,
					ageMs:         age,
					sig:           tlsPendingSignature(pending),
					quality:       tlsPendingQuality(pending),
					truncated:     pending.requestTruncated,
					observed:      pendingObserved(pending),
					contentLength: pendingContentLength(pending),
					bodyPartial:   pendingBodyPartial(pending),
					startLine:     summarizeDebugPrefix([]byte(startLine), 64),
				})
			}
		}
		shard.mu.Unlock()
	}
	if len(items) == 0 {
		return "none"
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ageMs != items[j].ageMs {
			return items[i].ageMs > items[j].ageMs
		}
		if items[i].sockID != items[j].sockID {
			return items[i].sockID < items[j].sockID
		}
		return items[i].chainID < items[j].chainID
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("sock=%d chain=%d src=%s emitted=%t age_ms=%d quality=%d truncated=%t observed=%d content_length=%d body_partial=%t sig=%q start_line=%q",
			item.sockID, item.chainID, item.requestSource, item.emitted, item.ageMs, item.quality,
			item.truncated, item.observed, item.contentLength, item.bodyPartial, item.sig, item.startLine))
	}
	return strings.Join(parts, " | ")
}

func (a *Assembler) tlsSessionShardFor(sockID uint64) *tlsSessionShard {
	if a == nil || len(a.tlsShards) == 0 {
		return nil
	}
	if sockID == 0 {
		sockID = 1
	}
	return &a.tlsShards[sockID%uint64(len(a.tlsShards))]
}

// enqueueTLSPending 将 TLS 请求添加到 TLS 会话队列中
func (a *Assembler) enqueueTLSPending(sockID uint64, pending pendingRequest) {
	shard := a.tlsSessionShardFor(sockID)
	if shard == nil {
		return
	}
	sig := tlsPendingSignature(pending)
	lowConfidence := tlsPendingShouldSuppress(pending)
	shard.mu.Lock()
	session := shard.sessions[sockID]
	if session == nil {
		session = &tlsSessionState{}
		shard.sessions[sockID] = session
	}
	if sig != "" {
		for idx, existing := range session.pending {
			if tlsPendingSignature(existing) != sig {
				continue
			}
			// 这里只允许替换“极像 phantom 的脏请求”，不要把同一条 keep-alive 连接上
			// 连续出现的真实同 URL 请求互相折叠掉。
			// 之前使用 tlsPendingLooksSuspicious（truncated/body_partial/大 body 都算可疑）
			// 会把像 /serviceinfo/update 这种大 body 的真实重复调用也当成 duplicate，
			// 最终表现成 raw request 已经到了用户态，但 update 数偏少。
			if tlsPendingShouldSuppress(existing) && tlsPendingQuality(pending) > tlsPendingQuality(existing) {
				if a.debugTLSQueue {
					log.Printf("TLS 队列替换：sock=%d old_chain=%d new_chain=%d sig=%q old_quality=%d new_quality=%d",
						sockID, existing.chainID, pending.chainID, sig, tlsPendingQuality(existing), tlsPendingQuality(pending))
				}
				session.pending = append(session.pending[:idx], session.pending[idx+1:]...)
				break
			}
			if tlsPendingShouldSuppress(pending) && tlsPendingQuality(existing) >= tlsPendingQuality(pending) {
				if a.debugTLSQueue {
					log.Printf("TLS 队列丢弃重复请求：sock=%d chain=%d existing_chain=%d sig=%q existing_quality=%d new_quality=%d",
						sockID, pending.chainID, existing.chainID, sig, tlsPendingQuality(existing), tlsPendingQuality(pending))
				}
				shard.mu.Unlock()
				return
			}
		}
	}
	// 对带 method/url 签名的 TLS request，不要在入队前直接 suppress。
	// 高并发下这类“低质量”请求里有一部分其实是真实请求；如果这里先丢掉，
	// 后续 response 仍然会出来，就会形成 response > request 的缺口。
	//
	// 保留它们进入 TLS session FIFO 后，后续同签名的更高质量请求仍然可以把它替换掉，
	// 这样既能处理 phantom duplicate，又不会凭空少记 request。
	if lowConfidence && sig == "" {
		if a.debugTLSQueue {
			log.Printf("TLS 队列抑制请求：sock=%d chain=%d source=%s sig=%q quality=%d observed=%d content_length=%d truncated=%t body_partial=%t",
				sockID, pending.chainID, pending.requestSource, sig, tlsPendingQuality(pending),
				pendingObserved(pending), pendingContentLength(pending), pending.requestTruncated, pendingBodyPartial(pending))
		}
		shard.mu.Unlock()
		return
	}
	session.pending = append(session.pending, pending)
	if a.debugTLSQueue {
		action := "enqueue"
		if lowConfidence {
			action = "enqueue-low-confidence"
		}
		log.Printf("TLS 队列%s：sock=%d chain=%d source=%s sig=%q quality=%d size=%d",
			action, sockID, pending.chainID, pending.requestSource, sig, tlsPendingQuality(pending), len(session.pending))
	}
	shard.mu.Unlock()
}

func (a *Assembler) tlsPendingCount(sockID uint64) int {
	shard := a.tlsSessionShardFor(sockID)
	if shard == nil {
		return 0
	}
	shard.mu.Lock()
	defer shard.mu.Unlock()
	session := shard.sessions[sockID]
	if session == nil {
		return 0
	}
	return len(session.pending)
}

func (a *Assembler) popTLSPending(sockID uint64) (pendingRequest, bool) {
	shard := a.tlsSessionShardFor(sockID)
	if shard == nil {
		return pendingRequest{}, false
	}
	shard.mu.Lock()
	defer shard.mu.Unlock()
	session := shard.sessions[sockID]
	if session == nil || len(session.pending) == 0 {
		return pendingRequest{}, false
	}
	pending := session.pending[0]
	session.pending[0] = pendingRequest{}
	session.pending = session.pending[1:]
	if len(session.pending) == 0 {
		delete(shard.sessions, sockID)
	}
	if a.debugTLSQueue {
		log.Printf("TLS 队列取出：sock=%d chain=%d source=%s sig=%q remain=%d",
			sockID, pending.chainID, pending.requestSource, tlsPendingSignature(pending), len(session.pending))
	}
	return pending, true
}

func (a *Assembler) assignTLSPending(state *traceState) bool {
	if a == nil || state == nil || state.tlsAssigned != nil {
		return false
	}
	pending, ok := a.popTLSPending(state.base.SockID)
	if !ok {
		return false
	}
	state.tlsAssigned = &pending
	if a.debugTLSQueue {
		log.Printf("TLS 队列分配：sock=%d response_chain=%d request_chain=%d response_source=%s request_source=%s sig=%q",
			state.base.SockID, state.base.ChainID, pending.chainID, state.responseSource, pending.requestSource, tlsPendingSignature(pending))
	}
	return true
}

func (a *Assembler) consumeTLSPendingForState(state *traceState) (pendingRequest, bool) {
	if state == nil {
		return pendingRequest{}, false
	}
	if state.tlsAssigned != nil {
		pending := *state.tlsAssigned
		state.tlsAssigned = nil
		if a.debugTLSQueue {
			log.Printf("TLS 队列消费已分配请求：sock=%d response_chain=%d request_chain=%d sig=%q",
				state.base.SockID, state.base.ChainID, pending.chainID, tlsPendingSignature(pending))
		}
		return pending, true
	}
	pending, ok := a.popTLSPending(state.base.SockID)
	if ok && a.debugTLSQueue {
		log.Printf("TLS 队列直接消费请求：sock=%d response_chain=%d request_chain=%d sig=%q",
			state.base.SockID, state.base.ChainID, pending.chainID, tlsPendingSignature(pending))
	}
	return pending, ok
}

func emitPendingRequestUpdate(pending *pendingRequest) (Update, bool) {
	if pending == nil || pending.emitted {
		return Update{}, false
	}
	pending.emitted = true
	return buildRequestUpdateFromPending(*pending), true
}

func markClosedTLSChain(shard *stateShard, chainID uint64, state *traceState) {
	if shard == nil || state == nil {
		return
	}
	if shard.closedTLS == nil {
		shard.closedTLS = make(map[uint64]tlsClosedDirections)
	}
	closed := shard.closedTLS[chainID]
	if state.requestEmitted {
		closed.request = true
	}
	if !state.responseUpdated.IsZero() {
		closed.response = true
	}
	closed.at = time.Now()
	shard.closedTLS[chainID] = closed
}

func markClosedTLSRawChain(shard *stateShard, chainID uint64, request, response bool) {
	if shard == nil {
		return
	}
	if shard.closedTLS == nil {
		shard.closedTLS = make(map[uint64]tlsClosedDirections)
	}
	closed := shard.closedTLS[chainID]
	if request {
		closed.request = true
	}
	if response {
		closed.response = true
	}
	closed.at = time.Now()
	shard.closedTLS[chainID] = closed
}

func (t *traceState) appendTLSResponseUpdates(updates []Update, pending pendingRequest, msg *ParsedMessage, ts *time.Time, truncated bool) []Update {
	if req, ok := emitPendingRequestUpdate(&pending); ok {
		updates = append(updates, req)
	}
	return append(updates, t.buildResponseUpdateFromPending(pending, msg, ts, truncated))
}

func tlsPendingSignature(p pendingRequest) string {
	if p.request == nil {
		return ""
	}
	req := p.request
	if req.Method == "" && req.URL == "" {
		return req.StartLine
	}
	return fmt.Sprintf("%s\x00%s", req.Method, req.URL)
}

func tlsPendingQuality(p pendingRequest) int {
	if p.request == nil {
		return -1000
	}
	req := p.request
	score := 0
	if req.Method != "" {
		score += 20
	}
	if req.URL != "" {
		score += 20
	}
	score += len(req.Headers) * 2
	if req.ContentLength >= 0 {
		score += 40
	}
	if !p.requestTruncated {
		score += 20
	} else {
		score -= 10
	}
	if !req.BodyPartial {
		score += 10
	} else {
		score -= 10
	}
	if req.ObservedMessageBytes > 8192 {
		score -= 30
	}
	return score
}

func tlsPendingShouldSuppress(p pendingRequest) bool {
	if p.request == nil {
		return true
	}
	req := p.request
	if !p.requestTruncated {
		return false
	}
	if req.ObservedMessageBytes < 16*1024 {
		return false
	}
	if req.ContentLength >= 0 || req.Chunked || req.TransferEncoding != "" {
		return false
	}
	if req.Body != "" || req.BodyPartial {
		return false
	}
	return true
}

func pendingObserved(p pendingRequest) uint64 {
	if p.request == nil {
		return 0
	}
	return p.request.ObservedMessageBytes
}

func pendingContentLength(p pendingRequest) int64 {
	if p.request == nil {
		return -1
	}
	return p.request.ContentLength
}

func pendingBodyPartial(p pendingRequest) bool {
	if p.request == nil {
		return false
	}
	return p.request.BodyPartial
}

func (a *Assembler) ResetCounters() {
	if a == nil {
		return
	}
	a.stalledFlushes.Swap(0)
	a.evictedFlushes.Swap(0)
	a.orphanResponses.Swap(0)
	a.promotedRequests.Swap(0)
	a.deferredResponses.Swap(0)
	a.bufferDrops.Swap(0)
}

func (a *Assembler) HasState(chainID uint64) bool {
	if chainID == 0 {
		return false
	}
	shard := &a.shards[chainID%uint64(len(a.shards))]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	_, ok := shard.traces[chainID]
	return ok
}

func (a *Assembler) finalizeOnClose(state *traceState, shard *stateShard, chainID uint64) ([]Update, error) {
	updates, err := a.tryEmitUpdates(state, shard, chainID, true)
	if err != nil {
		return nil, err
	}
	if state.canDelete() {
		a.deleteTraceState(shard, chainID, state)
	}
	return updates, nil
}

func (a *Assembler) tryEmitUpdates(state *traceState, shard *stateShard, chainID uint64, eof bool) ([]Update, error) {
	updates := make([]Update, 0, 4)

	requestUpdates, err := a.emitRequests(state, eof)
	if err != nil {
		return nil, err
	}
	updates = append(updates, requestUpdates...)

	responseUpdates, err := a.emitResponses(state, eof)
	if err != nil {
		return nil, err
	}
	updates = append(updates, responseUpdates...)

	if state.canDelete() {
		a.deleteTraceState(shard, chainID, state)
	}
	return updates, nil
}

func (a *Assembler) emitRequests(state *traceState, eof bool) ([]Update, error) {
	updates := make([]Update, 0, 2)

	for len(state.requestStream.buffer) > 0 {
		msg, complete, err := TryParseMessage(DirectionRequest, state.requestStream.buffer, ParseOptions{EOF: eof})
		if err != nil {
			if resyncStream(DirectionRequest, &state.requestStream) {
				continue
			}
			return updates, nil
		}
		if complete {
			annotateParsedMessage(msg, &state.requestStream)
			chainID := a.nextLogicalChainID(state)
			if isTLSSource(state.requestSource) {
				state.requestEmitted = true
				a.enqueueTLSPending(state.base.SockID, pendingRequest{
					chainID:          chainID,
					requestTS:        cloneTimePtr(state.requestStream.firstTS),
					request:          msg,
					requestTruncated: false,
					emitted:          false,
					requestSource:    state.requestSource,
					requestBase:      state.base,
				})
			} else {
				updates = append(updates, state.buildRequestUpdate(chainID, msg, state.requestStream.firstTS, false))
			}
			state.requestStream.consume(msg.ConsumedBytes)
			continue
		}

		// 当前 TLS 明文采集会输出便于 verifier 处理的短分片。请求采集一旦标记为截断，
		// 应立即保留已解析的请求头，而不是等待可能永远无法进入用户态的完整正文。
		if state.requestStream.truncated && (isTLSSource(state.requestSource) || state.requestStream.finalReady || eof) {
			msg, ok, err := TryParseMessageHead(DirectionRequest, state.requestStream.buffer, ParseOptions{EOF: false})
			if err == nil && ok {
				annotateParsedMessage(msg, &state.requestStream)
				chainID := a.nextLogicalChainID(state)
				if isTLSSource(state.requestSource) {
					state.requestEmitted = true
					a.enqueueTLSPending(state.base.SockID, pendingRequest{
						chainID:          chainID,
						requestTS:        cloneTimePtr(state.requestStream.firstTS),
						request:          msg,
						requestTruncated: true,
						emitted:          false,
						requestSource:    state.requestSource,
						requestBase:      state.base,
					})
				} else {
					updates = append(updates, state.buildRequestUpdate(chainID, msg, state.requestStream.firstTS, true))
				}
				state.requestStream.consumeAll()
				return updates, nil
			}
			msg, ok, err = TryParsePartialHead(DirectionRequest, state.requestStream.buffer)
			if err == nil && ok {
				annotateParsedMessage(msg, &state.requestStream)
				chainID := a.nextLogicalChainID(state)
				if isTLSSource(state.requestSource) {
					state.requestEmitted = true
					a.enqueueTLSPending(state.base.SockID, pendingRequest{
						chainID:          chainID,
						requestTS:        cloneTimePtr(state.requestStream.firstTS),
						request:          msg,
						requestTruncated: true,
						emitted:          false,
						requestSource:    state.requestSource,
						requestBase:      state.base,
					})
				} else {
					updates = append(updates, state.buildRequestUpdate(chainID, msg, state.requestStream.firstTS, true))
				}
				state.requestStream.consumeAll()
				return updates, nil
			}
		}

		if resyncStream(DirectionRequest, &state.requestStream) {
			continue
		}

		if !(state.requestStream.finalReady || eof) {
			return updates, nil
		}

		msg, ok, err := TryParseMessageHead(DirectionRequest, state.requestStream.buffer, ParseOptions{EOF: eof})
		if err != nil {
			if resyncStream(DirectionRequest, &state.requestStream) {
				continue
			}
			return updates, nil
		}
		if !ok {
			if resyncStream(DirectionRequest, &state.requestStream) {
				continue
			}
			return updates, nil
		}
		annotateParsedMessage(msg, &state.requestStream)
		chainID := a.nextLogicalChainID(state)
		if isTLSSource(state.requestSource) {
			state.requestEmitted = true
			a.enqueueTLSPending(state.base.SockID, pendingRequest{
				chainID:          chainID,
				requestTS:        cloneTimePtr(state.requestStream.firstTS),
				request:          msg,
				requestTruncated: state.requestStream.truncated || msg.BodyPartial,
				emitted:          false,
				requestSource:    state.requestSource,
				requestBase:      state.base,
			})
		} else {
			updates = append(updates, state.buildRequestUpdate(chainID, msg, state.requestStream.firstTS, state.requestStream.truncated || msg.BodyPartial))
		}
		state.requestStream.consumeAll()
		return updates, nil
	}

	return updates, nil
}

func isTLSSource(source string) bool {
	return strings.HasPrefix(source, "tls_")
}

func looksLikeTLSRequestStart(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	if FindMessageStart(DirectionRequest, payload) == 0 {
		return true
	}
	trimmed := bytes.TrimLeft(payload, "\r\n\t ")
	return len(trimmed) != len(payload) && FindMessageStart(DirectionRequest, trimmed) == 0
}

func (a *Assembler) emitResponses(state *traceState, eof bool) ([]Update, error) {
	updates := make([]Update, 0, 2)
	tlsSource := isTLSSource(state.responseSource) || isTLSSource(state.requestSource)
	pendingCount := len(state.pendingRequests)
	if tlsSource {
		pendingCount = a.tlsPendingCount(state.base.SockID)
		if state.tlsAssigned != nil {
			pendingCount++
		}
	}

	promoted, err := a.promoteRequestForResponse(state)
	if err != nil {
		return nil, err
	}
	updates = append(updates, promoted...)
	pendingCount = len(state.pendingRequests)
	if tlsSource {
		pendingCount = a.tlsPendingCount(state.base.SockID)
		if state.tlsAssigned != nil {
			pendingCount++
		}
	}

	/* 同一个 chain 的 response 有时会先于 request perf 记录进入用户态。
	 * 这在多 CPU perf buffer 交错读取时是可能发生的：
	 * - 内核态关联已经正确，但用户态先读到了 response 片段；
	 * - 如果这里直接把它当 orphan response 输出，后续 request 再到时，
	 *   就会留下 pending_no_resp，同时 orphan_resp 也会上升。
	 *
	 * 因此当当前 state 里还没有 pending request 时，先暂存 response，
	 * 等同链 request 到达后再配对；只有 EOF/截断这类“不会再等到 request”的场景，
	 * 才允许真正按 orphan response 输出。
	 */
	if pendingCount == 0 && len(state.responseStream.buffer) > 0 && !eof && !state.responseStream.truncated {
		a.deferredResponses.Add(1)
		return updates, nil
	}

	for len(state.responseStream.buffer) > 0 {
		opts := ParseOptions{EOF: eof}
		if !tlsSource && len(state.pendingRequests) > 0 {
			opts.RequestMethod = pendingRequestMethod(state.pendingRequests[0])
		}

		msg, complete, err := TryParseMessage(DirectionResponse, state.responseStream.buffer, opts)
		if err != nil {
			if resyncStream(DirectionResponse, &state.responseStream) {
				continue
			}
			return updates, nil
		}
		if complete {
			if pendingCount == 0 {
				a.orphanResponses.Add(1)
			}
			annotateParsedMessage(msg, &state.responseStream)
			if tlsSource {
				if pending, ok := a.consumeTLSPendingForState(state); ok {
					updates = state.appendTLSResponseUpdates(updates, pending, msg, state.responseStream.firstTS, false)
				} else {
					a.orphanResponses.Add(1)
					updates = append(updates, state.buildResponseUpdate(msg, state.responseStream.firstTS, false))
				}
			} else {
				updates = append(updates, state.buildResponseUpdate(msg, state.responseStream.firstTS, false))
			}
			state.responseStream.consume(msg.ConsumedBytes)
			continue
		}

		// 对 4xx/5xx 这类异常响应，优先保证“有记录、有 body”，而不是一直等到完整 body。
		// 这些异常页/错误 JSON 在不同框架/容器/Nginx 路径里，body 很容易被拆到后续 send 中，
		// 如果这里仍按 200 的策略等待完整响应，经常会在高并发下积压成 pending_resp。
		if head, ok, err := TryParseMessageHead(DirectionResponse, state.responseStream.buffer, opts); err == nil && ok && !state.responseStream.truncated && shouldEagerFlushErrorResponse(head) {
			if pendingCount == 0 {
				a.orphanResponses.Add(1)
			}
			annotateParsedMessage(head, &state.responseStream)
			if tlsSource {
				if pending, ok := a.consumeTLSPendingForState(state); ok {
					updates = state.appendTLSResponseUpdates(updates, pending, head, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, head))
				} else {
					a.orphanResponses.Add(1)
					updates = append(updates, state.buildResponseUpdate(head, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, head)))
				}
			} else {
				updates = append(updates, state.buildResponseUpdate(head, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, head)))
			}
			state.responseStream.consumeAll()
			continue
		}

		if resyncStream(DirectionResponse, &state.responseStream) {
			continue
		}

		// 同一条 keep-alive 连接上如果下一条 request 都已经进来了，
		// 说明当前这条 response 在 HTTP 语义上已经结束。
		// Nginx/sendfile 场景下 body 可能走了 sendpage 等旁路，当前 sendmsg 缓冲里只有响应头；
		// 这时不能一直等待“完整 body”，否则就会出现 request 数对上、response 持续偏少。
		if !tlsSource && pendingCount > 1 {
			msg, consumed, ok, err := splitAndParsePartialResponse(state.responseStream.buffer, opts)
			if err != nil {
				return updates, nil
			}
			if ok {
				if pendingCount == 0 {
					a.orphanResponses.Add(1)
				}
				annotateParsedMessage(msg, &state.responseStream)
				if tlsSource {
					if pending, ok := a.consumeTLSPendingForState(state); ok {
						updates = state.appendTLSResponseUpdates(updates, pending, msg, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, msg))
					} else {
						a.orphanResponses.Add(1)
						updates = append(updates, state.buildResponseUpdate(msg, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, msg)))
					}
				} else {
					updates = append(updates, state.buildResponseUpdate(msg, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, msg)))
				}
				state.responseStream.consume(consumed)
				continue
			}
		}

		if !(state.responseStream.finalReady || eof) {
			return updates, nil
		}

		msg, ok, err := TryParseMessageHead(DirectionResponse, state.responseStream.buffer, opts)
		if err != nil {
			if resyncStream(DirectionResponse, &state.responseStream) {
				continue
			}
			if partial, ok, perr := TryParsePartialHead(DirectionResponse, state.responseStream.buffer); perr == nil && ok {
				if pendingCount == 0 {
					a.orphanResponses.Add(1)
				}
				annotateParsedMessage(partial, &state.responseStream)
				maybePromoteStalledChunkedResponse(&state.responseStream, partial)
				if tlsSource {
					if pending, ok := a.consumeTLSPendingForState(state); ok {
						updates = state.appendTLSResponseUpdates(updates, pending, partial, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, partial))
					} else {
						a.orphanResponses.Add(1)
						updates = append(updates, state.buildResponseUpdate(partial, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, partial)))
					}
				} else {
					updates = append(updates, state.buildResponseUpdate(partial, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, partial)))
				}
				state.responseStream.consumeAll()
				return updates, nil
			}
			if synthetic, ok := BuildSyntheticResponse(state.responseStream.buffer); ok {
				if pendingCount == 0 {
					a.orphanResponses.Add(1)
				}
				annotateParsedMessage(synthetic, &state.responseStream)
				if tlsSource {
					if pending, ok := a.consumeTLSPendingForState(state); ok {
						updates = state.appendTLSResponseUpdates(updates, pending, synthetic, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, synthetic))
					} else {
						a.orphanResponses.Add(1)
						updates = append(updates, state.buildResponseUpdate(synthetic, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, synthetic)))
					}
				} else {
					updates = append(updates, state.buildResponseUpdate(synthetic, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, synthetic)))
				}
				state.responseStream.consumeAll()
			}
			return updates, nil
		}
		if !ok {
			if resyncStream(DirectionResponse, &state.responseStream) {
				continue
			}
			if partial, ok, perr := TryParsePartialHead(DirectionResponse, state.responseStream.buffer); perr == nil && ok {
				if pendingCount == 0 {
					a.orphanResponses.Add(1)
				}
				annotateParsedMessage(partial, &state.responseStream)
				maybePromoteStalledChunkedResponse(&state.responseStream, partial)
				if tlsSource {
					if pending, ok := a.consumeTLSPendingForState(state); ok {
						updates = state.appendTLSResponseUpdates(updates, pending, partial, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, partial))
					} else {
						a.orphanResponses.Add(1)
						updates = append(updates, state.buildResponseUpdate(partial, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, partial)))
					}
				} else {
					updates = append(updates, state.buildResponseUpdate(partial, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, partial)))
				}
				state.responseStream.consumeAll()
				return updates, nil
			}
			if synthetic, ok := BuildSyntheticResponse(state.responseStream.buffer); ok {
				if pendingCount == 0 {
					a.orphanResponses.Add(1)
				}
				annotateParsedMessage(synthetic, &state.responseStream)
				if tlsSource {
					if pending, ok := a.consumeTLSPendingForState(state); ok {
						updates = state.appendTLSResponseUpdates(updates, pending, synthetic, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, synthetic))
					} else {
						a.orphanResponses.Add(1)
						updates = append(updates, state.buildResponseUpdate(synthetic, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, synthetic)))
					}
				} else {
					updates = append(updates, state.buildResponseUpdate(synthetic, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, synthetic)))
				}
				state.responseStream.consumeAll()
			}
			return updates, nil
		}
		if pendingCount == 0 {
			a.orphanResponses.Add(1)
		}
		annotateParsedMessage(msg, &state.responseStream)
		if tlsSource {
			if pending, ok := a.consumeTLSPendingForState(state); ok {
				updates = state.appendTLSResponseUpdates(updates, pending, msg, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, msg))
			} else {
				a.orphanResponses.Add(1)
				updates = append(updates, state.buildResponseUpdate(msg, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, msg)))
			}
		} else {
			updates = append(updates, state.buildResponseUpdate(msg, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, msg)))
		}
		state.responseStream.consumeAll()
		return updates, nil
	}

	return updates, nil
}

func (a *Assembler) promoteRequestForResponse(state *traceState) ([]Update, error) {
	if isTLSSource(state.requestSource) || isTLSSource(state.responseSource) {
		return nil, nil
	}
	if len(state.pendingRequests) > 0 || len(state.requestStream.buffer) == 0 || len(state.responseStream.buffer) == 0 {
		return nil, nil
	}
	// 被截断采集的请求会保留前缀，直到内核在第一个非 1xx 响应时上报最终观测大小。
	// 如果过早提升它，计数会停留在超过采集上限的那个 syscall 时刻。
	if state.requestStream.truncated && !state.requestStream.finalReady {
		return nil, nil
	}

	msg, complete, err := TryParseMessage(DirectionRequest, state.requestStream.buffer, ParseOptions{EOF: false})
	if err == nil && complete {
		a.promotedRequests.Add(1)
		annotateParsedMessage(msg, &state.requestStream)
		update := state.buildRequestUpdate(a.nextLogicalChainID(state), msg, state.requestStream.firstTS, false)
		state.requestStream.consume(msg.ConsumedBytes)
		return []Update{update}, nil
	}

	msg, ok, err := TryParseMessageHead(DirectionRequest, state.requestStream.buffer, ParseOptions{EOF: true})
	if err != nil || !ok {
		msg, ok, err = TryParsePartialHead(DirectionRequest, state.requestStream.buffer)
		if err != nil || !ok {
			return nil, err
		}
	}

	a.promotedRequests.Add(1)
	annotateParsedMessage(msg, &state.requestStream)
	update := state.buildRequestUpdate(a.nextLogicalChainID(state), msg, state.requestStream.firstTS, state.requestStream.truncated || msg.BodyPartial)
	state.requestStream.consumeAll()
	return []Update{update}, nil
}

func splitAndParsePartialResponse(data []byte, opts ParseOptions) (*ParsedMessage, int, bool, error) {
	_, _, bodyStart, ok, err := parseMessageHead(DirectionResponse, data)
	if err != nil || !ok {
		return nil, 0, false, err
	}

	if next := FindMessageStart(DirectionResponse, data[bodyStart:]); next >= 0 {
		limit := bodyStart + next
		msg, ok, err := TryParseMessageHead(DirectionResponse, data[:limit], opts)
		if err != nil || !ok {
			return nil, 0, false, err
		}
		msg.Body = ""
		msg.BodyPartial = true
		msg.ConsumedBytes = limit
		// msg.RawPayload = string(data[:limit])
		return msg, limit, true, nil
	}

	msg, ok, err := TryParseMessageHead(DirectionResponse, data, opts)
	if err != nil || !ok {
		return nil, 0, false, err
	}
	return msg, len(data), true, nil
}

func (a *Assembler) flushPartialResponse(state *traceState) []Update {
	tlsSource := isTLSSource(state.responseSource) || isTLSSource(state.requestSource)
	pendingCount := len(state.pendingRequests)
	if tlsSource {
		pendingCount = a.tlsPendingCount(state.base.SockID)
		if state.tlsAssigned != nil {
			pendingCount++
		}
	}
	if pendingCount == 0 || len(state.responseStream.buffer) == 0 {
		return nil
	}

	opts := ParseOptions{}
	if !tlsSource {
		opts.RequestMethod = pendingRequestMethod(state.pendingRequests[0])
	}

	if msg, complete, err := TryParseMessage(DirectionResponse, state.responseStream.buffer, opts); err == nil && complete {
		if pendingCount == 0 {
			a.orphanResponses.Add(1)
		}
		annotateParsedMessage(msg, &state.responseStream)
		a.logResponseDecision("stalled-complete", state, msg, false)
		if tlsSource {
			if pending, ok := a.consumeTLSPendingForState(state); ok {
				out := state.appendTLSResponseUpdates(nil, pending, msg, state.responseStream.firstTS, false)
				state.responseStream.consume(msg.ConsumedBytes)
				return out
			}
		}
		update := state.buildResponseUpdate(msg, state.responseStream.firstTS, false)
		state.responseStream.consume(msg.ConsumedBytes)
		return []Update{update}
	}

	if resyncStream(DirectionResponse, &state.responseStream) {
		return a.flushPartialResponse(state)
	}

	msg, ok, err := TryParseMessageHead(DirectionResponse, state.responseStream.buffer, opts)
	if err != nil || !ok {
		if partial, ok, perr := TryParsePartialHead(DirectionResponse, state.responseStream.buffer); perr == nil && ok {
			if pendingCount == 0 {
				a.orphanResponses.Add(1)
			}
			annotateParsedMessage(partial, &state.responseStream)
			maybePromoteStalledChunkedResponse(&state.responseStream, partial)
			a.logResponseDecision("stalled-partial-head", state, partial, responseUpdateTruncated(&state.responseStream, partial))
			if tlsSource {
				if pending, ok := a.consumeTLSPendingForState(state); ok {
					out := state.appendTLSResponseUpdates(nil, pending, partial, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, partial))
					state.responseStream.consumeAll()
					return out
				}
			}
			update := state.buildResponseUpdate(partial, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, partial))
			state.responseStream.consumeAll()
			return []Update{update}
		}
		if synthetic, ok := BuildSyntheticResponse(state.responseStream.buffer); ok {
			if pendingCount == 0 {
				a.orphanResponses.Add(1)
			}
			annotateParsedMessage(synthetic, &state.responseStream)
			a.logResponseDecision("stalled-synthetic", state, synthetic, responseUpdateTruncated(&state.responseStream, synthetic))
			if tlsSource {
				if pending, ok := a.consumeTLSPendingForState(state); ok {
					out := state.appendTLSResponseUpdates(nil, pending, synthetic, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, synthetic))
					state.responseStream.consumeAll()
					return out
				}
			}
			update := state.buildResponseUpdate(synthetic, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, synthetic))
			state.responseStream.consumeAll()
			return []Update{update}
		}
		return nil
	}
	if pendingCount == 0 {
		a.orphanResponses.Add(1)
	}
	annotateParsedMessage(msg, &state.responseStream)
	maybePromoteStalledChunkedResponse(&state.responseStream, msg)
	a.logResponseDecision("stalled-head", state, msg, responseUpdateTruncated(&state.responseStream, msg))
	if tlsSource {
		if pending, ok := a.consumeTLSPendingForState(state); ok {
			out := state.appendTLSResponseUpdates(nil, pending, msg, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, msg))
			state.responseStream.consumeAll()
			return out
		}
	}
	update := state.buildResponseUpdate(msg, state.responseStream.firstTS, responseUpdateTruncated(&state.responseStream, msg))
	state.responseStream.consumeAll()
	return []Update{update}
}

func (a *Assembler) nextLogicalChainID(state *traceState) uint64 {
	seq := state.logicalSeq
	state.logicalSeq++
	if seq == 0 {
		return state.base.ChainID
	}
	return state.base.ChainID ^ (0x9e3779b97f4a7c15 * seq)
}

func (t *traceState) buildRequestUpdate(chainID uint64, msg *ParsedMessage, ts *time.Time, truncated bool) Update {
	update := t.makeRequestUpdate(pendingRequest{
		chainID:          chainID,
		requestTS:        cloneTimePtr(ts),
		request:          msg,
		requestTruncated: truncated,
		emitted:          true,
		requestSource:    t.requestSource,
		requestBase:      t.base,
	})
	t.requestEmitted = true
	t.pendingRequests = append(t.pendingRequests, pendingRequest{
		chainID:   chainID,
		requestTS: cloneTimePtr(ts),
		// 非 TLS 响应只需要请求方法来判断是否允许正文。将 msg 保存在这里会在响应到达前
		// 额外复制一份可能达到数 MiB 的采集正文。
		requestMethod:    msg.Method,
		requestTruncated: truncated,
		emitted:          true,
		requestSource:    t.requestSource,
		requestBase:      t.base,
	})
	return update
}

func buildRequestUpdateFromPending(pending pendingRequest) Update {
	doc := pending.requestBase
	doc.Kind = "request"
	doc.ChainID = pending.chainID
	doc.RequestTS = cloneTimePtr(pending.requestTS)
	doc.ResponseTS = nil
	doc.ResponseLatency = nil
	doc.Request = pending.request
	doc.Response = nil
	doc.CaptureSource = pending.requestSource
	doc.RequestTruncated = pending.requestTruncated
	doc.ResponseTruncated = false
	return Update{Kind: "request", Trace: doc}
}

// 构建响应更新
func (t *traceState) buildResponseUpdate(msg *ParsedMessage, ts *time.Time, truncated bool) Update {
	doc := t.base
	doc.Kind = "response"
	doc.ResponseTS = cloneTimePtr(ts)
	doc.RequestTS = nil
	doc.Request = nil
	doc.Response = msg
	doc.CaptureSource = t.responseSource
	doc.RequestTruncated = false
	doc.ResponseTruncated = truncated

	// 如果存在 pending request，则使用 pending request 的 chainID
	// 否则使用 base 的 chainID
	if len(t.pendingRequests) > 0 {
		pending := t.pendingRequests[0]
		t.pendingRequests[0] = pendingRequest{}
		t.pendingRequests = t.pendingRequests[1:]
		doc.ChainID = pending.chainID
		if pending.requestTS != nil && ts != nil {
			latency := ts.Sub(*pending.requestTS).Seconds() * 1000
			doc.ResponseLatency = &latency
		}
	} else {
		doc.ChainID = t.base.ChainID
	}

	return Update{Kind: "response", Trace: doc}
}

func (t *traceState) buildResponseUpdateFromPending(pending pendingRequest, msg *ParsedMessage, ts *time.Time, truncated bool) Update {
	doc := t.base
	doc.Kind = "response"
	doc.ChainID = pending.chainID
	doc.ResponseTS = cloneTimePtr(ts)
	doc.RequestTS = nil
	doc.Request = nil
	doc.Response = msg
	doc.CaptureSource = t.responseSource
	doc.RequestTruncated = false
	doc.ResponseTruncated = truncated
	if pending.requestTS != nil && ts != nil {
		latency := ts.Sub(*pending.requestTS).Seconds() * 1000
		doc.ResponseLatency = &latency
	} else {
		doc.ResponseLatency = nil
	}
	return Update{Kind: "response", Trace: doc}
}

func (t *traceState) queuePendingRequest(chainID uint64, msg *ParsedMessage, ts *time.Time, truncated bool, emitted bool) {
	t.requestEmitted = true
	t.pendingRequests = append(t.pendingRequests, pendingRequest{
		chainID:          chainID,
		requestTS:        cloneTimePtr(ts),
		request:          msg,
		requestMethod:    pendingRequestMethod(pendingRequest{request: msg}),
		requestTruncated: truncated,
		emitted:          emitted,
		requestSource:    t.requestSource,
		requestBase:      t.base,
	})
}

func pendingRequestMethod(pending pendingRequest) string {
	if pending.requestMethod != "" {
		return pending.requestMethod
	}
	if pending.request != nil {
		return pending.request.Method
	}
	return ""
}

func (t *traceState) makeRequestUpdate(pending pendingRequest) Update {
	if pending.requestBase.ChainID == 0 && pending.requestBase.SockID == 0 && pending.requestBase.PID == 0 {
		pending.requestBase = t.base
	}
	if pending.requestSource == "" {
		pending.requestSource = t.requestSource
	}
	return buildRequestUpdateFromPending(pending)
}

func (t *traceState) emitDelayedTLSRequestUpdate() (Update, bool) {
	if !isTLSSource(t.requestSource) || len(t.pendingRequests) == 0 {
		return Update{}, false
	}
	if t.pendingRequests[0].emitted {
		return Update{}, false
	}
	pending := t.pendingRequests[0]
	t.pendingRequests[0].emitted = true
	return t.makeRequestUpdate(pending), true
}

func (t *traceState) canDelete() bool {
	if t.tlsAssigned != nil {
		return false
	}
	return len(t.pendingRequests) == 0 &&
		len(t.requestStream.buffer) == 0 &&
		len(t.responseStream.buffer) == 0 &&
		len(t.requestStream.received) == 0 &&
		len(t.responseStream.received) == 0
}

func (t *traceState) shouldFlushStalledResponse(now time.Time, stall time.Duration) bool {
	if stall <= 0 {
		return false
	}
	if len(t.pendingRequests) == 0 || len(t.responseStream.buffer) == 0 {
		return false
	}
	if t.responseUpdated.IsZero() {
		return false
	}
	timeout := stall
	if timeout < minConservativeResponseStallTimeout && responseNeedsConservativeStall(t.responseStream.buffer) {
		timeout = minConservativeResponseStallTimeout
	}
	return now.Sub(t.responseUpdated) >= timeout
}

func responseNeedsConservativeStall(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	msg, _, _, ok, err := parseMessageHead(DirectionResponse, data)
	if err != nil || !ok || msg == nil {
		return false
	}
	if msg.Chunked {
		return true
	}
	if msg.StatusCode >= 400 {
		return true
	}
	if strings.EqualFold(msg.Headers["Connection"], "close") {
		return true
	}
	return false
}

func annotateParsedMessage(msg *ParsedMessage, stream *fragmentStream) {
	if msg == nil {
		return
	}
	if msg.BodySizeBytes == 0 {
		msg.BodySizeBytes = len(msg.Body)
	}
	if stream == nil {
		return
	}
	if stream.observedBytes > 0 {
		msg.ObservedMessageBytes = stream.observedBytes
		return
	}
	msg.ObservedMessageBytes = uint64(msg.ConsumedBytes)
}

func cloneTimePtr(ts *time.Time) *time.Time {
	if ts == nil {
		return nil
	}
	v := *ts
	return &v
}

func resyncStream(direction uint8, stream *fragmentStream) bool {
	if stream == nil || len(stream.buffer) == 0 {
		return false
	}
	idx := FindMessageStart(direction, stream.buffer)
	if idx > 0 {
		stream.consume(idx)
		return true
	}
	return false
}

func shouldEagerFlushErrorResponse(msg *ParsedMessage) bool {
	if msg == nil {
		return false
	}
	if msg.Direction != DirectionResponse || msg.StatusCode < 400 {
		return false
	}
	if msg.BodyPartial {
		return false
	}
	if msg.Chunked || msg.TransferEncoding != "" {
		return false
	}
	if strings.EqualFold(msg.Headers["Connection"], "close") {
		return false
	}
	return true
}

func responseUpdateTruncated(stream *fragmentStream, msg *ParsedMessage) bool {
	if msg != nil && msg.StatusCode == 502 {
		return false
	}
	if stream == nil {
		return msg != nil && msg.BodyPartial
	}
	if msg == nil {
		return stream.truncated
	}
	return stream.truncated || msg.BodyPartial
}

func maybePromoteStalledChunkedResponse(stream *fragmentStream, msg *ParsedMessage) {
	if stream == nil || msg == nil || !msg.Chunked || !msg.BodyPartial || stream.truncated {
		return
	}
	if stream.observedBytes == 0 || stream.observedBytes <= uint64(len(stream.buffer)) {
		return
	}
	_, _, bodyStart, ok, err := parseMessageHead(DirectionResponse, stream.buffer)
	if err != nil || !ok {
		return
	}
	decoded, missing, framingOnly := decodeChunkedBodyMissingOnlyFraming(stream.buffer[bodyStart:])
	if !framingOnly {
		return
	}
	missingObserved := int(stream.observedBytes) - len(stream.buffer)
	if missingObserved < missing {
		return
	}
	msg.Body = string(decoded)
	msg.BodySizeBytes = len(decoded)
	msg.BodyPartial = false
}

func (a *Assembler) deleteTraceState(shard *stateShard, chainID uint64, state *traceState) {
	if state == nil {
		delete(shard.traces, chainID)
		return
	}
	state.requestStream.consumeAll()
	state.responseStream.consumeAll()
	state.pendingRequests = nil
	if state.tlsAssigned != nil {
		a.releasePendingBody(state.tlsAssigned)
	}
	state.tlsAssigned = nil
	delete(shard.traces, chainID)
	a.activeStates.Add(-1)
	markClosedTLSChain(shard, chainID, state)
}

// SetMaxActiveStates 独立于分片字节数限制追踪元数据。仅大小事件的正文长度可能为零，
// 但追踪状态仍会持有映射、时间戳和待处理请求元数据。
func (a *Assembler) SetMaxActiveStates(limit int) {
	if a == nil {
		return
	}
	if limit <= 0 {
		limit = defaultMaxActiveStates
	}
	a.maxActiveStates.Store(int64(limit))
}

func (a *Assembler) reserveTraceState() bool {
	if a == nil {
		return false
	}
	limit := a.maxActiveStates.Load()
	for {
		current := a.activeStates.Load()
		if limit > 0 && current >= limit {
			return false
		}
		if a.activeStates.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// retainPendingBody 让会话 FIFO 中等待响应的 TLS 请求与未完成分片共用进程级上限。
// 已经输出的请求会进入拥有独立队列预算的控制台/Redis 管道，因此这里只统计 FIFO 副本。
func (a *Assembler) retainPendingBody(pending *pendingRequest) {
	if a == nil || pending == nil || pending.request == nil || pending.retainedBodyBytes > 0 {
		return
	}
	size := len(pending.request.Body)
	if size == 0 {
		return
	}
	if a.reserveStreamBytes(size) {
		pending.retainedBodyBytes = size
		return
	}
	// 保留已解析元数据和原始正文大小，但不保留会使聚合器超过配置预算的正文。
	pending.request.Body = ""
	pending.request.BodyPartial = true
	pending.requestTruncated = true
}

func (a *Assembler) releasePendingBody(pending *pendingRequest) {
	if a == nil || pending == nil || pending.retainedBodyBytes <= 0 {
		return
	}
	a.releaseStreamBytes(pending.retainedBodyBytes)
	pending.retainedBodyBytes = 0
}

func (s *fragmentStream) drain(maxMessageBytes int) {
	for {
		part, ok := s.received[s.nextFrag]
		if !ok {
			return
		}
		delete(s.received, s.nextFrag)
		s.nextFrag++
		if len(s.buffer)+len(part) > maxMessageBytes {
			remain := maxMessageBytes - len(s.buffer)
			if remain > 0 {
				s.buffer = append(s.buffer, part[:remain]...)
			}
			s.releaseBytes(len(part) - max(remain, 0))
			s.truncated = true
			continue
		}
		s.buffer = append(s.buffer, part...)
	}
}

func (s *fragmentStream) consume(n int) {
	if n <= 0 {
		return
	}
	if n >= len(s.buffer) {
		s.consumeAll()
		return
	}
	s.releaseBytes(n)
	s.buffer = append([]byte(nil), s.buffer[n:]...)
	if s.observedBytes > uint64(n) {
		s.observedBytes -= uint64(n)
	} else {
		s.observedBytes = 0
	}
	s.finalReady = false
}

func (s *fragmentStream) consumeAll() {
	released := len(s.buffer)
	for _, part := range s.received {
		released += len(part)
	}
	s.releaseBytes(released)
	s.buffer = nil
	if s.received != nil {
		for k := range s.received {
			delete(s.received, k)
		}
	}
	s.firstTS = nil
	s.observedBytes = 0
	s.truncated = false
	s.captureBoundary = false
	s.finalReady = false
}

func (s *fragmentStream) releaseBytes(n int) {
	if n > 0 && s.release != nil {
		s.release(n)
	}
}

func maxInt64(v, floor int64) int64 {
	if v < floor {
		return floor
	}
	return v
}

func summarizeDebugPrefix(payload []byte, limit int) string {
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

func (d TraceDocument) SummaryLine() string {
	switch {
	case d.Request != nil && d.Response == nil:
		return fmt.Sprintf("请求 chain=%d pid=%d fd=%d source=%s %s %s", d.ChainID, d.PID, d.FD, d.CaptureSource, d.Request.Method, d.Request.URL)
	case d.Request != nil && d.Response != nil:
		latency := 0.0
		if d.ResponseLatency != nil {
			latency = *d.ResponseLatency
		}
		return fmt.Sprintf("响应 chain=%d pid=%d fd=%d source=%s %d %.2fms", d.ChainID, d.PID, d.FD, d.CaptureSource, d.Response.StatusCode, latency)
	case d.Request == nil && d.Response != nil:
		return fmt.Sprintf("响应 chain=%d pid=%d fd=%d source=%s %d", d.ChainID, d.PID, d.FD, d.CaptureSource, d.Response.StatusCode)
	default:
		return fmt.Sprintf("追踪 chain=%d pid=%d fd=%d source=%s", d.ChainID, d.PID, d.FD, d.CaptureSource)
	}
}
