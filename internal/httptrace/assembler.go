package httptrace

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Timestamp time.Time
	TsNS      uint64
	ChainID   uint64
	SockID    uint64
	SeqHint   uint64
	PID       uint32
	TID       uint32
	FD        int32
	IfIndex   uint32
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	FragIdx   uint16
	Direction uint8
	Flags     uint8
	Comm      string
	Source    string
	Payload   []byte
}

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
	// TraceID           string         `json:trace_id`
}

type Update struct {
	Kind  string
	Trace TraceDocument
}

type Assembler struct {
	shards            []stateShard
	maxMessageBytes   int
	maxIdle           time.Duration
	responseStall     time.Duration
	stalledFlushes    atomic.Uint64
	evictedFlushes    atomic.Uint64
	orphanResponses   atomic.Uint64
	promotedRequests  atomic.Uint64
	deferredResponses atomic.Uint64
}

type stateShard struct {
	mu     sync.Mutex
	traces map[uint64]*traceState
}

type traceState struct {
	base            TraceDocument
	requestStream   fragmentStream
	responseStream  fragmentStream
	lastUpdated     time.Time
	responseUpdated time.Time
	logicalSeq      uint64
	pendingRequests []pendingRequest
	requestSource   string
	responseSource  string
}

type fragmentStream struct {
	received  map[uint16][]byte
	nextFrag  uint16
	buffer    []byte
	truncated bool
	firstTS   *time.Time
}

type pendingRequest struct {
	chainID          uint64
	requestTS        *time.Time
	request          *ParsedMessage
	requestTruncated bool
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
}

// NewAssembler 创建请求/响应聚合器。
// 它按 chain_id 把多次 perf 事件重组成一条 HTTP 请求/响应，再交给 parser。
func NewAssembler(maxMessageBytes int, maxIdle, responseStall time.Duration) *Assembler {
	shards := make([]stateShard, 64)
	for i := range shards {
		shards[i].traces = make(map[uint64]*traceState)
	}
	if responseStall <= 0 {
		responseStall = 500 * time.Millisecond
	}
	return &Assembler{
		shards:          shards,
		maxMessageBytes: maxMessageBytes,
		maxIdle:         maxIdle,
		responseStall:   responseStall,
	}
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

	state := shard.traces[event.ChainID]
	if event.Flags&(1<<4) != 0 && event.Flags&(1<<5) != 0 {
		if state == nil {
			return nil, nil
		}
		state.lastUpdated = time.Now()
		return a.finalizeOnClose(state, shard, event.ChainID)
	}

	if state == nil {
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
			requestStream:  fragmentStream{received: make(map[uint16][]byte)},
			responseStream: fragmentStream{received: make(map[uint16][]byte)},
			requestSource:  event.Source,
			responseSource: event.Source,
		}
		shard.traces[event.ChainID] = state
	}
	refreshBaseTuple(&state.base, event)
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

	var stream *fragmentStream
	switch event.Direction {
	case DirectionRequest:
		stream = &state.requestStream
	case DirectionResponse:
		stream = &state.responseStream
	default:
		return nil, nil
	}

	if stream.firstTS == nil {
		ts := event.Timestamp
		stream.firstTS = &ts
	}
	if len(event.Payload) > 0 {
		if !stream.truncated {
			if _, exists := stream.received[event.FragIdx]; !exists {
				stream.received[event.FragIdx] = append([]byte(nil), event.Payload...)
			}
		}
	}
	if event.Flags&(1<<2) != 0 {
		stream.truncated = true
	}
	if !stream.truncated {
		stream.drain(a.maxMessageBytes)
	} else {
		for frag := range stream.received {
			if frag < stream.nextFrag {
				delete(stream.received, frag)
			}
		}
		stream.drain(a.maxMessageBytes)
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
			if !state.shouldFlushStalledResponse(now, a.responseStall) {
				continue
			}
			flushed := a.flushPartialResponse(state)
			if len(flushed) > 0 {
				updates = append(updates, flushed...)
				a.stalledFlushes.Add(uint64(len(flushed)))
			}
			if state.canDelete() {
				delete(shard.traces, chainID)
			}
		}
		shard.mu.Unlock()
	}
	return updates
}

func (a *Assembler) EvictExpired(now time.Time) ([]Update, int) {
	evicted := 0
	updates := make([]Update, 0, 16)
	for i := range a.shards {
		shard := &a.shards[i]
		shard.mu.Lock()
		for chainID, state := range shard.traces {
			if now.Sub(state.lastUpdated) <= a.maxIdle {
				continue
			}
			flushed, _ := a.tryEmitUpdates(state, shard, chainID, true)
			if len(flushed) > 0 {
				updates = append(updates, flushed...)
				a.evictedFlushes.Add(uint64(len(flushed)))
			}
			delete(shard.traces, chainID)
			evicted++
		}
		shard.mu.Unlock()
	}
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
			delete(shard.traces, chainID)
			flushedStates++
		}
		shard.mu.Unlock()
	}
	return updates, flushedStates
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
	snap.StalledResponseFlushes = a.stalledFlushes.Load()
	snap.EvictedFlushes = a.evictedFlushes.Load()
	snap.OrphanResponses = a.orphanResponses.Load()
	snap.PromotedRequests = a.promotedRequests.Load()
	snap.DeferredResponses = a.deferredResponses.Load()
	return snap
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
		delete(shard.traces, chainID)
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
		delete(shard.traces, chainID)
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
			updates = append(updates, state.buildRequestUpdate(a.nextLogicalChainID(state), msg, state.requestStream.firstTS, false))
			state.requestStream.consume(msg.ConsumedBytes)
			continue
		}

		if resyncStream(DirectionRequest, &state.requestStream) {
			continue
		}

		if !(state.requestStream.truncated || eof) {
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
		updates = append(updates, state.buildRequestUpdate(a.nextLogicalChainID(state), msg, state.requestStream.firstTS, state.requestStream.truncated || msg.BodyPartial))
		state.requestStream.consumeAll()
		return updates, nil
	}

	return updates, nil
}

func (a *Assembler) emitResponses(state *traceState, eof bool) ([]Update, error) {
	updates := make([]Update, 0, 2)

	promoted, err := a.promoteRequestForResponse(state)
	if err != nil {
		return nil, err
	}
	updates = append(updates, promoted...)

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
	if len(state.pendingRequests) == 0 && len(state.responseStream.buffer) > 0 && !eof && !state.responseStream.truncated {
		a.deferredResponses.Add(1)
		return updates, nil
	}

	for len(state.responseStream.buffer) > 0 {
		opts := ParseOptions{EOF: eof}
		if len(state.pendingRequests) > 0 && state.pendingRequests[0].request != nil {
			opts.RequestMethod = state.pendingRequests[0].request.Method
		}

		msg, complete, err := TryParseMessage(DirectionResponse, state.responseStream.buffer, opts)
		if err != nil {
			if resyncStream(DirectionResponse, &state.responseStream) {
				continue
			}
			return updates, nil
		}
		if complete {
			if len(state.pendingRequests) == 0 {
				a.orphanResponses.Add(1)
			}
			updates = append(updates, state.buildResponseUpdate(msg, state.responseStream.firstTS, false))
			state.responseStream.consume(msg.ConsumedBytes)
			continue
		}

		// 对 4xx/5xx 这类异常响应，优先保证“有记录、有 body”，而不是一直等到完整 body。
		// 这些异常页/错误 JSON 在不同框架/容器/Nginx 路径里，body 很容易被拆到后续 send 中，
		// 如果这里仍按 200 的策略等待完整响应，经常会在高并发下积压成 pending_resp。
		if head, ok, err := TryParseMessageHead(DirectionResponse, state.responseStream.buffer, opts); err == nil && ok && shouldEagerFlushErrorResponse(head) {
			if len(state.pendingRequests) == 0 {
				a.orphanResponses.Add(1)
			}
			updates = append(updates, state.buildResponseUpdate(head, state.responseStream.firstTS, true))
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
		if len(state.pendingRequests) > 1 {
			msg, consumed, ok, err := splitAndParsePartialResponse(state.responseStream.buffer, opts)
			if err != nil {
				return updates, nil
			}
			if ok {
				if len(state.pendingRequests) == 0 {
					a.orphanResponses.Add(1)
				}
				updates = append(updates, state.buildResponseUpdate(msg, state.responseStream.firstTS, true))
				state.responseStream.consume(consumed)
				continue
			}
		}

		if !(state.responseStream.truncated || eof) {
			return updates, nil
		}

		msg, ok, err := TryParseMessageHead(DirectionResponse, state.responseStream.buffer, opts)
		if err != nil {
			if resyncStream(DirectionResponse, &state.responseStream) {
				continue
			}
			if synthetic, ok := BuildSyntheticResponse(state.responseStream.buffer); ok {
				if len(state.pendingRequests) == 0 {
					a.orphanResponses.Add(1)
				}
				updates = append(updates, state.buildResponseUpdate(synthetic, state.responseStream.firstTS, true))
				state.responseStream.consumeAll()
			}
			return updates, nil
		}
		if !ok {
			if resyncStream(DirectionResponse, &state.responseStream) {
				continue
			}
			if synthetic, ok := BuildSyntheticResponse(state.responseStream.buffer); ok {
				if len(state.pendingRequests) == 0 {
					a.orphanResponses.Add(1)
				}
				updates = append(updates, state.buildResponseUpdate(synthetic, state.responseStream.firstTS, true))
				state.responseStream.consumeAll()
			}
			return updates, nil
		}
		if len(state.pendingRequests) == 0 {
			a.orphanResponses.Add(1)
		}
		updates = append(updates, state.buildResponseUpdate(msg, state.responseStream.firstTS, state.responseStream.truncated || msg.BodyPartial))
		state.responseStream.consumeAll()
		return updates, nil
	}

	return updates, nil
}

func (a *Assembler) promoteRequestForResponse(state *traceState) ([]Update, error) {
	if len(state.pendingRequests) > 0 || len(state.requestStream.buffer) == 0 || len(state.responseStream.buffer) == 0 {
		return nil, nil
	}

	msg, complete, err := TryParseMessage(DirectionRequest, state.requestStream.buffer, ParseOptions{EOF: false})
	if err == nil && complete {
		a.promotedRequests.Add(1)
		update := state.buildRequestUpdate(a.nextLogicalChainID(state), msg, state.requestStream.firstTS, false)
		state.requestStream.consume(msg.ConsumedBytes)
		return []Update{update}, nil
	}

	msg, ok, err := TryParseMessageHead(DirectionRequest, state.requestStream.buffer, ParseOptions{EOF: true})
	if err != nil || !ok {
		return nil, err
	}

	a.promotedRequests.Add(1)
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
	if len(state.pendingRequests) == 0 || len(state.responseStream.buffer) == 0 {
		return nil
	}

	opts := ParseOptions{}
	if state.pendingRequests[0].request != nil {
		opts.RequestMethod = state.pendingRequests[0].request.Method
	}

	if msg, complete, err := TryParseMessage(DirectionResponse, state.responseStream.buffer, opts); err == nil && complete {
		if len(state.pendingRequests) == 0 {
			a.orphanResponses.Add(1)
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
		if synthetic, ok := BuildSyntheticResponse(state.responseStream.buffer); ok {
			if len(state.pendingRequests) == 0 {
				a.orphanResponses.Add(1)
			}
			update := state.buildResponseUpdate(synthetic, state.responseStream.firstTS, true)
			state.responseStream.consumeAll()
			return []Update{update}
		}
		return nil
	}
	if len(state.pendingRequests) == 0 {
		a.orphanResponses.Add(1)
	}
	update := state.buildResponseUpdate(msg, state.responseStream.firstTS, true)
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
	doc := t.base
	doc.Kind = "request"
	doc.ChainID = chainID
	doc.RequestTS = cloneTimePtr(ts)
	doc.ResponseTS = nil
	doc.ResponseLatency = nil
	doc.Request = msg
	doc.Response = nil
	doc.CaptureSource = t.requestSource
	doc.RequestTruncated = truncated
	doc.ResponseTruncated = false

	t.pendingRequests = append(t.pendingRequests, pendingRequest{
		chainID:          chainID,
		requestTS:        cloneTimePtr(ts),
		request:          msg,
		requestTruncated: truncated,
	})

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

func (t *traceState) canDelete() bool {
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
	return now.Sub(t.responseUpdated) >= stall
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
	return msg.Direction == DirectionResponse && msg.StatusCode >= 400
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
	s.buffer = append([]byte(nil), s.buffer[n:]...)
}

func (s *fragmentStream) consumeAll() {
	s.buffer = nil
	s.firstTS = nil
	s.truncated = false
}

func (d TraceDocument) SummaryLine() string {
	switch {
	case d.Request != nil && d.Response == nil:
		return fmt.Sprintf("request chain=%d pid=%d fd=%d source=%s %s %s", d.ChainID, d.PID, d.FD, d.CaptureSource, d.Request.Method, d.Request.URL)
	case d.Request != nil && d.Response != nil:
		latency := 0.0
		if d.ResponseLatency != nil {
			latency = *d.ResponseLatency
		}
		return fmt.Sprintf("response chain=%d pid=%d fd=%d source=%s %d %.2fms", d.ChainID, d.PID, d.FD, d.CaptureSource, d.Response.StatusCode, latency)
	case d.Request == nil && d.Response != nil:
		return fmt.Sprintf("response chain=%d pid=%d fd=%d source=%s %d", d.ChainID, d.PID, d.FD, d.CaptureSource, d.Response.StatusCode)
	default:
		return fmt.Sprintf("trace chain=%d pid=%d fd=%d source=%s", d.ChainID, d.PID, d.FD, d.CaptureSource)
	}
}
