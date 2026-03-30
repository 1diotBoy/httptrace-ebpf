package httptrace

import (
	"fmt"
	"sync"
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
	SrcIP             string         `json:"src_ip"`
	DstIP             string         `json:"dst_ip"`
	SrcPort           uint16         `json:"src_port"`
	DstPort           uint16         `json:"dst_port"`
	RequestTS         *time.Time     `json:"request_ts,omitempty"`
	ResponseTS        *time.Time     `json:"response_ts,omitempty"`
	ResponseLatency   *float64       `json:"response_latency_ms,omitempty"`
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
	shards          []stateShard
	maxMessageBytes int
	maxIdle         time.Duration
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
	logicalSeq      uint64
	pendingRequests []pendingRequest
}

type fragmentStream struct {
	received   map[uint16][]byte
	nextFrag   uint16
	buffer     []byte
	truncated  bool
	firstTS    *time.Time
}

type pendingRequest struct {
	chainID          uint64
	requestTS        *time.Time
	request          *ParsedMessage
	requestTruncated bool
}

// NewAssembler 创建请求/响应聚合器。
// 它按 chain_id 把多次 perf 事件重组成一条 HTTP 请求/响应，再交给 parser。
func NewAssembler(maxMessageBytes int, maxIdle time.Duration) *Assembler {
	shards := make([]stateShard, 64)
	for i := range shards {
		shards[i].traces = make(map[uint64]*traceState)
	}
	return &Assembler{
		shards:          shards,
		maxMessageBytes: maxMessageBytes,
		maxIdle:         maxIdle,
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
				ChainID: event.ChainID,
				SockID:  event.SockID,
				PID:     event.PID,
				TID:     event.TID,
				FD:      event.FD,
				IfIndex: event.IfIndex,
				Comm:    event.Comm,
				SrcIP:   event.SrcIP,
				DstIP:   event.DstIP,
				SrcPort: event.SrcPort,
				DstPort: event.DstPort,
			},
			requestStream:  fragmentStream{received: make(map[uint16][]byte)},
			responseStream: fragmentStream{received: make(map[uint16][]byte)},
		}
		shard.traces[event.ChainID] = state
	}
	state.lastUpdated = time.Now()

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

func (a *Assembler) EvictExpired(now time.Time) int {
	evicted := 0
	for i := range a.shards {
		shard := &a.shards[i]
		shard.mu.Lock()
		for chainID, state := range shard.traces {
			if now.Sub(state.lastUpdated) <= a.maxIdle {
				continue
			}
			delete(shard.traces, chainID)
			evicted++
		}
		shard.mu.Unlock()
	}
	return evicted
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

	if eof && state.canDelete() {
		delete(shard.traces, chainID)
	}
	return updates, nil
}

func (a *Assembler) emitRequests(state *traceState, eof bool) ([]Update, error) {
	updates := make([]Update, 0, 2)

	for len(state.requestStream.buffer) > 0 {
		msg, complete, err := TryParseMessage(DirectionRequest, state.requestStream.buffer, ParseOptions{EOF: eof})
		if err != nil {
			return updates, nil
		}
		if complete {
			updates = append(updates, state.buildRequestUpdate(a.nextLogicalChainID(state), msg, state.requestStream.firstTS, false))
			state.requestStream.consume(msg.ConsumedBytes)
			continue
		}

		if !(state.requestStream.truncated || eof) {
			return updates, nil
		}

		msg, ok, err := TryParseMessageHead(DirectionRequest, state.requestStream.buffer, ParseOptions{EOF: eof})
		if err != nil {
			return updates, nil
		}
		if !ok {
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

	for len(state.responseStream.buffer) > 0 {
		opts := ParseOptions{EOF: eof}
		if len(state.pendingRequests) > 0 && state.pendingRequests[0].request != nil {
			opts.RequestMethod = state.pendingRequests[0].request.Method
		}

		msg, complete, err := TryParseMessage(DirectionResponse, state.responseStream.buffer, opts)
		if err != nil {
			return updates, nil
		}
		if complete {
			updates = append(updates, state.buildResponseUpdate(msg, state.responseStream.firstTS, false))
			state.responseStream.consume(msg.ConsumedBytes)
			continue
		}

		if !(state.responseStream.truncated || eof) {
			return updates, nil
		}

		msg, ok, err := TryParseMessageHead(DirectionResponse, state.responseStream.buffer, opts)
		if err != nil {
			return updates, nil
		}
		if !ok {
			return updates, nil
		}
		updates = append(updates, state.buildResponseUpdate(msg, state.responseStream.firstTS, state.responseStream.truncated || msg.BodyPartial))
		state.responseStream.consumeAll()
		return updates, nil
	}

	return updates, nil
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

func (t *traceState) buildResponseUpdate(msg *ParsedMessage, ts *time.Time, truncated bool) Update {
	doc := t.base
	doc.Kind = "response"
	doc.ResponseTS = cloneTimePtr(ts)
	doc.RequestTS = nil
	doc.Request = nil
	doc.Response = msg
	doc.RequestTruncated = false
	doc.ResponseTruncated = truncated

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

func cloneTimePtr(ts *time.Time) *time.Time {
	if ts == nil {
		return nil
	}
	v := *ts
	return &v
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
		return fmt.Sprintf("request chain=%d pid=%d fd=%d %s %s", d.ChainID, d.PID, d.FD, d.Request.Method, d.Request.URL)
	case d.Request != nil && d.Response != nil:
		latency := 0.0
		if d.ResponseLatency != nil {
			latency = *d.ResponseLatency
		}
		return fmt.Sprintf("response chain=%d pid=%d fd=%d %d %.2fms", d.ChainID, d.PID, d.FD, d.Response.StatusCode, latency)
	case d.Request == nil && d.Response != nil:
		return fmt.Sprintf("response chain=%d pid=%d fd=%d %d", d.ChainID, d.PID, d.FD, d.Response.StatusCode)
	default:
		return fmt.Sprintf("trace chain=%d pid=%d fd=%d", d.ChainID, d.PID, d.FD)
	}
}
