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
	doc               TraceDocument
	requestStream     fragmentStream
	responseStream    fragmentStream
	requestEmitted    bool
	responseEmitted   bool
	lastUpdated       time.Time
	requestMethodHint string
}

type fragmentStream struct {
	received   map[uint16][]byte
	nextFrag   uint16
	buffer     []byte
	truncated  bool
	parseError string
	complete   bool
	message    *ParsedMessage
	firstTS    *time.Time
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
			doc: TraceDocument{
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
		if state.doc.RequestTS == nil {
			ts := event.Timestamp
			state.doc.RequestTS = &ts
		}
	case DirectionResponse:
		stream = &state.responseStream
		if state.doc.ResponseTS == nil {
			ts := event.Timestamp
			state.doc.ResponseTS = &ts
		}
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
	if state.requestEmitted && state.responseEmitted {
		delete(shard.traces, chainID)
	}
	return updates, nil
}

func (a *Assembler) tryEmitUpdates(state *traceState, shard *stateShard, chainID uint64, eof bool) ([]Update, error) {
	updates := make([]Update, 0, 2)

	if !state.requestStream.complete {
		msg, complete, err := TryParseMessage(DirectionRequest, state.requestStream.buffer, ParseOptions{EOF: eof})
		if err != nil {
			state.requestStream.parseError = err.Error()
		} else if complete {
			state.requestStream.complete = true
			state.requestStream.message = msg
			state.requestMethodHint = msg.Method
			state.doc.Request = msg
			state.doc.RequestTruncated = state.requestStream.truncated
		}
	}

	if !state.requestStream.complete && !state.requestEmitted && (state.requestStream.truncated || eof) {
		msg, ok, err := TryParseMessageHead(DirectionRequest, state.requestStream.buffer, ParseOptions{EOF: eof})
		if err != nil {
			state.requestStream.parseError = err.Error()
		} else if ok {
			state.requestMethodHint = msg.Method
			state.doc.Request = msg
			state.doc.RequestTruncated = state.requestStream.truncated || msg.BodyPartial
			state.requestStream.complete = eof || state.requestStream.truncated
		}
	}

	if state.requestStream.complete && !state.requestEmitted {
		state.requestEmitted = true
		updates = append(updates, Update{Kind: "request", Trace: state.snapshotRequest()})
	}

	if !state.responseStream.complete {
		msg, complete, err := TryParseMessage(DirectionResponse, state.responseStream.buffer, ParseOptions{
			RequestMethod: state.requestMethodHint,
			EOF:           eof,
		})
		if err != nil {
			state.responseStream.parseError = err.Error()
		} else if complete {
			state.responseStream.complete = true
			state.responseStream.message = msg
			state.doc.Response = msg
			state.doc.ResponseTruncated = state.responseStream.truncated
			if state.doc.RequestTS != nil && state.doc.ResponseTS != nil {
				latency := state.doc.ResponseTS.Sub(*state.doc.RequestTS).Seconds() * 1000
				state.doc.ResponseLatency = &latency
			}
		}
	}

	// 响应优先等完整 body。
	// 只有连接关闭或抓包被截断时，才降级成“头完整 + 部分 body”的 response，
	// 这样既不会把 request 卡到 response 一起输出，也尽量保留完整响应体。
	if !state.responseStream.complete && !state.responseEmitted && (state.responseStream.truncated || eof) {
		msg, ok, err := TryParseMessageHead(DirectionResponse, state.responseStream.buffer, ParseOptions{
			RequestMethod: state.requestMethodHint,
			EOF:           eof,
		})
		if err != nil {
			state.responseStream.parseError = err.Error()
		} else if ok {
			state.doc.Response = msg
			state.doc.ResponseTruncated = state.responseStream.truncated || msg.BodyPartial
			if state.doc.RequestTS != nil && state.doc.ResponseTS != nil {
				latency := state.doc.ResponseTS.Sub(*state.doc.RequestTS).Seconds() * 1000
				state.doc.ResponseLatency = &latency
			}
			state.responseStream.complete = eof || state.responseStream.truncated
		}
	}

	if state.doc.Response != nil && !state.responseEmitted {
		state.responseEmitted = true
		updates = append(updates, Update{Kind: "response", Trace: state.snapshotResponse()})
	}

	if state.requestEmitted && state.responseEmitted && (state.responseStream.complete || eof) {
		delete(shard.traces, chainID)
	}
	return updates, nil
}

func (t *traceState) snapshot() TraceDocument {
	doc := t.doc
	return doc
}

// snapshotRequest 返回“纯请求”视图，专门给控制台打印和 Redis 入库。
func (t *traceState) snapshotRequest() TraceDocument {
	doc := t.snapshot()
	doc.Kind = "request"
	doc.ResponseTS = nil
	doc.ResponseLatency = nil
	doc.Response = nil
	doc.ResponseTruncated = false
	return doc
}

// snapshotResponse 返回“纯响应”视图，避免把 request/response 混在同一条 JSON 里。
func (t *traceState) snapshotResponse() TraceDocument {
	doc := t.snapshot()
	doc.Kind = "response"
	doc.RequestTS = nil
	doc.Request = nil
	doc.RequestTruncated = false
	return doc
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
